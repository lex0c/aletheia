package mcp

import (
	"encoding/json"
	"sync"
)

// A negociação de era, e o único estado que este servidor guarda.
//
// A 2026-07-28 é STATELESS por desenho: "Servers MUST NOT rely on prior
// requests over the same connection to establish context". Toda requisição
// moderna traz a própria versão e as próprias capabilities em `params._meta`, e
// é dali que a era sai.
//
// A era LEGADA não tem como fazer isso: em 2025-11-25 a versão é acordada uma
// vez, no `initialize`, e as requisições seguintes não a repetem. Então o
// handshake legado — e SÓ ele — deixa um resíduo de conexão. Está registrado
// aqui em voz alta porque é a única exceção à statelessness, e alguém vai
// perguntar por que ela existe.

// Sessao guarda a versão acordada por um handshake legado. Vazia significa que
// nenhum `initialize` aconteceu nesta conexão.
type Sessao struct {
	mu     sync.Mutex
	legado string
}

func (s *Sessao) fixarLegado(v string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.legado = v
}

func (s *Sessao) versaoLegada() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.legado
}

// EraDe decide em que formato de fio esta requisição deve ser respondida.
//
// # Por que a era ambígua é RECUSADA em vez de adivinhada
//
// Não é escolha de estilo: a spec classifica requisição sem campo obrigatório
// como malformada e manda recusá-la com -32602. E a razão coincide com a desta
// ferramenta — adivinhar produz um documento que o cliente ACEITA e lê errado.
// Uma resposta de era 2025 entregue a um cliente de 2026 chega sem `resultType`,
// e a spec manda o cliente tratar ausência como `"complete"`; o inverso entrega
// campos que o cliente de 2025 ignora. Nos dois casos não há erro visível, e é
// exatamente essa classe de falha — silenciosa, com cara de resposta — que o
// resto do repositório existe para não cometer.
//
// Os dois códigos são DIFERENTES e a diferença importa para quem depura:
//
//	-32602  o campo obrigatório não veio (requisição malformada)
//	-32022  o campo veio com uma versão que este servidor não fala
//
// Confundi-los manda o cliente renegociar versão quando o problema era outro.
func (s *Sessao) EraDe(r *Requisicao) (Era, *ErroRPC) {
	m := lerMeta(r.Params)
	if m != nil && m.Versao != "" {
		// A spec exige clientCapabilities em TODA requisição, e a ausência é
		// malformação — não "capabilities vazias". `{}` é uma resposta; ausente
		// não é.
		if m.Caps == nil {
			return EraLegado, erroComDados(CodInvalidParams,
				"requisição sem "+MetaCapsCliente+" em params._meta: a spec 2026-07-28 "+
					"exige o campo em toda requisição (use {} se não houver nenhuma)",
				map[string]any{"missingField": MetaCapsCliente})
		}
		era, ok := EraDaVersao(m.Versao)
		if !ok {
			return EraLegado, erroComDados(CodVersaoNaoSuportada,
				"versão de protocolo não suportada: "+m.Versao,
				map[string]any{"supported": VersoesSuportadas})
		}
		return era, nil
	}
	if v := s.versaoLegada(); v != "" {
		return EraLegado, nil
	}
	return EraLegado, erroComDados(CodInvalidParams,
		"requisição sem "+MetaVersao+" em params._meta e sem handshake `initialize` "+
			"anterior: a era do protocolo é ambígua, e respondê-la no formato errado "+
			"produziria um documento que o cliente lê torto sem erro nenhum",
		map[string]any{"missingField": MetaVersao, "supported": VersoesSuportadas})
}

// ---------------------------------------------------------------- era legada

// paramsInitialize é o handshake de 2025-11-25 e anteriores. A versão vem no
// CORPO de params, e não em `_meta` — que nem existia com esse papel.
type paramsInitialize struct {
	ProtocolVersion string         `json:"protocolVersion"`
	ClientInfo      *Implementacao `json:"clientInfo"`
}

// resultadoInitialize é a resposta do handshake legado. Sem `resultType`: ele é
// da era 2026, e mandá-lo aqui seria vazamento de era.
type resultadoInitialize struct {
	ProtocolVersion string         `json:"protocolVersion"`
	Capabilities    Capacidades    `json:"capabilities"`
	ServerInfo      Implementacao  `json:"serverInfo"`
	Instructions    string         `json:"instructions,omitempty"`
	Meta            map[string]any `json:"_meta,omitempty"`
}

// Capacidades é o que este servidor oferece. Só tools: sem prompts, sem
// resources, sem logging, sem completions. Declarar capability que não se
// implementa faz o cliente chamar método que não existe.
type Capacidades struct {
	Tools *CapTools `json:"tools,omitempty"`
}

// CapTools sem `listChanged`: o registry é ESTÁTICO, fixado no lançamento do
// processo pelas flags. Ele não muda enquanto o servidor vive, então não há
// notificação a prometer — e prometer uma que nunca chega faz o cliente segurar
// cache velho esperando invalidação.
type CapTools struct{}

// tratarInitialize responde ao handshake legado e fixa a versão da conexão.
//
// Um `initialize` REPETIDO não é erro: a spec de 2025 não proíbe, e um cliente
// que reconecta o mesmo processo o reenvia. Ele simplesmente renegocia.
func (s *Sessao) tratarInitialize(srv *Servidor, r *Requisicao) (json.RawMessage, *ErroRPC) {
	var p paramsInitialize
	if len(r.Params) > 0 {
		if err := json.Unmarshal(r.Params, &p); err != nil {
			return nil, erro(CodInvalidParams, "params de initialize ilegíveis")
		}
	}

	// A versão que sai é a que o cliente pediu, quando este servidor a fala.
	// Quando não fala, sai a legada preferida — e o cliente decide se continua.
	// Devolver a versão PEDIDA sem falá-la seria a mentira de compatibilidade
	// mais cara possível: os dois lados seguiriam achando que combinaram.
	versao := Versao2025
	if era, ok := EraDaVersao(p.ProtocolVersion); ok && era == EraLegado {
		versao = p.ProtocolVersion
	}
	s.fixarLegado(versao)

	b, err := json.Marshal(resultadoInitialize{
		ProtocolVersion: versao,
		Capabilities:    Capacidades{Tools: &CapTools{}},
		ServerInfo:      srv.identidade(),
		Instructions:    Instrucoes,
	})
	if err != nil {
		return nil, erro(CodInternalError, "falha ao serializar initialize")
	}
	return b, nil
}
