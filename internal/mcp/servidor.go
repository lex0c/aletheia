package mcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/lex0c/aletheia/internal/env"
)

// Servidor é uma execução: uma policy, um acervo e um transporte.
type Servidor struct {
	pol    Policy
	acervo *Acervo
	versao string
	sessao Sessao
	aud    *Auditoria

	// O registry é resolvido UMA VEZ, no lançamento. Ele não pode variar por
	// conexão (a 2026-07-28 tornou as listas cacheáveis), e resolvê-lo por
	// chamada abriria a porta para ele variar por acidente.
	ativas  []Ferramenta
	fora    []Indisponivel
	porNome map[string]Ferramenta
}

// NovoServidor monta o servidor e CONGELA o registry.
func NovoServidor(p Policy, a *Acervo, versao string, aud *Auditoria) *Servidor {
	p = p.Padroes()
	fontes := a.Fontes()
	if f, ok := p.FonteDoModo(); ok {
		fontes |= f
	}
	ativas, fora := Registry(p, fontes)
	porNome := make(map[string]Ferramenta, len(ativas))
	for _, f := range ativas {
		porNome[f.Nome] = f
	}
	return &Servidor{pol: p, acervo: a, versao: versao, aud: aud,
		ativas: ativas, fora: fora, porNome: porNome}
}

func (s *Servidor) identidade() Implementacao {
	return Implementacao{Nome: "aletheia", Versao: s.versao}
}

// Policy e Acervo para as tools.
func (s *Servidor) Policy() Policy  { return s.pol }
func (s *Servidor) Acervo() *Acervo { return s.acervo }

// Ativas e Indisponiveis são o registry congelado, para quem lança o servidor
// poder dizer ao operador o que ele acabou de expor.
func (s *Servidor) Ativas() []Ferramenta          { return s.ativas }
func (s *Servidor) Indisponiveis() []Indisponivel { return s.fora }

// Fontes é a união do que este servidor pode responder.
func (s *Servidor) Fontes() env.Source {
	f := s.acervo.Fontes()
	if x, ok := s.pol.FonteDoModo(); ok {
		f |= x
	}
	return f
}

// Servir roda o laço até o fim da entrada.
//
// # Por que o laço é SEQUENCIAL
//
// Uma requisição por vez, resposta antes da próxima leitura. Em ModoSnapshot
// toda tool responde de memória sobre um retrato imutável, e a mais cara —
// findings.list, que roda o catálogo — é memoizada por retrato. Não há o que
// paralelizar, e concorrência aqui compraria uma classe inteira de corridas em
// troca de nada.
//
// O efeito colateral é bom: `notifications/cancelled` fica trivialmente
// correto. A spec manda o servidor parar o trabalho cancelado assim que
// praticável e NÃO mandar mais mensagem para aquele id. Como nunca há
// requisição em voo enquanto se lê, ou a resposta já saiu (e não há o que
// parar) ou ela ainda não começou (e o cancelamento chega antes). Quando a
// aquisição live entrar, isto deixa de ser verdade — e aí o limite tem de ser
// DITO, não fingido.
func (s *Servidor) Servir(entrada io.Reader, saida io.Writer) error {
	l := NovoLeitor(entrada, s.pol.MaxLinha)
	w := NovoEscritor(saida)

	for {
		linha, err := l.Linha()
		switch {
		case errors.Is(err, ErrFrameGrande):
			// O id não pôde ser lido — a linha nunca foi montada. A spec
			// JSON-RPC manda `null` nesse caso, e é o único lugar onde o id
			// nulo é legítimo.
			s.responderErro(w, json.RawMessage("null"), erro(CodInvalidRequest,
				"frame acima do teto deste servidor: a mensagem foi RECUSADA sem "+
					"ser alocada, e a leitura seguiu a partir da próxima linha"))
			continue
		case errors.Is(err, io.EOF):
			// Entrada fechada é o sinal de shutdown do stdio, e o único
			// portátil. Sair rápido evita que o cliente precise matar.
			return nil
		case err != nil:
			return err
		}

		req, erpc := decodificar(linha)
		if erpc != nil {
			s.responderErro(w, json.RawMessage("null"), erpc)
			continue
		}
		if req.EhNotificacao() {
			s.tratarNotificacao(req)
			continue
		}
		s.tratar(w, req)
	}
}

// tratarNotificacao: o receptor NÃO responde, nem para método desconhecido.
func (s *Servidor) tratarNotificacao(r *Requisicao) {
	if s.aud != nil {
		s.aud.Notificacao(r.Method)
	}
}

func (s *Servidor) tratar(w *Escritor, r *Requisicao) {
	fim := s.aud.Comeco(r.Method)

	// `initialize` é da era legada por definição: ele é o handshake, e não
	// carrega `_meta` com versão porque em 2025 isso não existia. Perguntar a
	// era antes dele recusaria todo cliente legado na primeira mensagem.
	if r.Method == "initialize" {
		res, erpc := s.sessao.tratarInitialize(s, r)
		s.responder(w, r, EraLegado, res, erpc, fim)
		return
	}

	era, erpc := s.sessao.EraDe(r)
	if erpc != nil {
		s.responder(w, r, EraLegado, nil, erpc, fim)
		return
	}

	var (
		corpo map[string]any
		er    *ErroRPC
	)
	switch r.Method {
	case "server/discover":
		corpo, er = s.discover()
	case "tools/list":
		corpo, er = s.listarTools()
	case "tools/call":
		corpo, er = s.chamarTool(r)
	default:
		er = erro(CodMethodNotFound, "método desconhecido: "+r.Method)
	}
	if er != nil {
		s.responder(w, r, era, nil, er, fim)
		return
	}
	s.responder(w, r, era, s.selar(era, corpo), nil, fim)
}

// selar acrescenta ao resultado o que é da ERA, e só o que é dela.
//
// `resultType` e a identidade do servidor em `_meta` nasceram na 2026-07-28.
// Mandá-los para um cliente de 2025 entrega campos que ele ignora — inofensivo
// — mas OMITI-LOS para um cliente de 2026 quebra um campo que a spec declara
// obrigatório. O contrário do vazamento é igualmente ruim, e é por isso que a
// era é decidida por requisição e nunca por padrão do servidor.
func (s *Servidor) selar(era Era, corpo map[string]any) json.RawMessage {
	if corpo == nil {
		corpo = map[string]any{}
	}
	if era == EraModerna {
		corpo["resultType"] = "complete"
		corpo["_meta"] = map[string]any{MetaInfoServidor: s.identidade()}
	}
	b, err := json.Marshal(corpo)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return b
}

func (s *Servidor) responder(w *Escritor, r *Requisicao, era Era,
	res json.RawMessage, er *ErroRPC, fim func(string, int)) {

	if er != nil {
		fim("error", 0)
		s.responderErro(w, r.ID, er)
		return
	}
	fim("ok", len(res))
	if err := w.Enviar(Resposta{JSONRPC: "2.0", ID: r.ID, Result: res}); err != nil {
		s.aud.Falha(r.Method, err)
	}
}

func (s *Servidor) responderErro(w *Escritor, id json.RawMessage, er *ErroRPC) {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	if err := w.Enviar(RespostaErro{JSONRPC: "2.0", ID: id, Error: er}); err != nil {
		s.aud.Falha("<erro>", err)
	}
}

// ----------------------------------------------------------------- métodos

// discover é OBRIGATÓRIO de implementar e OPCIONAL de chamar.
//
// A distinção decide o comportamento: o servidor nunca exige que ele tenha
// acontecido. Um cliente moderno pode abrir com `tools/call` direto, e um
// cliente que fala as duas eras usa este método como sonda de compatibilidade —
// se vier DiscoverResult, o servidor é moderno; se vier outro erro, ele cai
// para `initialize`. Recusar `tools/call` por falta de discover prévio
// quebraria o primeiro caso e mentiria no segundo.
func (s *Servidor) discover() (map[string]any, *ErroRPC) {
	return map[string]any{
		"supportedVersions": VersoesSuportadas,
		"capabilities":      Capacidades{Tools: &CapTools{}},
		"instructions":      Instrucoes,
		// A lista de tools deste servidor é fixa enquanto ele viver, e o que
		// ela contém foi decidido pelo operador no lançamento. Uma hora de
		// cache é folgada e não arrisca nada.
		"ttlMs": 3600000,
		// PRIVATE, e não public: a lista revela o modo, o perfil e as fontes
		// desta execução — quantos retratos, de host vivo ou de imagem. Não é
		// segredo, mas também não é coisa que um intermediário compartilhado
		// deva guardar e servir a outra pessoa.
		"cacheScope": "private",
	}, nil
}

type defTool struct {
	Nome        string          `json:"name"`
	Titulo      string          `json:"title,omitempty"`
	Descricao   string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
	OutSchema   json.RawMessage `json:"outputSchema,omitempty"`
	Annotations map[string]any  `json:"annotations,omitempty"`
}

func (s *Servidor) listarTools() (map[string]any, *ErroRPC) {
	tools := make([]defTool, 0, len(s.ativas))
	for _, f := range s.ativas {
		tools = append(tools, defTool{
			Nome: f.Nome, Titulo: f.Titulo, Descricao: f.Descricao,
			InputSchema: f.Entrada, OutSchema: f.Saida,
			// As annotations são HINTS no protocolo — a spec é explícita quanto
			// a isso, e um cliente pode ignorá-las. A proteção real é o
			// registry: o que não está aqui não pode ser chamado, e nenhuma
			// tool deste servidor tem caminho de escrita para ignorar.
			Annotations: map[string]any{
				"readOnlyHint": true, "destructiveHint": false, "openWorldHint": false,
			},
		})
	}
	return map[string]any{
		"tools": tools, "ttlMs": 3600000, "cacheScope": "private",
	}, nil
}

type paramsCall struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

func (s *Servidor) chamarTool(r *Requisicao) (map[string]any, *ErroRPC) {
	var p paramsCall
	if len(r.Params) > 0 {
		if err := json.Unmarshal(r.Params, &p); err != nil {
			return nil, erro(CodInvalidParams, "params de tools/call ilegíveis")
		}
	}
	if p.Name == "" {
		return nil, erro(CodInvalidParams, `tools/call sem "name"`)
	}
	f, ok := s.porNome[p.Name]
	if !ok {
		// METHOD NOT FOUND, e não permission denied.
		//
		// A diferença é de superfície, não de cortesia: "existe e você não
		// pode" convida o modelo a procurar como poder — e a insistir, e a
		// pedir ao operador que reinicie com outra flag. "não existe" fecha o
		// assunto. O que o operador não autorizou não deve nem parecer
		// alcançável.
		return nil, erroComDados(CodMethodNotFound,
			"tool desconhecida: "+p.Name,
			map[string]any{"available": s.nomesAtivos()})
	}
	saida, er := rodarProtegido(s, f, p.Arguments)
	if er != nil {
		return nil, er
	}
	b, err := json.Marshal(saida)
	if err != nil {
		return nil, erro(CodInternalError, "falha ao serializar o resultado")
	}
	if int64(len(b)) > s.pol.MaxResultado {
		// Não corta: recusa e diz como pedir menos. Cortar JSON serializado
		// produz documento inválido, e um cliente que recebe metade não tem
		// como saber que era metade.
		return nil, erro(CodInvalidParams,
			"resultado acima do teto deste servidor: peça uma página menor com "+
				`"limit", ou filtre a consulta`)
	}
	return map[string]any{
		// `content` é o caminho que todo cliente entende; `structuredContent` é
		// o que casa com o outputSchema. Mandar os dois é o que mantém a
		// resposta legível num cliente que ainda não lê schema de saída.
		"content":           []map[string]any{{"type": "text", "text": string(b)}},
		"structuredContent": saida,
		"isError":           false,
	}, nil
}

// rodarProtegido isola a falha de uma tool.
//
// O motor de checks já embrulha o mesmo risco em runGuarded, com o comentário
// que explica por quê: "Sem isto, o panic aborta o processo com status 2 — que
// o contrato desta ferramenta define como CRITICAL". Aqui a consequência é
// outra e é pior. O corpo de uma tool chega em info.Censo, info.Arvore,
// info.Arquivo e drift.Comparar, todos dirigidos por fatos de um dump que o
// Acervo valida só pela VERSÃO DE ESQUEMA — um índice fora de faixa vindo de um
// artefato malformado (ou escolhido) derrubaria o processo inteiro no meio da
// investigação: o cliente vê o cano fechar, o contexto acumulado se perde, e
// nenhuma linha de auditoria diz o que houve.
//
// A resposta é ERRO DE FERRAMENTA, e o texto precisa dizer isso: um defeito
// nosso não pode ser lido como afirmação sobre o host.
func rodarProtegido(s *Servidor, f Ferramenta, args json.RawMessage) (saida any, er *ErroRPC) {
	defer func() {
		if r := recover(); r != nil {
			saida = nil
			er = erroComDados(CodInternalError,
				"a tool "+f.Nome+" falhou durante a execução: isto é DEFEITO DA "+
					"FERRAMENTA, e não achado sobre o host — nada foi concluído sobre "+
					"o alvo por esta chamada",
				map[string]any{"tool": f.Nome})
			s.aud.Falha(f.Nome, fmt.Errorf("panic: %v", r))
		}
	}()
	return f.Rodar(s, args)
}

func (s *Servidor) nomesAtivos() []string {
	out := make([]string, 0, len(s.ativas))
	for _, f := range s.ativas {
		out = append(out, f.Nome)
	}
	return out
}
