package mcp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/lex0c/aletheia/internal/env"
)

// Servidor é uma execução: uma policy, um acervo e um transporte.
type Servidor struct {
	pol    Policy
	acervo *Acervo
	versao string
	sessao Sessao
	aud    *Auditoria

	// adquirir monta o ambiente de uma captura. nil em ModoSnapshot, onde
	// nenhuma leitura do host acontece.
	adquirir Aquisicao

	// cancelados são os ids que o cliente pediu para abortar.
	//
	// O laço é sequencial, então um cancelamento da requisição EM VOO não chega
	// a ser lido — esse limite é real e está dito na descrição da captura. O que
	// chega é o cancelamento de uma requisição PIPELINADA: o cliente mandou
	// três de uma vez e desistiu da terceira. Para essas, a spec é clara — o
	// receptor NÃO deve responder —, e responder mesmo assim entrega ao cliente
	// uma resposta de id que ele já liberou, que muitos tratam como violação de
	// protocolo e derrubam a conexão.
	cancelados map[string]bool
	muCanc     sync.Mutex

	// O registry é resolvido UMA VEZ, no lançamento. Ele não pode variar por
	// conexão (a 2026-07-28 tornou as listas cacheáveis), e resolvê-lo por
	// chamada abriria a porta para ele variar por acidente.
	ativas  []Ferramenta
	fora    []Indisponivel
	porNome map[string]Ferramenta

	// gastoDeColeta é quanto tempo de aquisição esta sessão já cobrou do host
	// investigado. Ver Policy.OrcamentoDeColeta.
	gastoDeColeta time.Duration
	muGasto       sync.Mutex
}

// orcamentoDeColeta devolve o gasto e o que sobra. Sobra zero significa que
// mais nenhuma captura acontece neste processo — nem depois de um release.
func (s *Servidor) orcamentoDeColeta() (gasto, resta time.Duration) {
	s.muGasto.Lock()
	defer s.muGasto.Unlock()
	resta = s.pol.OrcamentoDeColeta - s.gastoDeColeta
	if resta < 0 {
		resta = 0
	}
	return s.gastoDeColeta, resta
}

// cobrarColeta soma o tempo de uma aquisição, tenha ela dado certo ou não: o
// host pagou pela varredura de qualquer jeito, e cobrar só o sucesso deixaria a
// falha repetível de graça.
func (s *Servidor) cobrarColeta(d time.Duration) {
	s.muGasto.Lock()
	s.gastoDeColeta += d
	s.muGasto.Unlock()
}

// NovoServidor monta o servidor e CONGELA o registry.
func NovoServidor(p Policy, a *Acervo, versao string, aud *Auditoria,
	adquirir Aquisicao) *Servidor {
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
	return &Servidor{pol: p, acervo: a, versao: versao, aud: aud, adquirir: adquirir,
		cancelados: map[string]bool{},
		ativas:     ativas, fora: fora, porNome: porNome}
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
			// O id da requisição, quando ele PÔDE ser lido. `null` só onde ele
			// de fato não pôde — documento que não abriu, lote, id inválido.
			var id json.RawMessage
			if req != nil {
				id = req.ID
			}
			s.responderErro(w, id, erpc)
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
	if r.Method == "notifications/cancelled" {
		s.marcarCancelada(r.Params)
	}
	if s.aud != nil {
		s.aud.Notificacao(r.Method)
	}
}

func (s *Servidor) marcarCancelada(params json.RawMessage) {
	var p struct {
		RequestID json.RawMessage `json:"requestId"`
	}
	if json.Unmarshal(params, &p) != nil || len(p.RequestID) == 0 {
		return
	}
	s.muCanc.Lock()
	defer s.muCanc.Unlock()
	s.cancelados[string(bytes.TrimSpace(p.RequestID))] = true
}

// foiCancelada consome a marca: um id cancelado é atendido uma vez pelo
// silêncio, e não fica envenenado para sempre.
func (s *Servidor) foiCancelada(id json.RawMessage) bool {
	if len(id) == 0 {
		return false
	}
	k := string(bytes.TrimSpace(id))
	s.muCanc.Lock()
	defer s.muCanc.Unlock()
	if !s.cancelados[k] {
		return false
	}
	delete(s.cancelados, k)
	return true
}

func (s *Servidor) tratar(w *Escritor, r *Requisicao) {
	fim := s.aud.Comeco(r.Method)

	// `initialize` é da era legada por definição: ele é o handshake, e não
	// carrega `_meta` com versão porque em 2025 isso não existia. Perguntar a
	// era antes dele recusaria todo cliente legado na primeira mensagem.
	// PING é da era 2025, e SÓ dela.
	//
	// A 2026-07-28 o REMOVEU do protocolo, junto de logging/setLevel. Mas este
	// servidor fala as duas eras, e na legada ele é utilidade obrigatória: o
	// cliente o usa para saber se a conexão está viva, e uma recusa faz ele
	// concluir que o servidor morreu e reiniciar no meio da investigação.
	//
	// Ele vem ANTES do portão de era pelo mesmo motivo do initialize: a spec de
	// 2025 permite ping antes mesmo da resposta do handshake, então exigir
	// `_meta` ali recusaria o uso legítimo.
	if r.Method == "ping" {
		if s.sessao.versaoLegada() == "" && lerMeta(r.Params) != nil {
			// Cliente moderno pedindo ping: ele não existe mais na 2026-07-28.
			s.responder(w, r, EraModerna, "", nil,
				erro(CodMethodNotFound, "ping foi REMOVIDO na 2026-07-28: a saúde da "+
					"conexão stdio é o próprio processo estar vivo"), fim)
			return
		}
		s.responder(w, r, EraLegado, "", json.RawMessage(`{}`), nil, fim)
		return
	}

	if r.Method == "initialize" {
		res, erpc := s.sessao.tratarInitialize(s, r)
		s.responder(w, r, EraLegado, "", res, erpc, fim)
		return
	}

	era, erpc := s.sessao.EraDe(r)
	if erpc != nil {
		s.responder(w, r, EraLegado, "", nil, erpc, fim)
		return
	}

	var (
		corpo     map[string]any
		cacheavel bool
		alvo      string
		er        *ErroRPC
	)
	switch r.Method {
	case "server/discover":
		corpo, er = s.discover()
		cacheavel = true
	case "tools/list":
		corpo, er = s.listarTools()
		cacheavel = true
	case "tools/call":
		corpo, alvo, er = s.chamarTool(r)
	default:
		er = erro(CodMethodNotFound, "método desconhecido: "+r.Method)
	}
	if er != nil {
		s.responder(w, r, era, alvo, nil, er, fim)
		return
	}

	res := s.selar(era, cacheavel, corpo)

	// O TETO É DO FRAME, e não do corpo da tool.
	//
	// Ele era medido sobre o valor que a tool devolvia — antes de o resultado
	// ganhar `content`, que é a MESMA carga serializada em texto para o cliente
	// que ainda não lê schema de saída. Medido: 179 KB conferidos contra um
	// frame de 323 KB, 1,80x. Um teto de 4 MiB admitia quase 7, e quem quebra
	// não é este servidor — é o limite de frame do CLIENTE, do outro lado, onde
	// o operador não tem como diagnosticar.
	if int64(len(res)) > s.pol.MaxResultado {
		s.responder(w, r, era, alvo, nil, erroComDados(CodInvalidParams,
			"resultado acima do teto deste servidor: peça uma página menor com "+
				`"limit", ou filtre a consulta`,
			map[string]any{"bytes": len(res), "limit": s.pol.MaxResultado}), fim)
		return
	}
	s.responder(w, r, era, alvo, res, nil, fim)
}

// selar acrescenta ao resultado o que é da ERA, e só o que é dela.
//
// `resultType` e a identidade do servidor em `_meta` nasceram na 2026-07-28.
// Mandá-los para um cliente de 2025 entrega campos que ele ignora — inofensivo
// — mas OMITI-LOS para um cliente de 2026 quebra um campo que a spec declara
// obrigatório. O contrário do vazamento é igualmente ruim, e é por isso que a
// era é decidida por requisição e nunca por padrão do servidor.
func (s *Servidor) selar(era Era, cacheavel bool, corpo map[string]any) json.RawMessage {
	if corpo == nil {
		corpo = map[string]any{}
	}
	if era == EraModerna {
		corpo["resultType"] = "complete"
		corpo["_meta"] = map[string]any{MetaInfoServidor: s.identidade()}
		if cacheavel {
			// CacheableResult nasceu na 2026-07-28, junto com resultType. Estes
			// dois campos eram postos no CORPO pelos handlers, então saíam nas
			// DUAS eras — e o doc logo acima afirmava o contrário. Um cliente de
			// 2025 os ignora, e o dano é pequeno; a promessa quebrada não é.
			//
			// A lista deste servidor é fixa enquanto ele viver: o que ela contém
			// foi decidido pelo operador no lançamento. Uma hora é folgada.
			corpo["ttlMs"] = 3600000
			// PRIVATE, e não public: a lista revela o modo, o perfil e as fontes
			// desta execução. Não é segredo, e também não é coisa que um
			// intermediário compartilhado deva guardar e servir a outra pessoa.
			corpo["cacheScope"] = "private"
		}
	}
	b, err := json.Marshal(corpo)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return b
}

func (s *Servidor) responder(w *Escritor, r *Requisicao, era Era, alvo string,
	res json.RawMessage, er *ErroRPC, fim func(string, string, int)) {

	// A spec: o receptor NÃO deve responder a uma requisição cancelada. Isto
	// alcança a pipelinada; a que está EM VOO não é alcançável, porque o laço
	// não lê enquanto processa — e esse limite está dito, não fingido.
	if s.foiCancelada(r.ID) {
		fim(alvo, "cancelled", 0)
		return
	}
	if er != nil {
		fim(alvo, "error", 0)
		s.responderErro(w, r.ID, er)
		return
	}
	fim(alvo, "ok", len(res))
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
			// registry. Elas vêm da PRÓPRIA tool: eram um literal igual para
			// todas, e a aquisição trouxe duas que mudam estado.
			Annotations: f.Anotacoes.JSON(),
		})
	}
	return map[string]any{"tools": tools}, nil
}

type paramsCall struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

// chamarTool devolve, além do corpo, o ALVO para a trilha de auditoria: o nome
// da tool e o retrato que a chamada citou.
//
// A trilha registrava só `r.Method`, então toda invocação saía como a constante
// "tools/call" — e o doc dela promete responder "quem perguntou o quê, quando,
// sobre qual retrato". Respondia uma das três, e a menos útil. O nome estava na
// mão duas linhas abaixo.
//
// O retrato é o que a chamada PEDIU, e não o que o servidor resolveu: numa
// trilha de auditoria o que interessa é o que foi perguntado.
func (s *Servidor) chamarTool(r *Requisicao) (map[string]any, string, *ErroRPC) {
	var p paramsCall
	if len(r.Params) > 0 {
		if err := json.Unmarshal(r.Params, &p); err != nil {
			return nil, "", erro(CodInvalidParams, "params de tools/call ilegíveis")
		}
	}
	if p.Name == "" {
		return nil, "", erro(CodInvalidParams, `tools/call sem "name"`)
	}
	alvo := p.Name
	var quais argsSnapshot
	if len(p.Arguments) > 0 && json.Unmarshal(p.Arguments, &quais) == nil &&
		quais.SnapshotID != "" {
		alvo += " " + quais.SnapshotID
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
		return nil, alvo, erroComDados(CodMethodNotFound,
			"tool desconhecida: "+p.Name,
			map[string]any{"available": s.nomesAtivos()})
	}
	saida, er := rodarProtegido(s, f, p.Arguments)
	if er != nil {
		// FALHA DE TOOL É RESULTADO, e não erro de protocolo.
		//
		// A distinção decide QUEM LÊ a mensagem. Um erro JSON-RPC é do
		// transporte, e muitos clientes o tratam como falha de conexão sem
		// devolver o texto ao modelo. E as mensagens deste servidor foram
		// escritas para o modelo: "STALE_CURSOR: este cursor foi emitido sob
		// outro filtro", "a pergunta não se aplica a esta fonte", "isto é
		// DEFEITO DA FERRAMENTA, e não achado sobre o host". Escondê-las atrás
		// de um erro de transporte é escrevê-las para ninguém — e tira do
		// modelo a chance de se corrigir sozinho na chamada seguinte.
		//
		// O que continua sendo erro de protocolo é o que acontece ANTES do
		// despacho: método desconhecido, tool inexistente, era ambígua, frame
		// malformado. Aquilo o modelo não pode consertar.
		return resultadoDeFalha(f.Nome, er), alvo, nil
	}
	b, err := json.Marshal(saida)
	if err != nil {
		return nil, alvo, erro(CodInternalError, "falha ao serializar o resultado")
	}
	// O teto é conferido no FRAME, em tratar. Aqui só se monta.
	return map[string]any{
		// `content` é o caminho que todo cliente entende; `structuredContent` é
		// o que casa com o outputSchema. Mandar os dois é o que mantém a
		// resposta legível num cliente que ainda não lê schema de saída.
		"content":           []map[string]any{{"type": "text", "text": string(b)}},
		"structuredContent": saida,
		"isError":           false,
	}, alvo, nil
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

// resultadoDeFalha embrulha a recusa de uma tool na forma que o modelo lê.
func resultadoDeFalha(tool string, er *ErroRPC) map[string]any {
	corpo := map[string]any{"tool": tool, "error": er.Message}
	if er.Data != nil {
		corpo["details"] = er.Data
	}
	b, _ := json.Marshal(corpo)
	return map[string]any{
		"content":           []map[string]any{{"type": "text", "text": string(b)}},
		"structuredContent": corpo,
		"isError":           true,
	}
}

func (s *Servidor) nomesAtivos() []string {
	out := make([]string, 0, len(s.ativas))
	for _, f := range s.ativas {
		out = append(out, f.Nome)
	}
	return out
}
