package mcp

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
)

// A superfície de tools, e a regra que a governa:
//
//	Nome, título, descrição, inputSchema e outputSchema são CONSTANTES DE
//	COMPILAÇÃO. Nenhuma string vinda do host chega a eles, em nenhum modo.
//
// É a fronteira que impede um invasor de mudar a própria superfície de
// ferramentas do servidor plantando texto no alvo. Conteúdo do host aparece só
// dentro de `data`, sob um envelope marcado `trust.untrusted: true`.

// Ferramenta é uma tool do registry.
type Ferramenta struct {
	Nome      string
	Titulo    string
	Descricao string

	Entrada json.RawMessage // JSON Schema 2020-12
	Saida   json.RawMessage

	// Modos em que ela existe. Vazio = todos.
	Modos []Modo
	// Fontes que ela sabe responder. Zero = independe da fonte.
	//
	// É por aqui que um acervo só de imagens não expõe `process.get`: em modo
	// image não há /proc, e a tool não teria o que ler. Esconder o CALLABLE é
	// a regra do MCP (superfície que não existe não pode ser induzida); a
	// AUSÊNCIA continua declarada, em session.status e no server/discover,
	// porque a regra desta ferramenta é que nada fique silencioso.
	Fontes env.Source
	// PerfilMin é o perfil mínimo. PerfilPadrao = sempre disponível.
	PerfilMin Perfil

	// EscopoMin é o alcance de coleta que a PERGUNTA desta tool exige.
	//
	// Vazio significa que ela se sustenta sobre qualquer retrato. EscopoCompleto
	// significa que ela consulta famílias que a coleta volátil nem examina — e
	// respondê-la ali produziria uma AUSÊNCIA que se lê como resposta.
	//
	// Medido antes deste campo existir: `file.inspect` sobre um retrato volátil
	// devolvia found:false com o sinal "este caminho não aparece em nada que
	// esta coleta examinou: nem em execução, nem em pacote, nem em
	// agendamento". Pacote e agendamento NÃO FORAM examinados — a frase é
	// factualmente falsa, e é exatamente a confusão que a ferramenta inteira
	// existe para não cometer.
	EscopoMin Escopo

	// Anotacoes é o vocabulário de RISCO desta tool, e ele é POR TOOL.
	//
	// Ele era global: todas se anunciavam readOnly, não destrutivas e de mundo
	// fechado. Isso era verdade na entrega 1, em que nenhuma tool mudava nada.
	// A aquisição trouxe duas que mudam — snapshot.capture cria e RETÉM um
	// objeto, snapshot.release o DESTRÓI — e as duas continuavam anunciadas
	// como somente-leitura.
	//
	// O cliente usa esses hints para decidir se pede confirmação ao operador. E
	// o release é o que mais importa numa resposta a incidente: um retrato
	// volátil que capturou um processo memfd pode não ser reproduzível, porque o
	// processo terminou. Anunciá-lo como não destrutivo faz o cliente descartar
	// evidência sem perguntar.
	//
	// Os hints NÃO são a proteção — a spec é explícita, e um cliente pode
	// ignorá-los. A proteção é o registry. Eles são o que permite ao cliente
	// perguntar, e mentir neles tira do operador a chance de dizer não.
	Anotacoes Anotacoes

	// Dados declara a classe do que esta tool emite. OBRIGATÓRIO: o zero value
	// é inválido e quebra o teste de catálogo. Ver projecao.go.
	Dados ClasseDeDados

	// Alvo projeta os argumentos para a TRILHA DE AUDITORIA.
	//
	// A trilha registrava só o nome da tool mais o snapshot_id, e para o perfil
	// completo isso não responde a pergunta que o operador faz depois do
	// incidente: o que exatamente o agente acessou? Duas chamadas —
	//
	//	file.read {"path":"/etc/shadow"}
	//	file.read {"path":"/root/.ssh/id_ed25519"}
	//
	// — saíam idênticas no log. Num modo que permite a uma IA ler credencial
	// como root, a trilha precisa distinguir.
	//
	// A projeção é POR TOOL e devolve só IDENTIFICAÇÃO: caminho, pid, offset.
	// Nunca conteúdo, nunca valor de variável, nunca bytes lidos — a trilha vai
	// para stderr e para um arquivo, e transformá-la num segundo canal de
	// vazamento desfaria o portão que ela existe para auditar.
	//
	// nil = a tool não acrescenta nada além do nome e do snapshot.
	Alvo func(args json.RawMessage) string

	Rodar func(s *Servidor, args json.RawMessage) (any, *ErroRPC)
}

// Disponivel decide se esta tool existe sob esta policy e sobre estas fontes.
func (f Ferramenta) Disponivel(p Policy, fontes env.Source) (bool, string) {
	if ok, motivo := permiteClasse(f.Dados, p); !ok {
		return false, motivo
	}
	if f.PerfilMin > p.Perfil {
		return false, "exige --profile " + f.PerfilMin.String()
	}
	if len(f.Modos) > 0 && !contemModo(f.Modos, p.Modo) {
		return false, "não se aplica ao modo " + p.Modo.String()
	}
	if f.Fontes != 0 && fontes != 0 && f.Fontes&fontes == 0 {
		return false, "nenhum retrato carregado tem esta fonte: " +
			"a pergunta não existe sobre o que foi coletado"
	}
	return true, ""
}

func contemModo(ms []Modo, m Modo) bool {
	for _, x := range ms {
		if x == m {
			return true
		}
	}
	return false
}

// Anotacoes é o vocabulário de risco do MCP.
type Anotacoes struct {
	// SomenteLeitura: a tool NÃO modifica o ambiente dela. O padrão é o valor
	// zero `false`, e é o lado seguro: uma tool nova é tratada como se mudasse
	// algo até dizer que não.
	SomenteLeitura bool
	// Destrutiva só tem sentido quando SomenteLeitura é falso.
	Destrutiva bool
	// Idempotente: repetir com os mesmos argumentos é seguro.
	Idempotente bool
	// MundoAberto: a tool alcança algo fora deste processo. Nenhuma alcança.
	MundoAberto bool
}

// JSON monta o mapa de hints do protocolo.
func (a Anotacoes) JSON() map[string]any {
	return map[string]any{
		"readOnlyHint":    a.SomenteLeitura,
		"destructiveHint": a.Destrutiva,
		"idempotentHint":  a.Idempotente,
		"openWorldHint":   a.MundoAberto,
	}
}

// SomenteLeitura é a anotação da maioria: elas respondem sobre um retrato
// imutável, então repetir é sempre seguro.
var SomenteLeitura = Anotacoes{SomenteLeitura: true, Idempotente: true}

// Indisponivel é a ausência DECLARADA. Ver Ferramenta.Fontes.
type Indisponivel struct {
	Nome   string `json:"name"`
	Motivo string `json:"reason"`
}

// Registry devolve as tools disponíveis, em ordem ESTÁVEL, e as que ficaram de
// fora com o motivo.
//
// A ordem é alfabética e não a de declaração: a 2026-07-28 recomenda ordem
// determinística em tools/list para o cliente poder cachear e para o prompt do
// modelo ter cache hit. Ordem de declaração também seria determinística, mas
// mudaria ao mover uma função de lugar — e ninguém liga um refactor de arquivo
// a uma invalidação de cache do outro lado.
func Registry(p Policy, fontes env.Source) (ativas []Ferramenta, fora []Indisponivel) {
	todas := catalogo()
	sort.SliceStable(todas, func(i, j int) bool { return todas[i].Nome < todas[j].Nome })
	for _, f := range todas {
		if ok, motivo := f.Disponivel(p, fontes); ok {
			ativas = append(ativas, f)
		} else {
			fora = append(fora, Indisponivel{Nome: f.Nome, Motivo: motivo})
		}
	}
	return ativas, fora
}

// ------------------------------------------------------- argumentos de tool

// decodificarArgs lê os argumentos com campo desconhecido RECUSADO.
//
// # Por que não ignorar o que não se conhece
//
// Tolerar campo desconhecido é o padrão do encoding/json e é a escolha errada
// aqui. Quem chama estas tools é um modelo, e modelo inventa parâmetro: um
// `findings.list{"severity":"critical"}` onde o campo se chama `min_severity`
// seria silenciosamente ignorado, a resposta viria com a lista INTEIRA, e o
// modelo concluiria que o host tem 40 críticos. Uma resposta a outra pergunta,
// sem nada indicando que a pergunta mudou.
//
// Recusar transforma a alucinação em erro legível, que o modelo corrige na
// chamada seguinte.
func decodificarArgs(args json.RawMessage, destino any) *ErroRPC {
	if len(args) == 0 || string(args) == "null" {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(args))
	dec.DisallowUnknownFields()
	if err := dec.Decode(destino); err != nil {
		return erro(CodInvalidParams, "argumentos inválidos: "+limparErro(err.Error()))
	}
	// Lixo depois do objeto: `{"a":1} {"b":2}` decodifica o primeiro e ignora o
	// resto em silêncio.
	if dec.More() {
		return erro(CodInvalidParams, "argumentos com conteúdo extra depois do objeto")
	}
	return nil
}

// limparErro tira do texto do encoding/json o que não ajuda quem lê. Ele NUNCA
// carrega valor vindo do host — só nome de campo, que é do schema.
func limparErro(s string) string {
	s = strings.TrimPrefix(s, "json: ")
	if i := strings.Index(s, "\n"); i >= 0 {
		s = s[:i]
	}
	return s
}

// MaxTexto é o teto de um argumento textual.
//
// O frame já tem teto (MaxLinhaPadrao), então isto não é sobre memória: é sobre
// a resposta. Um `path` de 900 KiB produziria uma mensagem de erro de 900 KiB
// carregando texto que o cliente mandou — e num servidor cujo canal de saída
// vai para um modelo, resposta enorme é o próprio problema.
const MaxTexto = 4096

// validarGrupo e validarIDDeCheck fecham o conjunto.
//
// # Por que a validação existe
//
// `min_severity` é enum e o servidor recusa um valor errado em voz alta.
// `group` e `id` eram só medidos em tamanho — e o efeito de errá-los é
// SILENCIOSO e do pior tipo: `checks.catalog{"group":"network"}` (o grupo é
// "net") devolve `{"checks":[],"total":0}`, e o modelo conclui que este binário
// não tem check de rede. `findings.list{"id":"proc.memfd"}` (o id é
// proc.memfd_exec) devolve zero achados com veredito e cobertura descrevendo a
// execução INTEIRA, então nada sinaliza o engano — e o modelo relata que não há
// execução fileless num host que tem.
//
// É o mesmo raciocínio do DisallowUnknownFields do decodificarArgs, um nível
// abaixo: lá o NOME do campo é conjunto fechado, aqui o VALOR também é. E o
// defeito já era conhecido do lado do teste — o cenário M1 filtra por
// min_severity justamente porque "um id com erro de digitação devolveria zero
// achados e o cenário passaria trivialmente". A defesa tinha ido para o
// cenário, e não para o servidor.
func validarGrupo(g string) *ErroRPC {
	if g == "" {
		return nil
	}
	if er := validarTexto("group", g); er != nil {
		return er
	}
	for _, x := range check.Groups() {
		if strings.EqualFold(x, g) {
			return nil
		}
	}
	return erroComDados(CodInvalidParams,
		"grupo inexistente: "+g,
		map[string]any{"groups": check.Groups()})
}

func validarIDDeCheck(id string) *ErroRPC {
	if id == "" {
		return nil
	}
	if er := validarTexto("id", id); er != nil {
		return er
	}
	for _, c := range check.All() {
		if c.ID == id {
			return nil
		}
	}
	return erroComDados(CodInvalidParams,
		"id de check inexistente: "+id+" — use checks.catalog para o conjunto",
		map[string]any{"hint": "checks.catalog"})
}

func validarTexto(campo, v string) *ErroRPC {
	if len(v) > MaxTexto {
		return erro(CodInvalidParams, fmt.Sprintf(
			"%s: texto acima do teto de %d bytes", campo, MaxTexto))
	}
	return nil
}

// ------------------------------------------------------------- paginação

// Pagina são os argumentos de paginação, comuns a toda tool que lista.
type Pagina struct {
	Limite int    `json:"limit,omitempty"`
	Cursor string `json:"cursor,omitempty"`
}

const (
	LimitePadrao = 100
	LimiteMaximo = 1000
)

// Lista é a forma de toda resposta paginada.
type Lista struct {
	Itens      any    `json:"items"`
	ProxCursor string `json:"next_cursor,omitempty"`
	Total      int    `json:"total"`
	Truncado   bool   `json:"truncated"`
}

// fatiar aplica limite e cursor sobre um total, e devolve a janela.
//
// A ordem de quem chama tem de ser ESTÁVEL dentro do retrato — cada tool
// declara a sua, e o retrato é imutável, então duas chamadas com o mesmo cursor
// devolvem os mesmos itens. Sem isso a paginação embaralha: o item 100 vira o
// 101 entre duas páginas e some da leitura sem nunca aparecer.
func fatiar(p Pagina, snapID, filtro string, total int) (ini, fim int, prox string, e *ErroRPC) {
	lim := p.Limite
	switch {
	case lim <= 0:
		lim = LimitePadrao
	case lim > LimiteMaximo:
		lim = LimiteMaximo
	}
	ini, e = decodificarCursor(snapID, filtro, p.Cursor)
	if e != nil {
		return 0, 0, "", e
	}
	if ini > total {
		ini = total
	}
	fim = min(ini+lim, total)
	if fim < total {
		prox = codificarCursor(snapID, filtro, fim)
	}
	return ini, fim, prox, nil
}

// O cursor é opaco para quem usa e carrega POR DENTRO o retrato E o filtro.
//
// O retrato, porque sem ele um cursor obtido sobre `snap-a` continuaria
// "funcionando" sobre `snap-b`: a segunda página viria do outro host, e a
// leitura juntaria dois retratos numa lista só.
//
// O FILTRO, porque o offset é uma posição na lista JÁ FILTRADA. Um modelo que
// pagina costuma ecoar o cursor de volta e esquecer o resto dos argumentos —
// e aí `findings.list{"min_severity":"CRITICAL","limit":2}` seguido de
// `findings.list{"cursor":…}` fatiava a lista COMPLETA a partir do índice 2:
// linhas WARN e INFO chegavam como continuação da página de críticos, os
// críticos restantes nunca eram enumerados, e `truncated` dizia false. O
// caminho simétrico é pior — estreitar o filtro na página 2 devolve
// `{"items":[],"truncated":false}`, que se lê como "acabou".
func impressaoDoFiltro(partes ...string) string {
	h := sha256.Sum256([]byte(strings.Join(partes, "\x00")))
	return hex.EncodeToString(h[:4])
}

func codificarCursor(snapID, filtro string, off int) string {
	return base64.RawURLEncoding.EncodeToString(
		[]byte(snapID + "|" + filtro + "|" + strconv.Itoa(off)))
}

func decodificarCursor(snapID, filtro, cur string) (int, *ErroRPC) {
	if cur == "" {
		return 0, nil
	}
	b, err := base64.RawURLEncoding.DecodeString(cur)
	if err != nil {
		return 0, erro(CodInvalidParams, "cursor malformado")
	}
	partes := strings.Split(string(b), "|")
	if len(partes) != 3 {
		return 0, erro(CodInvalidParams, "cursor malformado")
	}
	if partes[0] != snapID {
		return 0, erroComDados(CodInvalidParams,
			"STALE_CURSOR: este cursor é de outro retrato — paginar através de dois "+
				"retratos juntaria hosts diferentes numa lista só",
			map[string]any{"cursorSnapshot": partes[0], "requestedSnapshot": snapID})
	}
	if partes[1] != filtro {
		return 0, erro(CodInvalidParams,
			"STALE_CURSOR: este cursor foi emitido sob OUTRO filtro. O offset é uma "+
				"posição na lista filtrada; continuá-lo com outro filtro devolveria "+
				"uma janela de uma lista diferente, sem nada indicando a troca. "+
				"Repita os mesmos argumentos da primeira chamada, com o cursor.")
	}
	n, err := strconv.Atoi(partes[2])
	if err != nil || n < 0 {
		return 0, erro(CodInvalidParams, "cursor malformado")
	}
	return n, nil
}
