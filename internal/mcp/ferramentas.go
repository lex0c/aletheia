package mcp

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

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

	// Dados declara a classe do que esta tool emite. OBRIGATÓRIO: o zero value
	// é inválido e quebra o teste de catálogo. Ver projecao.go.
	Dados ClasseDeDados

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
func fatiar(p Pagina, snapID string, total int) (ini, fim int, prox string, e *ErroRPC) {
	lim := p.Limite
	switch {
	case lim <= 0:
		lim = LimitePadrao
	case lim > LimiteMaximo:
		lim = LimiteMaximo
	}
	ini, e = decodificarCursor(snapID, p.Cursor)
	if e != nil {
		return 0, 0, "", e
	}
	if ini > total {
		ini = total
	}
	fim = min(ini+lim, total)
	if fim < total {
		prox = codificarCursor(snapID, fim)
	}
	return ini, fim, prox, nil
}

// O cursor é opaco para quem usa e CARREGA O RETRATO por dentro.
//
// Sem o retrato dentro dele, um cursor obtido sobre `snap-a` continuaria
// "funcionando" sobre `snap-b`: a segunda página viria do outro host, e a
// leitura juntaria dois retratos numa lista só sem nenhum sinal disso. Com ele,
// o erro é imediato e diz o que houve.
func codificarCursor(snapID string, off int) string {
	return base64.RawURLEncoding.EncodeToString([]byte(snapID + "|" + strconv.Itoa(off)))
}

func decodificarCursor(snapID, cur string) (int, *ErroRPC) {
	if cur == "" {
		return 0, nil
	}
	b, err := base64.RawURLEncoding.DecodeString(cur)
	if err != nil {
		return 0, erro(CodInvalidParams, "cursor malformado")
	}
	id, off, ok := strings.Cut(string(b), "|")
	if !ok {
		return 0, erro(CodInvalidParams, "cursor malformado")
	}
	if id != snapID {
		return 0, erroComDados(CodInvalidParams,
			"STALE_CURSOR: este cursor é de outro retrato — paginar através de dois "+
				"retratos juntaria hosts diferentes numa lista só",
			map[string]any{"cursorSnapshot": id, "requestedSnapshot": snapID})
	}
	n, err := strconv.Atoi(off)
	if err != nil || n < 0 {
		return 0, erro(CodInvalidParams, "cursor malformado")
	}
	return n, nil
}
