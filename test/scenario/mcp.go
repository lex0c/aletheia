package scenario

import (
	"fmt"
	"strings"
)

// A conversa com o servidor MCP, na forma em que um cenário a escreve.
//
// # Por que o modo MCP não cabia no harness existente
//
// Todo cenário até aqui roda `/aletheia <cmd> --json -` e lê o stdout como
// JSONL de ACHADOS. O servidor MCP não tem nenhuma das três pontas: ele não
// aceita --json, lê a requisição do STDIN, e o que sai é JSON-RPC — cujo `id` é
// numérico, então a linha nem desserializa no tipo que o harness usa para
// achado. Forçá-lo naquele caminho exigiria fingir que a saída é a mesma coisa.
//
// # O que estes cenários provam, e os unitários não
//
// As catracas de internal/mcp rodam sobre um Facts sintético. Elas provam a
// mecânica — que a cobertura é transportada, que o schema exige veredito, que a
// classe de dados é declarada. O que só o contêiner prova é o ciclo inteiro
// contra um /proc de verdade: um implante plantado num host real, coletado pelo
// binário real, servido pelo servidor real, e a fronteira ainda de pé do outro
// lado.

// Chamada é uma requisição ao servidor e o contrato da resposta.
type Chamada struct {
	// Tool é o nome da ferramenta. Vazio = `tools/list`.
	Tool string
	// Args é o JSON dos argumentos. Vazio = `{}`.
	Args string
	// Bruto substitui a requisição INTEIRA, para exercitar o protocolo em vez
	// de uma tool — era ambígua, frame acima do teto, método desconhecido.
	Bruto string

	// Espera e Proibe são substrings na resposta INTEIRA.
	Espera []string
	Proibe []string

	// SoEmDados é a fronteira de injeção escrita como asserção: a substring
	// precisa CHEGAR dentro de `data` e não aparecer em nenhum outro lugar da
	// resposta.
	//
	// As duas metades importam. "chegou" porque escapar não é truncar — a
	// forense precisa dos bytes que o atacante escolheu. "e em nenhum outro
	// lugar" porque texto do alvo fora de `data` significa que ele alcançou
	// procedência, cobertura ou a marca de confiança, que são afirmações da
	// FERRAMENTA sobre a evidência, e não a evidência.
	SoEmDados []string

	// TextoDoAlvo é a forma GERAL da fronteira, e a que o M8 precisa.
	//
	// A substring precisa aparecer na resposta, e TODA região de primeiro nível
	// onde ela aparece precisa estar declarada em trust.host_supplied_paths.
	// SoEmDados afirma um caso particular — "aparece em data e em mais nada" —,
	// que vale para o argv de um processo e NÃO vale para um nome que entrou
	// numa lacuna de coleta: ali o texto do alvo alcança observability
	// legitimamente, e o que importa é que o caminho esteja dito.
	TextoDoAlvo []string

	// Campos são asserções por caminho pontilhado sobre a resposta —
	// "observability.verdict": "INCOMPLETE". O valor é comparado como texto,
	// que é o que torna a escrita do cenário legível.
	Campos map[string]string
	// CampoNao é o simétrico, e vale tanto quanto: "observability.verdict"
	// DIFERENTE de "OK" é a asserção central desta feature.
	CampoNao map[string]string

	// ErroCodigo espera um erro JSON-RPC com este código.
	ErroCodigo int

	// ProibeTool recusa nomes em `tools/list`. Vale para provar a ausência de
	// superfície de execução — o que não está no registry não pode ser induzido.
	ProibeTool []string
	// ExigeReadOnly cobra a anotação em TODA tool listada.
	ExigeReadOnly bool
}

// MetaModerno é o cabeçalho que toda requisição da era 2026 carrega. Fica aqui,
// em um lugar só, porque repeti-lo em cada cenário faria a asserção sumir no
// meio do boilerplate.
const MetaModerno = `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28",` +
	`"io.modelcontextprotocol/clientCapabilities":{}}`

// Requisicao monta a linha JSON-RPC desta chamada.
func (c Chamada) Requisicao(id int) string {
	if c.Bruto != "" {
		return c.Bruto
	}
	if c.Tool == "" {
		return fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/list","params":{%s}}`,
			id, MetaModerno)
	}
	args := c.Args
	if args == "" {
		args = "{}"
	}
	return fmt.Sprintf(
		`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":%q,"arguments":%s,%s}}`,
		id, c.Tool, args, MetaModerno)
}

// Rotulo nomeia a chamada nas mensagens de falha.
func (c Chamada) Rotulo() string {
	switch {
	case c.Bruto != "":
		return "requisição crua"
	case c.Tool == "":
		return "tools/list"
	}
	return c.Tool
}

// Transcricao monta o roteiro inteiro, uma requisição por linha.
//
// O id de cada uma é a POSIÇÃO, começando em 1: é assim que a asserção
// reencontra a resposta da chamada N sem depender da ordem em que o servidor
// respondeu. (Ele responde em ordem, porque o laço é sequencial — mas amarrar a
// asserção a isso tornaria a suíte cúmplice de um detalhe de implementação.)
func Transcricao(cs []Chamada) string {
	var b strings.Builder
	for i, c := range cs {
		b.WriteString(c.Requisicao(i + 1))
		b.WriteByte('\n')
	}
	return b.String()
}
