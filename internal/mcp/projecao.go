package mcp

// A última barreira antes do stdout, e por que ela tem a forma que tem.
//
// # O problema real
//
// A redação neste projeto acontece na CONSTRUÇÃO da evidência, não na camada de
// saída: cada check que põe uma linha de comando num achado chama redact.Cmdline
// ou redact.Linha ele mesmo (checks/proc.go, checks/tree.go, checks/ioc.go,
// checks/path.go), o dump redige ao ESCREVER (dump.redigir), o drift redige ao
// montar os campos de mudança, e o info redige em linhaCurta. O report.Human só
// aplica Safe(), que é contra injeção de terminal, e o JSONL não aplica nada.
//
// Ou seja: a disciplina é POR AUTOR, espalhada por cinco pacotes. Ela funciona
// hoje, e o modo de falha é conhecido — um autor de check que escreva
// `ev = append(ev, "cmd="+strings.Join(p.Argv, " "))` vaza, e nada o impede.
// O MCP herda isso; o que ele não pode é PIORAR, e o que ele pode é ser o
// primeiro lugar onde a fronteira fica declarada.
//
// # Por que NÃO uma caminhada reflexiva redigindo toda string
//
// Foi a primeira ideia, e ela quebra. `redact.Linha` tokeniza por branco e
// re-junta com um espaço (strings.Fields + Join): aplicá-la a toda string do
// resultado destruiria o espaçamento de evidência multi-linha, da prosa dos
// dossiês e de qualquer texto formatado. Uma barreira que corrompe a evidência
// que ela deveria proteger não é barreira — é perda de dado com boa intenção.
//
// # O que ela é
//
// Uma DECLARAÇÃO obrigatória por tool, com portão. A tool diz de que classe é o
// que ela emite; a classe crua não entra no registry sem as duas flags; e um
// teste quebra o build se uma tool nova não declarar. O autor não precisa
// lembrar de redigir — ele precisa responder uma pergunta que o compilador e o
// teste fazem por ele.

// ClasseDeDados é o que a saída de uma tool carrega.
type ClasseDeDados uint8

const (
	// DadosNaoDeclarados é o zero value, e é PROPOSITALMENTE inválido: uma
	// tool nova nasce nele e o teste de catálogo quebra o build. É o mesmo
	// movimento de Check.FalsePositives ser obrigatório em check automático —
	// o autor não pode esquecer porque o esquecimento não compila verde.
	DadosNaoDeclarados ClasseDeDados = iota

	// DadosDoMotor: gerado por este binário, não pelo host. O catálogo de
	// checks, a aritmética de cobertura, o status desta sessão. Não há segredo
	// do alvo a proteger porque não há dado do alvo.
	DadosDoMotor

	// DadosRedigidosNaOrigem: vem do host, e já passou pela redação de quem o
	// construiu — dump.redigir, redact.Cmdline no check, linhaCurta no info.
	// Continua sendo texto ADVERSÁRIO (vai marcado untrusted), e não contém
	// segredo em claro.
	DadosRedigidosNaOrigem

	// DadosCrus: texto do host SEM redação. Conteúdo de arquivo, environ
	// completo, argv inteiro.
	//
	// A tool que declara isto não entra no registry sem --profile full E
	// --allow-secrets. Nenhuma existe ainda: é a entrega 3. A trava nasce
	// antes dela de propósito — trava escrita junto com a feature que ela
	// deveria conter é trava que se ajusta à feature.
	DadosCrus
)

func (c ClasseDeDados) String() string {
	switch c {
	case DadosDoMotor:
		return "engine"
	case DadosRedigidosNaOrigem:
		return "host_redacted"
	case DadosCrus:
		return "host_raw"
	}
	return "undeclared"
}

// permiteClasse é o portão. Ele roda no REGISTRY, e não na chamada: a tool que
// não pode ser servida não aparece em tools/list, e o que não aparece não pode
// ser induzido por texto plantado no host.
func permiteClasse(c ClasseDeDados, p Policy) (bool, string) {
	switch c {
	case DadosCrus:
		if p.Perfil == PerfilCompleto && p.PermitirSegredos {
			return true, ""
		}
		return false, "emite texto do host SEM redação: exige --profile full e --allow-secrets"
	case DadosNaoDeclarados:
		// Defesa em profundidade: o teste de catálogo já quebra o build, mas se
		// alguém desligar o teste, a tool não é servida. Fecha fechado.
		return false, "a tool não declarou a classe dos dados que emite"
	}
	return true, ""
}
