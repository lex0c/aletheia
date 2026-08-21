// Package redact remove segredo de dado vindo do alvo, ANTES de ele entrar num
// achado — e portanto antes de chegar ao relatório, ao JSONL e ao ticket.
//
// SPEC 5.4 exige redação na camada de saída, e o motivo está escrito lá: o
// relatório é o que vai para ticket, e-mail e post-mortem, e ele imprime
// `cmdline` com senha. Redigir só o dump seria proteger o artefato MENOS
// exposto. Fica em pacote próprio para que tanto os checks quanto o report
// possam usá-lo sem inverter a dependência.
package redact

import "strings"

// secretFlags são as formas comuns de passar segredo em linha de comando.
// A lista é heurística por natureza; o padrão é errar para o lado de redigir.
var secretFlags = []string{
	"-p", "--password", "--pass", "-password",
	"--token", "--api-key", "--apikey", "--secret",
	"-w", "--key", "--auth", "--credential", "--credentials",
}

var secretAssign = []string{
	"password=", "passwd=", "pwd=", "token=", "secret=",
	"apikey=", "api_key=", "auth=", "key=", "credential=",
}

// Cmdline redige valor de segredo numa linha de comando, preservando o
// que identifica o processo. O uso real é `mysqldump -u root -pS3cr3t` e
// `curl -H "Authorization: Bearer …"`.
func Cmdline(argv []string) []string {
	out := make([]string, 0, len(argv))
	skipNext := false
	noCabecalhoAuth := false
	for _, a := range argv {
		if skipNext {
			out = append(out, "<redacted>")
			skipNext = false
			continue
		}
		// Dentro de um `Authorization:` quebrado por branco — que é como ele
		// chega quando o cabeçalho vem dentro de um `sh -c` — tudo até a
		// próxima opção ou URL é credencial.
		if noCabecalhoAuth {
			if !fechaCabecalhoAuth(a) {
				out = append(out, "<redacted>")
				continue
			}
			noCabecalhoAuth = false
		}
		if abreCabecalhoAuth(a) {
			out = append(out, a)
			noCabecalhoAuth = true
			continue
		}
		// UM ARGUMENTO QUE É UMA LINHA DE COMANDO INTEIRA — decomposto ANTES
		// de qualquer outra regra.
		//
		// `sh -c "mysqldump -u root -pS3cr3t db"` tem o comando todo em UM
		// token de argv, e a varredura por token não olhava para dentro dele: a
		// senha atravessava a redação e saía crua na evidência de
		// proc.shell_from_service, que é justamente o check feito para reportar
		// essa forma. É o modo de uso MAIS comum do shell num incidente.
		//
		// A ORDEM importa e custou um teste: com a decomposição depois do
		// redactInline, o casamento de `authorization:` no MEIO do payload
		// devolvia `a[:fim] + " <redacted>"` e comia todo o resto da linha —
		// inclusive a URL do C2, que é a evidência principal. Decompor primeiro
		// garante que as regras seguintes só vejam tokens sem branco.
		//
		// A recursão é de um nível só: quem entra é o resultado do Fields, e
		// nenhum token dele contém branco.
		if strings.ContainsAny(a, " \t") {
			campos := strings.Fields(a)
			if len(campos) > 1 {
				out = append(out, strings.Join(Cmdline(campos), " "))
				continue
			}
		}
		// -pSENHA colado (padrão do mysql) e --password=SENHA
		if red, ok := redactInline(a); ok {
			out = append(out, red)
			continue
		}
		// flag isolada: o PRÓXIMO argumento é o valor
		if isSecretFlag(a) {
			out = append(out, a)
			skipNext = true
			continue
		}
		// URL com credencial embutida
		if strings.Contains(a, "://") && strings.Contains(a, "@") {
			out = append(out, redactURLCreds(a))
			continue
		}
		out = append(out, a)
	}
	return out
}

func redactInline(a string) (string, bool) {
	// Cabeçalho de autorização num token só, que é a forma em argv de verdade:
	// `curl -H "Authorization: Bearer tok"`. O NOME do cabeçalho fica, porque é
	// ele que identifica o que o processo estava fazendo; o valor sai.
	if i := indiceSemCaixa(a, "authorization:"); i >= 0 {
		fim := i + len("authorization:")
		if strings.TrimSpace(a[fim:]) != "" {
			return a[:fim] + " <redacted>", true
		}
	}
	for _, k := range secretAssign {
		if i := indiceSemCaixa(a, k); i >= 0 && i+len(k) < len(a) {
			return a[:i+len(k)] + "<redacted>", true
		}
	}
	// -pSENHA: prefixo de flag curta seguido de valor colado
	if len(a) > 2 && a[0] == '-' && a[1] != '-' {
		switch a[1] {
		case 'p', 'w':
			return a[:2] + "<redacted>", true
		}
	}
	return "", false
}

// abreCabecalhoAuth diz se o token é o NOME do cabeçalho de autorização, e
// portanto o que vem depois dele é a credencial.
//
// A decisão é por CONTEXTO, e não por uma lista de esquemas ("bearer",
// "basic", "token"). Uma lista solta redigiria o argumento seguinte a qualquer
// `token` da linha — `vault token lookup` viraria `vault token <redacted>` —,
// destruindo evidência sem ganhar segredo nenhum. Depois de `Authorization:`,
// ao contrário, tudo até o próximo argumento é credencial por definição.
func abreCabecalhoAuth(a string) bool {
	return len(a) >= len("authorization:") &&
		igualSemCaixa(a[len(a)-len("authorization:"):], "authorization:")
}

// fechaCabecalhoAuth diz que o token já NÃO faz parte do cabeçalho: é a próxima
// opção, ou a URL. Sem esse limite a redação engoliria o resto da linha.
func fechaCabecalhoAuth(a string) bool {
	return strings.HasPrefix(a, "-") || strings.Contains(a, "://")
}

func isSecretFlag(a string) bool {
	for _, f := range secretFlags {
		if len(a) == len(f) && igualSemCaixa(a, f) {
			return true
		}
	}
	return false
}

// indiceSemCaixa acha `alvo` em `s` ignorando caixa, e devolve o índice EM S.
//
// `strings.Index(strings.ToLower(s), alvo)` parece a mesma coisa e não é:
// `ToLower` muda o COMPRIMENTO EM BYTES de alguns pontos de código. O K do
// sinal de Kelvin ocupa 3 bytes e vira "k" com 1; o İ turco ocupa 2 e vira
// "i̇" com 3. O índice saía medido numa string e era usado para fatiar OUTRA,
// e onde a minúscula é maior o corte cai depois do começo do segredo — ou some
// com a redação inteira, porque a guarda de tamanho é medida na original. O
// resultado é a senha completa no relatório, que é exatamente o que este
// pacote existe para impedir.
//
// As chaves procuradas são todas ASCII, então dobrar a caixa em ASCII é ao
// mesmo tempo correto e alinhado byte a byte com a string original.
func indiceSemCaixa(s, alvo string) int {
	if alvo == "" || len(alvo) > len(s) {
		return -1
	}
	for i := 0; i+len(alvo) <= len(s); i++ {
		if igualSemCaixa(s[i:i+len(alvo)], alvo) {
			return i
		}
	}
	return -1
}

func igualSemCaixa(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if minusculaASCII(a[i]) != minusculaASCII(b[i]) {
			return false
		}
	}
	return true
}

func minusculaASCII(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}

func redactURLCreds(a string) string {
	i := strings.Index(a, "://")
	j := strings.Index(a[i+3:], "@")
	if j < 0 {
		return a
	}
	return a[:i+3] + "<redacted>@" + a[i+3+j+1:]
}

// Linha redige uma linha de comando que veio como STRING, e não como argv.
//
// É o caso do `ExecStart=` de uma unit, do comando de uma linha de cron e do
// valor de uma variável de ambiente de crontab. Todos carregam a mesma classe
// de segredo que o argv de um processo — `curl -u svc:S3cr3t`, `--token=…` — e
// todos viajavam INTEIROS: os checks os põem como evidência, e o report.Human
// e o JSONL os imprimem verbatim. Redigir só o argv protegia o caminho que já
// estava protegido.
//
// A tokenização é por branco, que é grosseira para shell de verdade (não
// entende aspas), mas erra para o lado seguro: um token com segredo dentro é
// redigido, e a estrutura da linha continua legível para quem investiga.
func Linha(s string) string {
	if s == "" {
		return s
	}
	campos := strings.Fields(s)
	if len(campos) == 0 {
		return s
	}
	return strings.Join(Cmdline(campos), " ")
}

// Valor redige o VALOR de uma variável de ambiente, onde não há flag nem
// estrutura: o nome já veio à parte, e o que sobra é o segredo inteiro ou nada.
// Só as URLs com credencial embutida são recuperáveis aqui.
func Valor(nome, v string) string {
	if v == "" {
		return v
	}
	for _, k := range secretAssign {
		if igualSemCaixa(nome+"=", k) {
			return "<redacted>"
		}
	}
	if strings.Contains(v, "://") && strings.Contains(v, "@") {
		return redactURLCreds(v)
	}
	return v
}
