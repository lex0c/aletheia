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
	for _, a := range argv {
		if skipNext {
			out = append(out, "<redacted>")
			skipNext = false
			continue
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
