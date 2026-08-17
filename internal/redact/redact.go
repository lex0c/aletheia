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
		low := strings.ToLower(a)

		// -pSENHA colado (padrão do mysql) e --password=SENHA
		if red, ok := redactInline(a, low); ok {
			out = append(out, red)
			continue
		}
		// flag isolada: o PRÓXIMO argumento é o valor
		if isSecretFlag(low) {
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

func redactInline(a, low string) (string, bool) {
	for _, k := range secretAssign {
		if i := strings.Index(low, k); i >= 0 && i+len(k) < len(a) {
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

func isSecretFlag(low string) bool {
	for _, f := range secretFlags {
		if low == f {
			return true
		}
	}
	return false
}

func redactURLCreds(a string) string {
	i := strings.Index(a, "://")
	j := strings.Index(a[i+3:], "@")
	if j < 0 {
		return a
	}
	return a[:i+3] + "<redacted>@" + a[i+3+j+1:]
}
