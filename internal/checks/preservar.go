package checks

import (
	"strconv"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
)

// A instrução de preservação, num lugar só.
//
// # A regra
//
// Quando a evidência MORRE COM O PROCESSO, o passo é `aletheia preserve`. Quando
// ela está num arquivo em disco, continua sendo `cp` — o arquivo não vai a lugar
// nenhum, e `cp` é o comando que todo respondedor lê sem hesitar.
//
// A distinção não é estética. Para um processo, `cp /proc/<pid>/exe` copia, mas
// não guarda o `stat`, não hasheia os dois lados, não sabe se o exe era um memfd
// e não dumpa memória. E o que a ferramenta recomendava para a memória era o
// `gcore`, que faz attach: para o processo e escreve TracerPid — um alvo parado
// no meio da coleta muda o que se está medindo, e um implante que lê o próprio
// TracerPid sabe que está sendo olhado.
//
// # Por que o caminho completo
//
// O binário é estático e costuma ser copiado ad hoc para o host — `/tmp/aletheia`,
// `./aletheia`, um disco montado. `sudo aletheia` presumiria PATH. O `ToolPath`
// é o caminho REAL do processo que acabou de rodar (com symlink resolvido), e é
// a única forma de a instrução funcionar colada no terminal.
func preservarPID(e *env.Env, pid int, flags ...string) string {
	s := "sudo " + check.Arg(ferramenta(e)) + " preserve --out \"$IR\" --pid " + strconv.Itoa(pid)
	for _, f := range flags {
		s += " " + f
	}
	return s
}

func ferramenta(e *env.Env) string {
	if e != nil && e.ToolPath != "" {
		return e.ToolPath
	}
	return "aletheia"
}
