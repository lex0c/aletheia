package checks

import (
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/facts"
)

func fEnv(linha string) *facts.Facts {
	return &facts.Facts{Triggers: []facts.Trigger{{
		File: "/etc/profile", Kind: "shell", When: "shell de LOGIN",
		Lines: []facts.TriggerLine{{N: 3, Text: linha}},
	}}}
}

func TestEnvNaoEhBashEnv(t *testing.T) {
	// ENV NÃO pode disparar o check de BASH_ENV.
	if r := bashEnv.Run(bashEnv, fEnv("export ENV=$HOME/.shrc"), imgEnv()); len(r.Findings) != 0 {
		t.Errorf("ENV disparou persist.bash_env: %+v", r.Findings)
	}
	// BASH_ENV continua disparando, crítico.
	r := bashEnv.Run(bashEnv, fEnv("export BASH_ENV=/tmp/.x"), imgEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevCritical {
		t.Fatalf("BASH_ENV deveria ser 1 crítico: %+v", r.Findings)
	}
}

func TestShellEnvSeveridadeVemDoAlvo(t *testing.T) {
	// Alvo comum: AVISO, não crítico. É config documentada.
	r := shellEnv.Run(shellEnv, fEnv("export ENV=/etc/shrc"), imgEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevWarn {
		t.Fatalf("ENV para caminho normal é AVISO: %+v", r.Findings)
	}
	// Alvo em tmpfs: aí sim crítico.
	r = shellEnv.Run(shellEnv, fEnv("export ENV=/dev/shm/.shrc"), imgEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevCritical {
		t.Fatalf("ENV apontando para tmpfs é CRÍTICO: %+v", r.Findings)
	}
	if !strings.Contains(strings.Join(r.Findings[0].Evidence, " "), "/dev/shm/.shrc") {
		t.Errorf("o ALVO precisa aparecer na evidência: %v", r.Findings[0].Evidence)
	}
	// E BASH_ENV não dispara o de ENV.
	if r := shellEnv.Run(shellEnv, fEnv("export BASH_ENV=/tmp/.x"), imgEnv()); len(r.Findings) != 0 {
		t.Errorf("BASH_ENV disparou persist.shell_env: %+v", r.Findings)
	}
}
