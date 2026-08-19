package checks

import (
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/facts"
)

func fDoas(rs ...facts.DoasRule) *facts.Facts { return &facts.Facts{Doas: rs} }

// permit nopass sem `as` e sem `cmd` = root, qualquer comando, sem senha: CRÍTICO.
func TestDoasNopassIrrestritoEhCritico(t *testing.T) {
	f := fDoas(facts.DoasRule{Permit: true, NoPass: true, Identidade: ":wheel", Text: "permit nopass :wheel"})
	r := doasSemSenha.Run(doasSemSenha, f, testEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevCritical {
		t.Fatalf("root sem senha, qualquer comando: %+v", r.Findings)
	}
}

// as OUTRA conta não é root: AVISO.
func TestDoasComoOutraContaEhAviso(t *testing.T) {
	f := fDoas(facts.DoasRule{Permit: true, NoPass: true, Identidade: "alice", Alvo: "postgres", Text: "permit nopass alice as postgres"})
	r := doasSemSenha.Run(doasSemSenha, f, testEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevWarn {
		t.Fatalf("como postgres é AVISO: %+v", r.Findings)
	}
}

// cmd restrito é menor privilégio: AVISO, não crítico.
func TestDoasCmdRestritoEhAviso(t *testing.T) {
	f := fDoas(facts.DoasRule{Permit: true, NoPass: true, Identidade: "bob", Comando: "/usr/bin/systemctl", Text: "permit nopass bob cmd /usr/bin/systemctl"})
	r := doasSemSenha.Run(doasSemSenha, f, testEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevWarn {
		t.Fatalf("cmd restrito é AVISO: %+v", r.Findings)
	}
}

// permit COM senha (sem nopass) e deny NÃO disparam.
func TestDoasComSenhaEDenyNaoDisparam(t *testing.T) {
	f := fDoas(
		facts.DoasRule{Permit: true, NoPass: false, Identidade: ":admin", Text: "permit :admin"},
		facts.DoasRule{Permit: false, NoPass: true, Identidade: "eve", Text: "deny nopass eve"},
	)
	r := doasSemSenha.Run(doasSemSenha, f, testEnv())
	if len(r.Findings) != 0 {
		t.Fatalf("permit COM senha e deny não são escalada sem senha: %+v", r.Findings)
	}
	_ = strings.TrimSpace
}
