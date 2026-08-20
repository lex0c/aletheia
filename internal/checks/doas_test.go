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

// cmd restrito a um SHELL como root é root irrestrito: CRÍTICO, não aviso.
// `permit nopass user cmd /bin/sh` restringe "a um comando" que executa
// qualquer outro — a restrição é ilusória.
func TestDoasCmdShellEhCritico(t *testing.T) {
	casos := []facts.DoasRule{
		{Permit: true, NoPass: true, Identidade: "bob", Comando: "/bin/sh", Text: "permit nopass bob cmd /bin/sh"},
		{Permit: true, NoPass: true, Identidade: "bob", Comando: "/usr/bin/bash", Text: "permit nopass bob cmd /usr/bin/bash"},
		{Permit: true, NoPass: true, Identidade: "bob", Comando: "python3 -c import os", Text: "permit nopass bob cmd python3"},
	}
	for _, d := range casos {
		f := fDoas(d)
		r := doasSemSenha.Run(doasSemSenha, f, testEnv())
		if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevCritical {
			t.Errorf("shell/interpretador como root é CRÍTICO: %q -> %+v", d.Comando, r.Findings)
		}
	}
}

// last-match: `permit nopass X` anulado por um `deny X` posterior NÃO dispara.
func TestDoasLastMatchDenyPosteriorAnula(t *testing.T) {
	f := fDoas(
		facts.DoasRule{Permit: true, NoPass: true, Identidade: "attacker", Text: "permit nopass attacker"},
		facts.DoasRule{Permit: false, Identidade: "attacker", Text: "deny attacker"},
	)
	r := doasSemSenha.Run(doasSemSenha, f, testEnv())
	if len(r.Findings) != 0 {
		t.Fatalf("deny posterior anula o permit nopass (last-match): %+v", r.Findings)
	}
}

// Mas um deny ANTES do permit não anula (a ordem importa).
func TestDoasDenyAntesNaoAnula(t *testing.T) {
	f := fDoas(
		facts.DoasRule{Permit: false, Identidade: "attacker", Text: "deny attacker"},
		facts.DoasRule{Permit: true, NoPass: true, Identidade: "attacker", Text: "permit nopass attacker"},
	)
	r := doasSemSenha.Run(doasSemSenha, f, testEnv())
	if len(r.Findings) != 1 {
		t.Fatalf("permit nopass depois do deny é a regra efetiva: %+v", r.Findings)
	}
}
