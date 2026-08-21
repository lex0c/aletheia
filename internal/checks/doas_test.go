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

// cmd restrito a um binário SEM primitiva de escalada é menor privilégio:
// AVISO, não crítico.
//
// O exemplo era `/usr/bin/systemctl`, e ele estava ERRADO: um `cmd
// /usr/bin/systemctl` sem `args` aceita QUALQUER argumento, e `systemctl edit`
// abre um editor como root. O teste passava porque o classificador antigo
// conhecia dezesseis nomes e systemctl não era um deles — ou seja, a suíte
// carimbava de "menor privilégio" exatamente o que a ferramenta não sabia ler.
func TestDoasCmdRestritoEhAviso(t *testing.T) {
	f := fDoas(facts.DoasRule{Permit: true, NoPass: true, Identidade: "bob", Comando: "/usr/sbin/nginx", Text: "permit nopass bob cmd /usr/sbin/nginx"})
	r := doasSemSenha.Run(doasSemSenha, f, testEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevWarn {
		t.Fatalf("cmd sem primitiva conhecida é AVISO: %+v", r.Findings)
	}
	if !strings.Contains(strings.Join(r.Findings[0].Evidence, " "), "NÃO reconhece") {
		t.Error("o que a ferramenta não examinou precisa ser DITO, e não virar " +
			"'é desenho de menor privilégio'")
	}
}

// E o caso que o teste anterior escondia: um binário legítimo com primitiva de
// execução, sem `args`, é root irrestrito — pelo doas exatamente como pelo sudo.
func TestDoasCmdComPrimitivaSemArgsEhCritico(t *testing.T) {
	for _, cmd := range []string{"/usr/bin/systemctl", "/usr/bin/find", "/usr/bin/tar", "/usr/bin/vim"} {
		f := fDoas(facts.DoasRule{Permit: true, NoPass: true, Identidade: "bob", Comando: cmd, Text: "permit nopass bob cmd " + cmd})
		r := doasSemSenha.Run(doasSemSenha, f, testEnv())
		if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevCritical {
			t.Errorf("%s sem args é root irrestrito: %+v", cmd, r.Findings)
		}
	}
}

// O FREIO: `args` fixado prende a primitiva, e a regra volta a ser aviso. Sem
// isto a tabela de primitivas viraria ruído em cima de toda automação de backup.
func TestDoasArgsFixadosPrendemAPrimitiva(t *testing.T) {
	f := fDoas(facts.DoasRule{
		Permit: true, NoPass: true, Identidade: "bkp", Comando: "/usr/bin/tar",
		TemArgs: true, Args: []string{"czf", "/backup/srv.tgz", "/srv"},
		Text: "permit nopass bkp cmd /usr/bin/tar args czf /backup/srv.tgz /srv",
	})
	r := doasSemSenha.Run(doasSemSenha, f, testEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevWarn {
		t.Fatalf("args fixados prendem a primitiva do tar: %+v", r.Findings)
	}
}

// MAS o editor escapa mesmo preso: `cmd /usr/bin/vim args /etc/motd` continua
// sendo `:!sh`, e é a regra mais inocente do arquivo.
func TestDoasEditorEscapaMesmoComArgsFixados(t *testing.T) {
	f := fDoas(facts.DoasRule{
		Permit: true, NoPass: true, Identidade: "ana", Comando: "/usr/bin/vim",
		TemArgs: true, Args: []string{"/etc/motd"},
		Text: "permit nopass ana cmd /usr/bin/vim args /etc/motd",
	})
	r := doasSemSenha.Run(doasSemSenha, f, testEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevCritical {
		t.Fatalf("o escape do vim não depende do argumento: %+v", r.Findings)
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
		// O campo Comando guarda UM token — é o que o parseDoas produz para
		// `cmd python3 -c import os`, porque na gramática do doas.conf o que vem
		// depois do programa só é argumento fixado se vier atrás de `args`.
		// O fixture antigo enfiava a linha inteira aqui, e passou a decidir
		// severidade quando o classificador aprendeu a ler argumento: uma regra
		// que o parser nunca gera estava governando o contrato.
		{Permit: true, NoPass: true, Identidade: "bob", Comando: "python3", Text: "permit nopass bob cmd python3 -c import os"},
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
