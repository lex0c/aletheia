package checks

import (
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/facts"
)

// `NOPASSWD: /bin/bash` como root É root irrestrito, e precisa sair CRITICAL.
//
// A escada do sudo só subia em `amplo && comoRoot` (a especificação ALL). O
// doasSemSenha, duzentas linhas abaixo no mesmo arquivo, já tinha o
// discriminador certo — `comoRoot && ehShellOuInterp`. O resultado era o MESMO
// poder saindo CRITICAL pelo doas e WARN pelo sudo, ou seja, exit 1 pelo caminho
// que 99% dos hosts usam.
func TestSudoNopasswdParaShellSaiCriticalComoODoas(t *testing.T) {
	rodar := func(regra string) check.Result {
		f := &facts.Facts{
			Sudoers: []facts.SudoRule{{
				File: "/etc/sudoers.d/deploy", Line: 1, Text: regra,
			}},
		}
		return sudoSemSenha.Run(sudoSemSenha, f, testEnv())
	}

	casos := []struct {
		regra string
		quer  check.Severity
		porqu string
	}{
		{"deploy ALL=(root) NOPASSWD: /bin/bash", check.SevCritical,
			"shell como root sem senha é root irrestrito"},
		{"deploy ALL=(root) NOPASSWD: /usr/bin/python3", check.SevCritical,
			"interpretador como root sem senha é root irrestrito"},
		{"deploy ALL=(root) NOPASSWD: ALL", check.SevCritical,
			"ALL como root continua crítico"},
		{"deploy ALL=(root) NOPASSWD: /usr/bin/systemctl restart nginx", check.SevWarn,
			"comando nomeado que não é shell continua sendo aviso"},
	}
	for _, c := range casos {
		r := rodar(c.regra)
		if len(r.Findings) == 0 {
			t.Errorf("%s: nenhum achado", c.regra)
			continue
		}
		if got := r.Findings[0].Sev; got != c.quer {
			t.Errorf("%s\n  severidade=%v, queria %v — %s",
				c.regra, got, c.quer, c.porqu)
		}
	}
}

// A isenção por dono de pacote na redundância vale para DOIS mecanismos, e não
// só para a transição do SysV.
//
// Estreitar para "dois, um deles init.d" parece o conserto óbvio — o comentário
// do código chegou a prometer isso — e rende ruído numa distribuição limpa: o
// apt entrega /etc/cron.daily/apt-compat E apt-daily.timer para o mesmo alvo, e
// o dpkg faz igual. Este teste trava as DUAS pontas para que a tentação não
// volte: dois com dono cala, três dispara.
func TestIsencaoDeRedundanciaValeParaDoisMecanismosComDono(t *testing.T) {
	alvo := "/usr/lib/apt/apt.systemd.daily"
	base := func() *facts.Facts {
		return &facts.Facts{
			Units: []facts.Unit{{
				Path: "/lib/systemd/system/apt-daily.service", Scope: "system",
				Kind: "service", Vendor: true,
				Exec: []facts.ExecLine{{Key: "ExecStart", Cmd: alvo}},
			}},
			Cron: []facts.CronEntry{{
				File: "/etc/cron.daily/apt-compat", Kind: "dir",
				Schedule: "diário", Cmd: alvo,
			}},
			Ownership: []facts.Ownership{{Path: alvo, Owned: true, Pacote: "apt"}},
			Pkg:       facts.PkgDB{Kind: "dpkg", Consultavel: true},
		}
	}

	if r := persistRedundant.Run(persistRedundant, base(), testEnv()); len(r.Findings) != 0 {
		t.Errorf("unit + cron para alvo EMPACOTADO virou achado (%d): é o que o "+
			"apt e o dpkg fazem numa debian limpa, e o ruído faz o operador "+
			"ignorar a saída", len(r.Findings))
	}

	// TRÊS mecanismos não são transição de ninguém: dispara mesmo com dono.
	f := base()
	f.Triggers = []facts.Trigger{{
		File: "/etc/rc.local", Kind: "rc",
		Lines: []facts.TriggerLine{{N: 3, Text: alvo}},
	}}
	if r := persistRedundant.Run(persistRedundant, f, testEnv()); len(r.Findings) == 0 {
		t.Error("três mecanismos para o mesmo alvo NÃO dispararam: a isenção " +
			"cobre a distribuição em transição, que usa dois")
	}
}

// A evidência de argv passa por redact antes de sair.
//
// checks/proc.go já redigia; tree.go, path.go e ioc.go não. Um
// `nginx → bash -c 'mysqldump -u root -pS3cr3t …'` levava a senha para o
// relatório humano, para o JSONL da frota e para o ticket (SPEC 5.4).
//
// (O pai é nginx e não sshd de propósito: sshd está FORA de daemonsDeRede,
// porque gerar shell é o trabalho dele.)
func TestArgvNaEvidenciaNaoVazaSegredo(t *testing.T) {
	const senha = "S3cr3tD3Verdade"
	f := &facts.Facts{
		Processes: []facts.Process{
			{PID: 100, Comm: "nginx", Exe: "/usr/sbin/nginx", UID: 0, Cgroup: "/"},
			{
				PID: 200, PPID: 100, Comm: "bash", Exe: "/bin/bash", UID: 0,
				Cgroup: "/",
				Argv:   []string{"bash", "-c", "mysqldump -u root -p" + senha + " db"},
			},
		},
	}
	r := shellDeServico.Run(shellDeServico, f, testEnv())
	if len(r.Findings) == 0 {
		t.Fatal("o check não disparou: sem achado o teste não prova nada sobre " +
			"redação — nginx gerando bash é a linhagem que ele existe para pegar")
	}
	viuArgv := false
	for _, fd := range r.Findings {
		for _, ev := range fd.Evidence {
			if strings.HasPrefix(ev, "argv=") {
				viuArgv = true
			}
			if strings.Contains(ev, senha) {
				t.Errorf("a senha saiu crua na evidência: %q\n"+
					"Ela vai daqui para o relatório, para o JSONL da frota e "+
					"para o ticket — redact.Cmdline existe para isso", ev)
			}
		}
	}
	if !viuArgv {
		t.Fatal("nenhuma linha de argv na evidência: o teste passaria por " +
			"ausência de argv, não por redação")
	}
}
