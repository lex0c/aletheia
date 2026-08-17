package checks

import (
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/facts"
)

func procAt(pid int, exe string) facts.Process {
	return facts.Process{PID: pid, Comm: "x", Exe: exe}
}

func TestSuspiciousPathDisparaOndeNadaSeInstala(t *testing.T) {
	casos := []string{
		"/tmp/.x",
		"/var/tmp/.systemd-private/agent",
		"/dev/shm/kworker",
		"/run/shm/x",
		"/run/user/1000/.cache/x",
		"/dev/.hidden/rk",
		"/home/app/.config/systemd-update/agent",
		"/root/.cache/.x",
	}
	for _, exe := range casos {
		f := &facts.Facts{Processes: []facts.Process{procAt(1, exe)}}
		r := suspiciousPath.Run(suspiciousPath, f, testEnv())
		if len(r.Findings) != 1 {
			t.Errorf("%s: achados = %d, quer 1", exe, len(r.Findings))
			continue
		}
		if !r.Findings[0].Irreversible {
			t.Errorf("%s: em tmpfs e /tmp a evidência some sozinha — preservar é irreversível", exe)
		}
	}
}

func TestSuspiciousPathNaoDisparaOndeSeInstala(t *testing.T) {
	casos := []string{
		"/usr/bin/curl",
		"/usr/local/bin/app",
		"/opt/vendor/agent",
		"/snap/core/1234/bin/x",
		// XDG: é o caminho PADRONIZADO para binário de usuário. pipx, pip
		// --user e cargo instalam aqui, e tratá-lo como suspeito faria a
		// ferramenta acusar rotina.
		"/home/app/.local/bin/tool",
		"/home/app/.local/share/nvim/mason/bin/lsp",
		"/home/app/projeto/build/servidor",
	}
	for _, exe := range casos {
		f := &facts.Facts{Processes: []facts.Process{procAt(1, exe)}}
		if r := suspiciousPath.Run(suspiciousPath, f, testEnv()); len(r.Findings) != 0 {
			t.Errorf("%s: disparou onde instalação legítima coloca binário", exe)
		}
	}
}

// memfd e binário apagado têm check próprio. Contar o mesmo processo em três
// achados infla a triagem e faz o operador investigar a mesma coisa três vezes.
func TestSuspiciousPathNaoDuplicaOsChecksDeExe(t *testing.T) {
	f := &facts.Facts{Processes: []facts.Process{
		{PID: 1, Exe: "/tmp/.x", ExeDeleted: true},
		{PID: 2, Exe: "/memfd:x", ExeMemfd: true},
	}}
	if r := suspiciousPath.Run(suspiciousPath, f, testEnv()); len(r.Findings) != 0 {
		t.Errorf("duplicou achado de exe apagado/memfd: %v", r.Findings[0].Subject)
	}
}

func TestSuspiciousPathContaExeIlegivelComoParcial(t *testing.T) {
	f := &facts.Facts{Processes: []facts.Process{
		{PID: 1, ExeErr: "sem permissão", ExeDenied: true},
		{PID: 2, ExeErr: "sem permissão", ExeDenied: true},
	}}
	r := suspiciousPath.Run(suspiciousPath, f, testEnv())
	if len(r.Partial) == 0 {
		t.Fatal("exe ilegível precisa virar cobertura parcial: sem isso, uma " +
			"execução sem root diria que olhou tudo")
	}
	if !strings.Contains(r.Partial[0], "2") {
		t.Errorf("a contagem precisa aparecer: %q", r.Partial[0])
	}
}
