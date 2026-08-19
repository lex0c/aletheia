package facts

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/lex0c/aletheia/internal/env"
)

func rootComArquivos(t *testing.T, arqs map[string]string) *env.Env {
	t.Helper()
	raiz := t.TempDir()
	for rel, conteudo := range arqs {
		full := filepath.Join(raiz, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(conteudo), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	e := env.Probe(env.Options{Root: raiz, Version: "test"})
	t.Cleanup(func() { e.Close() })
	return e
}

func trigPorKind(f *Facts, kind string) (Trigger, bool) {
	for _, t := range f.Triggers {
		if t.Kind == kind {
			return t, true
		}
	}
	return Trigger{}, false
}

// inetd.conf: o server é o campo 6 (índice 5) — depois de user. `internal` é
// serviço embutido, sem programa externo.
func TestCollectInetdCampoDoServer(t *testing.T) {
	e := rootComArquivos(t, map[string]string{
		"etc/inetd.conf": "# comentário\n" +
			"9999 stream tcp nowait root /tmp/.x bash -i\n" +
			"echo stream tcp nowait root internal\n", // internal: pulado
	})
	f := &Facts{}
	collectInetd(f, e)
	tr, ok := trigPorKind(f, "inetd")
	if !ok || len(tr.Lines) != 1 {
		t.Fatalf("uma linha de server esperada: %+v", f.Triggers)
	}
	if tr.Lines[0].Text != "/tmp/.x" {
		t.Errorf("o server é o campo 6 (índice 5), veio %q", tr.Lines[0].Text)
	}
}

// xinetd: server = programa, disable = yes desliga (mas o arquivo fica).
func TestCollectXinetdRespeitaDisable(t *testing.T) {
	e := rootComArquivos(t, map[string]string{
		"etc/xinetd.d/bd":  "service bd {\n  server = /dev/shm/agent\n  disable = no\n}\n",
		"etc/xinetd.d/off": "service off {\n  server = /tmp/.y\n  disable = yes\n}\n",
	})
	f := &Facts{}
	collectXinetd(f, e)
	if len(f.Triggers) != 1 {
		t.Fatalf("só o habilitado vira gatilho: %+v", f.Triggers)
	}
	if f.Triggers[0].Lines[0].Text != "/dev/shm/agent" {
		t.Errorf("server errado: %+v", f.Triggers[0])
	}
}

// inittab: só as ações que EXECUTAM (respawn/wait/once/boot/bootwait/sysinit).
func TestCollectInittabSoAcoesQueExecutam(t *testing.T) {
	e := rootComArquivos(t, map[string]string{
		"etc/inittab": "id:3:initdefault:\n" + // initdefault não executa
			"x:2345:respawn:/tmp/.boot\n" + // respawn: executa
			"si::sysinit:/etc/rc.d/rc.sysinit\n" + // sysinit: executa
			"# comentário\n",
	})
	f := &Facts{}
	collectInittab(f, e)
	tr, ok := trigPorKind(f, "inittab")
	if !ok {
		t.Fatal("inittab não virou gatilho")
	}
	if len(tr.Lines) != 2 {
		t.Fatalf("respawn e sysinit executam; initdefault não: %+v", tr.Lines)
	}
	if tr.Lines[0].Text != "/tmp/.boot" {
		t.Errorf("respawn: %q", tr.Lines[0].Text)
	}
}
