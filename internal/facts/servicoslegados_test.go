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

// inetd.conf: o server começa no campo 6 (índice 5), depois de user — e os
// ARGS depois dele fazem parte do comando. Guardar só o campo 5 apagava o
// payload de um wrapper (`/bin/sh sh -c /tmp/.x` viraria `/bin/sh`, e o
// /tmp/.x sumia da decisão). `internal` é serviço embutido, sem programa.
func TestCollectInetdServerMaisArgs(t *testing.T) {
	e := rootComArquivos(t, map[string]string{
		"etc/inetd.conf": "# comentário\n" +
			"9999 stream tcp nowait root /bin/sh sh -c /tmp/.x\n" +
			"echo stream tcp nowait root internal\n", // internal: pulado
	})
	f := &Facts{}
	collectInetd(f, e)
	tr, ok := trigPorKind(f, "inetd")
	if !ok || len(tr.Lines) != 1 {
		t.Fatalf("uma linha de server esperada: %+v", f.Triggers)
	}
	// Server + args preservados: sem isso o alvoEfetivo do check não teria o
	// `-c /tmp/.x` para desembrulhar.
	if tr.Lines[0].Text != "/bin/sh sh -c /tmp/.x" {
		t.Errorf("server+args esperados, veio %q", tr.Lines[0].Text)
	}
}

// xinetd: server = programa, disable = yes desliga (mas o arquivo fica), e
// server_args entra no comando — com NAMEINARGS/tcpd o programa real está lá.
func TestCollectXinetdRespeitaDisable(t *testing.T) {
	e := rootComArquivos(t, map[string]string{
		"etc/xinetd.conf":  "includedir /etc/xinetd.d\n",
		"etc/xinetd.d/bd":  "service bd {\n  server = /usr/sbin/tcpd\n  server_args = /tmp/.x\n  disable = no\n}\n",
		"etc/xinetd.d/off": "service off {\n  server = /tmp/.y\n  disable = yes\n}\n",
	})
	f := &Facts{}
	collectXinetd(f, e)
	if len(f.Triggers) != 1 {
		t.Fatalf("só o habilitado vira gatilho: %+v", f.Triggers)
	}
	if f.Triggers[0].Lines[0].Text != "/usr/sbin/tcpd /tmp/.x" {
		t.Errorf("server+server_args esperados: %+v", f.Triggers[0])
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

// xinetd com DOIS blocos no mesmo arquivo: a forma ingênua (último server= do
// arquivo) fundia os blocos. O backdoor mora no segundo; o parser de blocos o vê.
func TestCollectXinetdDoisBlocosNoMesmoArquivo(t *testing.T) {
	e := rootComArquivos(t, map[string]string{
		"etc/xinetd.conf": "includedir /etc/xinetd.d\n",
		"etc/xinetd.d/dois": "service ftp\n{\n  server = /usr/sbin/in.ftpd\n  disable = yes\n}\n" +
			"service bd\n{\n  server = /dev/shm/agent\n  disable = no\n}\n",
	})
	f := &Facts{}
	collectXinetd(f, e)
	tr, ok := trigPorKind(f, "xinetd")
	if !ok || len(tr.Lines) != 1 {
		t.Fatalf("só o segundo bloco (habilitado) vira gatilho: %+v", f.Triggers)
	}
	if tr.Lines[0].Text != "/dev/shm/agent" {
		t.Errorf("server do 2º bloco esperado, veio %q", tr.Lines[0].Text)
	}
}

// defaults{ disabled = svc } desliga um serviço declarado em OUTRO arquivo. Sem
// ler o defaults, a ferramenta reportaria um serviço que o xinetd nunca sobe.
func TestCollectXinetdDefaultsDisabled(t *testing.T) {
	e := rootComArquivos(t, map[string]string{
		"etc/xinetd.conf":     "defaults\n{\n  disabled = telnet\n}\nincludedir /etc/xinetd.d\n",
		"etc/xinetd.d/telnet": "service telnet\n{\n  server = /usr/sbin/in.telnetd\n  disable = no\n}\n",
	})
	f := &Facts{}
	collectXinetd(f, e)
	if _, ok := trigPorKind(f, "xinetd"); ok {
		t.Fatalf("defaults{disabled=telnet} desliga o serviço: %+v", f.Triggers)
	}
}

// defaults{ enabled = ... } é lista branca: um serviço fora dela não sobe,
// mesmo com disable=no próprio.
func TestCollectXinetdDefaultsEnabledEhListaBranca(t *testing.T) {
	e := rootComArquivos(t, map[string]string{
		"etc/xinetd.conf": "defaults\n{\n  enabled = ssh\n}\n" +
			"service bd\n{\n  server = /tmp/.x\n  disable = no\n}\n",
	})
	f := &Facts{}
	collectXinetd(f, e)
	if _, ok := trigPorKind(f, "xinetd"); ok {
		t.Fatalf("bd não está no enabled=; não deveria subir: %+v", f.Triggers)
	}
}

// Serviço declarado DIRETO no xinetd.conf (sem includedir), forma antiga.
func TestCollectXinetdServicoNoConf(t *testing.T) {
	e := rootComArquivos(t, map[string]string{
		"etc/xinetd.conf": "service rsync\n{\n  server = /usr/bin/rsync\n  server_args = --daemon\n  disable = no\n}\n",
	})
	f := &Facts{}
	collectXinetd(f, e)
	tr, ok := trigPorKind(f, "xinetd")
	if !ok || len(tr.Lines) != 1 {
		t.Fatalf("serviço no próprio xinetd.conf deve ser visto: %+v", f.Triggers)
	}
	if tr.Lines[0].Text != "/usr/bin/rsync --daemon" {
		t.Errorf("server+args esperados, veio %q", tr.Lines[0].Text)
	}
}

// includedir arbitrário: xinetd segue o includedir DECLARADO, não um caminho
// fixo. Um serviço num diretório que só o xinetd.conf conhece precisa aparecer.
func TestCollectXinetdSegueIncludedirArbitrario(t *testing.T) {
	e := rootComArquivos(t, map[string]string{
		"etc/xinetd.conf": "includedir /opt/.xinetd\n",
		"opt/.xinetd/bd":  "service bd {\n  server = /tmp/.x\n  disable = no\n}\n",
	})
	f := &Facts{}
	collectXinetd(f, e)
	tr, ok := trigPorKind(f, "xinetd")
	if !ok || len(tr.Lines) != 1 || tr.Lines[0].Text != "/tmp/.x" {
		t.Fatalf("serviço no includedir arbitrário deve aparecer: %+v", f.Triggers)
	}
}

// include de ARQUIVO único (não diretório).
func TestCollectXinetdSegueInclude(t *testing.T) {
	e := rootComArquivos(t, map[string]string{
		"etc/xinetd.conf":  "include /etc/xinetd.extra\n",
		"etc/xinetd.extra": "service bd {\n  server = /dev/shm/x\n  disable = no\n}\n",
	})
	f := &Facts{}
	collectXinetd(f, e)
	tr, ok := trigPorKind(f, "xinetd")
	if !ok || len(tr.Lines) != 1 || tr.Lines[0].Text != "/dev/shm/x" {
		t.Fatalf("include de arquivo deve ser seguido: %+v", f.Triggers)
	}
}

// FP simétrico: /etc/xinetd.d que NINGUÉM inclui é config inerte — o xinetd não
// a lê, e a ferramenta também não deve.
func TestCollectXinetdNaoVarreDirNaoIncluido(t *testing.T) {
	e := rootComArquivos(t, map[string]string{
		"etc/xinetd.conf": "defaults {\n}\n", // sem includedir
		"etc/xinetd.d/bd": "service bd {\n  server = /tmp/.x\n  disable = no\n}\n",
	})
	f := &Facts{}
	collectXinetd(f, e)
	if _, ok := trigPorKind(f, "xinetd"); ok {
		t.Fatalf("xinetd.d não incluído é inerte; não deveria virar achado: %+v", f.Triggers)
	}
}

// enabled += : lista branca ACUMULA. `enabled = bd` seguido de `enabled += ssh`
// é {bd, ssh}; tratar += como = apagaria bd e ele viraria "desabilitado".
func TestCollectXinetdEnabledAcumulaComMaisIgual(t *testing.T) {
	e := rootComArquivos(t, map[string]string{
		"etc/xinetd.conf": "defaults\n{\n  enabled = bd\n  enabled += ssh\n}\n" +
			"service bd\n{\n  server = /tmp/.x\n  disable = no\n}\n",
	})
	f := &Facts{}
	collectXinetd(f, e)
	tr, ok := trigPorKind(f, "xinetd")
	if !ok || len(tr.Lines) != 1 || tr.Lines[0].Text != "/tmp/.x" {
		t.Fatalf("bd está no enabled acumulado; deveria subir: %+v", f.Triggers)
	}
}

// disabled -= : remove da lista de desligados. `disabled = bd` e depois
// `disabled -= bd` reabilita bd.
func TestCollectXinetdDisabledMenosIgualReabilita(t *testing.T) {
	e := rootComArquivos(t, map[string]string{
		"etc/xinetd.conf": "defaults\n{\n  disabled = bd other\n  disabled -= bd\n}\n" +
			"service bd\n{\n  server = /tmp/.x\n  disable = no\n}\n",
	})
	f := &Facts{}
	collectXinetd(f, e)
	tr, ok := trigPorKind(f, "xinetd")
	if !ok || len(tr.Lines) != 1 {
		t.Fatalf("disabled -= bd reabilita bd: %+v", f.Triggers)
	}
}
