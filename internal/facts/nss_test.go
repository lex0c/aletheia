package facts

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/lex0c/aletheia/internal/env"
)

func raizNSS(t *testing.T, arqs map[string]string) *env.Env {
	t.Helper()
	raiz := t.TempDir()
	for rel, c := range arqs {
		full := filepath.Join(raiz, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	e := env.Probe(env.Options{Root: raiz, Version: "test"})
	t.Cleanup(func() { e.Close() })
	return e
}

func nssPorFonte(f *Facts, fonte string) (NSSModule, bool) {
	for _, m := range f.NSSModules {
		if m.Fonte == fonte {
			return m, true
		}
	}
	return NSSModule{}, false
}

// A fonte maliciosa é lida, a lib é localizada, e blocos de ação [..] não viram
// fonte — nem quando têm espaço dentro.
func TestCollectNSSLocalizaLibEIgnoraAcoes(t *testing.T) {
	e := raizNSS(t, map[string]string{
		"etc/nsswitch.conf": "# comentário\n" +
			"passwd:  files [SUCCESS=return] impl\n" +
			"hosts:   files [ NOTFOUND = return ] dns\n",
		"usr/lib/libnss_impl.so.2": "\x7fELF-falso",
	})
	f := &Facts{}
	collectNSS(f, e)

	m, ok := nssPorFonte(f, "impl")
	if !ok {
		t.Fatalf("fonte impl não coletada: %+v", f.NSSModules)
	}
	if m.Path != "/usr/lib/libnss_impl.so.2" {
		t.Errorf("lib não localizada: %q", m.Path)
	}
	// blocos de ação NÃO podem virar fonte
	for _, bad := range []string{"SUCCESS=return", "NOTFOUND", "return", "[SUCCESS=return]"} {
		if _, achou := nssPorFonte(f, bad); achou {
			t.Errorf("bloco de ação %q virou fonte", bad)
		}
	}
	// files e dns são fontes legítimas, coletadas mas sem lib plantada aqui
	if _, ok := nssPorFonte(f, "files"); !ok {
		t.Error("files deveria ser coletada como fonte")
	}
}

// nsswitch.conf ausente NÃO é lacuna (glibc tem padrão embutido); ilegível É.
func TestCollectNSSAusenteNaoEhLacuna(t *testing.T) {
	e := raizNSS(t, map[string]string{"etc/hosts": "127.0.0.1 localhost\n"})
	f := &Facts{}
	collectNSS(f, e)
	if len(f.PersistDenied["nss"]) != 0 {
		t.Errorf("ausência de nsswitch.conf não é lacuna: %+v", f.PersistDenied["nss"])
	}
}

// item 1: a lib pode morar num dir que só o ld.so.conf conhece. O coletor usa a
// visão do loader (SearchDirs), não só a lista fixa.
func TestCollectNSSSegueSearchDirsDoLoader(t *testing.T) {
	e := raizNSS(t, map[string]string{
		"etc/nsswitch.conf":         "passwd: files impl\n",
		"opt/.lib/libnss_impl.so.2": "\x7fELF",
	})
	f := &Facts{}
	// simula o que collectLoader deixaria: /opt/.lib como diretório de busca
	f.Loader.SearchDirs = []LoaderDir{{Dir: "/opt/.lib", From: "/etc/ld.so.conf.d/x.conf"}}
	collectNSS(f, e)
	m, ok := nssPorFonte(f, "impl")
	if !ok || m.Path != "/opt/.lib/libnss_impl.so.2" {
		t.Fatalf("lib em dir do ld.so.conf deve ser localizada: %+v", f.NSSModules)
	}
}
