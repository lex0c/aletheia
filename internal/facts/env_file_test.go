package facts

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/lex0c/aletheia/internal/env"
)

func envDe(u Unit, key string) (string, bool) {
	for _, s := range u.Environment {
		if s.Key == key {
			return s.Value, true
		}
	}
	return "", false
}

// EnvironmentFile com WILDCARD: um LD_PRELOAD num arquivo que casa o glob não
// pode virar FN só porque o systemd expande e o parser lia o literal.
func TestEnvironmentFileGlobExpande(t *testing.T) {
	raiz := t.TempDir()
	os.MkdirAll(filepath.Join(raiz, "etc/app"), 0o755)
	os.WriteFile(filepath.Join(raiz, "etc/app/backdoor.env"), []byte("LD_PRELOAD=/tmp/.x.so\n"), 0o644)
	os.WriteFile(filepath.Join(raiz, "svc.service"),
		[]byte("[Service]\nEnvironmentFile=/etc/app/*.env\nExecStart=/usr/bin/svc\n"), 0o644)
	e := env.Probe(env.Options{Root: raiz, Version: "test"})
	t.Cleanup(func() { e.Close() })
	u := parseUnitFile(e, "/svc.service", "system", false)
	v, ok := envDe(u, "LD_PRELOAD")
	if !ok || v != "/tmp/.x.so" {
		t.Fatalf("glob /etc/app/*.env deve incorporar backdoor.env: %+v", u.Environment)
	}
}

// EnvironmentFile= vazio REDEFINE: o old.env já incorporado é descartado, e o
// Environment= em linha permanece.
func TestEnvironmentFileVazioRedefine(t *testing.T) {
	raiz := t.TempDir()
	os.WriteFile(filepath.Join(raiz, "etc/old.env"), []byte("LD_PRELOAD=/tmp/.old.so\n"), 0o644)
	os.MkdirAll(filepath.Join(raiz, "etc"), 0o755)
	os.WriteFile(filepath.Join(raiz, "etc/old.env"), []byte("LD_PRELOAD=/tmp/.old.so\n"), 0o644)
	os.WriteFile(filepath.Join(raiz, "svc.service"),
		[]byte("[Service]\nEnvironment=FOO=bar\nEnvironmentFile=/etc/old.env\nEnvironmentFile=\nExecStart=/usr/bin/svc\n"), 0o644)
	e := env.Probe(env.Options{Root: raiz, Version: "test"})
	t.Cleanup(func() { e.Close() })
	u := parseUnitFile(e, "/svc.service", "system", false)
	if _, ok := envDe(u, "LD_PRELOAD"); ok {
		t.Errorf("EnvironmentFile= vazio deveria descartar old.env: %+v", u.Environment)
	}
	if v, ok := envDe(u, "FOO"); !ok || v != "bar" {
		t.Errorf("Environment= em linha deve sobreviver ao reset: %+v", u.Environment)
	}
}

// Glob cujo diretório é ilegível vira LACUNA, não silêncio.
func TestEnvironmentFileGlobDirIlegivelLacuna(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("modo 000 não impede root")
	}
	raiz := t.TempDir()
	os.MkdirAll(filepath.Join(raiz, "etc/app"), 0o755)
	os.WriteFile(filepath.Join(raiz, "etc/app/x.env"), []byte("LD_PRELOAD=/tmp/.x.so\n"), 0o644)
	os.WriteFile(filepath.Join(raiz, "svc.service"),
		[]byte("[Service]\nEnvironmentFile=/etc/app/*.env\nExecStart=/usr/bin/svc\n"), 0o644)
	os.Chmod(filepath.Join(raiz, "etc/app"), 0o000)
	t.Cleanup(func() { os.Chmod(filepath.Join(raiz, "etc/app"), 0o755) })
	e := env.Probe(env.Options{Root: raiz, Version: "test"})
	t.Cleanup(func() { e.Close() })
	u := parseUnitFile(e, "/svc.service", "system", false)
	if len(u.EnvFilesIlegiveis) == 0 {
		t.Errorf("diretório do glob ilegível tem de virar lacuna: %+v", u)
	}
}

// item 4: EnvironmentFile= vazio num DROP-IN redefine a lista da unit base de
// mesmo nome. Antes, o LD_PRELOAD da base sobrevivia — FP.
func TestEnvironmentFileResetDeDropInLimpaBase(t *testing.T) {
	raiz := t.TempDir()
	os.MkdirAll(filepath.Join(raiz, "etc/systemd/system/x.service.d"), 0o755)
	os.MkdirAll(filepath.Join(raiz, "etc"), 0o755)
	os.WriteFile(filepath.Join(raiz, "etc/x.env"), []byte("LD_PRELOAD=/tmp/.old.so\n"), 0o644)
	os.WriteFile(filepath.Join(raiz, "usr/lib/systemd/system/x.service"),
		[]byte("[Service]\nEnvironmentFile=/etc/x.env\nExecStart=/usr/bin/x\n"), 0o644)
	os.MkdirAll(filepath.Join(raiz, "usr/lib/systemd/system"), 0o755)
	os.WriteFile(filepath.Join(raiz, "usr/lib/systemd/system/x.service"),
		[]byte("[Service]\nEnvironmentFile=/etc/x.env\nExecStart=/usr/bin/x\n"), 0o644)
	os.WriteFile(filepath.Join(raiz, "etc/systemd/system/x.service.d/override.conf"),
		[]byte("[Service]\nEnvironmentFile=\n"), 0o644)
	e := env.Probe(env.Options{Root: raiz, Version: "test"})
	t.Cleanup(func() { e.Close() })
	f := Collect(e)
	for _, ev := range f.Loader.EnvVars {
		if ev.Key == "LD_PRELOAD" && ev.Value == "/tmp/.old.so" {
			t.Fatalf("drop-in com EnvironmentFile= vazio deveria limpar o preload da base: %+v", f.Loader.EnvVars)
		}
	}
}

// item 5: %-specifier vira lacuna, não ENOENT silencioso.
func TestEnvironmentFileEspecificadorViraLacuna(t *testing.T) {
	raiz := t.TempDir()
	os.MkdirAll(filepath.Join(raiz, "svc"), 0o755)
	os.WriteFile(filepath.Join(raiz, "svc.service"),
		[]byte("[Service]\nEnvironmentFile=%h/.config/.env\nExecStart=/usr/bin/svc\n"), 0o644)
	e := env.Probe(env.Options{Root: raiz, Version: "test"})
	t.Cleanup(func() { e.Close() })
	u := parseUnitFile(e, "/svc.service", "system", false)
	if len(u.EnvFilesIlegiveis) == 0 {
		t.Errorf("%%h não expandido tem de virar lacuna, não sumir: %+v", u)
	}
}
