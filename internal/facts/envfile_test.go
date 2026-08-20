package facts

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/lex0c/aletheia/internal/env"
)

// EnvironmentFile= carrega variáveis de um arquivo à parte. Um LD_PRELOAD ali
// é a rota da §7.8 um nível abaixo: a unit só referencia o arquivo.
func TestParseUnitEnvironmentFile(t *testing.T) {
	raiz := t.TempDir()
	esc := func(rel, c string, modo os.FileMode) {
		full := filepath.Join(raiz, rel)
		os.MkdirAll(filepath.Dir(full), 0o755)
		if err := os.WriteFile(full, []byte(c), modo); err != nil {
			t.Fatal(err)
		}
	}
	esc("etc/systemd/system/x.service",
		"[Service]\nExecStart=/usr/bin/d\nEnvironmentFile=-/etc/.env\n", 0o644)
	esc("etc/.env", "# env\nLD_PRELOAD=/tmp/.x.so\nPATH=/usr/bin\n", 0o644)

	e := env.Probe(env.Options{Root: raiz, Version: "test"})
	defer e.Close()
	u := parseUnitFile(&Facts{}, e, "/etc/systemd/system/x.service", "system", false)

	var achou bool
	for _, s := range u.Environment {
		if s.Key == "LD_PRELOAD" && s.Value == "/tmp/.x.so" && s.File == "/etc/.env" {
			achou = true
		}
	}
	if !achou {
		t.Fatalf("o LD_PRELOAD do EnvironmentFile tinha de ser lido, com File apontando "+
			"o arquivo: %+v", u.Environment)
	}
}

// EnvironmentFile ilegível vira lacuna declarada (um LD_PRELOAD ali não foi visto).
func TestEnvironmentFileIlegivelDeclaraLacuna(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("modo 000 não bloqueia root")
	}
	raiz := t.TempDir()
	os.MkdirAll(filepath.Join(raiz, "etc/systemd/system"), 0o755)
	os.WriteFile(filepath.Join(raiz, "etc/systemd/system/x.service"),
		[]byte("[Service]\nExecStart=/d\nEnvironmentFile=/etc/.secret.env\n"), 0o644)
	os.WriteFile(filepath.Join(raiz, "etc/.secret.env"), []byte("LD_PRELOAD=/tmp/.x\n"), 0o644)
	os.Chmod(filepath.Join(raiz, "etc/.secret.env"), 0o000)
	defer os.Chmod(filepath.Join(raiz, "etc/.secret.env"), 0o644)

	e := env.Probe(env.Options{Root: raiz, Version: "test"})
	defer e.Close()
	u := parseUnitFile(&Facts{}, e, "/etc/systemd/system/x.service", "system", false)
	if len(u.EnvFilesIlegiveis) == 0 {
		t.Error("EnvironmentFile ilegível tinha de ser registrado para virar lacuna")
	}
}
