package facts

import (
	"os"
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/env"
)

// Um diretório de âncoras de confiança que não pode ser LISTADO não é "nenhuma
// CA extra" — é evidência perdida (uma CA raiz plantada ali dá MITM de todo o
// TLS). Vira lacuna declarada; não-existe não é lacuna. (Item #6 do review:
// ReadDirNames engolia o erro.)
func TestDirDeAncorasIlegivelViraLacuna(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root lê tudo — este teste só vale sem privilégio")
	}
	raiz := t.TempDir()
	ca := raiz + "/etc/pki/ca-trust/source/anchors"
	if err := os.MkdirAll(ca, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(ca+"/x.crt", []byte("-"), 0o644)
	if err := os.Chmod(ca, 0); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(ca, 0o755)

	e := env.Probe(env.Options{Root: raiz, Version: "test"})
	defer e.Close()
	f := &Facts{}
	collectTrust(f, e)

	if !strings.Contains(strings.Join(f.PersistDenied["trust"], " "), "não pôde ser LISTADO") {
		t.Errorf("dir de âncoras ilegível tinha de virar lacuna: %q", f.PersistDenied["trust"])
	}
}

// A busca de git-hooks: um diretório ilegível sob a árvore de repositórios não
// pode virar "nenhum repo aqui" em silêncio — vira lacuna. (Item #6 do review.)
func TestGitHookDirIlegivelViraLacuna(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root lê tudo")
	}
	raiz := t.TempDir()
	seg := raiz + "/var/www/segredo"
	if err := os.MkdirAll(seg, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(seg, 0); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(seg, 0o755)

	e := env.Probe(env.Options{Root: raiz, Version: "test"})
	defer e.Close()
	f := &Facts{}
	collectGitHooks(f, e)

	if !strings.Contains(strings.Join(f.PersistDenied["githook"], " "), "não puderam ser LISTADOS") {
		t.Errorf("dir ilegível sob a árvore de repos tinha de virar lacuna: %q", f.PersistDenied["githook"])
	}
}
