package facts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/env"
)

func raizComArqs(t *testing.T, arqs map[string]string) *env.Env {
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

func temRegraSudo(f *Facts, sub string) bool {
	for _, r := range f.Sudoers {
		if strings.Contains(r.Text, sub) {
			return true
		}
	}
	return false
}

// @includedir para diretório arbitrário: a regra do atacante mora num dir que
// só o /etc/sudoers conhece, e precisa ser seguida.
func TestSudoersSegueIncludedirArbitrario(t *testing.T) {
	e := raizComArqs(t, map[string]string{
		"etc/sudoers":       "root ALL=(ALL:ALL) ALL\n@includedir /opt/.sudoers\n",
		"opt/.sudoers/back": "attacker ALL=(ALL) NOPASSWD: ALL\n",
	})
	f := &Facts{}
	collectSudoers(f, e)
	if !temRegraSudo(f, "attacker") {
		t.Fatalf("regra em @includedir arbitrário deve ser lida: %+v", f.Sudoers)
	}
}

// #include legado: NÃO é comentário. A forma antiga ainda é válida.
func TestSudoersSegueIncludeLegado(t *testing.T) {
	e := raizComArqs(t, map[string]string{
		"etc/sudoers":       "#include /etc/sudoers.local\n",
		"etc/sudoers.local": "attacker ALL=(ALL) NOPASSWD: ALL\n",
	})
	f := &Facts{}
	collectSudoers(f, e)
	if !temRegraSudo(f, "attacker") {
		t.Fatalf("#include legado deve ser seguido, não tratado como comentário: %+v", f.Sudoers)
	}
}

// FP simétrico: /etc/sudoers.d que ninguém inclui é inerte.
func TestSudoersNaoVarreDirNaoIncluido(t *testing.T) {
	e := raizComArqs(t, map[string]string{
		"etc/sudoers":     "root ALL=(ALL:ALL) ALL\n", // sem @includedir
		"etc/sudoers.d/x": "attacker ALL=(ALL) NOPASSWD: ALL\n",
	})
	f := &Facts{}
	collectSudoers(f, e)
	if temRegraSudo(f, "attacker") {
		t.Fatalf("sudoers.d não incluído é inerte; não deveria ser lido: %+v", f.Sudoers)
	}
}

// includedir ilegível vira LACUNA, não silêncio.
func TestSudoersIncludedirIlegivelDeclaraLacuna(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("modo 000 não impede root")
	}
	raiz := t.TempDir()
	os.MkdirAll(filepath.Join(raiz, "etc/sudoers.d"), 0o755)
	os.WriteFile(filepath.Join(raiz, "etc/sudoers"), []byte("@includedir /etc/sudoers.d\n"), 0o644)
	os.WriteFile(filepath.Join(raiz, "etc/sudoers.d/x"), []byte("attacker ALL=(ALL) NOPASSWD: ALL\n"), 0o644)
	os.Chmod(filepath.Join(raiz, "etc/sudoers.d"), 0o000)
	t.Cleanup(func() { os.Chmod(filepath.Join(raiz, "etc/sudoers.d"), 0o755) })
	e := env.Probe(env.Options{Root: raiz, Version: "test"})
	t.Cleanup(func() { e.Close() })
	f := &Facts{}
	collectSudoers(f, e)
	achou := false
	for _, m := range f.PersistDenied["users"] {
		if strings.Contains(m, "sudoers.d") {
			achou = true
		}
	}
	if !achou {
		t.Errorf("includedir ilegível tem de declarar lacuna: %+v", f.PersistDenied["users"])
	}
}
