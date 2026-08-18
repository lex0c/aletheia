package facts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/env"
)

// Diretório que não abre precisa aparecer na cobertura.
//
// O código dizia "sem permissão neste galho: o resto da árvore continua" e
// seguia em silêncio. /home é 0700 por usuário na maioria das distribuições, e
// um `chmod u+s` num binário dentro de um home é retenção de privilégio que
// sobrevive à faxina — a varredura sem root pulava exatamente esse lugar e
// dizia "nenhum SUID fora do padrão".
func TestGalhoIlegivelNaVarreduraDeSuidViraLacuna(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root abre tudo")
	}
	raiz := t.TempDir()
	fundo := filepath.Join(raiz, "home/alvo/.cache")
	if err := os.MkdirAll(fundo, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fundo, "x"), []byte("bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(raiz, "home/alvo"), 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(filepath.Join(raiz, "home/alvo"), 0o755) })

	e := env.Probe(env.Options{Root: raiz})
	t.Cleanup(func() { e.Close() })
	f := Collect(e)

	var citou bool
	for _, m := range f.PersistDenied["suid"] {
		if strings.Contains(m, "/home/alvo") {
			citou = true
		}
	}
	if !citou {
		t.Errorf("o galho negado não foi declarado: %v", f.PersistDenied["suid"])
	}
}
