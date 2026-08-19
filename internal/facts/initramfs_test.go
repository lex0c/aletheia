package facts

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/lex0c/aletheia/internal/env"
)

// imagemInitramfs monta uma raiz com os arquivos e permissões dados e roda o
// coletor sobre ela.
func imagemInitramfs(t *testing.T, arquivos map[string]int) *Facts {
	t.Helper()
	raiz := t.TempDir()
	for rel, modo := range arquivos {
		full := filepath.Join(raiz, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("#!/bin/sh\n"), os.FileMode(modo)); err != nil {
			t.Fatal(err)
		}
	}
	e := env.Probe(env.Options{Root: raiz})
	t.Cleanup(func() { e.Close() })
	f := &Facts{}
	collectInitramfs(f, e)
	return f
}

// install_items do dracut é uma atribuição de shell: `install_items+=" /a /b "`.
// Extrair só os caminhos absolutos, sem aspas, e ignorar token relativo.
func TestCaminhosDeAtribuicaoShell(t *testing.T) {
	corpo := `# comentário
hostonly="yes"
install_items+=" /tmp/.payload /usr/bin/legit relativo "
install_items=" /opt/x "`
	got := caminhosDeAtribuicaoShell(corpo, "install_items")
	quer := []string{"/tmp/.payload", "/usr/bin/legit", "/opt/x"}
	if !reflect.DeepEqual(got, quer) {
		t.Errorf("got %v, quer %v (relativo NÃO entra)", got, quer)
	}
}

// FILES do mkinitcpio é um array de shell que pode ocupar VÁRIAS linhas até o
// `)`. Parar na primeira linha perderia o resto.
func TestCaminhosDeArrayShellMultilinha(t *testing.T) {
	corpo := `MODULES=()
FILES=(/crypto_keyfile.bin
  /opt/x/backdoor.so)
HOOKS=(base udev)`
	got := caminhosDeArrayShell(corpo, "FILES")
	quer := []string{"/crypto_keyfile.bin", "/opt/x/backdoor.so"}
	if !reflect.DeepEqual(got, quer) {
		t.Errorf("got %v, quer %v", got, quer)
	}
	// HOOKS não tem caminho absoluto: não deve devolver nada.
	if h := caminhosDeArrayShell(corpo, "HOOKS"); len(h) != 0 {
		t.Errorf("HOOKS não tem caminho absoluto: %v", h)
	}
	// Só a forma ARRAY conta. Uma atribuição escalar `FILES=/x` (que o
	// mkinitcpio nem trata como lista) não pode virar caminho embutido.
	if e := caminhosDeArrayShell("FILES=/etc/x\n", "FILES"); len(e) != 0 {
		t.Errorf("FILES escalar não é array: %v", e)
	}
}

// absolutosEm tira aspas e parênteses e devolve só o que começa com /.
func TestAbsolutosEm(t *testing.T) {
	got := absolutosEm(`"/a" '/b' (/c) rel $VAR`)
	quer := []string{"/a", "/b", "/c"}
	if !reflect.DeepEqual(got, quer) {
		t.Errorf("got %v, quer %v", got, quer)
	}
}

// Só o arquivo EXECUTÁVEL vira hook: um README no diretório de geração não roda
// na criação da imagem nem no boot, e coletá-lo encheria o retrato de ruído.
func TestCollectInitramfsSoPegaExecutavel(t *testing.T) {
	f := imagemInitramfs(t, map[string]int{
		"usr/lib/dracut/modules.d/99x/module-setup.sh": 0o755,
		"usr/lib/dracut/modules.d/99x/README":          0o644,
	})
	var paths []string
	for _, a := range f.Initramfs {
		paths = append(paths, a.Path)
	}
	if len(paths) != 1 || paths[0] != "/usr/lib/dracut/modules.d/99x/module-setup.sh" {
		t.Errorf("só o executável entra: %v", paths)
	}
}
