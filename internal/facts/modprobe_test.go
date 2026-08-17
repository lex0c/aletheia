package facts

import (
	"os"
	"testing"

	"github.com/lex0c/aletheia/internal/env"
)

func TestColetaModuloEmDisco(t *testing.T) {
	raiz := t.TempDir()
	os.MkdirAll(raiz+"/lib/modules/6.1.0/kernel/drivers/misc", 0o755)
	os.WriteFile(raiz+"/lib/modules/6.1.0/kernel/drivers/misc/x.ko", []byte("y"), 0o644)
	// DKMS é compilado localmente e nunca vem de pacote: sem esta exclusão,
	// toda estação com placa dedicada vira dezenas de achados.
	os.MkdirAll(raiz+"/lib/modules/6.1.0/updates/dkms", 0o755)
	os.WriteFile(raiz+"/lib/modules/6.1.0/updates/dkms/nvidia.ko", []byte("y"), 0o644)

	e := env.Probe(env.Options{Root: raiz})
	f := &Facts{}
	collectModuleFiles(f, e)
	if len(f.ModuleFiles) != 1 {
		t.Fatalf("ModuleFiles = %v", f.ModuleFiles)
	}
}
