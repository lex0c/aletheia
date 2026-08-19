package checks

import (
	"testing"

	"github.com/lex0c/aletheia/internal/facts"
)

func TestDracutModuleSetup0644ChegaAoAchado(t *testing.T) {
	f := &facts.Facts{
		Initramfs: []facts.ArtefatoInitramfs{{
			Path:      "/usr/lib/dracut/modules.d/99evil/module-setup.sh",
			Mecanismo: "dracut",
			Como:      "módulo de dracut (sourceado, não executado)",
			Tipo:      facts.InitramfsCodigo,
		}},
		Ownership: []facts.Ownership{{
			Path: "/usr/lib/dracut/modules.d/99evil/module-setup.sh", Owned: false,
		}},
		Pkg: facts.PkgDB{Kind: "dpkg"},
	}
	r := initramfsHook.Run(initramfsHook, f, testEnv())
	if len(r.Findings) == 0 {
		t.Fatal("módulo de dracut sem dono de pacote tem de virar achado — " +
			"ele é SOURCEADO na geração, e o bit de execução não decide nada ali")
	}
}
