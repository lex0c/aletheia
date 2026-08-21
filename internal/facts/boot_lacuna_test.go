package facts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/env"
)

// Fonte de cmdline que EXISTE e não abre é LACUNA, não silêncio.
//
// Enquanto o check de cmdline marcava lacuna sempre que NENHUMA configuração
// fosse lida, um EACCES aqui produzia degradação de cobertura por acidente —
// com o texto errado, mas produzia. Aquela lacuna saiu (ela disparava em
// contêiner, VM e kexec, onde configuração de bootloader não existe e nunca vai
// existir), e sem este teste o acidente teria saído junto: num host onde
// /etc/kernel/cmdline é a única fonte e está ilegível, o relatório passaria a
// não dizer nada.
//
// As outras fontes de boot (grub, systemd-boot, EFI) já declaravam. Estas eram
// as que faltavam.
func TestFonteDeCmdlineIlegivelViraLacuna(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root lê arquivo com modo 0000: o caso não se forma")
	}
	raiz := t.TempDir()
	if err := os.MkdirAll(filepath.Join(raiz, "etc/kernel"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(raiz, "etc/kernel/cmdline")
	if err := os.WriteFile(p, []byte("root=UUID=1 apparmor=0\n"), 0o000); err != nil {
		t.Fatal(err)
	}

	f := &Facts{}
	lerCmdlineSolta(f, env.Probe(env.Options{Root: raiz}), func(string, string, bool) {})

	if junto := strings.Join(f.PersistDenied["boot"], " | "); !strings.Contains(junto, "cmdline") {
		t.Errorf("arquivo ilegível não virou lacuna declarada: %q", junto)
	}
	if f.BootConfigLido {
		t.Error("não foi lido, então BootConfigLido não pode ficar verdadeiro — " +
			"é ele que separa `não havia` de `não consegui ver`")
	}
}

// E o contrário: arquivo que simplesmente NÃO EXISTE não é lacuna. É a metade
// da regra que motivou remover o Partial do check — contêiner, VM com -append e
// kexec não têm nenhuma destas fontes, e chamar isso de degradação fazia todo
// host limpo nesses ambientes sair INCOMPLETE.
func TestFonteDeCmdlineAusenteNaoEhLacuna(t *testing.T) {
	f := &Facts{}
	lerCmdlineSolta(f, env.Probe(env.Options{Root: t.TempDir()}), func(string, string, bool) {})

	if n := len(f.PersistDenied["boot"]); n != 0 {
		t.Errorf("ausência virou %d lacuna(s): %v", n, f.PersistDenied["boot"])
	}
}
