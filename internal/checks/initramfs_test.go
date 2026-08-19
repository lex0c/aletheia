package checks

import (
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/facts"
)

func initramfsF(art []facts.ArtefatoInitramfs, unowned ...string) *facts.Facts {
	f := &facts.Facts{Initramfs: art}
	for _, u := range unowned {
		f.Ownership = append(f.Ownership, facts.Ownership{Path: u, Owned: false})
	}
	return f
}

// Hook sem dono num diretório de pacote é forte: tudo ali deveria vir de pacote.
func TestInitramfsHookSemDonoEmPacoteECritico(t *testing.T) {
	f := initramfsF([]facts.ArtefatoInitramfs{
		{Path: "/usr/lib/dracut/modules.d/99x/module-setup.sh", Mecanismo: "dracut", Como: "hook executável"},
	}, "/usr/lib/dracut/modules.d/99x/module-setup.sh")
	r := initramfsHook.Run(initramfsHook, f, testEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevCritical {
		t.Fatalf("achados = %+v, quer 1 CRITICAL", r.Findings)
	}
}

// Hook sem dono em /etc é território do administrador: WARN, não CRITICAL.
func TestInitramfsHookEmEtcEAviso(t *testing.T) {
	f := initramfsF([]facts.ArtefatoInitramfs{
		{Path: "/etc/initramfs-tools/hooks/custom", Mecanismo: "initramfs-tools", Como: "hook executável"},
	}, "/etc/initramfs-tools/hooks/custom")
	r := initramfsHook.Run(initramfsHook, f, testEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevWarn {
		t.Fatalf("achados = %+v, quer 1 WARN", r.Findings)
	}
}

// Hook com dono de pacote é o normal: não dispara.
func TestInitramfsHookComDonoNaoDispara(t *testing.T) {
	f := initramfsF([]facts.ArtefatoInitramfs{
		{Path: "/usr/lib/initcpio/hooks/encrypt", Mecanismo: "mkinitcpio", Como: "hook executável"},
	}) // não está em Ownership como unowned -> tratado como owned
	if r := initramfsHook.Run(initramfsHook, f, testEnv()); len(r.Findings) != 0 {
		t.Errorf("hook de pacote não dispara: %+v", r.Findings)
	}
}

// O FP que a keyfile LUKS revelou: um arquivo REFERENCIADO (FILES/install_items)
// fora de diretório gravável é dado de admin, e propriedade não o distingue de
// payload. Não pode disparar — senão todo host com disco cifrado vira achado.
func TestInitramfsArquivoReferenciadoNaoEhJulgadoPorPropriedade(t *testing.T) {
	f := initramfsF([]facts.ArtefatoInitramfs{
		{Path: "/crypto_keyfile.bin", Mecanismo: "mkinitcpio", Como: "FILES em mkinitcpio.conf"},
	}, "/crypto_keyfile.bin")
	if r := initramfsHook.Run(initramfsHook, f, testEnv()); len(r.Findings) != 0 {
		t.Errorf("keyfile LUKS referenciada não pode virar achado: %+v", r.Findings)
	}
}

// Mas um arquivo referenciado de diretório GRAVÁVEL não tem leitura inocente:
// não há razão para embutir algo de /tmp no initramfs.
func TestInitramfsReferenciadoEmTmpECritico(t *testing.T) {
	f := initramfsF([]facts.ArtefatoInitramfs{
		{Path: "/tmp/.payload", Mecanismo: "dracut", Como: "install_items em evil.conf"},
	})
	r := initramfsHook.Run(initramfsHook, f, testEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevCritical {
		t.Fatalf("achados = %+v, quer 1 CRITICAL", r.Findings)
	}
	if !strings.Contains(strings.Join(r.Findings[0].Evidence, " "), "ANTES do userland") {
		t.Errorf("a evidência precisa situar o momento: %v", r.Findings[0].Evidence)
	}
}
