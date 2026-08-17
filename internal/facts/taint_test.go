package facts

import (
	"strings"
	"testing"
)

// O dado deste teste é REAL: veio de um Manjaro com driver nvidia, que é o caso
// que decide se este check é usável ou é ruído. Bits 12 e 13 ligados, quatro
// módulos exibindo as duas letras — e a resposta certa é NENHUM achado.
const modulosManjaroComNvidia = `nvidia_drm 131072 12 - Live 0x0000000000000000 (OE)
nvidia_modeset 1712128 6 nvidia_drm, Live 0x0000000000000000 (OE)
nvidia_uvm 3960832 0 - Live 0x0000000000000000 (OE)
nvidia 78815232 62 nvidia_modeset,nvidia_uvm, Live 0x0000000000000000 (OE)
snd_hda_intel 61440 5 - Live 0x0000000000000000
kvm 1400832 1 kvm_amd, Live 0x0000000000000000
`

func TestTaintComDonoNaoViraAchado(t *testing.T) {
	mods := modulosComTaint(modulosManjaroComNvidia)
	if len(mods) != 4 {
		t.Fatalf("módulos com marca = %d, queria 4: %v", len(mods), mods)
	}
	// 12288 = bits 12 (O) e 13 (E).
	if sem := TaintSemDono(12288, mods); len(sem) != 0 {
		t.Errorf("host com nvidia carregado não pode produzir marca sem dono: %v", sem)
	}
}

// E o mesmo kernel, com o módulo REMOVIDO depois: as marcas continuam e não há
// mais quem as assuma. É a forma que o check existe para achar.
func TestTaintSemDonoQuandoOModuloSaiu(t *testing.T) {
	sem := TaintSemDono(12288, nil)
	var letras []string
	for _, m := range sem {
		letras = append(letras, string(m.Letra))
	}
	if strings.Join(letras, "") != "OE" {
		t.Errorf("marcas sem dono = %v, queria O e E", letras)
	}
}

// Marca que módulo NENHUM pode assumir não entra na conta de "sem dono": o
// kernel morrer (D) ou o usuário pedir taint (U) não é atribuível a módulo, e
// tratá-las como órfãs faria todo host com um oops antigo produzir achado.
func TestTaintSoAtribuiOQueEDeModulo(t *testing.T) {
	// bit 7 (D, morreu) + bit 6 (U, pedido por userspace) + bit 9 (W, aviso)
	bits := uint64(1<<7 | 1<<6 | 1<<9)
	if sem := TaintSemDono(bits, nil); len(sem) != 0 {
		t.Errorf("marca não atribuível a módulo não pode virar órfã: %v", sem)
	}
	if !TaintTem(bits, 'D') {
		t.Error("TaintTem deveria enxergar o bit 7 como D")
	}
	if TaintTem(bits, 'E') {
		t.Error("bit 13 não está ligado")
	}
}

// A decodificação precisa nomear TODO bit ligado — inclusive os que este
// binário não conhece. Um kernel mais novo tem bits novos, e omiti-los faria a
// ferramenta dizer menos do que o kernel disse.
func TestDecodeTaintNaoOmiteBitDesconhecido(t *testing.T) {
	letras, motivos := decodeTaint(1<<13 | 1<<40)
	if letras != "E" {
		t.Errorf("letras = %q, queria E", letras)
	}
	junto := strings.Join(motivos, " | ")
	if !strings.Contains(junto, "não conhece") {
		t.Errorf("o bit desconhecido precisa ser declarado: %q", junto)
	}
}

// O campo de marca só existe quando o módulo tem alguma, e o resto da linha
// varia entre kernels. Confundir o último campo com marca inventaria módulos
// sujos onde não há nenhum.
func TestModulosComTaintIgnoraLinhaSemMarca(t *testing.T) {
	texto := `ext4 1036288 1 - Live 0x0000000000000000
vboxdrv 663552 3 vboxnetadp,vboxnetflt, Live 0x0000000000000000 (OE)
zram 32768 2 - Live 0x0000000000000000 (X)
lixo
`
	mods := modulosComTaint(texto)
	if len(mods) != 2 {
		t.Fatalf("módulos = %v, queria só vboxdrv e zram", mods)
	}
	if mods[0].Nome != "vboxdrv" || mods[0].Letras != "OE" {
		t.Errorf("primeiro módulo = %+v", mods[0])
	}
}

// parseUint é deliberadamente estrito: qualquer coisa que não seja dígito é
// conteúdo inesperado, e a resposta certa é declarar em vez de chutar zero —
// zero significaria "kernel limpo".
func TestParseUintRecusaConteudoEstranho(t *testing.T) {
	if _, ok := parseUint("12288"); !ok {
		t.Error("número simples deveria passar")
	}
	for _, s := range []string{"", "0x3000", "12 288", "-1"} {
		if _, ok := parseUint(s); ok {
			t.Errorf("%q não deveria ser aceito como taint", s)
		}
	}
}
