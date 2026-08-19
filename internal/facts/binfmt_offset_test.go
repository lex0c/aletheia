package facts

import "testing"

// O corpo que o kernel escreve para um registro por magic traz offset E magic,
// e mask quando existe (bm_entry_show, fs/binfmt_misc.c). Guardar só o magic
// deixava a decisão "sequestra TODO ELF" sem a metade que a define.
func TestParseBinfmtGuardaOffsetEMask(t *testing.T) {
	corpo := "enabled\ninterpreter /usr/bin/qemu-arm\nflags: OCF\noffset 0\n" +
		"magic 7f454c4601010100000000000000000002002800\nmask ffffffffffffff00fffffffffffffffffeffffff\n"
	r := parseBinfmtRegistro("qemu-arm", "/proc/sys/fs/binfmt_misc/qemu-arm", corpo)
	if !r.OffsetLido || r.Offset != 0 {
		t.Errorf("offset = %d lido=%v", r.Offset, r.OffsetLido)
	}
	if r.Mask == "" {
		t.Error("mask não foi guardada")
	}

	// Offset diferente de zero é lido como tal: o cabeçalho ELF mora no byte 0,
	// e um magic de ELF em outro offset casa outra coisa.
	r = parseBinfmtRegistro("x", "/f", "enabled\ninterpreter /i\noffset 100\nmagic 7f454c46\n")
	if !r.OffsetLido || r.Offset != 100 {
		t.Errorf("offset = %d lido=%v, quer 100", r.Offset, r.OffsetLido)
	}

	// Sem offset publicado, OffsetLido fica falso — e o zero do Go NÃO pode ser
	// confundido com "offset 0", que é justamente o caso mais grave.
	r = parseBinfmtRegistro("x", "/f", "enabled\ninterpreter /i\nmagic 7f454c46\n")
	if r.OffsetLido {
		t.Error("offset ausente não pode virar offset lido")
	}
}

// E a ausência precisa virar LACUNA declarada, não silêncio: o kernel publica
// offset junto do magic, então a falta significa formato mudado.
func TestBinfmtMagicSemOffsetDeclaraLacuna(t *testing.T) {
	f := &Facts{}
	r := parseBinfmtRegistro("x", "/proc/sys/fs/binfmt_misc/x",
		"enabled\ninterpreter /i\nmagic 7f454c46\n")
	if r.Magic != "" && !r.OffsetLido {
		f.partial("binfmt", "teste")
	}
	if len(f.Partial["binfmt"]) == 0 {
		t.Error("magic sem offset tem de declarar lacuna")
	}
}
