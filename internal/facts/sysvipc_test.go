package facts

import "testing"

// A coluna de permissão é OCTAL (o kernel imprime %o): "666" tem de virar 0666,
// não o decimal 666. Se virar decimal, toda a lógica de bit do check quebra.
func TestPermSysVShmEhOctal(t *testing.T) {
	if got := atoiOctal("666"); got != 0o666 {
		t.Errorf("perms 666 (octal) = %o, quer 0666", got)
	}
	if got := atoiOctal("600"); got != 0o600 {
		t.Errorf("perms 600 (octal) = %o, quer 0600", got)
	}
	// o bit de outro-escreve é o que o check procura
	if 0o666&0o002 == 0 {
		t.Error("0666 devia ter o bit de outro-escreve")
	}
	if 0o640&0o006 != 0 {
		t.Error("0640 (grupo-lê) NÃO pode ter bit de outro — senão o banco vira FP")
	}
}
