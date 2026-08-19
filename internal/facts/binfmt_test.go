package facts

import "testing"

// A linha de config tem o PRIMEIRO caractere como delimitador, e os campos são
// name:type:offset:magic:mask:interpreter:flags. Extrair o interpretador do
// campo errado o faria virar o magic, que é conteúdo binário.
func TestParseBinfmtLinha(t *testing.T) {
	c, ok := parseBinfmtLinha(`:qemu-aarch64:M::\x7fELF:\xff:/usr/bin/qemu-aarch64-static:OCF`)
	if !ok {
		t.Fatal("linha de registro válida não foi entendida")
	}
	if c.Nome != "qemu-aarch64" {
		t.Errorf("nome = %q", c.Nome)
	}
	if c.Interpreter != "/usr/bin/qemu-aarch64-static" {
		t.Errorf("interpretador = %q (não pode pegar o campo do magic)", c.Interpreter)
	}
	if c.Flags != "OCF" {
		t.Errorf("flags = %q", c.Flags)
	}
	// delimitador alternativo (o kernel aceita qualquer caractere).
	if c2, ok := parseBinfmtLinha(`|py|E||py||/opt/run|`); !ok || c2.Interpreter != "/opt/run" {
		t.Errorf("delimitador alternativo: ok=%v %+v", ok, c2)
	}
	// linha sem interpretador ou malformada não vira registro. O caso de 6
	// campos é o que separa "< 7" de "< 6": sem o campo do interpretador, aceitar
	// leria campos[6] fora do slice.
	if _, ok := parseBinfmtLinha(":x:M:"); ok {
		t.Error("linha com poucos campos não pode virar registro")
	}
	if _, ok := parseBinfmtLinha(":x:M:0:aa:bb"); ok {
		t.Error("6 campos (sem interpretador) não podem virar registro")
	}
	if _, ok := parseBinfmtLinha(""); ok {
		t.Error("linha vazia não vira registro")
	}
}
