package facts

import "testing"

// As duas formas do core_pattern fazem coisas completamente diferentes, e
// confundi-las acusaria todo host que apenas escolheu onde gravar o core.
func TestAlvoDeCorePattern(t *testing.T) {
	casos := []struct {
		valor  string
		alvo   string
		padrao bool
	}{
		// A forma de fábrica num host com systemd: EXECUTA, e o alvo é o
		// primeiro campo — o resto são os especificadores do kernel.
		{"|/usr/lib/systemd/systemd-coredump %P %u %g %s %t %c %h", "/usr/lib/systemd/systemd-coredump", false},
		{"|/usr/share/apport/apport %p %s %c %d %P %E", "/usr/share/apport/apport", false},
		{"|/tmp/.x", "/tmp/.x", false},
		// Sem o cano não há programa nenhum: é modelo de nome de arquivo.
		{"core", "", true},
		{"/var/crash/core.%e.%p", "", true},
	}
	for _, c := range casos {
		alvo, padrao := alvoDeCorePattern(c.valor)
		if alvo != c.alvo || padrao != c.padrao {
			t.Errorf("%q → alvo=%q padrao=%v, queria alvo=%q padrao=%v",
				c.valor, alvo, padrao, c.alvo, c.padrao)
		}
	}
}

// O registro de binfmt tem uma linha por campo, e só a do interpretador aponta
// para um executável — o `magic` é conteúdo binário e não pode virar caminho.
func TestParseBinfmtRegistro(t *testing.T) {
	corpo := `enabled
interpreter /usr/bin/qemu-aarch64-static
flags: OCF
offset 0
magic 7f454c460201010000000000000000000200b700`
	r := parseBinfmtRegistro("qemu-aarch64", "/proc/sys/fs/binfmt_misc/qemu-aarch64", corpo)
	if r.Interpreter != "/usr/bin/qemu-aarch64-static" {
		t.Errorf("interpretador = %q", r.Interpreter)
	}
	if !r.Habilitado {
		t.Error("enabled não foi lido")
	}
	if r.Flags != "OCF" {
		t.Errorf("flags = %q, quer OCF", r.Flags)
	}
	// o magic é longo (20 bytes): NÃO sequestra ELF nativo, e vem em minúsculas.
	if r.Magic != "7f454c460201010000000000000000000200b700" {
		t.Errorf("magic = %q", r.Magic)
	}
	// registro desabilitado e sem interpretador.
	d := parseBinfmtRegistro("x", "/x", "disabled\nflags: F\n")
	if d.Habilitado || d.Interpreter != "" {
		t.Errorf("registro vazio/desabilitado: %+v", d)
	}
	if d.Flags != "F" {
		t.Errorf("flags = %q, quer F", d.Flags)
	}
}
