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
func TestInterpretadorDeBinfmt(t *testing.T) {
	corpo := `enabled
interpreter /usr/bin/qemu-aarch64-static
flags: OCF
offset 0
magic 7f454c460201010000000000000000000200b700`
	if got := interpretadorDeBinfmt(corpo); got != "/usr/bin/qemu-aarch64-static" {
		t.Errorf("interpretador = %q", got)
	}
	if got := interpretadorDeBinfmt("enabled\nflags: F\n"); got != "" {
		t.Errorf("registro sem interpretador devolveu %q", got)
	}
}
