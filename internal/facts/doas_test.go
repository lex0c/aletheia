package facts

import "testing"

// A gramática do doas: permit/deny, opções (nopass/keepenv/persist/setenv{}),
// identidade (usuário ou :grupo), `as alvo`, `cmd programa`. As opções vêm
// ANTES da identidade, e setenv leva chaves — errar a fronteira faz a
// identidade sair errada e a regra não ser avaliada.
func TestParseDoasFormas(t *testing.T) {
	casos := []struct {
		texto          string
		permit, nopass bool
		id, alvo, cmd  string
		ok             bool
	}{
		{"permit nopass keepenv :wheel", true, true, ":wheel", "", "", true},
		{"permit nopass alice as postgres", true, true, "alice", "postgres", "", true},
		{"permit nopass bob cmd /usr/bin/systemctl", true, true, "bob", "", "/usr/bin/systemctl", true},
		{"permit :admin", true, false, ":admin", "", "", true},
		{"deny nopass eve", false, true, "eve", "", "", true},
		{"permit persist setenv { PATH } carol", true, false, "carol", "", "", true},
		{"permit nopass dan as root cmd /bin/id", true, true, "dan", "root", "/bin/id", true},
		{"# comentário", false, false, "", "", "", false},
		{"garbage line", false, false, "", "", "", false},
	}
	for _, c := range casos {
		r, ok := parseDoas("/etc/doas.conf", 1, c.texto)
		if ok != c.ok {
			t.Errorf("%q: ok=%v, quer %v", c.texto, ok, c.ok)
			continue
		}
		if !ok {
			continue
		}
		if r.Permit != c.permit || r.NoPass != c.nopass || r.Identidade != c.id ||
			r.Alvo != c.alvo || r.Comando != c.cmd {
			t.Errorf("%q → permit=%v nopass=%v id=%q alvo=%q cmd=%q\n"+
				"   quer permit=%v nopass=%v id=%q alvo=%q cmd=%q",
				c.texto, r.Permit, r.NoPass, r.Identidade, r.Alvo, r.Comando,
				c.permit, c.nopass, c.id, c.alvo, c.cmd)
		}
	}
}
