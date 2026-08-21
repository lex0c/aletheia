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

// O `args` do doas.conf, e as TRÊS formas que ele produz. A gramática é
// contraintuitiva no ponto que mais importa: a regra que NÃO cita argumento é a
// mais AMPLA das três, e é a que mais parece restrita para quem lê depressa.
//
//	cmd /usr/bin/tar               QUALQUER argumento
//	cmd /usr/bin/tar args          NENHUM argumento
//	cmd /usr/bin/tar args czf /x   só exatamente aqueles
//
// Sem esta decodificação o classificador de primitiva lia a terceira forma como
// a primeira, e acusava de root irrestrito a automação de backup que o time
// escreveu.
func TestParseDoasArgs(t *testing.T) {
	casos := []struct {
		texto   string
		cmd     string
		temArgs bool
		args    []string
	}{
		{"permit nopass bkp cmd /usr/bin/tar", "/usr/bin/tar", false, nil},
		{"permit nopass bkp cmd /usr/bin/tar args", "/usr/bin/tar", true, nil},
		{"permit nopass bkp cmd /usr/bin/tar args czf /b.tgz /srv", "/usr/bin/tar", true,
			[]string{"czf", "/b.tgz", "/srv"}},
		// O `as` pode vir antes do `cmd`, e o `args` consome o RESTO da linha —
		// ele é sempre o último elemento da gramática.
		{"permit nopass ana as root cmd /usr/bin/vim args /etc/motd", "/usr/bin/vim", true,
			[]string{"/etc/motd"}},
		// E o caso que um fixture de teste inventava: sem a palavra `args`, o
		// que vem depois do programa NÃO é argumento fixado — o parser guarda
		// só o programa.
		{"permit nopass bob cmd python3 -c import os", "python3", false, nil},
	}
	for _, c := range casos {
		r, ok := parseDoas("/etc/doas.conf", 1, c.texto)
		if !ok {
			t.Errorf("%q não foi reconhecida como regra", c.texto)
			continue
		}
		if r.Comando != c.cmd {
			t.Errorf("%q: cmd = %q, quer %q", c.texto, r.Comando, c.cmd)
		}
		if r.TemArgs != c.temArgs {
			t.Errorf("%q: temArgs = %v, quer %v", c.texto, r.TemArgs, c.temArgs)
		}
		if len(r.Args) != len(c.args) {
			t.Errorf("%q: args = %v, quer %v", c.texto, r.Args, c.args)
			continue
		}
		for i := range c.args {
			if r.Args[i] != c.args[i] {
				t.Errorf("%q: args = %v, quer %v", c.texto, r.Args, c.args)
				break
			}
		}
	}
}
