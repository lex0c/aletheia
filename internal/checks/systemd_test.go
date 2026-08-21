package checks

import (
	"testing"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/facts"
)

// unit_unowned: o discriminador é dirDePacote. Um binário órfão em /bin (dir de
// pacote) dispara; o MESMO órfão em /usr/local (instalação manual) não — senão
// todo serviço local legítimo viraria achado. E unit de PACOTE (Vendor) nunca.
func TestUnitSemDono(t *testing.T) {
	mkUnit := func(path, cmd string, vendor bool) facts.Unit {
		// Target é o alvo efetivo que o coletor (mesclarUnits) computa — a fonte
		// da verdade que unit_unowned consome. A fixture o carimba como o dado
		// pós-coleta faria.
		return facts.Unit{
			Name: baseDe(path), Path: path, Kind: "service", Vendor: vendor,
			Exec: []facts.ExecLine{{Key: "ExecStart", Cmd: cmd, Target: alvoDeTeste(cmd)}},
		}
	}
	casos := []struct {
		nome    string
		unit    facts.Unit
		exe     string
		owned   bool
		esperaN int
	}{
		{"backdoor em /bin, sem dono, unit de /etc", mkUnit("/etc/systemd/system/shellserver.service", "/bin/shellserver", false), "/bin/shellserver", false, 1},
		{"embrulhado em env ainda dispara", mkUnit("/etc/systemd/system/bd.service", "/usr/bin/env /bin/shellserver", false), "/bin/shellserver", false, 1},
		{"órfão em /usr/local NÃO dispara (instalação manual)", mkUnit("/etc/systemd/system/api.service", "/usr/local/bin/node /srv/app.js", false), "/usr/local/bin/node", false, 0},
		{"em /bin mas COM dono NÃO dispara", mkUnit("/etc/systemd/system/x.service", "/bin/legit", false), "/bin/legit", true, 0},
		{"unit em ÁRVORE VENDOR com binário órfão DISPARA (Vendor != dono de pacote)", mkUnit("/usr/lib/systemd/system/.maintenance.service", "/bin/shellserver", true), "/bin/shellserver", false, 1},
		{"unit vendor com binário COM dono não dispara", mkUnit("/usr/lib/systemd/system/sshd.service", "/usr/sbin/sshd", true), "/usr/sbin/sshd", true, 0},
	}
	for _, c := range casos {
		f := &facts.Facts{
			Units:     []facts.Unit{c.unit},
			Ownership: []facts.Ownership{{Path: c.exe, Owned: c.owned}},
			Pkg:       facts.PkgDB{Kind: "dpkg"},
		}
		r := unitSemDono.Run(unitSemDono, f, testEnv())
		if len(r.Findings) != c.esperaN {
			t.Errorf("[%s] achados=%d, quer %d: %+v", c.nome, len(r.Findings), c.esperaN, r.Findings)
		}
		if c.esperaN == 1 && len(r.Findings) == 1 && r.Findings[0].Sev != check.SevCritical {
			t.Errorf("[%s] severidade = %v, quer CRITICAL", c.nome, r.Findings[0].Sev)
		}
	}
}

// alvoDeTeste descarta o "indeterminado" — os casos deste arquivo têm alvo
// provável, e quem exercita a indeterminação é o teste do próprio resolvedor.
func alvoDeTeste(cmd string) string {
	alvo, _ := facts.AlvoEfetivoDeExec(cmd)
	return alvo
}
