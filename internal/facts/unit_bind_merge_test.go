package facts

import (
	"testing"

	"github.com/lex0c/aletheia/internal/env"
)

// O reset de BindPaths precisa alcançar a BASE, não só as linhas do mesmo
// arquivo.
//
// O parser tratava `BindPaths=` vazio limpando a lista dentro do arquivo, e o
// teste que escrevi media exatamente isso — duas linhas no mesmo .service, que
// é o caso fácil. O caso que importa é o outro:
//
//	foo.service                 BindReadOnlyPaths=/tmp/.a:/usr/bin/x
//	foo.service.d/20-reset.conf BindReadOnlyPaths=
//
// Para o systemd não sobra bind nenhum. Sem o reset pós-merge, a ferramenta
// continuava acusando uma troca de arquivo já desfeita — falso positivo, e num
// check que sai CRITICAL.
func TestBindResetAlcancaABase(t *testing.T) {
	units := []Unit{
		{
			Name: "foo.service", Scope: "system", Path: "/etc/systemd/system/foo.service",
			Binds: []BindDaUnit{{Origem: "/tmp/.a", Destino: "/usr/bin/x", SomenteL: true}},
		},
		{
			Name: "foo.service", Scope: "system", DropInFor: "foo.service",
			Path: "/etc/systemd/system/foo.service.d/20-reset.conf", BindReset: true,
		},
	}
	mesclarUnits(&Facts{}, units, env.Probe(env.Options{Root: t.TempDir(), Version: "test"}))
	for i := range units {
		if len(units[i].Binds) != 0 {
			t.Errorf("%s: o reset do drop-in tem de limpar a base: %+v",
				units[i].Path, units[i].Binds)
		}
	}
}

// E o contrário: sem reset, o bind da base vale para a unit efetiva inteira —
// o drop-in que só acrescenta outra coisa não pode apagá-lo por omissão.
func TestBindDaBaseSobreviveASomaComDropin(t *testing.T) {
	units := []Unit{
		{
			Name: "foo.service", Scope: "system", Path: "/etc/systemd/system/foo.service",
			Binds: []BindDaUnit{{Origem: "/tmp/.a", Destino: "/usr/bin/x"}},
		},
		{
			Name: "foo.service", Scope: "system", DropInFor: "foo.service",
			Path:  "/etc/systemd/system/foo.service.d/10-mais.conf",
			Binds: []BindDaUnit{{Origem: "/tmp/.b", Destino: "/usr/bin/y"}},
		},
	}
	mesclarUnits(&Facts{}, units, env.Probe(env.Options{Root: t.TempDir(), Version: "test"}))
	for i := range units {
		if len(units[i].Binds) != 2 {
			t.Errorf("%s: a unit efetiva tem os DOIS binds: %+v", units[i].Path, units[i].Binds)
		}
	}
}
