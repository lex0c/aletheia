package facts

import (
	"strings"
	"testing"
)

// O `systemd --user` da alice funde a árvore COMPARTILHADA (/etc, /usr/lib) com
// a dela (~/.config) numa configuração só. Esta coleta as mantém separadas — a
// compartilhada com Manager vazio, a por-home com o nome do usuário — e o merge
// agrupa por Scope+Manager+Nome, que são chaves diferentes.
//
// O resultado é um FN de forma específica: um drop-in por-home sobre uma unit
// compartilhada não é atribuído a ela, e se o drop-in só acrescenta
// ExecSearchPath ele nem tem Exec próprio para o unit_dropin_exec denunciar.
//
// Reconstruir a configuração efetiva por manager é caro e o ataque é estreito.
// O que não pode é ficar SILENCIOSO.
func TestLacunaDeManagerDeUsuario(t *testing.T) {
	casos := []struct {
		nome     string
		units    []Unit
		querGap  bool
		querCita string
	}{
		{
			// A colisão: o mesmo nome nos dois domínios. É exatamente onde a
			// precedência decidiria algo e ninguém a resolveu.
			nome: "mesmo nome na árvore compartilhada e na do usuário",
			units: []Unit{
				{Name: "agent.service", Scope: "user", Manager: ""},
				{Name: "agent.service", Scope: "user", Manager: "alice"},
			},
			querGap: true, querCita: "alice/agent.service",
		},
		{
			// SEM colisão não há o que declarar. Declarar aqui faria toda
			// workstation com unit de usuário sair com lacuna, e lacuna que
			// aparece em toda instância de um ambiente não informa nada — já
			// custou caro quatro vezes nesta base.
			nome: "árvores separadas sem nome em comum: nada a declarar",
			units: []Unit{
				{Name: "agent.service", Scope: "user", Manager: ""},
				{Name: "meu-backup.service", Scope: "user", Manager: "alice"},
			},
		},
		{
			nome: "só árvore compartilhada",
			units: []Unit{
				{Name: "agent.service", Scope: "user", Manager: ""},
			},
		},
		{
			nome: "só por-home",
			units: []Unit{
				{Name: "agent.service", Scope: "user", Manager: "alice"},
			},
		},
		{
			// Unit de SISTEMA com o mesmo nome não colide: outro manager, outro
			// load path, e o escopo já separa.
			nome: "colisão entre system e user não é o caso",
			units: []Unit{
				{Name: "agent.service", Scope: "system", Manager: ""},
				{Name: "agent.service", Scope: "user", Manager: "alice"},
			},
		},
	}
	for _, c := range casos {
		f := &Facts{}
		lacunaDeManagerDeUsuario(f, c.units)
		got := strings.Join(f.PersistDenied["unit"], " | ")
		if (got != "") != c.querGap {
			t.Errorf("[%s] lacuna=%q, queria gap=%v", c.nome, got, c.querGap)
			continue
		}
		if c.querCita != "" && !strings.Contains(got, c.querCita) {
			t.Errorf("[%s] a lacuna precisa NOMEAR o par manager/unit: %q", c.nome, got)
		}
	}
}

// A mesma unit vem de vários subdiretórios do mesmo home (.config/systemd/user,
// user.control, .local/share). Repetir a linha por origem não acrescenta nada e
// transforma uma lacuna em parede.
func TestLacunaDeManagerNaoRepetePorOrigem(t *testing.T) {
	f := &Facts{}
	lacunaDeManagerDeUsuario(f, []Unit{
		{Name: "agent.service", Scope: "user", Manager: ""},
		{Name: "agent.service", Scope: "user", Manager: "alice", Path: "/home/alice/.config/systemd/user/agent.service"},
		{Name: "agent.service", Scope: "user", Manager: "alice", Path: "/home/alice/.config/systemd/user.control/agent.service"},
	})
	if n := len(f.PersistDenied["unit"]); n != 1 {
		t.Fatalf("%d linhas de lacuna, queria 1: %v", n, f.PersistDenied["unit"])
	}
	if !strings.Contains(f.PersistDenied["unit"][0], "1 unit(s)") {
		t.Errorf("a contagem tem de ser por par manager/unit: %q", f.PersistDenied["unit"][0])
	}
}
