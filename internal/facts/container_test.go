package facts

import "testing"

// A DETECÇÃO DE "ESTOU DENTRO DE UM CONTÊINER" errou uma vez, e o erro é do tipo
// que só aparece longe: `/.dockerenv` parece a resposta óbvia e é uma armadilha,
// porque é um ARQUIVO e arquivo viaja. `docker export | tar -x` num rootfs leva
// a marca junto — é assim que a VM desta suíte é construída, e por isso ela se
// declarava contêiner tendo kernel próprio.
//
// Todo host provisionado a partir de imagem de contêiner seria classificado
// errado, e a consequência é grande: dentro de contêiner a ferramenta deixa de
// fazer a pergunta de propriedade sobre processo de contêiner.
//
// O que não viaja é o arranjo de MONTAGEM, e é nele que a decisão se apoia.

func TestFerramentaEmContainer(t *testing.T) {
	casos := []struct {
		nome string
		f    Facts
		quer bool
	}{
		{
			nome: "contêiner: raiz em overlay",
			f: Facts{Mounts: []Montagem{
				{Ponto: "/", Tipo: "overlay", Origem: "overlay"},
				{Ponto: "/proc", Tipo: "proc"},
			}},
			quer: true,
		},
		{
			// O CASO QUE QUEBROU: rootfs exportado de imagem, com a marca do
			// docker dentro, mas rodando numa VM com kernel próprio.
			nome: "VM com rootfs vindo de imagem: NÃO é contêiner",
			f: Facts{
				Mounts:    []Montagem{{Ponto: "/", Tipo: "rootfs"}},
				Processes: []Process{{PID: 1, Cgroup: "/init.scope"}},
			},
			quer: false,
		},
		{
			nome: "host normal",
			f: Facts{
				Mounts:    []Montagem{{Ponto: "/", Tipo: "ext4", Origem: "/dev/sda1"}},
				Processes: []Process{{PID: 1, Cgroup: "/init.scope"}},
			},
			quer: false,
		},
		{
			// Quando o namespace de cgroup NÃO está isolado, o pid 1 mostra o
			// cgroup do runtime — e aí ele fecha o caso sozinho.
			nome: "contêiner sem namespace de cgroup isolado",
			f: Facts{
				Mounts:    []Montagem{{Ponto: "/", Tipo: "btrfs"}},
				Processes: []Process{{PID: 1, Cgroup: "/system.slice/docker-abc123def456.scope"}},
			},
			quer: true,
		},
		{
			nome: "sem dado nenhum não se afirma nada",
			f:    Facts{},
			quer: false,
		},
	}

	for _, c := range casos {
		t.Run(c.nome, func(t *testing.T) {
			if got := ferramentaEmContainer(&c.f); got != c.quer {
				t.Errorf("ferramentaEmContainer = %v, queria %v", got, c.quer)
			}
		})
	}
}

// classificaContainers preenche o runtime de cada processo, e é dele que
// depende a decisão de perguntar ou não pela propriedade do binário.
func TestClassificaContainersMarcaCadaProcesso(t *testing.T) {
	f := &Facts{
		Mounts: []Montagem{{Ponto: "/", Tipo: "ext4"}},
		Processes: []Process{
			{PID: 1, Cgroup: "/init.scope"},
			{PID: 10, Cgroup: "/system.slice/docker-2549dd25988f0f64c491475e481d0cd1.scope"},
			{PID: 11, Cgroup: "/kubepods.slice/kubepods-besteffort.slice/cri-containerd-9f3c1a2b4d5e.scope"},
			{PID: 12, Cgroup: "/user.slice/user-1000.slice/session-2.scope"},
		},
	}
	classificaContainers(f)

	if f.Host.EmContainer {
		t.Error("raiz em ext4 e pid 1 no init.scope é um HOST")
	}
	quer := map[int]string{1: "", 10: "docker", 11: "kubernetes", 12: ""}
	for i := range f.Processes {
		p := &f.Processes[i]
		if p.Container != quer[p.PID] {
			t.Errorf("pid=%d runtime=%q, queria %q", p.PID, p.Container, quer[p.PID])
		}
	}
	if f.Processes[1].ContainerID != "2549dd25988f" {
		t.Errorf("o id curto é o que o `docker ps` mostra, e saiu %q", f.Processes[1].ContainerID)
	}
}
