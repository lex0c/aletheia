package facts

import (
	"strings"
	"testing"
)

// A comparação de módulos é a decisão mais cara do cruzamento: ela é o que
// acusa um LKM que se esconde. Estava embutida na função que lê /proc, e por
// isso só podia ser exercitada bootando uma VM — todo ajuste na regra era feito
// no escuro.
func TestDiferencaDeModulos(t *testing.T) {
	casos := []struct {
		nome       string
		proc, sys  []string
		querAcusar []string
	}{
		{
			nome: "iguais: nada a dizer",
			proc: []string{"ext4", "nvme", "kvm"},
			sys:  []string{"ext4", "nvme", "kvm"},
		},
		{
			// A FORMA DO ROOTKIT: carregado e sem entrada no sysfs.
			nome:       "carregado e ausente do sysfs",
			proc:       []string{"ext4", "diamorphine"},
			sys:        []string{"ext4"},
			querAcusar: []string{"diamorphine"},
		},
		{
			// A DIREÇÃO OPOSTA É RUÍDO, e é a maioria: módulo embutido no
			// kernel aparece em /sys/module e nunca em /proc/modules. Acusar
			// esta direção encheria todo host de achado.
			nome: "embutido no kernel: sysfs tem, proc não",
			proc: []string{"ext4"},
			sys:  []string{"ext4", "kernel", "cpuidle", "printk", "sched"},
		},
		{
			// O sysfs normaliza "-" para "_". Sem normalizar, cada módulo com
			// hífen viraria uma divergência falsa.
			nome: "hífen contra sublinhado é a MESMA coisa",
			proc: []string{"snd-hda-intel", "i2c-dev"},
			sys:  []string{"snd_hda_intel", "i2c_dev"},
		},
		{
			nome:       "vários ocultos saem ordenados",
			proc:       []string{"zzz_rk", "ext4", "aaa_rk"},
			sys:        []string{"ext4"},
			querAcusar: []string{"aaa_rk", "zzz_rk"},
		},
	}

	for _, c := range casos {
		t.Run(c.nome, func(t *testing.T) {
			got := DiferencaDeModulos(c.proc, c.sys)
			if len(got) != len(c.querAcusar) {
				t.Fatalf("%d divergência(s), queria %d: %v", len(got), len(c.querAcusar), got)
			}
			for i, quer := range c.querAcusar {
				if !strings.HasPrefix(got[i], quer+" ") {
					t.Errorf("divergência %d = %q, queria começar com %q", i, got[i], quer)
				}
				// A frase tem que dizer a DIREÇÃO: sem ela o operador não sabe
				// qual das duas fontes está calando o quê.
				if !strings.Contains(got[i], "em /proc/modules e NÃO em /sys/module") {
					t.Errorf("a direção sumiu da mensagem: %q", got[i])
				}
			}
		})
	}
}

// Lista vazia dos dois lados não é divergência — é ausência de dado, e a
// distinção é a mesma que a ferramenta faz em todo lugar.
func TestDiferencaDeModulosComListaVazia(t *testing.T) {
	if got := DiferencaDeModulos(nil, nil); len(got) != 0 {
		t.Errorf("sem módulo nenhum não há o que divergir: %v", got)
	}
	if got := DiferencaDeModulos(nil, []string{"ext4"}); len(got) != 0 {
		t.Errorf("nada carregado e sysfs com embutidos é o normal: %v", got)
	}
	// E o caso inverso É achado: há módulo carregado e o sysfs não mostra
	// NENHUM. É a forma de alguém ter apagado a árvore inteira.
	if got := DiferencaDeModulos([]string{"rk"}, nil); len(got) != 1 {
		t.Errorf("carregado sem sysfs nenhum tem que acusar: %v", got)
	}
}

func TestNormalizaModulo(t *testing.T) {
	for _, c := range []struct{ in, quer string }{
		{"snd-hda-intel", "snd_hda_intel"},
		{"ext4", "ext4"},
		{"", ""},
	} {
		if got := normalizaModulo(c.in); got != c.quer {
			t.Errorf("normalizaModulo(%q) = %q, queria %q", c.in, got, c.quer)
		}
	}
}

// A extração de tags é o coração do cruzamento: função de builtin sai SEM tag e
// não pode virar módulo, função de módulo sai COM tag e conta uma vez só por
// mais que apareça.
func TestTagsDeModuloDoFtrace(t *testing.T) {
	texto := `vfs_read
vfs_write
nf_conntrack_lock [nf_conntrack]
nf_conntrack_find [nf_conntrack]
ext4_file_open [ext4]
evil_marcador [evil]
__x64_sys_read
`
	got := tagsDeModuloDoFtrace(texto)
	quer := []string{"evil", "ext4", "nf_conntrack"}
	if len(got) != len(quer) {
		t.Fatalf("tags = %v, queria %v", got, quer)
	}
	for i := range quer {
		if got[i] != quer[i] {
			t.Errorf("tags = %v, queria %v (ordenado, sem duplicar)", got, quer)
		}
	}
}

// O achado: uma tag no ftrace que /proc/modules nega. É a assinatura do LKM que
// se desencadeia da lista — provado em VM, ver test/vm/ftrace-hidden-module.sh.
func TestModuloEscondidoApareceSoNoFtrace(t *testing.T) {
	ftrace := []string{"nf_conntrack", "ext4", "evil"}
	proc := []string{"nf_conntrack", "ext4"} // evil se removeu daqui
	got := ModulosSoNoFtrace(ftrace, proc)
	if len(got) != 1 {
		t.Fatalf("diff = %v, queria 1", got)
	}
	if !strings.Contains(got[0], "evil") {
		t.Errorf("o módulo escondido precisa ser nomeado: %q", got[0])
	}
}

// A direção OPOSTA é normal e não pode virar achado. Um módulo carregado sem
// função rastreável — muitos são assim — está em /proc/modules e não no ftrace.
// Acusar isso encheria todo host de falso positivo.
func TestModuloSemFuncaoRastreavelNaoEhAchado(t *testing.T) {
	ftrace := []string{"ext4"}
	proc := []string{"ext4", "sem_ftrace_algum", "outro"}
	if got := ModulosSoNoFtrace(ftrace, proc); len(got) != 0 {
		t.Errorf("estar em /proc e não no ftrace é normal: %v", got)
	}
}

// Hífen e sublinhado são o MESMO módulo nas duas fontes, como no crossview de
// sysfs. Sem normalizar, `nf-conntrack` no ftrace contra `nf_conntrack` no proc
// inventaria um módulo escondido a cada host.
func TestModulosSoNoFtraceNormalizaHifen(t *testing.T) {
	if got := ModulosSoNoFtrace([]string{"nf-conntrack"}, []string{"nf_conntrack"}); len(got) != 0 {
		t.Errorf("mesmo módulo, grafias diferentes: %v", got)
	}
}

// O caso que a VM da prova pegou e o teste não tinha: o módulo escondido é o
// ÚNICO — /proc/modules vazio, ftrace com uma tag. A regra tem de acusar, e não
// tratar lista vazia como "nada a comparar". Confundir vazio com ilegível
// deixaria passar justamente o host mínimo onde o oculto não tem vizinho.
func TestModuloEscondidoSozinhoComProcVazio(t *testing.T) {
	got := ModulosSoNoFtrace([]string{"evil"}, nil)
	if len(got) != 1 || !strings.Contains(got[0], "evil") {
		t.Fatalf("proc vazio e uma tag no ftrace é um módulo oculto: %v", got)
	}
}

// A reconfirmação é uma INTERSEÇÃO: só a divergência presente NAS DUAS leituras
// sobrevive. Uma que aparece só na primeira é corrida e é descartada. (O caso de
// a segunda leitura FALHAR — vazio ≠ ilegível — é guardado pelas flags okProc/
// okSys em quem chama, que declaram lacuna e zeram a divergência.)
func TestReconfirmacaoEhIntersecao(t *testing.T) {
	primeira := []string{"evil está em X", "ext4 está em X", "algo está em X"}
	segunda := []string{"evil está em X"} // só evil persistiu
	got := soPersistentes(primeira, segunda)
	if len(got) != 1 || got[0] != "evil está em X" {
		t.Fatalf("só o que persiste nas duas leituras sobrevive: %v", got)
	}
	// segunda leitura sem divergência nenhuma = tudo era corrida.
	if got := soPersistentes(primeira, nil); len(got) != 0 {
		t.Errorf("segunda leitura concordou (sem divergência): tudo descartado, veio %v", got)
	}
}

// Pipe de inode ZERO não pode entrar no índice: seria uma chave que junta todo
// fd de pipe degenerado num balde só, e a ponte de reverse shell passaria a
// casar processos que não compartilham nada.
func TestPidsComPipeIgnoraInodeZero(t *testing.T) {
	f := &Facts{Processes: []Process{
		{PID: 1, FDs: []FD{{N: 0, Pipe: true, PipeInode: 0}}},
		{PID: 2, FDs: []FD{{N: 0, Pipe: true, PipeInode: 0}}},
	}}
	f.Index()
	if len(f.PidsComPipe(0)) != 0 {
		t.Errorf("inode 0 não pode indexar ninguém: %v", f.PidsComPipe(0))
	}
}
