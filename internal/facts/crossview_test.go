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
