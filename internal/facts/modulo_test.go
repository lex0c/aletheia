package facts

import "testing"

// As duas armadilhas do casamento por nome. Cada uma sozinha produz falso
// positivo em MASSA — num desktop real são 249 módulos carregados, e errar
// qualquer uma delas acusaria dezenas de uma vez.
func TestIndiceDeModulosCasaNomeComArquivo(t *testing.T) {
	idx := indiceDeModulosEmDisco([]string{
		"/lib/modules/6.12/kernel/fs/ext4/ext4.ko.zst",
		"/lib/modules/6.12/kernel/sound/pci/hda/snd-hda-intel.ko.xz",
		"/lib/modules/6.12/kernel/drivers/net/dummy.ko",
		"/lib/modules/6.12/extra/nvidia.ko.gz",
		"/lib/modules/6.12/kernel/lixo.txt",
	})
	casos := map[string]bool{
		"ext4":          true,
		"snd_hda_intel": true, // o kernel chama assim o que o arquivo chama com traço
		"dummy":         true,
		"nvidia":        true,
		"diamorphine":   false,
		"lixo":          false, // não é módulo
	}
	for nome, quero := range casos {
		_, achou := idx[normalizaModulo(nome)]
		if achou != quero {
			t.Errorf("%s: achou = %v, queria %v", nome, achou, quero)
		}
	}
}

func TestModuloSemArquivoENaoAssinado(t *testing.T) {
	casos := []struct {
		m                    ModuloCarregado
		semArquivo, semAssin bool
	}{
		{ModuloCarregado{Nome: "ext4", Arquivo: "/lib/modules/x/ext4.ko"}, false, false},
		{ModuloCarregado{Nome: "x"}, true, false},
		{ModuloCarregado{Nome: "nvidia", Letras: "OE", Arquivo: "/x.ko"}, false, true},
		{ModuloCarregado{Nome: "y", Letras: "F"}, true, true},
		// `P` é módulo proprietário e `C` é staging: nenhum dos dois diz que o
		// módulo veio de fora do conjunto assinado, e tratá-los como tal
		// promoveria driver de fábrica a crítico.
		{ModuloCarregado{Nome: "z", Letras: "PC"}, true, false},
	}
	for _, c := range casos {
		if got := c.m.SemArquivo(); got != c.semArquivo {
			t.Errorf("%s: SemArquivo = %v", c.m.Nome, got)
		}
		if got := c.m.NaoAssinado(); got != c.semAssin {
			t.Errorf("%s (letras %q): NaoAssinado = %v", c.m.Nome, c.m.Letras, got)
		}
	}
}

func TestValorEntreColchetes(t *testing.T) {
	casos := map[string]string{
		"none [integrity] confidentiality": "integrity",
		"[none] integrity":                 "none",
		"none integrity":                   "none integrity", // sem marcação, devolve como veio
		"":                                 "",
	}
	for entrada, quero := range casos {
		if got := valorEntreColchetes(entrada); got != quero {
			t.Errorf("valorEntreColchetes(%q) = %q, queria %q", entrada, got, quero)
		}
	}
}

// Lido separa "o kernel não tem esta proteção" de "não consegui ler nada".
func TestProtecaoLido(t *testing.T) {
	if (ProtecaoKernel{}).Lido() {
		t.Error("vazio não pode contar como lido")
	}
	if !(ProtecaoKernel{PtraceScope: "0"}).Lido() {
		t.Error("um único valor lido já é contexto")
	}
	// SecurityFS montado é informação mesmo com todo o resto vazio: diz que o
	// lockdown foi PROCURADO onde ele mora.
	if !(ProtecaoKernel{SecurityFS: true}).Lido() {
		t.Error("securityfs montado conta como leitura")
	}
}

func TestTrancaModulo(t *testing.T) {
	casos := []struct {
		p     ProtecaoKernel
		quero bool
	}{
		{ProtecaoKernel{}, false},
		{ProtecaoKernel{SigEnforce: "N", ModulesDisabled: "0"}, false},
		{ProtecaoKernel{SigEnforce: "Y"}, true},
		{ProtecaoKernel{ModulesDisabled: "1"}, true},
	}
	for _, c := range casos {
		if got := c.p.TrancaModulo(); got != c.quero {
			t.Errorf("%+v: TrancaModulo = %v", c.p, got)
		}
	}
}
