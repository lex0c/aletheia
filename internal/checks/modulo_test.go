package checks

import (
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/facts"
)

func fatosModulo(mods ...facts.ModuloCarregado) *facts.Facts {
	return &facts.Facts{ArvoreDeModulos: true, Carregados: mods}
}

// A medição que decide se este check é usável: num desktop real são 249 módulos
// carregados e 12 mil arquivos .ko em disco. Zero achados — e é isso que o
// primeiro caso trava.
func TestModuloComArquivoNaoDispara(t *testing.T) {
	f := fatosModulo(
		facts.ModuloCarregado{Nome: "ext4", Arquivo: "/lib/modules/6.12/kernel/fs/ext4/ext4.ko.zst", NoSys: true},
		// Módulo de terceiro, fora da árvore e com marca de taint — mas COM
		// arquivo. É o nvidia de todo desktop, e acusá-lo seria o fim do check.
		facts.ModuloCarregado{Nome: "nvidia", Letras: "OE", NoSys: true,
			Arquivo: "/lib/modules/6.12/extra/nvidia.ko.zst"},
	)
	if r := moduloSemArquivo.Run(moduloSemArquivo, f, testEnv()); len(r.Findings) != 0 {
		t.Errorf("módulo com arquivo não é achado: %v", r.Findings)
	}
}

// A escada de severidade é o coração do check: a mesma ausência de arquivo
// significa coisas muito diferentes conforme o que o KERNEL diz do módulo.
func TestEscadaDeSeveridade(t *testing.T) {
	casos := []struct {
		nome   string
		mod    facts.ModuloCarregado
		quero  check.Severity
		trecho string
	}{
		{
			// A causa legítima e comum: atualizar o kernel apaga os .ko da
			// versão antiga, e a máquina segue rodando a antiga por semanas.
			nome:  "sem arquivo, mas assinado",
			mod:   facts.ModuloCarregado{Nome: "ext4", NoSys: true},
			quero: check.SevWarn, trecho: "não está em disco",
		},
		{
			// O kernel diz que não veio do conjunto assinado da distribuição, E
			// não há arquivo. As duas coisas juntas não têm explicação de rotina.
			nome:  "sem arquivo e sem assinatura",
			mod:   facts.ModuloCarregado{Nome: "diamorphine", Letras: "OE", NoSys: true},
			quero: check.SevCritical, trecho: "SEM assinatura válida",
		},
		{
			nome:  "carregado à força",
			mod:   facts.ModuloCarregado{Nome: "x", Letras: "F", NoSys: true},
			quero: check.SevCritical, trecho: "À FORÇA",
		},
	}
	for _, c := range casos {
		t.Run(c.nome, func(t *testing.T) {
			r := moduloSemArquivo.Run(moduloSemArquivo, fatosModulo(c.mod), testEnv())
			if len(r.Findings) != 1 {
				t.Fatalf("achados = %v", r.Findings)
			}
			fd := r.Findings[0]
			if fd.Sev != c.quero {
				t.Errorf("sev = %v, queria %v", fd.Sev, c.quero)
			}
			if !strings.Contains(strings.Join(fd.Evidence, " "), c.trecho) {
				t.Errorf("a evidência não explica o caso (%q): %v", c.trecho, fd.Evidence)
			}
			if !fd.Irreversible {
				t.Error("rmmod destrói o código: o achado precisa ser Irreversible")
			}
		})
	}
}

// A divergência entre as duas interfaces do kernel é sinal SOMADO, não
// substituto: um módulo que o /proc lista e o /sys não conhece é a forma de
// quem se removeu de uma das listas.
func TestAusenciaNoSysfsEntraNaEvidencia(t *testing.T) {
	f := fatosModulo(facts.ModuloCarregado{Nome: "oculto"}) // NoSys: false
	r := moduloSemArquivo.Run(moduloSemArquivo, f, testEnv())
	if len(r.Findings) != 1 {
		t.Fatalf("achados = %v", r.Findings)
	}
	if !strings.Contains(strings.Join(r.Findings[0].Evidence, " "), "NÃO aparece em /sys/module") {
		t.Errorf("evidência = %v", r.Findings[0].Evidence)
	}
}

// SEM A ÁRVORE LIDA, ausência de arquivo não significa ausência: significa que
// ninguém olhou. É a distinção que a ferramenta inteira existe para manter, e
// aqui ela vale por dezenas de achados falsos.
func TestSemArvoreDeModulosNaoAcusaNinguem(t *testing.T) {
	f := &facts.Facts{
		ArvoreDeModulos: false,
		Carregados: []facts.ModuloCarregado{
			{Nome: "ext4"}, {Nome: "overlay"}, {Nome: "nvidia", Letras: "OE"},
		},
		Partial: map[string][]string{"modulo": {"nenhum arquivo de módulo encontrado"}},
	}
	r := moduloSemArquivo.Run(moduloSemArquivo, f, testEnv())
	if len(r.Findings) != 0 {
		t.Errorf("sem árvore lida não há acusação possível: %v", r.Findings)
	}
	if len(r.Partial) == 0 {
		t.Error("e a lacuna precisa ser DECLARADA, senão vira silêncio")
	}
}

// Em contêiner a comparação não tem sentido: /proc/modules é o do HOST e
// /lib/modules é o da imagem. É a mesma armadilha que derrubou a enumeração de
// eBPF, e ela acusaria todos os módulos do host de uma vez.
func TestEmContainerNaoCompara(t *testing.T) {
	f := fatosModulo(
		facts.ModuloCarregado{Nome: "ext4"},
		facts.ModuloCarregado{Nome: "nvidia", Letras: "OE"},
	)
	f.Host.EmContainer = true
	r := moduloSemArquivo.Run(moduloSemArquivo, f, testEnv())
	if len(r.Findings) != 0 {
		t.Errorf("em contêiner o check precisa se calar: %v", r.Findings)
	}
	// E o silêncio NÃO é lacuna de cobertura: marcar parcial faria toda
	// varredura dentro de contêiner sair incompleta e com exit 1, inclusive a de
	// um contêiner limpo. Quem declara o escopo é o proc.container_boundary,
	// uma vez, em vez de cada check repetir a degradação.
	if len(r.Partial) != 0 {
		t.Errorf("o escopo é declarado pelo boundary, não por degradação aqui: %v", r.Partial)
	}
}

// O contexto de proteção muda o que o operador procura em seguida, e por isso
// viaja junto do achado em vez de ficar num bloco separado que ninguém cruza.
func TestOAchadoCarregaOContextoDoKernel(t *testing.T) {
	f := fatosModulo(facts.ModuloCarregado{Nome: "x", Letras: "OE"})
	f.Protecao = facts.ProtecaoKernel{SigEnforce: "Y", ModulesDisabled: "1", Lockdown: "integrity"}
	r := moduloSemArquivo.Run(moduloSemArquivo, f, testEnv())
	ev := strings.Join(r.Findings[0].Evidence, " ")
	for _, trecho := range []string{"EXIGE assinatura", "TRANCADO agora", "lockdown do kernel em modo integrity"} {
		if !strings.Contains(ev, trecho) {
			t.Errorf("faltou %q na evidência: %v", trecho, r.Findings[0].Evidence)
		}
	}
}

func TestProtecaoDoKernelInventaria(t *testing.T) {
	f := &facts.Facts{Protecao: facts.ProtecaoKernel{
		SecurityFS: true, Lockdown: "none", SigEnforce: "N", ModulesDisabled: "0",
		SecureBoot: "off", PtraceScope: "1", KptrRestrict: "0",
	}}
	r := protecaoDoKernel.Run(protecaoDoKernel, f, testEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevInfo {
		t.Fatalf("achados = %v", r.Findings)
	}
	ev := strings.Join(r.Findings[0].Evidence, " ")
	for _, trecho := range []string{"assinatura de módulo obrigatória: não", "lockdown: none",
		"Secure Boot: off", "ptrace_scope=1"} {
		if !strings.Contains(ev, trecho) {
			t.Errorf("faltou %q: %v", trecho, r.Findings[0].Evidence)
		}
	}
}

// Um inventário em que TUDO é "não determinado" não é contexto: é lacuna. Seis
// linhas dizendo "não sei" gastam a atenção do operador e não entregam nada.
func TestProtecaoNaoLidaViraLacunaEmVezDeInventario(t *testing.T) {
	r := protecaoDoKernel.Run(protecaoDoKernel, &facts.Facts{}, testEnv())
	if len(r.Findings) != 0 {
		t.Errorf("sem nada lido não há inventário a imprimir: %v", r.Findings)
	}
	if len(r.Partial) == 0 {
		t.Error("e a ausência precisa ser declarada")
	}
}

// O securityfs não montado é o caso comum em contêiner e em guest mínimo: o
// lockdown fica ilegível, e a ferramenta NÃO monta nada para descobrir.
func TestSecurityFSAusenteEhDeclarado(t *testing.T) {
	f := &facts.Facts{Protecao: facts.ProtecaoKernel{SigEnforce: "N", PtraceScope: "0"}}
	r := protecaoDoKernel.Run(protecaoDoKernel, f, testEnv())
	if len(r.Findings) != 1 {
		t.Fatalf("achados = %v", r.Findings)
	}
	ev := strings.Join(r.Findings[0].Evidence, " ")
	if !strings.Contains(ev, "não monta nada") {
		t.Errorf("a recusa de montar precisa estar escrita: %v", r.Findings[0].Evidence)
	}
	// E NÃO degrada a cobertura: a ausência está escrita no próprio inventário,
	// na frente de quem o está lendo. Degradar aqui marcaria como incompleta
	// toda execução em contêiner e em guest mínimo — gastando a atenção que uma
	// lacuna de verdade precisa.
	if len(r.Partial) != 0 {
		t.Errorf("a ausência já está dita no inventário; degradar a cobertura por "+
			"ela marcaria como incompleta toda execução em contêiner: %v", r.Partial)
	}
}

// Arquivo que EXISTE e não abre é outra coisa: ali houve tentativa de leitura e
// ela falhou, e isso é lacuna de verdade.
func TestArquivoDeProtecaoIlegivelDegradaACobertura(t *testing.T) {
	f := &facts.Facts{Protecao: facts.ProtecaoKernel{
		PtraceScope: "1",
		NaoLidos:    []string{"/sys/kernel/security/lockdown: permission denied"},
	}}
	r := protecaoDoKernel.Run(protecaoDoKernel, f, testEnv())
	if len(r.Partial) == 0 {
		t.Error("leitura que falhou precisa degradar a cobertura")
	}
}
