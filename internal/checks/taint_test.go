package checks

import (
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/facts"
)

func fatosTaint(bits uint64, mods ...facts.ModuloTaint) *facts.Facts {
	return &facts.Facts{Taint: facts.Taint{
		Lido: true, ListaLida: true, Bits: bits, Modulos: mods,
	}}
}

// O caso que decide se este check é usável: um desktop com driver nvidia tem
// dois bits ligados e quatro módulos que os assumem. Zero achados.
func TestTaintExplicadoNaoViraAchado(t *testing.T) {
	f := fatosTaint(12288,
		facts.ModuloTaint{Nome: "nvidia", Letras: "OE"},
		facts.ModuloTaint{Nome: "nvidia_drm", Letras: "OE"},
	)
	if r := taintSemDono.Run(taintSemDono, f, testEnv()); len(r.Findings) != 0 {
		t.Errorf("marca com dono não é achado: %v", r.Findings)
	}
}

// O mesmo kernel depois que o módulo saiu: as marcas ficam, e ninguém as assume.
func TestTaintSemDonoEhAviso(t *testing.T) {
	r := taintSemDono.Run(taintSemDono, fatosTaint(12288), testEnv())
	if len(r.Findings) != 1 {
		t.Fatalf("achados = %v", r.Findings)
	}
	fd := r.Findings[0]
	if fd.Sev != check.SevWarn {
		t.Errorf("sev = %v, queria WARN", fd.Sev)
	}
	if fd.Subject != "taint OE" {
		t.Errorf("subject = %q", fd.Subject)
	}
	junto := strings.Join(fd.Evidence, " | ")
	// A propriedade que dá valor ao achado precisa estar dita: o bit não some.
	if !strings.Contains(junto, "não pode ser apagada") {
		t.Errorf("a evidência precisa dizer que a marca não se apaga: %q", junto)
	}
}

// Carregar módulo à força passa por cima da checagem de versão do kernel, e a
// maioria das distribuições nem compila a opção: quando aparece, é decisão de
// alguém contornando uma recusa.
func TestTaintForcadoEhCritico(t *testing.T) {
	r := taintSemDono.Run(taintSemDono, fatosTaint(1<<1), testEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevCritical {
		t.Fatalf("módulo forçado é crítico: %v", r.Findings)
	}
}

// Remoção forçada é caso próprio: módulo NENHUM pode assumi-la, porque quem a
// sofreu já não está carregado. Sem uma regra própria, ela nunca apareceria.
func TestTaintRemocaoForcada(t *testing.T) {
	r := taintSemDono.Run(taintSemDono, fatosTaint(1<<3), testEnv())
	if len(r.Findings) != 1 {
		t.Fatalf("achados = %v", r.Findings)
	}
	if r.Findings[0].Subject != "taint R" || r.Findings[0].Sev != check.SevWarn {
		t.Errorf("achado = %+v", r.Findings[0])
	}
}

// O kernel ter morrido é CONTEXTO, não acusação: driver com defeito produz
// oops. Vale a linha porque exploit de kernel que falha produz a mesma marca.
func TestTaintOopsEhInformativo(t *testing.T) {
	r := taintSemDono.Run(taintSemDono, fatosTaint(1<<7), testEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevInfo {
		t.Fatalf("oops é INFO: %v", r.Findings)
	}
}

// De dentro de um contêiner a marca é real e não é do contêiner: dizer sim,
// acusar não.
func TestTaintEmContainerRebaixa(t *testing.T) {
	f := fatosTaint(12288)
	f.Host.EmContainer = true
	r := taintSemDono.Run(taintSemDono, f, testEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevInfo {
		t.Fatalf("em contêiner o achado sai como INFO: %v", r.Findings)
	}
	if !strings.Contains(strings.Join(r.Findings[0].Evidence, " "), "kernel") {
		t.Error("a evidência precisa explicar que o kernel é do host")
	}
}

// Sem a lista de módulos não existe atribuição, e sem atribuição não existe
// pergunta: acusar aqui acusaria todo host com driver de vídeo.
func TestTaintSemListaNaoAcusa(t *testing.T) {
	f := &facts.Facts{
		Taint:   facts.Taint{Lido: true, ListaLida: false, Bits: 12288},
		Partial: map[string][]string{"taint": {"/proc/modules ilegível"}},
	}
	r := taintSemDono.Run(taintSemDono, f, testEnv())
	if len(r.Findings) != 0 {
		t.Errorf("sem lista de módulos não se acusa: %v", r.Findings)
	}
	if len(r.Partial) == 0 {
		t.Error("e a falta precisa degradar a cobertura")
	}
}
