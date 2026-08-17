package check

import (
	"testing"
	"time"
)

var agora = time.Date(2026, 8, 17, 22, 0, 0, 0, time.UTC)

func TestParseJanelaAceitaAsDuasFormas(t *testing.T) {
	casos := []struct {
		spec  string
		desde time.Time
	}{
		{"72h", agora.Add(-72 * time.Hour)},
		{"7d", agora.Add(-7 * 24 * time.Hour)},
		{"30m", agora.Add(-30 * time.Minute)},
		{"2026-04-30T18:00:00Z", time.Date(2026, 4, 30, 18, 0, 0, 0, time.UTC)},
		// Sem segundos: é a forma que a SPEC escreve, e o RFC3339 do Go recusa.
		{"2026-04-30T18:00Z", time.Date(2026, 4, 30, 18, 0, 0, 0, time.UTC)},
		// Sem fuso: UTC, porque a ferramenta inteira é UTC — assumir o fuso
		// local faria a mesma janela recortar diferente em dois hosts da frota.
		{"2026-04-30", time.Date(2026, 4, 30, 0, 0, 0, 0, time.UTC)},
	}
	for _, c := range casos {
		j, err := ParseJanela(c.spec, agora)
		if err != nil {
			t.Errorf("%q: %v", c.spec, err)
			continue
		}
		if !j.Desde.Equal(c.desde) {
			t.Errorf("%q: desde = %v, queria %v", c.spec, j.Desde, c.desde)
		}
		if !j.Ativa || j.Spec != c.spec {
			t.Errorf("%q: a janela precisa citar o que o operador escreveu", c.spec)
		}
	}
}

// Recusar é melhor que interpretar: uma janela entendida errado recorta o
// relatório errado, e ninguém percebe.
func TestParseJanelaRecusaOQueNaoEntende(t *testing.T) {
	for _, spec := range []string{"ontem", "72", "-3h", "30/04/2026", "0h"} {
		if _, err := ParseJanela(spec, agora); err == nil {
			t.Errorf("%q deveria ser recusado", spec)
		}
	}
	// Vazio não é erro: é a execução normal, sem janela.
	if j, err := ParseJanela("", agora); err != nil || j.Ativa {
		t.Errorf("sem --since não há janela: %v %v", j, err)
	}
}

// A decisão que decide tudo: o achado SEM DATA fica. Descartá-lo seria esconder
// por ignorância, e é o que permite datar os checks aos poucos.
func TestJanelaMantemOQueNaoTemData(t *testing.T) {
	r := &Report{Findings: []Finding{
		{ID: "a", Sev: SevCritical, Quando: "2026-08-17T21:00:00Z"}, // dentro
		{ID: "b", Sev: SevCritical, Quando: "2026-01-01T00:00:00Z"}, // fora
		{ID: "c", Sev: SevWarn, Quando: "2026-01-02T00:00:00Z"},     // fora
		{ID: "d", Sev: SevWarn},                          // sem data
		{ID: "e", Sev: SevWarn, Quando: "data inválida"}, // ilegível = sem data
	}}
	j, err := ParseJanela("24h", agora)
	if err != nil {
		t.Fatal(err)
	}
	rec := r.Aplicar(j)

	if len(r.Findings) != 3 {
		t.Fatalf("ficaram %d achados, queria 3 (o de dentro e os dois sem data)", len(r.Findings))
	}
	if rec.Fora != 2 || rec.SemData != 2 {
		t.Errorf("fora = %d, semData = %d", rec.Fora, rec.SemData)
	}
	if rec.ForaSev[SevCritical] != 1 || rec.ForaSev[SevWarn] != 1 {
		t.Errorf("contagem por severidade errada: %v", rec.ForaSev)
	}
	// E o crítico recortado precisa impedir o exit 0: a varredura ACHOU algo.
	if r.CriticosForaDaJanela != 1 {
		t.Errorf("críticos fora = %d", r.CriticosForaDaJanela)
	}
	if r.Exit() == 0 || r.Verdict() == "OK" {
		t.Errorf("um crítico recortado não pode deixar a execução sair OK: %s/%d",
			r.Verdict(), r.Exit())
	}
}

// Sem --since, o âncora vem do achado MAIS SEVERO — e entre iguais, do mais
// recente. É o ovo-e-galinha da §9: a timeline precisa de um começo.
func TestAncoraDerivaDoAchadoMaisSevero(t *testing.T) {
	r := &Report{Findings: []Finding{
		{ID: "warn.velho", Sev: SevWarn, Quando: "2026-08-01T10:00:00Z", Subject: "x"},
		{ID: "crit.antigo", Sev: SevCritical, Quando: "2026-08-10T10:00:00Z", Subject: "a",
			QuandoFonte: "mtime do arquivo"},
		{ID: "crit.recente", Sev: SevCritical, Quando: "2026-08-12T10:00:00Z", Subject: "b",
			QuandoFonte: "início do processo"},
		{ID: "warn.novo", Sev: SevWarn, Quando: "2026-08-16T10:00:00Z", Subject: "y"},
	}}
	a := r.DerivarAncora(Janela{})
	if a.Quando != "2026-08-12T10:00:00Z" {
		t.Errorf("âncora = %q, queria o crítico mais recente", a.Quando)
	}
	if a.Origem != "derivado desta execução" {
		t.Errorf("origem = %q — a ferramenta precisa DIZER que derivou", a.Origem)
	}
	if a.De != "crit.recente em b (início do processo)" {
		t.Errorf("de = %q: o achado que produziu o âncora precisa ser nomeado", a.De)
	}
}

// Sem achado datável, o âncora é VAZIO. Inventar sete dias e apresentá-los como
// âncora seria fingir que derivou de alguma coisa.
func TestSemAchadoDatavelNaoInventaAncora(t *testing.T) {
	r := &Report{Findings: []Finding{{ID: "a", Sev: SevWarn}}}
	if a := r.DerivarAncora(Janela{}); a.Quando != "" {
		t.Errorf("âncora inventado: %+v", a)
	}
	// Com --since, o âncora é o que o operador informou, e a origem diz isso.
	j, _ := ParseJanela("72h", agora)
	a := r.DerivarAncora(j)
	if a.Quando == "" || a.Origem != "informado em --since 72h" {
		t.Errorf("âncora com janela = %+v", a)
	}
}

// E o caso que o exit code existe para cobrir: a janela levou TODOS os achados,
// e um deles era crítico. O relatório fica limpo; a execução não pode sair OK.
//
// É a promessa central da ferramenta — exit 0 significa "não há o que ver" —, e
// aqui há: a varredura ACHOU o crítico, e foi o recorte pedido que o escondeu.
// Um `verdict: OK` mandaria a automação de frota arquivar um host comprometido.
func TestCriticoRecortadoNaoDeixaSairOK(t *testing.T) {
	r := &Report{
		Coverage: Coverage{Total: 3, Complete: 3}, // cobertura completa de propósito
		Findings: []Finding{
			{ID: "crit.antigo", Sev: SevCritical, Quando: "2026-01-01T00:00:00Z"},
			{ID: "warn.antigo", Sev: SevWarn, Quando: "2026-01-02T00:00:00Z"},
		},
	}
	j, err := ParseJanela("24h", agora)
	if err != nil {
		t.Fatal(err)
	}
	r.Aplicar(j)

	if len(r.Findings) != 0 {
		t.Fatalf("os dois achados eram antigos: %v", r.Findings)
	}
	if r.Exit() != 1 {
		t.Errorf("exit = %d, queria 1: há um crítico que este recorte escondeu", r.Exit())
	}
	if r.Verdict() == "OK" {
		t.Error("verdict OK com um crítico recortado é a mentira que a frota lê")
	}
}
