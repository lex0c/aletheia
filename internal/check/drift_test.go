package check

import (
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/facts"
)

// A MUDANÇA PRECISA ENCONTRAR O ACHADO QUE FALA DA MESMA COISA.
//
// Sem isto, drift e checks viveriam em dois relatórios paralelos sobre o mesmo
// host: um dizendo "isto está errado", outro dizendo "isto mudou", e o operador
// juntando na cabeça — que é exatamente o que a resolução de ator já existe
// para não pedir.
func TestAchadoGanhaAMudancaDoObjetoDele(t *testing.T) {
	f := &facts.Facts{DriftDados: &facts.Drift{
		DeQuando: "2026-01-01T00:00:00Z", AteQuando: "2026-01-02T00:00:00Z",
		Mudancas: []facts.MudancaDrift{{
			Tipo: "conta", Titulo: "conta local", ID: "suporte", Kind: "surgiu",
			Alvos: []string{"suporte"},
		}},
	}}
	r := &Report{Findings: []Finding{
		{ID: "priv.uid_zero", Subject: "suporte", Sev: SevCritical},
		{ID: "priv.uid_zero", Subject: "root", Sev: SevCritical},
	}}
	marcarDrift(r, f)

	if !r.Findings[0].Driftou {
		t.Error("o achado sobre `suporte` precisa carregar a mudança que o data")
	}
	if ev := strings.Join(r.Findings[0].Evidence, " "); !strings.Contains(ev, "conta local `suporte`") {
		t.Errorf("e a evidência precisa NOMEAR a mudança:\n%s", ev)
	}
	if r.Findings[1].Driftou {
		t.Error("`root` não mudou: marcar seria afirmar o que não houve")
	}
	// A SEVERIDADE NÃO SOBE. É a mesma assimetria da baseline pelo outro lado:
	// lá, casar com a referência nunca APAGA um achado; aqui, mudar desde a
	// referência nunca o PROMOVE. "Mudou desde ontem" tem a forma de um deploy,
	// e o crítico desta ferramenta é a severidade que faz uma frota parar.
	if r.Findings[0].Sev != SevCritical {
		t.Error("a marca dirige o olho; ela não mexe na severidade")
	}
}

// O achado de DRIFT não se marca: ele já É a mudança, e dizer-lhe que algo
// mudou sob ele seria a ferramenta se citando como fonte.
func TestAchadoDeDriftNaoSeMarca(t *testing.T) {
	daDrift := idsDeDrift()
	if len(daDrift) == 0 {
		t.Skip("nenhum check de drift registrado neste binário de teste")
	}
	var algum string
	for id := range daDrift {
		algum = id
		break
	}
	f := &facts.Facts{DriftDados: &facts.Drift{Mudancas: []facts.MudancaDrift{{
		Tipo: "conta", Titulo: "conta local", ID: "x", Kind: "surgiu",
		Alvos: []string{"x"},
	}}}}
	r := &Report{Findings: []Finding{{ID: algum, Subject: "x"}}}
	marcarDrift(r, f)
	if r.Findings[0].Driftou {
		t.Errorf("%s já fala de mudança: marcá-lo é circular", algum)
	}
}
