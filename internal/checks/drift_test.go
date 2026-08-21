package checks

import (
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/drift"
	"github.com/lex0c/aletheia/internal/facts"
)

func comDrift(m ...facts.MudancaDrift) *facts.Facts {
	return &facts.Facts{DriftDados: &facts.Drift{
		DeQuando: "2026-01-01T00:00:00Z", AteQuando: "2026-01-02T00:00:00Z",
		DeHost: "h", ParaHost: "h", Mudancas: m,
		Cobertura: []facts.CoberturaDrift{{Tipo: "systemd.unit", Titulo: "unit do systemd", Simetrico: true}},
	}}
}

// A FRASE DO DROP-IN SÓ VALE PARA DROP-IN.
//
// A condição era `m.Campo == "dropin_for" || strings.Contains(m.ID, "/") &&
// m.Kind == "surgiu"`, e o ID de uma unit é `nome@caminho` — caminho SEMPRE tem
// barra. Toda unit nova recebia "drop-in ALTERA outra unit sem tocar no arquivo
// dela", que é falso sobre uma unit comum. Afirmação falsa na evidência é o
// defeito mais caro desta base, e entrou por um `&&` sem parênteses.
func TestFraseDeDropInSoSaiEmDropIn(t *testing.T) {
	comum := facts.MudancaDrift{
		Tipo: "systemd.unit", Titulo: "unit do systemd",
		ID: "nova.service@/etc/systemd/system/nova.service", Kind: "surgiu",
		Campos: []string{"exec=ExecStart=/bin/true"},
	}
	r := driftUnit.Run(driftUnit, comDrift(comum), testEnv())
	if len(r.Findings) != 1 {
		t.Fatalf("%+v", r.Findings)
	}
	if ev := strings.Join(r.Findings[0].Evidence, " "); strings.Contains(ev, "drop-in") {
		t.Errorf("unit comum não é drop-in, e a evidência afirmava que era:\n%s", ev)
	}

	// E o drop-in de verdade continua sendo dito — com o alvo NOMEADO, que é a
	// informação que faz a frase valer alguma coisa.
	dropin := comum
	dropin.ID = "override.conf@/etc/systemd/system/sshd.service.d/override.conf"
	dropin.Campos = []string{"dropin_for=sshd.service", "exec=ExecStart=/bin/true"}
	r = driftUnit.Run(driftUnit, comDrift(dropin), testEnv())
	ev := strings.Join(r.Findings[0].Evidence, " ")
	if !strings.Contains(ev, "DROP-IN de `sshd.service`") {
		t.Errorf("o drop-in precisa ser dito, com o alvo:\n%s", ev)
	}
}

// O separador interno de lista não pode vazar para o relatório: `juntar` usa
// 0x1f para não colidir com conteúdo, e o sanitizador o transforma num `\x1f`
// visível — seguro e ilegível.
func TestSeparadorInternoNaoVazaNaEvidencia(t *testing.T) {
	m := facts.MudancaDrift{
		Tipo: "systemd.unit", Titulo: "unit do systemd", ID: "u.service@/x", Kind: "mudou",
		Campo:  "exec",
		Antes:  "ExecStart=/bin/a\x1fExecStartPre=/bin/b",
		Depois: "ExecStart=/bin/c\x1fExecStartPre=/bin/b",
	}
	r := driftUnit.Run(driftUnit, comDrift(m), testEnv())
	for _, e := range r.Findings[0].Evidence {
		if strings.ContainsRune(e, '\x1f') {
			t.Errorf("0x1f cru na evidência: %q", e)
		}
	}
}

// O corte é por RUNA. Fatiar por byte parte um caractere multibyte no meio, e o
// sanitizador entrega o pedaço como `\x?`.
func TestCorteNaoParteRuna(t *testing.T) {
	longo := strings.Repeat("ç", 200)
	got := cortaMeio(longo, 80)
	if strings.ContainsRune(got, '�') {
		t.Errorf("runa partida no corte: %q", got)
	}
	if !strings.Contains(got, "...") {
		t.Errorf("o corte precisa acontecer: %q", got)
	}
}

// Drift sozinho é AVISO, e os três tipos pesam igual: `options` retirado de uma
// chave que continua a mesma vale tanto quanto uma unit nova. A escada que o
// comentário anterior descrevia não existia no código.
func TestDriftSozinhoNuncaEhCritico(t *testing.T) {
	for _, kind := range []string{"surgiu", "sumiu", "mudou"} {
		m := facts.MudancaDrift{
			Tipo: "systemd.unit", Titulo: "unit do systemd", ID: "u.service@/x",
			Kind: kind, Campo: "exec", Antes: "a", Depois: "b",
		}
		r := driftUnit.Run(driftUnit, comDrift(m), testEnv())
		if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevWarn {
			t.Errorf("%s: severidade = %v", kind, r.Findings[0].Sev)
		}
	}
}

// TODA FAMÍLIA DE DRIFT PRECISA SER LIDA POR ALGUM CHECK.
//
// É o par da catraca que já existe para lacunas ("toda lacuna emitida é lida
// por alguém"), e ela existe pelo mesmo motivo: uma família comparada e nunca
// consumida é trabalho que vira silêncio. Foi exatamente o que aconteceu ao
// acrescentar as classes da segunda leva — o motor passou a comparar conta,
// porta, módulo e CA, e nenhum check lia nada disso. O relatório saía limpo
// sobre mudanças que a ferramenta tinha na mão.
func TestTodaFamiliaDeDriftEhLida(t *testing.T) {
	for _, tipo := range drift.Tipos() {
		m := facts.MudancaDrift{
			Tipo: tipo, Titulo: tipo, ID: "alvo-de-teste", Kind: "surgiu",
			Decide: true, Campos: []string{"x=1"},
		}
		var achados int
		for _, c := range check.All() {
			if !c.Drift {
				continue
			}
			r := c.Run(c, comDrift(m), testEnv())
			achados += len(r.Findings)
		}
		// O check de cobertura sempre emite um; o que se exige é MAIS que ele.
		if achados < 2 {
			t.Errorf("a família `%s` é comparada pelo motor e NENHUM check a lê: "+
				"a mudança seria computada e nunca reportada", tipo)
		}
	}
}
