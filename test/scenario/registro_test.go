package scenario_test

import (
	"sort"
	"testing"

	"github.com/lex0c/aletheia/internal/check"
	_ "github.com/lex0c/aletheia/internal/checks" // registra o catálogo
	"github.com/lex0c/aletheia/test/scenario"
)

// Este arquivo NÃO tem a tag `scenarios`, e é o ponto inteiro dele.
//
// A suíte de cenários precisa de docker e de qemu, e por isso fica fora da CI —
// decisão documentada no ci.yml e correta pelos motivos que ele dá. O efeito
// colateral é que TODO contrato escrito ali deixou de ter portão automático, e
// a suíte ficou vermelha por dezenas de commits sem ninguém ver.
//
// A parte do contrato que é só NOME DE CHECK não precisa de contêiner nenhum
// para ser conferida: é uma comparação entre dois registros que já estão em
// memória. Aqui ela roda no `go test ./...`, ou seja, na CI.
//
// # O que isto pega, e o que não pega
//
// Pega: rename, erro de digitação, e check novo que ninguém provou disparar. O
// caso mais silencioso dos três é um ID errado em `Forbid` — a proibição
// simplesmente nunca casa, e o cenário segue VERDE afirmando um silêncio que
// nunca foi verificado.
//
// NÃO pega divisão de check em que o ID antigo sobrevive, que foi exatamente o
// que aconteceu com o `U3-binfmt-com-interpretador-plantado`: o binfmt_misc
// saiu do `persist.kernel_helper` para o `kernel.binfmt_interpreter`, o ID
// antigo continuou existindo (ele ainda cobre modprobe e core_pattern) e o
// novo ganhou cenário próprio no mesmo commit. Os dois lados do ciclo fecham, e
// mesmo assim o U3 passou a cobrar de um check uma coisa que não é mais dele.
// Isso só a suíte que EXECUTA enxerga — o que este arquivo faz é reduzir o que
// depende dela, não substituí-la.
//
// Uma condição para tudo isto funcionar: o catálogo de cenários tem que compilar
// SEM a tag. Sete arquivos de cases_*.go tinham `//go:build scenarios` — em
// arquivo que só contém `Register(Scenario{…})`, dado puro, a tag não protegia
// nada e escondia sete checks deste teste.

// TestCenarioNaoCitaCheckInexistente pega rename, divisão e erro de digitação.
//
// Vale para as quatro formas de nomear um check num cenário. As três de recusa
// (Forbid, ForbidFinding, ForbidOutput por ID) são as mais perigosas: um ID
// errado ali não falha nada — a proibição simplesmente nunca casa, e o cenário
// segue verde afirmando um silêncio que ninguém verificou.
func TestCenarioNaoCitaCheckInexistente(t *testing.T) {
	existe := map[string]bool{}
	for _, c := range check.All() {
		existe[c.ID] = true
	}
	if len(existe) == 0 {
		t.Fatal("catálogo vazio: o import de internal/checks não registrou nada")
	}

	// Uma citação órfã por ID, com o cenário e o campo onde ela está — sem isso
	// a mensagem manda procurar num diretório de 39 arquivos.
	type citacao struct{ cenario, campo, id string }
	var orfas []citacao

	for _, s := range scenario.All() {
		ver := func(campo, id string) {
			if id != "" && !existe[id] {
				orfas = append(orfas, citacao{s.ID, campo, id})
			}
		}
		for _, e := range s.Expect {
			ver("Expect", e.ID)
		}
		for _, e := range s.ForbidFinding {
			ver("ForbidFinding", e.ID)
		}
		for _, id := range s.Forbid {
			ver("Forbid", id)
		}
		for _, id := range s.UntestableChecks {
			ver("UntestableChecks", id)
		}
	}

	sort.Slice(orfas, func(i, j int) bool {
		if orfas[i].cenario != orfas[j].cenario {
			return orfas[i].cenario < orfas[j].cenario
		}
		return orfas[i].id < orfas[j].id
	})
	for _, o := range orfas {
		t.Errorf("cenário %s: %s cita %q, que não é um check registrado — "+
			"o check foi renomeado, dividido ou nunca existiu",
			o.cenario, o.campo, o.id)
	}
}

// TestTodoCheckTemCenario fecha o ciclo pelo outro lado: do mesmo jeito que o
// Register recusa check sem FalsePositives, aqui se recusa check que ninguém
// provou disparar. Sem isto, dá para acrescentar um check e nunca demonstrar
// que ele funciona.
//
// Estava na suíte com tag, e não precisava: só compara dois registros. Aqui ele
// roda na CI, e um check novo sem cenário falha antes de o autor abrir o PR.
func TestTodoCheckTemCenario(t *testing.T) {
	coberto := scenario.CoveredCheckIDs()
	for _, c := range check.All() {
		if c.Mode == check.ModeManual {
			continue
		}
		if !coberto[c.ID] {
			t.Errorf("%s não aparece no Expect de nenhum cenário: ninguém demonstrou "+
				"que ele dispara contra um host real", c.ID)
		}
	}
}
