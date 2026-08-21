package checks

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// A CATRACA das lacunas: toda chave que um coletor EMITE precisa ser lida por
// algum check.
//
// # O defeito que ela existe para impedir
//
// Um coletor que não consegue ler uma fonte declara a lacuna com
// `f.partial("mac", …)` ou `f.denyPersist("segredo", …)`. Quem transforma isso
// em cobertura degradada DAQUELE check é o próprio check, lendo a chave — e o
// motor (check/engine.go) faz `Coverage.Complete++` sempre que `res.Partial`
// sai vazio.
//
// Doze chaves eram emitidas e lidas por NINGUÉM: audit, credencial, helper,
// historico, interpretador, logs, mac, net, persist, proc, segredo e vigia.
// Consequência: com /etc/selinux/config ilegível, `antiforense.mac_downgraded`
// contava como COMPLETO; com /srv ilegível, `cred.secret_file` também. Dois
// deles ainda liam a chave do VIZINHO — cred.secret_file lia ["ssh"] enquanto o
// coletor gravava em ["segredo"].
//
// O veredito global ainda saía INCOMPLETE pelo CollectorGaps, então nada disso
// aparecia como bug óbvio. O que estava errado é a ATRIBUIÇÃO: o relatório
// dizia qual check não cobriu o que devia, e dizia errado.
//
// # Por que uma catraca, e não só o conserto
//
// É a mesma razão do TestImpressaoDoEsquema, escrita no comentário dele: regra
// que depende de alguém lembrar continua sendo esquecida. O conserto de hoje
// não impede a próxima chave nova de nascer órfã.
//
// # O que ela NÃO exige
//
// Não exige que a chave seja lida pelo check "certo" — isso nenhum teste sabe
// julgar. Exige que exista ALGUÉM lendo, que é o que separa "lacuna declarada"
// de "lacuna declarada e jogada fora".
func TestTodaLacunaEmitidaEhConsumidaPorAlgumCheck(t *testing.T) {
	emitidas := chavesEmitidas(t)
	consumidas := chavesConsumidas(t)

	if len(emitidas) == 0 || len(consumidas) == 0 {
		t.Fatalf("a varredura não achou chaves (emitidas=%d consumidas=%d): "+
			"o teste ficou cego, conserte o padrão antes de confiar nele",
			len(emitidas), len(consumidas))
	}

	var orfas []string
	for k := range emitidas {
		if !consumidas[k] {
			orfas = append(orfas, k)
		}
	}
	sort.Strings(orfas)
	if len(orfas) > 0 {
		t.Errorf("estas chaves de lacuna são EMITIDAS por um coletor e lidas por "+
			"check NENHUM: %s\n\n"+
			"O coletor declarou que não conseguiu ler a fonte, e nenhum check "+
			"degrada por isso — então o check sai COMPLETO sobre o que ninguém "+
			"olhou, que é a mentira central que esta ferramenta existe para não "+
			"contar.\n"+
			"Conserto: `r.Partial = append(r.Partial, f.Partial[\"<chave>\"]...)` "+
			"(ou f.PersistDenied) no check que depende daquela fonte, ANTES de "+
			"qualquer return antecipado.",
			strings.Join(orfas, ", "))
	}
}

// A direção INVERSA: um check que espera uma chave que ninguém emite fica
// esperando para sempre, e a lacuna que ele acha que declara nunca aparece.
// Costuma ser erro de digitação, ou a chave do vizinho.
func TestTodaChaveLidaPorCheckEhEmitidaPorAlgumColetor(t *testing.T) {
	emitidas := chavesEmitidas(t)
	consumidas := chavesConsumidas(t)

	var fantasmas []string
	for k := range consumidas {
		if !emitidas[k] {
			fantasmas = append(fantasmas, k)
		}
	}
	sort.Strings(fantasmas)
	if len(fantasmas) > 0 {
		t.Errorf("estes checks leem uma chave de lacuna que coletor NENHUM emite: %s\n\n"+
			"A leitura nunca traz nada, e o check parece degradar quando a fonte "+
			"falha — mas não degrada. Confira se não é a chave do coletor vizinho.",
			strings.Join(fantasmas, ", "))
	}
}

var (
	// Emissão literal, direta ou por helper que RECEBE a categoria.
	reEmiteLiteral = regexp.MustCompile(
		`(?:f\.partial|f\.partialSeguro|f\.denyPersist)\("([a-z_]+)"`)
	reEmitePorHelper = regexp.MustCompile(
		`(?:listarNegando|lerNegando)\(e, "([a-z_]+)"`)
	reEmitePorColetor = regexp.MustCompile(`rodarColetor\(f, "([a-z_]+)"`)

	reConsome = regexp.MustCompile(
		`f\.(?:Partial|PersistDenied)\["([a-z_]+)"\]`)
	// A forma em tabela: `for _, cat := range []string{"unit", "cron", …}`.
	reConsomeTabela = regexp.MustCompile(
		`(?s)range \[\]string\{([^}]*)\}\s*\{\s*r\.Partial = append\(r\.Partial, f\.(?:Partial|PersistDenied)\[cat\]`)
	reLiteral = regexp.MustCompile(`"([a-z_]+)"`)
)

func chavesEmitidas(t *testing.T) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, src := range fontesDoPacote(t, "../facts") {
		for _, re := range []*regexp.Regexp{reEmiteLiteral, reEmitePorHelper, reEmitePorColetor} {
			for _, m := range re.FindAllStringSubmatch(src, -1) {
				out[m[1]] = true
			}
		}
	}
	return out
}

func chavesConsumidas(t *testing.T) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, src := range fontesDoPacote(t, ".") {
		for _, m := range reConsome.FindAllStringSubmatch(src, -1) {
			out[m[1]] = true
		}
		for _, m := range reConsomeTabela.FindAllStringSubmatch(src, -1) {
			for _, l := range reLiteral.FindAllStringSubmatch(m[1], -1) {
				out[l[1]] = true
			}
		}
	}
	return out
}

// fontesDoPacote lê os .go NÃO-teste de um diretório. Ler o fonte é o que
// permite ver a EMISSÃO — ela acontece dentro de um coletor que só roda com
// host de verdade, e nenhuma fixture a exercitaria.
func fontesDoPacote(t *testing.T, dir string) []string {
	t.Helper()
	nomes, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatalf("glob em %s: %v", dir, err)
	}
	var out []string
	for _, n := range nomes {
		if strings.HasSuffix(n, "_test.go") {
			continue
		}
		b, err := os.ReadFile(n)
		if err != nil {
			t.Fatalf("ler %s: %v", n, err)
		}
		out = append(out, string(b))
	}
	return out
}
