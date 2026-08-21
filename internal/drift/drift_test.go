package drift

import (
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

func unit(nome, exec string) facts.Unit {
	return facts.Unit{
		Name: nome, Path: "/etc/systemd/system/" + nome, Kind: "service",
		Exec: []facts.ExecLine{{Key: "ExecStart", Cmd: exec}},
	}
}

func lado(f *facts.Facts, caps env.Cap) Lado {
	return Lado{F: f, Caps: caps, Host: "h", Quando: "2026-01-01T00:00:00Z"}
}

const tudoVisivel = env.CapFilesystem | env.CapRoot

// A COMPARAÇÃO É POR DIREÇÃO, e o que a invalida é a ASSIMETRIA — não a
// limitação.
//
// A primeira versão era binária: os dois lados viram tudo, ou a família não é
// comparada. Contra um host real sem root isso recusou três das quatro
// famílias, por lacunas do tamanho de "6 diretórios de unit de usuário
// ilegíveis". Honesto e inútil, e inútil vira desligado.
func TestDirecaoSuprimidaPorAssimetria(t *testing.T) {
	casos := []struct {
		nome                  string
		capsAntes, capsDepois env.Cap
		lacunaAntes           bool
		lacunaDepois          bool
		semSurgiu, semSumiu   bool
		simetrico             bool
	}{
		{nome: "os dois viram tudo",
			capsAntes: tudoVisivel, capsDepois: tudoVisivel,
			simetrico: true},
		{nome: "os dois sem root: escopo, não defeito",
			capsAntes: env.CapFilesystem, capsDepois: env.CapFilesystem,
			semSurgiu: true, semSumiu: true, simetrico: true},
		{nome: "só o ANTES sem root: o que parece NOVO pode ser o que ele não viu",
			capsAntes: env.CapFilesystem, capsDepois: tudoVisivel,
			semSurgiu: true, simetrico: false},
		{nome: "só o DEPOIS sem root: o que parece REMOVIDO pode continuar lá",
			capsAntes: tudoVisivel, capsDepois: env.CapFilesystem,
			semSumiu: true, simetrico: false},
		{nome: "lacuna nos dois: escopo",
			capsAntes: tudoVisivel, capsDepois: tudoVisivel,
			lacunaAntes: true, lacunaDepois: true,
			semSurgiu: true, semSumiu: true, simetrico: true},
		{nome: "lacuna só no ANTES",
			capsAntes: tudoVisivel, capsDepois: tudoVisivel,
			lacunaAntes: true,
			semSurgiu:   true, simetrico: false},
		{nome: "lacuna só no DEPOIS",
			capsAntes: tudoVisivel, capsDepois: tudoVisivel,
			lacunaDepois: true,
			semSumiu:     true, simetrico: false},
	}
	classe := Classe{
		Tipo: "t", Titulo: "t", Requires: tudoVisivel, Lacunas: []string{"unit"},
	}
	for _, c := range casos {
		fa, fd := &facts.Facts{}, &facts.Facts{}
		if c.lacunaAntes {
			fa.Partial = map[string][]string{"unit": {"algo"}}
		}
		if c.lacunaDepois {
			fd.Partial = map[string][]string{"unit": {"algo"}}
		}
		got := comparabilidadeDe(classe, lado(fa, c.capsAntes), lado(fd, c.capsDepois))
		if got.SemSurgiu != c.semSurgiu || got.SemSumiu != c.semSumiu || got.Simetrico != c.simetrico {
			t.Errorf("%s:\n  surgiu=%v sumiu=%v simetrico=%v\n  queria  surgiu=%v sumiu=%v simetrico=%v",
				c.nome, got.SemSurgiu, got.SemSumiu, got.Simetrico,
				c.semSurgiu, c.semSumiu, c.simetrico)
		}
		if got.Restrita() && len(got.Motivos) == 0 {
			t.Errorf("%s: direção suprimida sem motivo dito — o operador não tem "+
				"como saber por que o silêncio não é resposta", c.nome)
		}
	}
}

// "MUDOU" SOBREVIVE A TODAS AS RESTRIÇÕES, e é o que torna a leitura por
// direção útil em vez de só honesta: ele exige a entidade presente nos DOIS
// lados, então nenhum dos dois pode ter deixado de olhá-la.
func TestMudouSobreviveASupressaoDeDirecao(t *testing.T) {
	antes := &facts.Facts{
		Units:   []facts.Unit{unit("a.service", "/usr/bin/env sleep 30")},
		Partial: map[string][]string{"unit": {"parcial dos dois lados"}},
	}
	depois := &facts.Facts{
		Units:   []facts.Unit{unit("a.service", "/usr/bin/env tail -f /dev/null")},
		Partial: map[string][]string{"unit": {"parcial dos dois lados"}},
	}
	d := Comparar(lado(antes, tudoVisivel), lado(depois, tudoVisivel))
	var achou bool
	for _, m := range d.Mudancas {
		if m.Tipo == "systemd.unit" && m.Kind == Mudou && m.Campo == "exec" {
			achou = true
			if !strings.Contains(m.Antes, "sleep 30") || !strings.Contains(m.Depois, "tail") {
				t.Errorf("o par antes/depois é o achado: %+v", m)
			}
		}
	}
	if !achou {
		t.Fatalf("mudança de ExecStart precisa sobreviver à lacuna simétrica: %+v", d.Mudancas)
	}
}

// E o outro lado da mesma regra: com a direção suprimida, "surgiu" e "sumiu"
// NÃO viram achado — viram declaração na cobertura.
func TestSurgiuESumiuCalamQuandoADirecaoNaoEhConfiavel(t *testing.T) {
	antes := &facts.Facts{Units: []facts.Unit{unit("velha.service", "/bin/true")}}
	depois := &facts.Facts{Units: []facts.Unit{unit("nova.service", "/bin/true")}}
	// A capacidade de que a família depende falta nos DOIS: as duas direções
	// caem, e o que sobraria seria "mudou" — que aqui não existe, porque as
	// entidades são outras.
	d := Comparar(lado(antes, 0), lado(depois, 0))
	for _, m := range d.Mudancas {
		if m.Kind == Surgiu || m.Kind == Sumiu {
			t.Errorf("direção suprimida não pode virar achado: %+v", m)
		}
	}
	var visto bool
	for _, c := range d.Cobertura {
		if c.Tipo == "systemd.unit" {
			visto = true
			if !c.Restrita() {
				t.Error("a cobertura precisa DIZER que a direção caiu")
			}
		}
	}
	if !visto {
		t.Fatal("toda família entra na cobertura da comparação, comparada ou não")
	}
}

// A MESMA NORMALIZAÇÃO NOS DOIS LADOS.
//
// O dump é redigido ao ser escrito; o host vivo não é. Sem normalizar os dois,
// `ExecStartPre=-plymouth --wait quit` vira `-p<redacted>` de um lado só, e
// NOVE units deste desktop "mudaram" sem nada ter mudado. Foi assim que o
// defeito apareceu — e é assim que ele volta se alguém tirar a redação daqui.
func TestRedacaoNaoInventaMudanca(t *testing.T) {
	vivo := &facts.Facts{Units: []facts.Unit{unit("p.service", "-plymouth --wait quit")}}
	// O que o dump.go grava depois de passar pelo redator.
	doDump := &facts.Facts{Units: []facts.Unit{unit("p.service", "-p<redacted> --wait quit")}}
	d := Comparar(lado(doDump, tudoVisivel), lado(vivo, tudoVisivel))
	for _, m := range d.Mudancas {
		if m.Campo == "exec" {
			t.Errorf("a redação de um lado só inventou drift: %+v", m)
		}
	}
}

// Campo que NÃO decide não vira achado — vira número. Um relatório que imprime
// todo mtime de toda atualização de pacote é um que ninguém lê depois da
// terceira execução; um que os corta em silêncio se lê como "cobri tudo".
func TestCampoQueNaoDecideEhContadoENaoImpresso(t *testing.T) {
	a := unit("a.service", "/bin/true")
	a.ModUTC = "2026-01-01T00:00:00Z"
	b := unit("a.service", "/bin/true")
	b.ModUTC = "2026-06-06T00:00:00Z"

	d := Comparar(
		lado(&facts.Facts{Units: []facts.Unit{a}}, tudoVisivel),
		lado(&facts.Facts{Units: []facts.Unit{b}}, tudoVisivel))
	if len(d.Mudancas) != 0 {
		t.Errorf("mtime não é campo de decisão: %+v", d.Mudancas)
	}
	if d.Contadas != 1 {
		t.Errorf("mas o número precisa sair: Contadas=%d", d.Contadas)
	}
}

// Identidade repetida não pode depender da ORDEM da coleta: duas entidades de
// mesmo ID precisam produzir o mesmo valor nos dois lados, senão a mesma
// máquina dá drift contra si mesma.
func TestIdentidadeRepetidaEhEstavel(t *testing.T) {
	c := Classe{Tipo: "t", Extrair: func(f *facts.Facts) []Entidade {
		return []Entidade{
			{ID: "x", Campos: map[string]string{"c": "a"}},
			{ID: "x", Campos: map[string]string{"c": "b"}},
		}
	}}
	invertida := Classe{Tipo: "t", Extrair: func(f *facts.Facts) []Entidade {
		return []Entidade{
			{ID: "x", Campos: map[string]string{"c": "b"}},
			{ID: "x", Campos: map[string]string{"c": "a"}},
		}
	}}
	ia, _ := indexar(c, &facts.Facts{})
	ib, _ := indexar(invertida, &facts.Facts{})
	um, outro := ia["x"].Campos["c"], ib["x"].Campos["c"]
	if um != outro {
		t.Errorf("a ordem da coleta decidiu o valor: %q vs %q", um, outro)
	}
}

// Toda classe registrada precisa declarar de que capacidade depende. Sem isso a
// comparabilidade dela é sempre "tudo certo", e a família passa a ser comparada
// entre retratos de alcance diferente sem ninguém saber.
func TestTodaClasseDeclaraDoQueDepende(t *testing.T) {
	for _, c := range classes {
		if c.Requires == 0 {
			t.Errorf("%s: não declara Requires — a comparação dela nunca seria "+
				"recusada por assimetria de alcance", c.Tipo)
		}
		if c.Extrair == nil || c.Titulo == "" || c.Tipo == "" {
			t.Errorf("%s: classe incompleta", c.Tipo)
		}
		if len(c.Decide) == 0 {
			t.Errorf("%s: nenhum campo decide — a família inteira viraria contagem", c.Tipo)
		}
	}
}

// TODO CAMPO QUE DECIDE PRECISA SER EXTRAÍDO — e este teste existe porque a
// conferência à mão pegou um que não era.
//
// `binds` estava declarado no Decide da unit e o extrator nunca o emitia: uma
// mudança em `BindPaths=` não produzia drift NEM lacuna. Silêncio limpo, que é
// o pior modo de falha desta base, e invisível para qualquer teste que só
// olhasse o que a ferramenta acha.
func TestTodoCampoQueDecideEhExtraido(t *testing.T) {
	// Fatos com uma entidade de cada família, para que os extratores emitam
	// algo. O conteúdo não importa: o que se mede é o CONJUNTO DE CHAVES.
	f := &facts.Facts{
		Units: []facts.Unit{{Name: "u.service", Path: "/etc/systemd/system/u.service"}},
		Cron:  []facts.CronEntry{{File: "/etc/cron.d/x", Kind: "dropin", Cmd: "/bin/true"}},
		Sudoers: []facts.SudoRule{{File: "/etc/sudoers", Line: 1,
			Text: "root ALL=(ALL) ALL"}},
		SSHKeys: []facts.SSHKey{{User: "root", File: "/root/.ssh/authorized_keys",
			Type: "ssh-ed25519", Fingerprint: "SHA256:x"}},
	}
	for _, c := range classes {
		ents := c.Extrair(f)
		if len(ents) == 0 {
			t.Errorf("%s: o fixture não produziu entidade — o teste deixaria de "+
				"conferir esta família em silêncio", c.Tipo)
			continue
		}
		for campo := range c.Decide {
			if _, ok := ents[0].Campos[campo]; !ok {
				t.Errorf("%s: `%s` decide a severidade e NÃO é extraído — mudança "+
					"nele não produziria drift nem lacuna", c.Tipo, campo)
			}
		}
	}
}

// A UNIÃO das chaves: uma chave que existia no ANTES e some no DEPOIS é uma
// mudança, e o laço que itera só o DEPOIS nunca a visita.
func TestChaveRemovidaEhComparada(t *testing.T) {
	c := Classe{
		Tipo: "t", Titulo: "t", Requires: env.CapFilesystem,
		Decide: map[string]bool{"some": true},
	}
	ea := Entidade{ID: "x", Campos: map[string]string{"some": "valia"}}
	eb := Entidade{ID: "x", Campos: map[string]string{}}
	var d facts.Drift
	compararClasse(c, facts.CoberturaDrift{Simetrico: true},
		map[string]Entidade{"x": ea}, map[string]Entidade{"x": eb}, &d)
	if len(d.Mudancas) != 1 || d.Mudancas[0].Depois != "" || d.Mudancas[0].Antes != "valia" {
		t.Fatalf("a chave que sumiu do lado de depois precisa ser comparada: %+v", d.Mudancas)
	}
}

// Entidade sem identidade estável não é comparada — e isso SAI DITO. Descartar
// em silêncio esconderia justamente a linha malformada, que é onde uma inserção
// estranha se esconde.
func TestEntidadeSemIdentidadeSaiNaCobertura(t *testing.T) {
	original := classes
	defer func() { classes = original }()
	classes = []Classe{{
		Tipo: "t", Titulo: "t", Requires: env.CapFilesystem,
		Decide: map[string]bool{"c": true},
		Extrair: func(*facts.Facts) []Entidade {
			return []Entidade{{ID: "", Campos: map[string]string{"c": "x"}}}
		},
	}}
	d := Comparar(lado(&facts.Facts{}, tudoVisivel), lado(&facts.Facts{}, tudoVisivel))
	if len(d.Cobertura) != 1 {
		t.Fatalf("%+v", d.Cobertura)
	}
	if !strings.Contains(strings.Join(d.Cobertura[0].Motivos, " "), "sem identidade estável") {
		t.Errorf("a entidade descartada precisa sair dita: %+v", d.Cobertura[0].Motivos)
	}
}
