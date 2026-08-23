package info

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/facts"
)

func fatosComCiclo() *facts.Facts {
	f := &facts.Facts{Processes: []facts.Process{
		{PID: 1, PPID: 0, Comm: "init"},
		// Um ciclo: 10 diz que o pai é 11, e 11 diz que o pai é 10.
		{PID: 10, PPID: 11, Comm: "oculto-a"},
		{PID: 11, PPID: 10, Comm: "oculto-b"},
		// E um auto-pai.
		{PID: 42, PPID: 42, Comm: "auto-pai"},
	}}
	f.Index()
	return f
}

// UM CICLO DE PPID NÃO PODE ESCONDER PROCESSO.
//
// A raiz era "quem não tem pai visível". Num ciclo os dois têm pai visível,
// então nenhum era raiz — e nenhum era alcançado a partir de raiz nenhuma. Os
// dois sumiam da árvore, com truncated:false e sinal nenhum.
//
// Apontar o próprio PPid para um filho era um jeito grátis de desaparecer da
// única ferramenta feita para expor linhagem.
func TestCicloDePaiNaoEscondeProcesso(t *testing.T) {
	a := Arvore(fatosComCiclo(), 0, 4)
	b, _ := json.Marshal(a)

	for _, pid := range []string{`"pid":10`, `"pid":11`, `"pid":42`} {
		if !strings.Contains(string(b), pid) {
			t.Errorf("%s sumiu da árvore: %s", pid, b)
		}
	}
	if len(a.Sinais) == 0 {
		t.Fatal("o órfão precisa ser DITO: uma cadeia de pais cíclica não é " +
			"estado normal de /proc, e some numa árvore ingênua")
	}
	if !strings.Contains(strings.Join(a.Sinais, " "), "NENHUMA") {
		t.Fatalf("o sinal precisa dizer o que houve: %v", a.Sinais)
	}
}

// E a descida PARA no ciclo, em vez de fabricar gerações.
//
// A guarda anterior só recusava a autorreferência direta (A→A), e deixava
// passar A→B→A: com depth 6 a resposta trazia seis níveis alternando os mesmos
// dois processos — uma linhagem que não existe, indistinguível de uma real.
func TestDescidaParaNoCicloEmVezDeFabricarGeracoes(t *testing.T) {
	a := Arvore(fatosComCiclo(), 10, 6)
	b, _ := json.Marshal(a)

	if !strings.Contains(string(b), `"cycle":true`) {
		t.Fatalf("a parada precisa ser marcada: %s", b)
	}
	// Três nós no caminho (10, 11, e o 10 que fecha o ciclo) e nada além.
	if n := strings.Count(string(b), `"pid":10`); n > 2 {
		t.Fatalf("o ciclo fabricou %d aparições do pid 10: %s", n, b)
	}
}

// A TRUNCAGEM POR PROFUNDIDADE também é truncagem.
//
// Truncado saía só do orçamento de nós, e o corte comum é o outro: profPadrao é
// 4. Uma árvore de systemd com sete níveis voltava com truncated:false e
// dezenas de nós carregando children_omitted>0 — e um modelo que confere a
// bandeira antes de concluir "não há descendente que case com X" era informado
// de que a visão estava completa.
func TestTruncagemPorProfundidadeEhDeclarada(t *testing.T) {
	f := &facts.Facts{Processes: []facts.Process{
		{PID: 1, PPID: 0, Comm: "a"}, {PID: 2, PPID: 1, Comm: "b"},
		{PID: 3, PPID: 2, Comm: "c"}, {PID: 4, PPID: 3, Comm: "d"},
		{PID: 5, PPID: 4, Comm: "e"}, {PID: 6, PPID: 5, Comm: "f"},
	}}
	f.Index()

	a := Arvore(f, 1, 2)
	if !a.Truncado {
		t.Fatal("a árvore foi cortada na profundidade e disse que não")
	}
	if !strings.Contains(strings.Join(a.Sinais, " "), "profundidade") {
		t.Fatalf("o corte precisa dizer ONDE caiu: %v", a.Sinais)
	}

	// E a árvore que cabe inteira NÃO se diz truncada.
	if b := Arvore(f, 1, 8); b.Truncado {
		t.Fatalf("árvore completa marcada como truncada: %v", b.Sinais)
	}
}

// Um retrato são não ganha sinal nenhum: o ruído de um caso que não existe
// treina quem lê a ignorar o caso que existe.
func TestArvoreSaNaoEmiteSinal(t *testing.T) {
	f := &facts.Facts{Processes: []facts.Process{
		{PID: 1, PPID: 0, Comm: "init"},
		{PID: 2, PPID: 1, Comm: "filho"},
	}}
	f.Index()
	a := Arvore(f, 0, 4)
	if len(a.Sinais) != 0 || a.Truncado {
		t.Fatalf("host são: sinais=%v truncado=%v", a.Sinais, a.Truncado)
	}
}
