package check

import (
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

// A mecânica que decide COBERTURA e SELEÇÃO não tinha teste próprio — a
// mutação encontrou seis pontos aqui onde estragar a decisão não incomodava
// ninguém. É a metade do contrato que a ferramenta não pode errar: "não
// encontrei" e "não consegui olhar" saem por este caminho.

// registroDeTeste isola o registro global, que é compartilhado entre testes.
func registroDeTeste(t *testing.T, gs ...string) {
	t.Helper()
	saved := registry
	registry = map[string]Check{}
	t.Cleanup(func() { registry = saved })
	for i, g := range gs {
		Register(Check{
			ID: g + "." + string(rune('a'+i)), Ref: "1", Group: g,
			Title: "t", Mode: ModeAuto, Sources: env.SourceLive,
			FalsePositives: []string{"nenhum: check de teste"},
			Run:            func(Check, *facts.Facts, *env.Env) Result { return Result{} },
		})
	}
}

// UnknownGroups é o que recusa `--group` inventado. Invertida, a ferramenta
// aceitaria um grupo inexistente, rodaria zero check e diria OK — que é o modo
// de falha mais caro que existe aqui.
func TestUnknownGroups(t *testing.T) {
	registroDeTeste(t, "proc", "net")
	if got := UnknownGroups([]string{"proc", "net"}); len(got) != 0 {
		t.Errorf("grupo que existe não pode ser recusado: %v", got)
	}
	got := UnknownGroups([]string{"proc", "nao-existe"})
	if len(got) != 1 || got[0] != "nao-existe" {
		t.Errorf("queria só o inventado, deu %v", got)
	}
}

// Groups não pode repetir: há dezenas de checks por grupo, e a lista vai para a
// mensagem de erro que o operador lê para se corrigir.
func TestGroupsSemRepetir(t *testing.T) {
	registroDeTeste(t, "proc", "proc", "net")
	if got := Groups(); len(got) != 2 {
		t.Errorf("dois grupos distintos em três checks, deu %v", got)
	}
}

func TestContains(t *testing.T) {
	if !contains([]string{"a", "b"}, "b") {
		t.Error("não achou o que está lá")
	}
	if contains([]string{"a", "b"}, "c") {
		t.Error("achou o que não está")
	}
	if contains(nil, "a") {
		t.Error("lista vazia não contém nada")
	}
}

// Refs carrega, na linha do `wtf`, quais seções do runbook um alvo envolve.
// Com a correlação por ator ela ficou mais carregada ainda: é o que resta
// quando o resumo dos títulos é cortado para caber na tela.
func TestRefsDeduplicaEPreservaOrdem(t *testing.T) {
	g := SubjectGroup{Findings: []Finding{
		{Ref: "24"}, {Ref: "4.3"}, {Ref: "24"}, {Ref: ""}, {Ref: "7.2"},
	}}
	got := strings.Join(g.Refs(), " ")
	if got != "24 4.3 7.2" {
		t.Errorf("queria \"24 4.3 7.2\", deu %q", got)
	}
}

// Origin e FalsePositives são preenchidos pelo MOTOR quando o check não os
// informa. O primeiro decide se o achado é rebaixado quando a confiança no
// userland cai; o segundo é o que o operador lê ANTES de investigar.
func TestMotorPreencheOrigemEFalsosPositivos(t *testing.T) {
	c := Check{
		ID: "t.x", Ref: "1", Group: "proc",
		Mode: ModeAuto, Sources: env.SourceLive,
		FalsePositives: []string{"o motivo de sempre"},
		Run: func(self Check, f *facts.Facts, e *env.Env) Result {
			return Result{Findings: []Finding{
				{ID: "t.x", Sev: SevWarn, Subject: "a"},
				// este já traz os seus, e o motor não pode sobrescrever
				{ID: "t.x", Sev: SevWarn, Subject: "b", Origin: ToolOrigin("ss"),
					FalsePositives: []string{"os meus"}},
			}}
		},
	}
	r := Run([]Check{c}, &facts.Facts{}, &env.Env{Source: env.SourceLive})
	if len(r.Findings) != 2 {
		t.Fatalf("esperava 2 achados, deu %d", len(r.Findings))
	}
	var a, b *Finding
	for i := range r.Findings {
		switch r.Findings[i].Subject {
		case "a":
			a = &r.Findings[i]
		case "b":
			b = &r.Findings[i]
		}
	}
	if a.Origin != OriginNative {
		t.Errorf("origem vazia tem que virar nativa, deu %q", a.Origin)
	}
	if len(a.FalsePositives) != 1 || a.FalsePositives[0] != "o motivo de sempre" {
		t.Errorf("o achado sem falsos positivos herda os do check, deu %v", a.FalsePositives)
	}
	if b.Origin != ToolOrigin("ss") {
		t.Errorf("o motor não pode sobrescrever origem já informada, deu %q", b.Origin)
	}
	if len(b.FalsePositives) != 1 || b.FalsePositives[0] != "os meus" {
		t.Errorf("nem os falsos positivos próprios, deu %v", b.FalsePositives)
	}
}
