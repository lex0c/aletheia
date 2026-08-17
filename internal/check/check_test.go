package check

import (
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

func mustPanic(t *testing.T, want string, fn func()) {
	t.Helper()
	defer func() {
		r := recover()
		if r == nil {
			t.Fatalf("esperava panic contendo %q, não houve panic", want)
		}
		if msg, ok := r.(string); !ok || !strings.Contains(msg, want) {
			t.Fatalf("panic = %v, esperava conter %q", r, want)
		}
	}()
	fn()
}

// FalsePositives é obrigatório e a validação é no Register — ou seja, o binário
// nem sobe. É assim que a exigência deixa de ser boa intenção e vira estrutura
// (SPEC 5.2).
func TestRegisterExigeFalsePositives(t *testing.T) {
	mustPanic(t, "FalsePositives", func() {
		Register(Check{
			ID: "sem.fp", Ref: "1", Title: "t", Group: "g",
			Mode: ModeAuto, Sources: env.SourceLive,
			Run: func(Check, *facts.Facts, *env.Env) Result { return Result{} },
		})
	})
}

// Check manual não precisa declarar FP: ele não conclui nada sozinho.
func TestRegisterManualDispensaFalsePositives(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("check manual não deveria falhar no Register: %v", r)
		}
		delete(registry, "manual.ok")
	}()
	Register(Check{
		ID: "manual.ok", Ref: "37.2", Title: "t", Group: "cloud",
		Mode: ModeManual, Sources: env.SourceLive,
		Run: func(Check, *facts.Facts, *env.Env) Result { return Result{} },
	})
}

func TestRegisterExigeRefDoRunbook(t *testing.T) {
	mustPanic(t, "sem Ref", func() {
		Register(Check{
			ID: "sem.ref", Title: "t", Group: "g",
			Mode: ModeAuto, Sources: env.SourceLive,
			FalsePositives: []string{"nenhum"},
			Run:            func(Check, *facts.Facts, *env.Env) Result { return Result{} },
		})
	})
}

func TestRegisterRecusaDuplicado(t *testing.T) {
	c := Check{
		ID: "dup.teste", Ref: "1", Title: "t", Group: "g",
		Mode: ModeAuto, Sources: env.SourceLive,
		FalsePositives: []string{"nenhum"},
		Run:            func(Check, *facts.Facts, *env.Env) Result { return Result{} },
	}
	Register(c)
	defer delete(registry, "dup.teste")
	mustPanic(t, "duplicado", func() { Register(c) })
}

// O teste de invariantes do CATÁLOGO mora em internal/checks, não aqui.
// Aqui ele iterava um registry VAZIO: o pacote check não pode importar checks
// (ciclo de import), então All() devolvia 0 elementos e o corpo do laço nunca
// executava. Um teste verde que não testa nada é pior que teste nenhum — ele
// compra confiança.
func TestRegistryVazioNesteContexto(t *testing.T) {
	// Guarda contra alguém reintroduzir um teste de catálogo aqui achando que
	// ele cobre os checks reais.
	if len(All()) > 0 {
		t.Log("registry não vazio: outro teste registrou checks; invariantes de catálogo ficam em internal/checks")
	}
}

func TestSelectPorGrupoEModo(t *testing.T) {
	base := func(id, group string, mode Mode) Check {
		return Check{
			ID: id, Ref: "1", Title: "t", Group: group,
			Mode: mode, Sources: env.SourceLive,
			FalsePositives: []string{"nenhum"},
			Run:            func(Check, *facts.Facts, *env.Env) Result { return Result{} },
		}
	}
	saved := registry
	registry = map[string]Check{}
	defer func() { registry = saved }()

	Register(base("proc.a", "proc", ModeAuto))
	Register(base("net.b", "net", ModeAuto))
	Register(base("cloud.c", "cloud", ModeManual))
	Register(func() Check { c := base("proc.d", "proc", ModeAuto); c.Wtf = true; return c }())

	if got := len(Select(Selection{})); got != 4 {
		t.Errorf("sem filtro = %d, quer 4", got)
	}
	if got := len(Select(Selection{Groups: []string{"proc"}})); got != 2 {
		t.Errorf("--only proc = %d, quer 2", got)
	}
	if got := len(Select(Selection{Mode: "manual"})); got != 1 {
		t.Errorf("--mode manual = %d, quer 1", got)
	}
	if got := len(Select(Selection{Mode: "auto"})); got != 3 {
		t.Errorf("--mode auto = %d, quer 3", got)
	}
	// wtf e --only são EIXOS diferentes: o wtf é um recorte de orçamento,
	// não um subsistema.
	if got := len(Select(Selection{Wtf: true})); got != 1 {
		t.Errorf("wtf = %d, quer 1", got)
	}
}

func TestOriginIsTool(t *testing.T) {
	if OriginNative.IsTool() {
		t.Error("native não é tool")
	}
	if !ToolOrigin("dpkg").IsTool() {
		t.Error("tool:dpkg é tool")
	}
	if got := string(ToolOrigin("rpm")); got != "tool:rpm" {
		t.Errorf("ToolOrigin = %q", got)
	}
}

// F copia FalsePositives do check para o achado: o operador precisa saber o que
// descartar junto do achado, não num catálogo separado.
func TestFindingHerdaFalsePositives(t *testing.T) {
	c := Check{
		ID: "x.y", Ref: "3.8", Title: "titulo do check",
		FalsePositives: []string{"socket activation"},
	}
	f := c.F(SevCritical, "pid=1", "")
	if f.Title != "titulo do check" {
		t.Errorf("título vazio deve herdar o do check, veio %q", f.Title)
	}
	if len(f.FalsePositives) != 1 || f.FalsePositives[0] != "socket activation" {
		t.Errorf("FalsePositives não herdado: %v", f.FalsePositives)
	}
	if f.Origin != OriginNative {
		t.Errorf("Origin padrão = %q, quer native", f.Origin)
	}
}
