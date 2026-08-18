package check

import (
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

// Depois que o kernel demonstra entregar visões INCONSISTENTES de si mesmo, a
// ausência de achado deixa de ser resposta.
//
// É a tese da ferramenta um nível acima. A cobertura já separa "não achei" de
// "não consegui olhar"; falta o terceiro estado, que só existe quando a
// AUTORIDADE foi desqualificada: olhei, ela respondeu, e a resposta não vale.
func TestKernelInconsistenteInvalidaAsAusencias(t *testing.T) {
	// Um check que acha a contradição, e dois que não acham nada.
	achaContradicao := Check{
		ID: "cross.hidden_pid", Ref: "35", Title: "pid oculto", Group: "cross",
		Mode: ModeAuto, Sources: env.SourceLive, Requires: env.CapProcfs,
		FalsePositives: []string{"corrida de criação de processo"},
		Run: func(c Check, f *facts.Facts, e *env.Env) Result {
			return Result{Findings: []Finding{c.F(SevCritical, "pid=4242", "", "existe e não lista")}}
		},
	}
	calado := func(id string) Check {
		return Check{
			ID: id, Ref: "3", Title: "silencioso", Group: "proc",
			Mode: ModeAuto, Sources: env.SourceLive, Requires: env.CapProcfs,
			FalsePositives: []string{"x"},
			Run:            func(Check, *facts.Facts, *env.Env) Result { return Result{} },
		}
	}

	f := &facts.Facts{}
	f.Index()
	r := Run([]Check{achaContradicao, calado("proc.a"), calado("proc.b")}, f, liveEnv(env.CapProcfs|env.CapFilesystem))

	if len(r.KernelTrustBroken) == 0 {
		t.Fatal("cross.hidden_pid CRÍTICO precisa marcar o kernel como contraditório")
	}
	// Os dois calados saem de "completo" e entram em parcial.
	if r.Coverage.Complete != 1 {
		t.Errorf("completos = %d, queria 1 — só o que ACHOU continua completo",
			r.Coverage.Complete)
	}
	var invalidados int
	for _, p := range r.Coverage.Partial {
		for _, m := range p.Reasons {
			if strings.Contains(m, "não vale como resposta") {
				invalidados++
			}
		}
	}
	if invalidados != 2 {
		t.Errorf("ausências invalidadas = %d, queria 2: %+v", invalidados, r.Coverage.Partial)
	}
	// E o achado positivo continua valendo — vale mais, aliás.
	if len(r.Findings) != 1 || r.Findings[0].Sev != SevCritical {
		t.Errorf("o achado que provou a contradição não pode ser rebaixado: %+v", r.Findings)
	}
}

// Sem contradição não há invalidação: um host silencioso continua com
// cobertura completa, e transformar todo scan limpo em "indeterminado" mataria
// o sinal que a ferramenta existe para dar.
func TestSemContradicaoACoberturaSegueCompleta(t *testing.T) {
	calado := Check{
		ID: "proc.a", Ref: "3", Title: "silencioso", Group: "proc",
		Mode: ModeAuto, Sources: env.SourceLive, Requires: env.CapProcfs,
		FalsePositives: []string{"x"},
		Run:            func(Check, *facts.Facts, *env.Env) Result { return Result{} },
	}
	f := &facts.Facts{}
	f.Index()
	r := Run([]Check{calado}, f, liveEnv(env.CapProcfs|env.CapFilesystem))
	if len(r.KernelTrustBroken) != 0 || r.Coverage.Complete != 1 {
		t.Errorf("host quieto: trust=%v completos=%d", r.KernelTrustBroken, r.Coverage.Complete)
	}
}

// Em modo IMAGEM o kernel é o do ANALISTA: uma contradição registrada no dump
// não desqualifica a leitura que ele mesmo fez. Invalidar ali seria punir a
// única fonte confiável que existe.
func TestModoImagemNaoTemAusenciaInvalidada(t *testing.T) {
	acha := Check{
		ID: "cross.hidden_pid", Ref: "35", Title: "pid oculto", Group: "cross",
		Mode: ModeAuto, Sources: env.SourceLive | env.SourceImage, Requires: env.CapFilesystem,
		FalsePositives: []string{"x"},
		Run: func(c Check, f *facts.Facts, e *env.Env) Result {
			return Result{Findings: []Finding{c.F(SevCritical, "pid=1", "", "x")}}
		},
	}
	f := &facts.Facts{}
	f.Index()
	e := liveEnv(env.CapProcfs | env.CapFilesystem)
	e.Source = env.SourceImage
	if r := Run([]Check{acha}, f, e); len(r.KernelTrustBroken) != 0 {
		t.Errorf("em imagem o kernel é o do analista: %v", r.KernelTrustBroken)
	}
}
