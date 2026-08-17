package report

import (
	"bytes"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

func wtfEnv() *env.Env {
	return &env.Env{
		Source: env.SourceLive, Clock: env.ClockSynced,
		Now: time.Date(2026, 4, 30, 21, 44, 3, 0, time.UTC),
	}
}

func renderWtf(r *check.Report, f *facts.Facts) string {
	var b bytes.Buffer
	if f == nil {
		f = &facts.Facts{}
	}
	Wtf(&b, r, f, wtfEnv(), 57*time.Millisecond)
	return b.String()
}

// O rodapé é obrigatório e é a razão de o comando poder existir: `wtf` é o
// comando com maior risco de ser lido como "host limpo".
func TestWtfNuncaPodeSerLidoComoVarredura(t *testing.T) {
	casos := map[string]*check.Report{
		"sem achado": {Coverage: check.Coverage{Total: 10, Complete: 10}},
		"com achado": {
			Findings: []check.Finding{{ID: "x.y", Sev: check.SevCritical, Subject: "pid=1", Title: "t"}},
			Coverage: check.Coverage{Total: 10, Complete: 10},
		},
	}
	for nome, r := range casos {
		out := renderWtf(r, nil)
		if !strings.Contains(out, "NÃO é varredura") {
			t.Errorf("%s: o rodapé precisa dizer que isto não foi varredura:\n%s", nome, out)
		}
	}
	// Sem achado, o texto precisa dizer o contrário do que a tela sugere.
	out := renderWtf(casos["sem achado"], nil)
	if !strings.Contains(out, "NÃO significa host limpo") {
		t.Errorf("execução limpa precisa negar explicitamente 'host limpo':\n%s", out)
	}
}

// O wtf decide POR ONDE COMEÇAR. Detalhar o aviso rouba a tela do que precisa
// de ação agora — e o passo irreversível é o único que não pode esperar.
func TestWtfDetalhaCriticoENaoAviso(t *testing.T) {
	r := &check.Report{
		Findings: []check.Finding{
			{ID: "correlate.revshell", Sev: check.SevCritical, Subject: "pid=6574",
				Title: "reverse shell", Ref: "17", Irreversible: true,
				Evidence:  []string{"fd 0,1,2 → socket:[889]", "peer=51.91.190.241:443", "terceira linha"},
				NextSteps: []string{"NÃO mate antes de preservar", "sudo cp /proc/6574/exe x"}},
			{ID: "net.pivot", Sev: check.SevWarn, Subject: "pid=3311",
				Title: "pivô", Ref: "12.2", Evidence: []string{"evidência de aviso"}},
		},
		Coverage: check.Coverage{Total: 10, Complete: 10},
	}
	out := renderWtf(r, nil)

	for _, want := range []string{"socket:[889]", "peer=51.91.190.241:443", "sudo cp /proc/6574/exe"} {
		if !strings.Contains(out, want) {
			t.Errorf("faltou %q na saída:\n%s", want, out)
		}
	}
	if strings.Contains(out, "terceira linha") {
		t.Error("evidência de crítico é cortada em 2 linhas: a tela é o orçamento")
	}
	if strings.Contains(out, "evidência de aviso") {
		t.Error("aviso não ganha evidência no wtf — só o crítico")
	}
	if !strings.Contains(out, "pid=3311") {
		t.Error("mas o aviso precisa APARECER")
	}
}

func TestWtfCortaComContagemVisivel(t *testing.T) {
	r := &check.Report{Coverage: check.Coverage{Total: 10, Complete: 10}}
	for i := 0; i < maxWtfLinhas+5; i++ {
		r.Findings = append(r.Findings, check.Finding{
			ID: "x.y", Sev: check.SevWarn, Subject: "pid=" + strconv.Itoa(i), Title: "t"})
	}
	out := renderWtf(r, nil)
	if !strings.Contains(out, "e mais 5 achados") {
		t.Errorf("corte silencioso: a tela precisa dizer quanto ficou de fora:\n%s", out)
	}
}

func TestWtfContagensSaemDaMesmaColeta(t *testing.T) {
	f := &facts.Facts{
		Processes: make([]facts.Process, 3),
		Sockets: []facts.Socket{
			{State: "ESTAB", LocalIP: "10.0.0.5"},
			{State: "ESTAB", LocalIP: "10.0.0.5"},
			{State: "LISTEN", LocalIP: "0.0.0.0"},
			{State: "LISTEN", LocalIP: "127.0.0.1"}, // loopback não conta
		},
	}
	out := renderWtf(&check.Report{Coverage: check.Coverage{Total: 1, Complete: 1}}, f)
	if !strings.Contains(out, "3 proc · 2 estab · 1 listen fora de loopback") {
		t.Errorf("o enquadramento saiu errado:\n%s", out)
	}
}

func TestWtfDeclaraLacunaDeCobertura(t *testing.T) {
	r := &check.Report{Coverage: check.Coverage{
		Total: 10, Complete: 4,
		NotChecked:    []check.NotChecked{{ID: "a", Reason: "não estamos como root: environ"}},
		CollectorGaps: []string{"proc: 250 processos ilegíveis", "net: 3 sockets sem dono"},
	}}
	out := renderWtf(r, nil)
	if !strings.Contains(out, "não verificado:") || !strings.Contains(out, "coleta: 2 lacunas") {
		t.Errorf("a linha de lacuna é o que impede a tela de ser lida como limpa:\n%s", out)
	}
	if strings.Contains(out, "RESULT: OK") {
		t.Error("cobertura 4/10 não pode sair como OK")
	}
}

// --- oneline: triagem de frota ---

func oneline(r *check.Report) string {
	var b bytes.Buffer
	Oneline(&b, r)
	return strings.TrimRight(b.String(), "\n")
}

func TestOnelineFormato(t *testing.T) {
	r := &check.Report{
		Findings: []check.Finding{
			{ID: "correlate.revshell", Sev: check.SevCritical, Subject: "pid=6574"},
			{ID: "net.pivot", Sev: check.SevWarn, Subject: "pid=3311"},
		},
		Coverage: check.Coverage{Total: 10, Complete: 10},
	}
	got := oneline(r)
	if !strings.HasPrefix(got, "CRITICAL") {
		t.Errorf("o veredito vem primeiro, é por ele que a frota se ordena: %q", got)
	}
	for _, want := range []string{"revshell(6574)", "pivot(3311)"} {
		if !strings.Contains(got, want) {
			t.Errorf("faltou %q em %q", want, got)
		}
	}
	if strings.Contains(got, "cobertura") {
		t.Errorf("cobertura completa não gasta largura da linha: %q", got)
	}
}

// Sem isto, um host onde metade não rodou aparece na frota igual a um host
// varrido inteiro — e é esse host que precisa de atenção primeiro.
func TestOnelineMostraCoberturaDegradada(t *testing.T) {
	r := &check.Report{Coverage: check.Coverage{Total: 10, Complete: 4}}
	got := oneline(r)
	if !strings.Contains(got, "[cobertura 4/10]") {
		t.Errorf("cobertura degradada precisa aparecer: %q", got)
	}
	if !strings.HasPrefix(got, "INCOMPLETE") {
		t.Errorf("e o veredito não pode ser OK: %q", got)
	}
}

func TestOnelineAgrupaAlvos(t *testing.T) {
	r := &check.Report{Coverage: check.Coverage{Total: 1, Complete: 1}}
	for _, pid := range []string{"1", "2", "3", "4", "5"} {
		r.Findings = append(r.Findings, check.Finding{
			ID: "proc.memfd_exec", Sev: check.SevCritical, Subject: "pid=" + pid})
	}
	got := oneline(r)
	if !strings.Contains(got, "memfd_exec(1,2,3,+2)") {
		t.Errorf("cinco alvos precisam caber numa linha: %q", got)
	}
}

func TestOnelineLimpoNaoFingeSilencio(t *testing.T) {
	r := &check.Report{Coverage: check.Coverage{Total: 10, Complete: 10}}
	got := oneline(r)
	if got != "OK         —" {
		t.Errorf("oneline limpo = %q", got)
	}
}

// argv chega ao Subject, e argv é escolhido pelo atacante. Numa varredura de
// frota a saída de dezenas de hosts é concatenada — uma sequência de escape
// forjaria a linha dos outros.
func TestOnelineEscapaControleDeTerminal(t *testing.T) {
	r := &check.Report{
		Findings: []check.Finding{{ID: "x.y", Sev: check.SevWarn,
			Subject: "pid=1\x1b[2J\x1b[HOK        —"}},
		Coverage: check.Coverage{Total: 1, Complete: 1},
	}
	if strings.Contains(oneline(r), "\x1b") {
		t.Error("ESC cru na linha de frota")
	}
}
