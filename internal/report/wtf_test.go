package report

import (
	"bytes"
	"regexp"
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
	Wtf(&b, r, f, wtfEnv(), 57*time.Millisecond, r.Coverage.Total, nil)
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
		if !strings.Contains(out, "não varredura") && !strings.Contains(out, "NÃO é varredura") {
			t.Errorf("%s: o rodapé precisa negar que isto foi varredura:\n%s", nome, out)
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
				Evidence:  []string{"fd 0,1,2 → socket:[889]", "peer=198.51.100.241:443", "terceira linha"},
				NextSteps: []string{"NÃO mate antes de preservar", "sudo cp /proc/6574/exe x"}},
			{ID: "net.pivot", Sev: check.SevWarn, Subject: "pid=3311",
				Title: "pivô", Ref: "12.2", Evidence: []string{"evidência de aviso"}},
		},
		Coverage: check.Coverage{Total: 10, Complete: 10},
	}
	out := renderWtf(r, nil)

	for _, want := range []string{"socket:[889]", "peer=198.51.100.241:443", "sudo cp /proc/6574/exe"} {
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
			{Proto: "tcp", State: "ESTAB", Dir: facts.DirOut, LocalIP: "10.0.0.5"},
			{Proto: "tcp", State: "ESTAB", Dir: facts.DirIn, LocalIP: "10.0.0.5"},
			// 0.0.0.0 é TODAS as interfaces: o caso mais exposto que existe.
			{Proto: "tcp", State: "LISTEN", Dir: facts.DirListen, LocalIP: "0.0.0.0"},
			{Proto: "tcp", State: "LISTEN", Dir: facts.DirListen, LocalIP: "127.0.0.1"},
			// UDP ligado a uma porta não tem estado LISTEN, e mesmo assim está
			// escutando. Contar só por State esconderia todo serviço UDP.
			{Proto: "udp", State: "CLOSE", Dir: facts.DirListen, LocalIP: "0.0.0.0"},
		},
	}
	out := renderWtf(&check.Report{Coverage: check.Coverage{Total: 1, Complete: 1}}, f)
	if !strings.Contains(out, "3 proc · 2 estab · 2 listen fora de loopback") {
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

// O rodapé não pode mandar o operador repetir trabalho. Enquanto o catálogo
// inteiro couber no orçamento do wtf, "rode aletheia scan" é uma instrução que
// não muda nada — o mesmo tipo de afirmação vazia que a ferramenta recusa nos
// achados.
func TestRodapeSoMandaRodarScanQuandoEleAcrescenta(t *testing.T) {
	rel := func(catalogo int) string {
		var b bytes.Buffer
		r := &check.Report{Coverage: check.Coverage{Total: 10, Complete: 10}}
		Wtf(&b, r, &facts.Facts{}, wtfEnv(), 57*time.Millisecond, catalogo, nil)
		return b.String()
	}

	// wtf == catálogo: não sugere nada.
	if out := rel(10); strings.Contains(out, "rode `aletheia scan`") {
		t.Errorf("sugeriu scan sem ter o que acrescentar:\n%s", out)
	}
	// catálogo maior: sugere, dizendo QUANTOS checks a mais.
	out := rel(47)
	if !strings.Contains(out, "rode `aletheia scan` (+37 checks)") {
		t.Errorf("faltou dizer quanto o scan acrescenta:\n%s", out)
	}
}

// A contagem do corte não pode incluir INFO: eles nunca são impressos, e a
// linha prometeria achados que o operador não encontraria em lugar nenhum.
func TestContagemDoCorteIgnoraInfo(t *testing.T) {
	r := &check.Report{Coverage: check.Coverage{Total: 10, Complete: 10}}
	for i := 0; i < maxWtfLinhas+3; i++ {
		r.Findings = append(r.Findings, check.Finding{
			ID: "x.y", Sev: check.SevWarn, Subject: "pid=" + strconv.Itoa(i), Title: "t"})
	}
	for i := 0; i < 5; i++ {
		r.Findings = append(r.Findings, check.Finding{ID: "z.w", Sev: check.SevInfo, Title: "i"})
	}
	if out := renderWtf(r, nil); !strings.Contains(out, "e mais 3 achados") {
		t.Errorf("a contagem incluiu achados INFO, que nunca aparecem:\n%s", out)
	}
}

// O wtf promete UMA TELA. Contar só os avulsos deixava vinte alvos
// correlacionados imprimirem vinte linhas.
func TestWtfLimitaGruposEAvulsosJuntos(t *testing.T) {
	r := &check.Report{Coverage: check.Coverage{Total: 1, Complete: 1}}
	// 12 alvos correlacionados (2 sinais cada) + 5 avulsos
	for i := 0; i < 12; i++ {
		s := "pid=" + strconv.Itoa(i)
		r.Findings = append(r.Findings,
			check.Finding{ID: "a.b", Subject: s, Sev: check.SevCritical, Title: "t"},
			check.Finding{ID: "c.d", Subject: s, Sev: check.SevWarn, Title: "t"})
	}
	for i := 0; i < 5; i++ {
		r.Findings = append(r.Findings, check.Finding{
			ID: "e.f", Subject: "x" + strconv.Itoa(i), Sev: check.SevWarn, Title: "t"})
	}
	out := renderWtf(r, nil)
	if n := strings.Count(out, "sinais:"); n > maxWtfLinhas {
		t.Errorf("%d linhas de grupo, teto é %d:\n%s", n, maxWtfLinhas, out)
	}
	if !strings.Contains(out, "e mais") {
		t.Errorf("o que ficou de fora precisa ser contado:\n%s", out)
	}
}

// Um caminho longo sozinho estoura o orçamento da linha, e o resumo fica sem
// espaço. O que não pode sair é "3 sinais:" com nada depois — dois-pontos vazio
// parece defeito de truncamento, e a linha do `wtf` é lida em dez segundos.
func TestWtfComAlvoLongoNaoDeixaDoisPontosVazio(t *testing.T) {
	longo := "/home/deploy/.local/share/aplicacao/versions/1.2.3/bin/daemon-longo"
	r := &check.Report{
		Coverage: check.Coverage{Total: 2, Complete: 2},
		Findings: []check.Finding{
			{ID: "integrity.no_package_owner", Ref: "24", Sev: check.SevWarn,
				Subject: longo, Title: "binário que nenhum pacote reivindica"},
			{ID: "net.egress_unowned", Ref: "4.3", Sev: check.SevWarn,
				Subject: "pid=7", Ator: longo, Title: "conexão para endereço público"},
		},
	}
	var b bytes.Buffer
	Wtf(&b, r, &facts.Facts{}, wtfEnv(), time.Second, r.Coverage.Total, nil)

	for _, l := range strings.Split(b.String(), "\n") {
		if !strings.Contains(l, "sinais") {
			continue
		}
		// O `pad` insere espaço depois do cabeçalho, então a forma ruim é
		// "sinais:" seguido só de branco até a seção ou até o fim da linha.
		if regexp.MustCompile(`sinais:\s*(§|$)`).MatchString(l) {
			t.Errorf("dois-pontos sem resumo atrás: %q", l)
		}
		if !strings.Contains(l, "§24") || !strings.Contains(l, "§4.3") {
			t.Errorf("as seções são o que sobra quando o resumo não cabe: %q", l)
		}
	}
}
