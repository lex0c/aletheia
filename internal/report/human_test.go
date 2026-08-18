package report

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

func testEnv() *env.Env {
	return &env.Env{
		Source: env.SourceLive, Clock: env.ClockSynced,
		Now:         time.Date(2026, 4, 30, 21, 44, 3, 0, time.UTC),
		ToolVersion: "0.1.0-test",
		CapReason:   map[string]string{},
	}
}

func testFacts() *facts.Facts {
	return &facts.Facts{Host: facts.Host{
		Hostname: "web-01", Kernel: "4.19.0-21", OS: "Debian 10",
		Uptime: "47d", Load1: 8.02, NumCPU: 2,
	}}
}

func f(id, ref, subject string, sev check.Severity) check.Finding {
	return check.Finding{
		ID: id, Ref: ref, Title: "título de " + id, Subject: subject,
		Sev: sev, Origin: check.OriginNative,
		FalsePositives: []string{"algum FP"},
	}
}

func render(r *check.Report, v int) string {
	var b bytes.Buffer
	Human(&b, r, testFacts(), testEnv(), Options{Verbose: v})
	return b.String()
}

// O load só significa algo com o número de CPUs junto: 8.02 é catastrófico em
// 2 cpu e normal em 16. Sem o contexto, o alerta vira ruído justamente no sinal
// de minerador, que é o comprometimento nº 1 em VM de nuvem.
func TestCabecalhoTrazLoadComCPUs(t *testing.T) {
	out := render(&check.Report{Coverage: check.Coverage{Total: 1, Complete: 1}}, 0)
	if !strings.Contains(out, "load 8.02 (2 cpu)") {
		t.Errorf("load deve vir com nº de CPUs:\n%s", out)
	}
	if !strings.Contains(out, "⚠") {
		t.Error("load 8.02 em 2 cpu precisa ser sinalizado")
	}
}

func TestCabecalhoTrazRelogioEModo(t *testing.T) {
	out := render(&check.Report{Coverage: check.Coverage{Total: 1, Complete: 1}}, 0)
	for _, want := range []string{"relógio sincronizado", "2026-04-30T21:44:03Z", "modo live"} {
		if !strings.Contains(out, want) {
			t.Errorf("cabeçalho sem %q:\n%s", want, out)
		}
	}
}

// A saída compacta agrupa por ID para que o tamanho do relatório não cresça com
// o tamanho do incidente.
func TestCompactoAgrupaPorID(t *testing.T) {
	r := &check.Report{Coverage: check.Coverage{Total: 1, Complete: 1}}
	for _, pid := range []string{"pid=10", "pid=20", "pid=30", "pid=40"} {
		r.Findings = append(r.Findings, f("proc.suspeito", "8", pid, check.SevWarn))
	}
	out := render(r, 0)

	if !strings.Contains(out, "4×") {
		t.Errorf("quatro achados do mesmo ID devem virar uma linha com 4×:\n%s", out)
	}
	if n := strings.Count(out, "proc.suspeito"); n > 1 {
		t.Errorf("o ID não deve se repetir na saída compacta (%d vezes)", n)
	}
}

// O default é o formato de DECISÃO: ~18 linhas independentemente do incidente.
func TestCompactoNaoCresceComOIncidente(t *testing.T) {
	r := &check.Report{Coverage: check.Coverage{Total: 20, Complete: 20}}
	for i := 0; i < 200; i++ {
		r.Findings = append(r.Findings, f("proc.ruido", "8", "pid="+strings.Repeat("9", i%5+1), check.SevWarn))
	}
	lines := strings.Count(render(r, 0), "\n")
	if lines > 25 {
		t.Errorf("saída default com %d linhas para 200 achados: deveria agrupar", lines)
	}
}

// O bloco de ação adapta: com crítico, é a ordem do runbook §19, e o passo
// irreversível vem primeiro.
func TestBlocoDeAcaoPriorizaPreserve(t *testing.T) {
	fd := f("proc.memfd_exec", "3.16", "pid=6574", check.SevCritical)
	fd.Irreversible = true
	fd.NextSteps = []string{"sudo cp /proc/6574/exe \"$IR/pid-6574.bin\""}
	r := &check.Report{Findings: []check.Finding{fd}, Coverage: check.Coverage{Total: 1, Complete: 1}}
	out := render(r, 0)

	if !strings.Contains(out, "AGORA, nesta ordem") {
		t.Errorf("com crítico, o bloco de ação é obrigatório:\n%s", out)
	}
	iPreserve := strings.Index(out, "cp /proc/6574/exe")
	iIsolar := strings.Index(out, "isolar na camada de REDE")
	if iPreserve < 0 || iIsolar < 0 || iPreserve > iIsolar {
		t.Error("preservar vem ANTES de isolar: é o único passo irreversível se pulado")
	}
	if !strings.Contains(out, "irreversível") {
		t.Error("o passo irreversível precisa estar marcado como tal")
	}
}

func TestBlocoDeAcaoSomeSemAchado(t *testing.T) {
	out := render(&check.Report{Coverage: check.Coverage{Total: 3, Complete: 3}}, 0)
	if strings.Contains(out, "AGORA, nesta ordem") {
		t.Error("sem achado não há ordem de ação a sugerir")
	}
}

// A regra central da ferramenta: OK nunca pode ser lido como "host limpo".
func TestOKNuncaAfirmaHostLimpo(t *testing.T) {
	out := render(&check.Report{Coverage: check.Coverage{Total: 3, Complete: 3}}, 0)
	if !strings.Contains(out, "RESULT: OK") {
		t.Fatalf("esperava RESULT: OK\n%s", out)
	}
	if !strings.Contains(out, "NÃO prova que o host está limpo") {
		t.Errorf("OK sem a ressalva é a leitura errada que a ferramenta existe para evitar:\n%s", out)
	}
	if !strings.Contains(out, "35.8") {
		t.Error("a ressalva precisa apontar a seção do runbook que a sustenta")
	}
}

// Cobertura incompleta sem achado vira INCOMPLETE, não OK.
func TestCoberturaIncompletaViraIncomplete(t *testing.T) {
	r := &check.Report{Coverage: check.Coverage{
		Total: 5, Complete: 3,
		NotChecked: []check.NotChecked{
			{ID: "kernel.ftrace", Ref: "35.3", Reason: "debugfs não montado"},
			{ID: "kernel.ebpf", Ref: "35.4", Reason: "bpftool ausente"},
		},
	}}
	out := render(r, 0)
	if !strings.Contains(out, "RESULT: INCOMPLETE") {
		t.Errorf("esperava INCOMPLETE:\n%s", out)
	}
	if strings.Contains(out, "RESULT: OK") {
		t.Error("nunca OK com cobertura incompleta")
	}
}

// A aritmética da cobertura precisa fechar: completos + parciais + não
// verificados = total. Foi um erro real da spec antes da revisão.
func TestAritmeticaDaCoberturaFecha(t *testing.T) {
	r := &check.Report{Coverage: check.Coverage{
		Total: 6, Complete: 3,
		Partial:    []check.Partial{{ID: "a"}, {ID: "b"}},
		NotChecked: []check.NotChecked{{ID: "c", Reason: "sem root"}},
	}}
	out := render(r, 0)
	if !strings.Contains(out, "completos 3 · parciais 2 · não verificados 1 · total 6") {
		t.Errorf("a linha de cobertura precisa fechar a conta:\n%s", out)
	}
}

// Lacuna de coleta aparece num eixo próprio e NÃO entra na conta de checks.
func TestLacunaDeColetaTemLinhaPropria(t *testing.T) {
	r := &check.Report{Coverage: check.Coverage{
		Total: 3, Complete: 3,
		CollectorGaps: []string{"proc: 250 processos com fds ilegíveis (sem permissão)"},
	}}
	out := render(r, 0)
	if !strings.Contains(out, "coleta") || !strings.Contains(out, "250 processos") {
		t.Errorf("a lacuna de coleta precisa de linha própria:\n%s", out)
	}
	if !strings.Contains(out, "completos 3 · parciais 0 · não verificados 0 · total 3") {
		t.Error("a lacuna de coleta não pode mexer na aritmética de checks")
	}
	if !strings.Contains(out, "RESULT: INCOMPLETE") {
		t.Error("não conseguir ler é literalmente 'não olhei': impede OK")
	}
}

func TestRebaixamentoApareceNoRelatorio(t *testing.T) {
	fd := f("integrity.pkg", "24", "path=/usr/bin/ss", check.SevWarn)
	fd.Origin = check.ToolOrigin("dpkg")
	fd.Downgraded = true
	r := &check.Report{
		Findings:    []check.Finding{fd},
		Coverage:    check.Coverage{Total: 1, Complete: 1},
		TrustBroken: []string{"/etc/ld.so.preload presente"},
	}
	out := render(r, 0)
	if !strings.Contains(out, "rebaixado") {
		t.Errorf("achado rebaixado precisa estar marcado na linha:\n%s", out)
	}
	if !strings.Contains(out, "CONFIANÇA REBAIXADA") {
		t.Error("o motivo do rebaixamento precisa estar explicado no fim")
	}
}

// A promoção do passo irreversível é por CAMPO, não por casar o texto do
// comando: acoplar por string faz uma reescrita inocente silenciar o passo que
// não pode ser pulado, com todos os testes continuando verdes na própria cópia
// do literal.
func TestPromocaoIrreversivelNaoDependeDoTextoDoComando(t *testing.T) {
	fd := f("qualquer.check", "9.9", "pid=42", check.SevCritical)
	fd.Irreversible = true
	fd.NextSteps = []string{"sudo dd if=/proc/42/mem of=$IR/x bs=1M count=1"}
	r := &check.Report{Findings: []check.Finding{fd}, Coverage: check.Coverage{Total: 1, Complete: 1}}
	out := render(r, 0)
	if !strings.Contains(out, "irreversível") || !strings.Contains(out, "dd if=/proc/42/mem") {
		t.Errorf("comando totalmente diferente deve ser promovido pelo campo:\n%s", out)
	}
}

// Injeção de terminal: o argv é controlado pelo alvo e vai para a evidência.
// Sem sanitização, um implante limpa a tela e pinta um veredito limpo forjado —
// usando o campo de evidência do próprio achado como veículo.
func TestEvidenciaNaoInjetaNoTerminal(t *testing.T) {
	fd := f("proc.memfd_exec", "3.16", "pid=8812", check.SevCritical)
	fd.Evidence = []string{
		"cmdline=nginx: worker\x1b[2J\x1b[H⛔ 0 ⚠ 0 · cobertura 3/3\n\n✓ nenhum indicador coberto disparou\n\nRESULT: OK",
	}
	r := &check.Report{Findings: []check.Finding{fd}, Coverage: check.Coverage{Total: 1, Complete: 1}}
	out := render(r, 1)

	if strings.Contains(out, "\x1b") {
		t.Error("byte ESC cru chegou ao terminal: o alvo controla a tela do analista")
	}
	// O que torna a injeção perigosa não é o texto existir na evidência — é ele
	// COMEÇAR UMA LINHA e se passar pelo veredito da própria ferramenta. Depois
	// da sanitização o conteúdo continua visível, mas confinado à linha da
	// evidência.
	var forjadas int
	for _, ln := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(ln), "RESULT:") {
			forjadas++
		}
	}
	if forjadas != 1 {
		t.Errorf("%d linhas começando com RESULT: — o veredito é falsificável pelo alvo", forjadas)
	}
	for _, ln := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(ln), "✓ nenhum indicador") {
			t.Error("o alvo conseguiu forjar a linha de 'nada encontrado'")
		}
	}
	if !strings.Contains(out, "\\x1b") {
		t.Error("a tentativa precisa aparecer VISÍVEL: o operador tem de saber que houve injeção")
	}
}

// -v traz evidência e falso positivo; o default, não.
func TestVerboseTrazEvidenciaEFalsoPositivo(t *testing.T) {
	fd := f("proc.memfd_exec", "3.16", "pid=8812", check.SevCritical)
	fd.Evidence = []string{"exe=/memfd:x"}
	fd.FalsePositives = []string{"runtime que usa memfd para JIT"}
	r := &check.Report{Findings: []check.Finding{fd}, Coverage: check.Coverage{Total: 1, Complete: 1}}

	compact := render(r, 0)
	if strings.Contains(compact, "runtime que usa memfd") {
		t.Error("o default é formato de DECISÃO: FP detalhado é ruído ali")
	}

	verbose := render(r, 1)
	for _, want := range []string{"exe=/memfd:x", "FP:", "runtime que usa memfd"} {
		if !strings.Contains(verbose, want) {
			t.Errorf("-v sem %q:\n%s", want, verbose)
		}
	}
}

// O JSONL nunca é afetado pela verbosidade: senão a agregação de frota passaria
// a depender de qual flag o operador usou (SPEC 7.1).
func TestJSONLNaoDependeDaVerbosidade(t *testing.T) {
	fd := f("proc.memfd_exec", "3.16", "pid=8812", check.SevCritical)
	fd.Evidence = []string{"exe=/memfd:x"}
	r := &check.Report{Findings: []check.Finding{fd}, Coverage: check.Coverage{Total: 2, Complete: 1}}

	var a, b bytes.Buffer
	if err := JSONL(&a, r, testFacts(), testEnv(), nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := JSONL(&b, r, testFacts(), testEnv(), nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if a.String() != b.String() {
		t.Error("JSONL precisa ser estável entre execuções")
	}
	if !strings.Contains(a.String(), "exe=/memfd:x") {
		t.Error("JSONL sempre traz a evidência completa, independentemente da exibição")
	}
}

// A linha de cobertura no JSONL é o que impede a agregação de frota mostrar
// "web-02 sem achados" escondendo que lá metade dos checks não rodou.
func TestJSONLSempreTrazLinhaDeCobertura(t *testing.T) {
	r := &check.Report{Coverage: check.Coverage{
		Total: 47, Complete: 39,
		NotChecked: []check.NotChecked{{ID: "kernel.ebpf", Ref: "35.4", Reason: "bpftool ausente"}},
	}}
	var buf bytes.Buffer
	if err := JSONL(&buf, r, testFacts(), testEnv(), nil, nil, nil); err != nil {
		t.Fatal(err)
	}

	var found bool
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("linha não é JSON válido: %v", err)
		}
		if m["id"] == "coverage" {
			found = true
			if m["verdict"] != "INCOMPLETE" {
				t.Errorf("verdict = %v, quer INCOMPLETE", m["verdict"])
			}
			if m["total"].(float64) != 47 || m["complete"].(float64) != 39 {
				t.Errorf("cobertura errada na linha: %v", m)
			}
		}
	}
	if !found {
		t.Error("a linha de cobertura é obrigatória, mesmo sem achados")
	}
}

func TestSummarizeAgrupaMotivos(t *testing.T) {
	got := summarize([]string{
		"sem root: environ invisível",
		"sem root: /etc/shadow invisível",
		"debugfs não montado",
	}, 3)
	// `2× sem root`, e não `sem root: 2`: a razão já tem dois-pontos dentro
	// dela, e o segundo faria a contagem parecer parte do texto.
	if !strings.Contains(got, "2× sem root") {
		t.Errorf("motivos repetidos devem ser contados: %q", got)
	}
}

func TestPadContaRunesNaoBytes(t *testing.T) {
	// O marcador de severidade é multibyte; padding por len() desalinha a
	// coluna de §ref em toda linha com acento.
	if got := pad("⛔ ação", 10); len([]rune(got)) != 10 {
		t.Errorf("pad devolveu %d runes, quer 10", len([]rune(got)))
	}
}

// A cota entra no cabeçalho como CONTEXTO, não como limiar. O load vem de
// /proc/loadavg, que não é isolado por namespace: dentro de contêiner ele
// descreve o HOST, enquanto a cota descreve a fatia deste alvo. Misturar os
// dois num aviso seria comparar coisas diferentes.
func TestCabecalhoMostraCotaDeCPU(t *testing.T) {
	rel := func(quota float64) string {
		fa := &facts.Facts{Host: facts.Host{
			Hostname: "web-01", NumCPU: 12, Load1: 1.4, CPUQuota: quota,
		}}
		var b bytes.Buffer
		Human(&b, &check.Report{Coverage: check.Coverage{Total: 1, Complete: 1}},
			fa, testEnv(), Options{})
		// só o cabeçalho: o corpo do relatório tem ⚠ na contagem por severidade
		return strings.SplitN(b.String(), "\n", 2)[0]
	}

	cab := rel(0.5)
	if !strings.Contains(cab, "(12 cpu · cota 0.5)") {
		t.Errorf("cabeçalho sem a cota: %q", cab)
	}
	if strings.Contains(cab, "⚠") {
		t.Errorf("load 1.4 em 12 cpu não é aviso: a cota é contexto, não limiar: %q", cab)
	}

	// Sem cota, o cabeçalho não inventa uma.
	if cab := rel(0); strings.Contains(cab, "cota") {
		t.Errorf("host sem cota não pode exibir cota: %q", cab)
	}
}

// Num implante de verdade três checks disparam no MESMO pid, e cada um
// contribui o mesmo `cp /proc/N/exe`. O bloco de ação existe para ser a lista
// curta do que fazer agora — repetir a linha o transforma numa parede.
func TestBlocoDeAcaoNaoRepeteOMesmoComando(t *testing.T) {
	mk := func(id string) check.Finding {
		fd := f(id, "17", "pid=20", check.SevCritical)
		fd.Irreversible = true
		fd.NextSteps = []string{"NÃO mate antes de preservar", `sudo cp /proc/20/exe "$IR/pid-20.bin"`}
		return fd
	}
	r := &check.Report{
		Findings: []check.Finding{mk("correlate.revshell"), mk("proc.kthread_disguise"),
			mk("proc.suspicious_path")},
		Coverage: check.Coverage{Total: 3, Complete: 3},
	}
	out := render(r, 0)
	if n := strings.Count(out, "cp /proc/20/exe"); n != 1 {
		t.Errorf("o mesmo comando apareceu %d vezes:\n%s", n, out)
	}
}

// A correlação precisa aparecer no relatório, não só no modelo: é ela que
// transforma quatro fatos soltos numa história. E cada achado aparece uma vez
// só — correlacionado OU na compactação por ID, nunca nos dois.
func TestRelatorioMostraAlvoCorrelacionado(t *testing.T) {
	mk := func(id, subj string, sev check.Severity) check.Finding {
		return f(id, "17", subj, sev)
	}
	r := &check.Report{
		Findings: []check.Finding{
			mk("correlate.revshell", "pid=19", check.SevCritical),
			mk("proc.env_tool_marker", "pid=19", check.SevCritical),
			mk("proc.suspicious_path", "pid=19", check.SevWarn),
			mk("proc.suspicious_path", "pid=77", check.SevWarn),
		},
		Coverage: check.Coverage{Total: 4, Complete: 4},
	}
	out := render(r, 0)

	if !strings.Contains(out, "3 sinais no mesmo alvo") {
		t.Errorf("o alvo correlacionado não apareceu:\n%s", out)
	}
	// pid=19 aparece uma vez como cabeçalho do grupo; pid=77 uma vez solto.
	if n := strings.Count(out, "pid=19"); n != 1 {
		t.Errorf("pid=19 apareceu %d vezes: cada achado sai uma vez só\n%s", n, out)
	}
	if !strings.Contains(out, "pid=77") {
		t.Errorf("o alvo com um sinal só precisa continuar aparecendo:\n%s", out)
	}
}

// A deduplicação do bloco de ação é pelo COMANDO, não pela linha: dois checks
// contribuem o mesmo `cp` com comentários diferentes, e comparar a linha
// inteira deixava os dois passarem. Foi assim que o defeito voltou depois de
// corrigido — pela porta do comentário.
func TestDedupeDoBlocoIgnoraComentario(t *testing.T) {
	mk := func(id, passo string) check.Finding {
		fd := f(id, "7", "/usr/local/sbin/x", check.SevCritical)
		fd.Irreversible = true
		fd.NextSteps = []string{passo}
		return fd
	}
	r := &check.Report{
		Findings: []check.Finding{
			mk("a.b", `sudo cp /usr/local/sbin/x "$IR/"   # o binário é a amostra`),
			mk("c.d", `sudo cp /usr/local/sbin/x "$IR/"   # a amostra, antes de tudo`),
		},
		Coverage: check.Coverage{Total: 2, Complete: 2},
	}
	if n := strings.Count(render(r, 0), "cp /usr/local/sbin/x"); n != 1 {
		t.Errorf("o mesmo comando apareceu %d vezes", n)
	}
}

// Quando o primeiro comando de um achado já apareceu, ele precisa contribuir
// com o PRÓXIMO distinto — não ficar de fora. O passo que se perdia era
// justamente o `gcore`, que é o único jeito de preservar a memória.
func TestAcoesNaoPerdemComandoDistinto(t *testing.T) {
	r := &check.Report{Findings: []check.Finding{
		{ID: "a", Sev: check.SevCritical, Subject: "pid=10", Irreversible: true,
			NextSteps: []string{`sudo cp /proc/10/exe "$IR/pid-10.bin"`}},
		{ID: "b", Sev: check.SevCritical, Subject: "pid=10", Irreversible: true,
			NextSteps: []string{
				`sudo cp /proc/10/exe "$IR/pid-10.bin"`,
				`sudo gcore -o "$IR/pid-10.core" 10`,
			}},
	}}
	var b strings.Builder
	Human(&b, r, testFacts(), testEnv(), Options{})
	out := b.String()
	if !strings.Contains(out, "gcore") {
		t.Errorf("o comando distinto do segundo achado se perdeu:\n%s", out)
	}
	if strings.Count(out, "cp /proc/10/exe") != 1 {
		t.Errorf("o comando repetido precisa aparecer UMA vez:\n%s", out)
	}
}

// Dois listeners do mesmo processo produzem dois achados de mesmo ID e mesmo
// sujeito. Dentro do bloco de um alvo eles viravam duas linhas idênticas — o
// que as separa está na evidência, não no título — e o operador procurava uma
// diferença que a tela não mostrava.
func TestSinaisDoGrupoCompactaRepeticao(t *testing.T) {
	g := check.SubjectGroup{Subject: "/x", Findings: []check.Finding{
		{ID: "net.listener_unowned", Subject: "pid=1", Title: "porta exposta"},
		{ID: "net.listener_unowned", Subject: "pid=1", Title: "porta exposta"},
		{ID: "integrity.no_package_owner", Subject: "/x", Title: "sem dono"},
	}}
	s := sinaisDoGrupo(g)
	if len(s) != 2 {
		t.Fatalf("duas linhas: a repetida e a outra; deu %d", len(s))
	}
	if s[0].n != 2 {
		t.Errorf("a contagem tem que sobreviver — duas portas não são uma: n=%d", s[0].n)
	}
	if s[1].n != 1 {
		t.Errorf("o achado distinto não pode ser somado ao anterior: n=%d", s[1].n)
	}
	// A ORDEM é a do relatório: compactar não pode reordenar o bloco.
	if s[0].fd.ID != "net.listener_unowned" || s[1].fd.ID != "integrity.no_package_owner" {
		t.Error("a ordem original do grupo se perdeu")
	}
}

func TestCortaPorRune(t *testing.T) {
	// Cortar por byte parte o acento no meio e emite lixo no terminal.
	if got := corta("binário", 4); got != "bin…" {
		t.Errorf("corta = %q", got)
	}
	if got := corta("abc", 10); got != "abc" {
		t.Errorf("o que cabe não é tocado: %q", got)
	}
	if got := corta("abc", 1); got != "" {
		t.Errorf("sem espaço não se inventa linha: %q", got)
	}
}

// O bloco de um alvo é onde a correlação por ator aparece para o operador, e
// ele tem três decisões que a mutação alcança e nenhum teste unitário afirmava.
func TestBlocoDeAlvoPorAtor(t *testing.T) {
	fd := func(id, subj, ator, title string) check.Finding {
		return check.Finding{ID: id, Ref: "1", Subject: subj, Ator: ator,
			Title: title, Sev: check.SevWarn}
	}
	r := &check.Report{
		Coverage: check.Coverage{Total: 1, Complete: 1},
		Findings: []check.Finding{
			fd("a", "/x", "", "sem dono"),
			fd("b", "pid=7", "/x", "fala com a internet"),
		},
	}
	out := render(r, 0)

	if !strings.Contains(out, "/x") || !strings.Contains(out, "2 sinais no mesmo alvo") {
		t.Fatalf("o grupo tinha que se formar pelo ator:\n%s", out)
	}
	// O sujeito PRÓPRIO do achado sobrevive: é ele que o operador usa depois.
	if !strings.Contains(out, "(pid=7)") {
		t.Errorf("o pid do achado de rede sumiu dentro do bloco:\n%s", out)
	}
	// E o achado que JÁ é o alvo não ganha um parêntese redundante "(/x)".
	if strings.Contains(out, "(/x)") {
		t.Errorf("o achado cujo sujeito é o próprio alvo não repete o alvo:\n%s", out)
	}
}

// Um binário acusado reúne todo processo que o executa. Vinte deles não podem
// imprimir vinte linhas numa seção que existe para caber na tela — e o que
// ficou de fora precisa aparecer como contagem, nunca sumir calado.
func TestBlocoDeAlvoCortaComContagem(t *testing.T) {
	var fs []check.Finding
	for i := 0; i < 20; i++ {
		fs = append(fs, check.Finding{
			ID: "net.egress_unowned", Ref: "4.3", Sev: check.SevWarn,
			Subject: "pid=" + strconv.Itoa(i), Ator: "/x",
			Title: "fala com a internet",
		})
	}
	fs = append(fs, check.Finding{ID: "integrity.no_package_owner", Ref: "24",
		Sev: check.SevWarn, Subject: "/x", Title: "sem dono"})
	r := &check.Report{Coverage: check.Coverage{Total: 1, Complete: 1}, Findings: fs}

	out := render(r, 0)
	if !strings.Contains(out, "21 sinais no mesmo alvo") {
		t.Errorf("a contagem do cabeçalho tem que ser a real:\n%s", out)
	}
	if !strings.Contains(out, "e mais 13 sinal(is)") {
		t.Errorf("o que passou do teto tem que aparecer como contagem:\n%s", out)
	}
	if n := strings.Count(out, "     · "); n != 9 {
		t.Errorf("esperava 8 linhas de sinal + a do corte, deu %d:\n%s", n, out)
	}
}

// As oito linhas impressas podem representar MAIS de oito achados, porque a
// repetição já foi compactada. Contar o corte sobre o total bruto dizia "e mais
// 14" onde faltavam 5 — um número inventado no lugar exato onde o comentário
// promete que nada some calado.
func TestBlocoDeAlvoContaOCorteSobreLinhasCompactadas(t *testing.T) {
	var fs []check.Finding
	for i := 0; i < 10; i++ { // dez achados IDÊNTICOS: uma linha só, n=10
		fs = append(fs, check.Finding{ID: "net.listener_unowned", Ref: "4.2",
			Sev: check.SevWarn, Subject: "pid=1", Ator: "/x", Title: "porta exposta"})
	}
	for i := 0; i < 11; i++ { // e onze distintos
		fs = append(fs, check.Finding{ID: "net.egress_unowned", Ref: "4.3",
			Sev: check.SevWarn, Subject: "pid=" + strconv.Itoa(100+i), Ator: "/x",
			Title: "fala com a internet"})
	}
	fs = append(fs, check.Finding{ID: "integrity.no_package_owner", Ref: "24",
		Sev: check.SevWarn, Subject: "/x", Title: "sem dono"})

	out := render(&check.Report{Coverage: check.Coverage{Total: 1, Complete: 1}, Findings: fs}, 0)
	if !strings.Contains(out, "22 sinais no mesmo alvo") {
		t.Errorf("o cabeçalho conta ACHADOS, e são 22:\n%s", out)
	}
	// 8 linhas cobrem 10+7 = 17 achados; sobram 5.
	if !strings.Contains(out, "e mais 5 sinal(is)") {
		t.Errorf("o corte tem que contar o que sobrou de verdade:\n%s", out)
	}
}

// A linha de COBERTURA fabricava categoria.
//
// summarize cortava a razão no primeiro ":" ou "(" para inventar um rótulo, e
// o parêntese chega cedo demais em português: "2 arquivo(s) com dono de pacote
// NÃO puderam ser comparados por hash (…)" virava a categoria "2 arquivo", com
// contagem ao lado. Saía na seção que é a promessa central desta ferramenta uma
// linha que não se lê.
func TestResumoDeCoberturaNaoInventaCategoria(t *testing.T) {
	razoes := []string{
		"2 arquivo(s) com dono de pacote NÃO puderam ser comparados por hash (a base não declara)",
		"não estamos como root: environ e /etc/shadow ficam invisíveis",
		"não estamos como root: environ e /etc/shadow ficam invisíveis",
		"não estamos como root: environ e /etc/shadow ficam invisíveis",
	}
	got := summarize(razoes, 3)

	if strings.Contains(got, "2 arquivo:") {
		t.Errorf("cortar no parêntese inventou a categoria \"2 arquivo\": %q", got)
	}
	// A razão que degradou MAIS checks vem primeiro: é ela que o operador
	// resolve para recuperar mais cobertura de uma vez.
	if !strings.HasPrefix(got, "3× não estamos como root") {
		t.Errorf("a razão dominante precisa vir primeiro, com a contagem: %q", got)
	}
	// E o corte precisa DIZER que houve corte.
	if !strings.Contains(got, "…") {
		t.Errorf("corte sem reticências esconde que houve corte: %q", got)
	}
}

// Quando há mais razões que o teto, o número das que ficaram de fora sai junto
// — e o caminho para vê-las também. "…" sozinho não diz quantas.
func TestResumoDizQuantasFicaramDeFora(t *testing.T) {
	razoes := []string{"a", "b", "c", "d", "e"}
	got := summarize(razoes, 3)
	if !strings.Contains(got, "+2 outras") {
		t.Errorf("faltou o número do que ficou de fora: %q", got)
	}
	if !strings.Contains(got, "-v") {
		t.Errorf("e o caminho para ver o resto: %q", got)
	}
}
