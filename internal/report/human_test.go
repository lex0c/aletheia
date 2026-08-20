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

// renderCob renderiza com a seção de cobertura VISÍVEL (--coverage).
func renderCob(r *check.Report) string {
	var b bytes.Buffer
	Human(&b, r, testFacts(), testEnv(), Options{Coverage: true})
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

	if !strings.Contains(out, "×4") {
		t.Errorf("quatro achados do mesmo ID devem virar uma linha com ×4:\n%s", out)
	}
	// O detalhe agrupa: no máximo uma linha no FOCUS (resumo) e uma no detalhe.
	// Quatro linhas seria a falha de agrupamento que este teste guarda.
	if n := strings.Count(out, "proc.suspeito"); n > 2 {
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

// O bloco verboso de ação saiu da view. O que FICA é a salvaguarda que a pressa
// destrói: um achado irreversível (memfd, binário apagado) tem UMA cópia, e ela
// some no kill. A view avisa; os comandos, por achado, ficam no -v.
func TestSalvaguardaDePreservacao(t *testing.T) {
	fd := f("proc.memfd_exec", "3.16", "pid=6574", check.SevCritical)
	fd.Irreversible = true
	fd.NextSteps = []string{"sudo cp /proc/6574/exe \"$IR/pid-6574.bin\""}
	r := &check.Report{Findings: []check.Finding{fd}, Coverage: check.Coverage{Total: 1, Complete: 1}}
	out := render(r, 0)

	if !strings.Contains(out, "preserve ANTES de matar") {
		t.Errorf("achado irreversível precisa avisar para preservar antes de matar:\n%s", out)
	}
	// O bloco verboso antigo NÃO volta.
	if strings.Contains(out, "AGORA, nesta ordem") || strings.Contains(out, "isolar na camada de REDE") {
		t.Errorf("o bloco verboso saiu da view:\n%s", out)
	}
	// O comando de preservação continua acessível — no -v.
	if !strings.Contains(render(r, 1), "cp /proc/6574/exe") {
		t.Error("o comando de preservação precisa continuar no -v")
	}
}

func TestSalvaguardaSomeSemIrreversivel(t *testing.T) {
	out := render(&check.Report{Coverage: check.Coverage{Total: 3, Complete: 3}}, 0)
	if strings.Contains(out, "preserve ANTES de matar") {
		t.Error("sem achado irreversível não há o que preservar antes de matar")
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
	out := renderCob(r)
	if !strings.Contains(out, "3/6 completos") || !strings.Contains(out, "2 parciais") || !strings.Contains(out, "1 não verificados") {
		t.Errorf("a linha de cobertura precisa fechar a conta (completos/parciais/não verificados):\n%s", out)
	}
}

// A SEÇÃO de cobertura é oculta por padrão (UX), MAS o NÚMERO fica no resumo —
// é a invariante da ferramenta: um OK nunca pode esconder "olhei 19 de 104".
func TestCoberturaOcultaMasNumeroFica(t *testing.T) {
	r := &check.Report{Coverage: check.Coverage{
		Total: 104, Complete: 19,
		Partial: []check.Partial{{ID: "a", Reasons: []string{"sem root"}}},
	}}
	out := render(r, 0)
	if strings.Contains(out, "COBERTURA") {
		t.Errorf("a SEÇÃO de cobertura deve ficar oculta por padrão:\n%s", out)
	}
	if !strings.Contains(out, "cobertura 19/104") {
		t.Errorf("o NÚMERO de cobertura DEVE ficar no resumo (invariante):\n%s", out)
	}
	if !strings.Contains(out, "--coverage") {
		t.Errorf("cobertura incompleta e oculta precisa da dica --coverage:\n%s", out)
	}
	if strings.Contains(render(r, 1), "COBERTURA") {
		t.Error("o -v sozinho NÃO liga a seção (é evidência, outro eixo)")
	}
	if !strings.Contains(render(r, 2), "COBERTURA") {
		t.Error("-vv (o 'mostra tudo') DEVE ligar a seção")
	}
	if !strings.Contains(renderCob(r), "COBERTURA") {
		t.Error("--coverage deve mostrar a seção")
	}
}

// Lacuna de coleta aparece num eixo próprio e NÃO entra na conta de checks.
func TestLacunaDeColetaTemLinhaPropria(t *testing.T) {
	r := &check.Report{Coverage: check.Coverage{
		Total: 3, Complete: 3,
		CollectorGaps: []string{"proc: 250 processos com fds ilegíveis (sem permissão)"},
	}}
	out := renderCob(r)
	if !strings.Contains(out, "coleta") || !strings.Contains(out, "250 processos") {
		t.Errorf("a lacuna de coleta precisa de linha própria:\n%s", out)
	}
	if !strings.Contains(out, "3/3 completos") {
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
	// A salvaguarda dispara pelo CAMPO Irreversible, não por casar o texto: um
	// comando totalmente diferente ainda avisa. O comando em si fica no -v.
	if !strings.Contains(render(r, 0), "preserve ANTES de matar") {
		t.Error("a promoção deve ser pelo campo, não pelo texto do comando")
	}
	if !strings.Contains(render(r, 1), "dd if=/proc/42/mem") {
		t.Error("o comando de preservação precisa estar no -v")
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

	// -v traz o FATO (evidência); o FP (explicação) desce para -vv, para o -v
	// não virar parede de prosa.
	verbose := render(r, 1)
	if !strings.Contains(verbose, "exe=/memfd:x") {
		t.Errorf("-v precisa do fato (evidência):\n%s", verbose)
	}
	if strings.Contains(verbose, "runtime que usa memfd") {
		t.Error("-v NÃO deve trazer o FP (explicação): isso é -vv")
	}
	vv := render(r, 2)
	for _, want := range []string{"exe=/memfd:x", "FP:", "runtime que usa memfd"} {
		if !strings.Contains(vv, want) {
			t.Errorf("-vv sem %q:\n%s", want, vv)
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

	// A entidade correlacionada pid=19 sai numa linha com os rótulos dos 3
	// sinais e a contagem — a "história" do incidente, escaneável.
	if !strings.Contains(out, "pid=19") || !strings.Contains(out, "×3") {
		t.Errorf("o alvo correlacionado não apareceu com a contagem:\n%s", out)
	}
	if !strings.Contains(out, "revshell") {
		t.Errorf("os rótulos curtos dos sinais devem aparecer:\n%s", out)
	}
	// O alvo com um sinal só continua na lista.
	if !strings.Contains(out, "pid=77") {
		t.Errorf("o alvo com um sinal só precisa continuar aparecendo:\n%s", out)
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
	// terse: a entidade /x sai numa linha com os rótulos dos dois sinais.
	out := render(r, 0)
	if !strings.Contains(out, "/x") {
		t.Fatalf("o grupo tinha que se formar pelo ator:\n%s", out)
	}
	// -v: o sujeito PRÓPRIO de cada achado (pid=7) sobrevive no detalhe.
	outv := render(r, 1)
	if !strings.Contains(outv, "pid=7") {
		t.Errorf("o pid do achado de rede sumiu do detalhe -v:\n%s", outv)
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

	// terse: /x com a contagem real de achados (21).
	out := render(r, 0)
	if !strings.Contains(out, "×21") {
		t.Errorf("a contagem do alvo tem que ser a real (21):\n%s", out)
	}
	// -v: o detalhe corta os membros repetidos e diz quantos sobraram.
	outv := render(r, 1)
	if !strings.Contains(outv, "iguais") {
		t.Errorf("o que passou do teto de membros tem que aparecer como contagem:\n%s", outv)
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
	// O alvo correlacionado /x sai numa linha só, com a contagem de achados (22)
	// e os rótulos curtos dos sinais. Sem paredão: o operador escaneia.
	if !strings.Contains(out, "/x") || !strings.Contains(out, "×22") {
		t.Errorf("o correlacionado /x deve sair numa linha com ×22:\n%s", out)
	}
	if !strings.Contains(out, "egress_unowned") {
		t.Errorf("os rótulos curtos dos sinais devem aparecer:\n%s", out)
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

// O bloco mais forte que este relatório imprime: depois que o kernel se
// contradisse, ele não rebaixa achado — ele invalida AUSÊNCIA. Precisa dizer as
// três coisas: o que continua valendo, o que deixou de valer, e para onde ir.
func TestBlocoDeKernelContraditorioDizOQueFazer(t *testing.T) {
	r := &check.Report{
		KernelTrustBroken: []string{"um PID responde a /proc/<pid> e não apareceu na listagem"},
	}
	var b bytes.Buffer
	writeResult(&b, temaPara(false), r)
	got := b.String()

	for _, quer := range []string{
		"O KERNEL SE CONTRADISSE",
		"Os ACHADOS acima continuam valendo",
		"O que deixou de valer é a AUSÊNCIA",
		"scan --root",
	} {
		if !strings.Contains(got, quer) {
			t.Errorf("o bloco precisa conter %q:\n%s", quer, got)
		}
	}
}
