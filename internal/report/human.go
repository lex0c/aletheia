// Package report renderiza o resultado. Compactação é decisão de EXIBIÇÃO:
// o JSONL nunca é afetado pelo nível de verbosidade, senão a agregação de
// frota passaria a depender de qual flag o operador usou (SPEC 7.1).
package report

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

// Options controla apenas a apresentação.
type Options struct {
	Verbose int  // 0 = decisão, 1 = investigação, 2 = + INFO e detalhe
	Color   bool // reservado; o padrão é texto puro para caber em ticket
}

// Human escreve o relatório de decisão: uma linha por GRUPO de achado, bloco
// de ação, rodapé de cobertura. ~18 linhas independentemente do tamanho do
// incidente.
func Human(w io.Writer, r *check.Report, f *facts.Facts, e *env.Env, o Options) {
	writeHeader(w, f, e)

	if o.Verbose > 0 {
		writeVerbose(w, r, o)
	} else {
		writeCompact(w, r)
	}

	writeNextSteps(w, r)
	writeCoverage(w, r, o)
	writeResult(w, r)
}

func writeHeader(w io.Writer, f *facts.Facts, e *env.Env) {
	h := f.Host
	var b strings.Builder
	b.WriteString(Safe(nz(h.Hostname, "host-desconhecido")))
	if h.Kernel != "" {
		b.WriteString(" · " + Safe(h.Kernel))
	}
	if h.OS != "" {
		b.WriteString(" · " + Safe(h.OS))
	}
	if h.Virt != "" {
		b.WriteString(" · " + Safe(h.Virt))
	}
	if h.Uptime != "" {
		b.WriteString(" · up " + Safe(h.Uptime))
	}
	if h.Load1 > 0 || h.NumCPU > 0 {
		// load SEMPRE com o número de CPUs: 8.02 é catastrófico em 2 cpu e
		// normal em 16. Sem o contexto, o alerta vira ruído justamente no
		// sinal de minerador.
		l := fmt.Sprintf(" · load %.2f (%d cpu%s)", h.Load1, h.NumCPU, cotaStr(h))
		if h.NumCPU > 0 && h.Load1 > float64(h.NumCPU)*1.5 {
			l += " ⚠"
		}
		b.WriteString(l)
	}
	fmt.Fprintln(w, b.String())

	fmt.Fprintf(w, "relógio %s · %s · modo %s · aletheia %s\n",
		e.Clock, e.Now.Format("2006-01-02T15:04:05Z"), e.Source, nz(e.ToolVersion, "dev"))
	fmt.Fprintln(w)
}

func writeCompact(w io.Writer, r *check.Report) {
	crit, warn, manual, _ := r.Counts()
	cov := r.Coverage
	fmt.Fprintf(w, "⛔ %d   ⚠ %d   ◆ %d manuais   ·   cobertura %d/%d\n\n",
		crit, warn, manual, cov.Complete, cov.Total)

	if len(r.Findings) == 0 {
		fmt.Fprintln(w, "✓ nenhum indicador coberto disparou")
		fmt.Fprintln(w)
		return
	}

	// O mesmo alvo visto por checks diferentes vem PRIMEIRO e junto: é a forma
	// de um incidente, e listá-lo solto contaria quatro fatos onde há uma
	// história.
	grupos, resto := r.Correlate()
	for _, g := range grupos {
		fmt.Fprintf(w, "%s %-13s %d sinais no mesmo alvo\n",
			g.Sev().Mark(), Safe(g.Subject), len(g.Findings))
		for _, fd := range g.Findings {
			line := "     · " + Safe(fd.Title)
			if fd.Downgraded {
				line += " ⚠rebaixado"
			}
			fmt.Fprintln(w, pad(line, 76)+"§"+Safe(fd.Ref))
		}
	}
	if len(grupos) > 0 && len(resto) > 0 {
		fmt.Fprintln(w)
	}

	for _, g := range check.GroupByIDSev(resto) {
		first := g.First()
		if first.Sev == check.SevInfo {
			continue
		}
		subj := first.Subject
		if g.N() > 1 {
			subj = strconv.Itoa(g.N()) + "×"
		}
		line := fmt.Sprintf("%s %-13s %s", first.Sev.Mark(), Safe(subj), Safe(first.Title))
		if g.N() > 1 {
			line += " (" + Safe(g.Subjects(3)) + ")"
		}
		if first.Downgraded {
			line += " ⚠rebaixado"
		}
		fmt.Fprintln(w, pad(line, 76)+"§"+first.Ref)
	}
	fmt.Fprintln(w)
}

// grouped compacta por ID: "8× exe em local suspeito" no lugar de oito linhas.
// É a outra metade da leitura — o mesmo check em muitos alvos, contra muitos
// checks no mesmo alvo.
func writeVerbose(w io.Writer, r *check.Report, o Options) {
	var lastSev check.Severity = -1
	for _, fd := range r.Findings {
		if fd.Sev == check.SevInfo && o.Verbose < 2 {
			continue
		}
		if fd.Sev != lastSev {
			fmt.Fprintf(w, "════ %s %s\n\n", fd.Sev, strings.Repeat("═", max(0, 62-len(fd.Sev.String()))))
			lastSev = fd.Sev
		}
		head := fmt.Sprintf("%s %-40s §%-6s %s", fd.Sev.Mark(), Safe(fd.ID), Safe(fd.Ref), fd.Origin)
		if fd.Downgraded {
			head += " ⚠rebaixado"
		}
		fmt.Fprintln(w, head)
		if fd.Subject != "" {
			fmt.Fprintln(w, "   "+Safe(fd.Subject))
		}
		fmt.Fprintln(w, "   "+Safe(fd.Title))
		for _, ev := range fd.Evidence {
			fmt.Fprintln(w, "   · "+Safe(ev))
		}
		for _, ns := range fd.NextSteps {
			fmt.Fprintln(w, "   → "+Safe(ns))
		}
		if len(fd.FalsePositives) > 0 {
			fmt.Fprintln(w, "   FP: "+Safe(strings.Join(fd.FalsePositives, " · ")))
		}
		fmt.Fprintln(w)
	}
}

// writeNextSteps adapta: com crítico, é a ordem do runbook §19; só com aviso,
// vira "revise antes de agir"; sem nada, some.
func writeNextSteps(w io.Writer, r *check.Report) {
	crit, warn, _, _ := r.Counts()
	if crit == 0 && warn == 0 {
		return
	}

	if crit == 0 {
		fmt.Fprintln(w, "Revise os avisos antes de qualquer ação. Ordem em runbook §19.")
		fmt.Fprintln(w)
		return
	}

	fmt.Fprintln(w, "AGORA, nesta ordem (runbook §19 — não inverta):")
	n := 1
	// O passo irreversível vem primeiro. A seleção é pelo campo Irreversible,
	// não por casar o texto do comando: acoplar por string faz uma reescrita
	// inocente silenciar o passo que não pode ser pulado, com todos os testes
	// continuando verdes.
	// Deduplicado por COMANDO, não por achado: num implante de verdade, três
	// checks disparam no mesmo PID e cada um contribui o mesmo `cp /proc/N/exe`.
	// Repetir a linha três vezes transforma uma lista de ações numa parede — e
	// o bloco existe justamente para ser a lista curta do que fazer AGORA.
	// A chave da deduplicação é o COMANDO, não a linha: dois checks podem
	// contribuir o mesmo `cp` com comentários diferentes, e comparar a linha
	// inteira deixaria os dois passarem. Foi como este defeito voltou depois de
	// corrigido — pela porta do comentário.
	var cmds []string
	vistos := map[string]bool{}
	for _, fd := range r.Irreversible() {
		for _, ns := range fd.NextSteps {
			if !strings.HasPrefix(ns, "sudo ") {
				continue
			}
			chave := strings.TrimSpace(ns)
			if i := strings.Index(chave, "#"); i > 0 {
				chave = strings.TrimSpace(chave[:i])
			}
			if vistos[chave] {
				// `continue`, não `break`: o achado ainda pode contribuir com um
				// comando DIFERENTE mais adiante na lista dele. Interromper aqui
				// fazia um achado cujo primeiro passo já apareceu não contribuir
				// com nada — e o passo perdido costuma ser o `gcore`, que é o
				// único jeito de preservar a memória antes de matar.
				continue
			}
			vistos[chave] = true
			cmds = append(cmds, ns)
			break
		}
	}
	for i, c := range cmds {
		if i >= 3 {
			fmt.Fprintf(w, "     (…e mais %d comandos de preservação — veja -v)\n", len(cmds)-3)
			break
		}
		fmt.Fprintf(w, "  %d. %s   ← irreversível se pulado\n", n, Safe(c))
		n++
	}
	fmt.Fprintf(w, "  %d. isolar na camada de REDE, não no host (runbook §18)\n", n)
	fmt.Fprintf(w, "  %d. remover persistência ANTES de matar (runbook §19)\n", n+1)
	fmt.Fprintln(w)
}

func writeCoverage(w io.Writer, r *check.Report, o Options) {
	c := r.Coverage
	nPartial, nNot := len(c.Partial), len(c.NotChecked)

	fmt.Fprintf(w, "COBERTURA   completos %d · parciais %d · não verificados %d · total %d\n",
		c.Complete, nPartial, nNot, c.Total)

	if nNot > 0 {
		if o.Verbose > 0 {
			for _, nc := range c.NotChecked {
				fmt.Fprintf(w, "  não verificado  %s (§%s) — %s\n", Safe(nc.ID), Safe(nc.Ref), Safe(nc.Reason))
			}
		} else {
			fmt.Fprintln(w, "  não verificado  "+Safe(summarize(reasonsOf(c.NotChecked), 3)))
		}
	}
	if len(c.CollectorGaps) > 0 {
		for _, g := range c.CollectorGaps {
			fmt.Fprintln(w, "  coleta          "+Safe(g))
		}
	}
	if nPartial > 0 {
		if o.Verbose > 0 {
			for _, p := range c.Partial {
				fmt.Fprintf(w, "  parcial         %s (§%s) — %s\n", Safe(p.ID), Safe(p.Ref), Safe(strings.Join(p.Reasons, " · ")))
			}
		} else {
			var rs []string
			for _, p := range c.Partial {
				rs = append(rs, p.Reasons...)
			}
			fmt.Fprintln(w, "  parcial         "+Safe(summarize(rs, 3)))
		}
	}
	fmt.Fprintln(w)
}

func writeResult(w io.Writer, r *check.Report) {
	crit, warn, manual, _ := r.Counts()
	v := r.Verdict()
	fmt.Fprintf(w, "RESULT: %s", v)

	switch v {
	case "OK":
		fmt.Fprintf(w, " — %d/%d checks. Nenhum indicador coberto disparou.\n", r.Coverage.Complete, r.Coverage.Total)
		fmt.Fprintln(w, "        Isto NÃO prova que o host está limpo (runbook §35.8).")
	case "INCOMPLETE":
		miss := r.Coverage.Total - r.Coverage.Complete
		switch {
		case miss > 0:
			fmt.Fprintf(w, " — 0 achados, mas %d checks não cobriram o que deveriam.\n", miss)
		default:
			fmt.Fprintf(w, " — 0 achados, mas a coleta não conseguiu ler tudo (%d lacunas).\n",
				len(r.Coverage.CollectorGaps))
		}
		fmt.Fprintln(w, "        Isto NÃO é o mesmo que host limpo (runbook §35.8).")
	default:
		fmt.Fprintf(w, "        %d críticos · %d avisos · %d manuais · cobertura %d/%d\n",
			crit, warn, manual, r.Coverage.Complete, r.Coverage.Total)
	}

	if len(r.TrustBroken) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "CONFIANÇA REBAIXADA — achados vindos de binário do host não valem como prova:")
		for _, t := range dedupe(r.TrustBroken) {
			fmt.Fprintln(w, "  · "+Safe(t))
		}
	}
}

// --- utilitários de formatação ---

func reasonsOf(ncs []check.NotChecked) []string {
	out := make([]string, 0, len(ncs))
	for _, n := range ncs {
		out = append(out, n.Reason)
	}
	return out
}

// summarize agrupa motivos repetidos: "sem root: 14 · debugfs não montado: 2".
func summarize(reasons []string, max int) string {
	count := map[string]int{}
	var order []string
	for _, r := range reasons {
		short := r
		if i := strings.IndexAny(short, ":("); i > 0 {
			short = strings.TrimSpace(short[:i])
		}
		if _, ok := count[short]; !ok {
			order = append(order, short)
		}
		count[short]++
	}
	var parts []string
	for i, s := range order {
		if i >= max {
			parts = append(parts, "…")
			break
		}
		parts = append(parts, s+": "+strconv.Itoa(count[s]))
	}
	return strings.Join(parts, " · ")
}

func dedupe(ss []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func pad(s string, n int) string {
	// contagem por runes: o marcador de severidade é multibyte
	if r := len([]rune(s)); r < n {
		return s + strings.Repeat(" ", n-r)
	}
	return s + " "
}

// cotaStr mostra a cota de cgroup quando existe. O load vem de /proc/loadavg,
// que NÃO é isolado por namespace: dentro de contêiner ele descreve o HOST,
// enquanto a cota descreve a fatia que este alvo recebe. São coisas diferentes,
// e por isso a cota aparece como contexto e não muda o limiar do aviso.
func cotaStr(h facts.Host) string {
	if h.CPUQuota <= 0 {
		return ""
	}
	return " · cota " + strconv.FormatFloat(h.CPUQuota, 'g', 3, 64)
}

func nz(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
