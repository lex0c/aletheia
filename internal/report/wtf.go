package report

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

// maxWtfLinhas mantém a promessa de UMA TELA. O que não couber vira uma linha
// dizendo quanto ficou de fora — nunca corte silencioso.
const maxWtfLinhas = 8

// Wtf responde uma pergunta diferente do scan: acabei de ser acionado, este
// host está pegando fogo? (SPEC 6.1)
//
// Não é "scan compacto". A densidade de exibição fica parecida; o que muda é a
// COBERTURA — um punhado de checks decisivos contra o catálogo inteiro. O
// rodapé existe para que ninguém confunda os dois.
// catalogo é o total de checks registrados. Serve para o rodapé só mandar rodar
// o `scan` quando ele REALMENTE acrescenta — mandar o operador repetir trabalho
// que não muda nada é o mesmo tipo de mentira que a ferramenta evita nos
// achados.
func Wtf(w io.Writer, r *check.Report, f *facts.Facts, e *env.Env, elapsed time.Duration, catalogo int) {
	writeWtfHeader(w, f, e)

	sobra := catalogo - r.Coverage.Total

	if len(r.Findings) == 0 {
		fmt.Fprintf(w, "✓ nenhum indicador decisivo em %d checks (%s)\n", r.Coverage.Total, dur(elapsed))
		fmt.Fprintln(w, "  isto NÃO significa host limpo (runbook §35.8)."+maisChecks(sobra))
		fmt.Fprintln(w)
	} else {
		writeWtfFindings(w, r)
	}

	writeWtfGaps(w, r)
	writeWtfResult(w, r, elapsed, sobra)
}

func maisChecks(sobra int) string {
	if sobra <= 0 {
		return ""
	}
	return " Para o resto: aletheia scan (+" + strconv.Itoa(sobra) + " checks)"
}

func writeWtfHeader(w io.Writer, f *facts.Facts, e *env.Env) {
	h := f.Host
	var b strings.Builder
	b.WriteString(Safe(nz(h.Hostname, "host-desconhecido")))
	if h.Kernel != "" {
		b.WriteString(" · " + Safe(h.Kernel))
	}
	if h.Virt != "" {
		b.WriteString(" · " + Safe(h.Virt))
	}
	if h.Uptime != "" {
		b.WriteString(" · up " + Safe(h.Uptime))
	}
	if h.NumCPU > 0 {
		// Minerador aparece aqui na hora, e é o comprometimento nº 1 em VM de
		// nuvem. Sempre com o número de CPUs: 8.02 é catástrofe em 2 e rotina
		// em 16.
		b.WriteString(fmt.Sprintf(" · load %.2f %.2f %.2f (%d cpu%s)",
			h.Load1, h.Load5, h.Load15, h.NumCPU, cotaStr(h)))
		if h.Load1 > float64(h.NumCPU)*1.5 {
			b.WriteString(" ⚠")
		}
	}
	fmt.Fprintln(w, b.String())

	// Relógio primeiro: sem ele, todo horário abaixo é frágil (runbook §9).
	fmt.Fprintf(w, "relógio %s · %s · %s\n\n",
		e.Clock, e.Now.Format("2006-01-02T15:04:05Z"), contagens(f))
}

// contagens é o enquadramento que sai de graça da mesma coleta.
func contagens(f *facts.Facts) string {
	estab, pub := 0, 0
	for _, s := range f.Sockets {
		switch {
		case s.State == "ESTAB":
			estab++
		case s.Dir == facts.DirListen && facts.IsExposedLocal(s.LocalIP):
			pub++
		}
	}
	return fmt.Sprintf("%d proc · %d estab · %d listen fora de loopback",
		len(f.Processes), estab, pub)
}

func writeWtfFindings(w io.Writer, r *check.Report) {
	// O denominador conta só o que SERIA impresso: usar len(r.Findings) incluiria
	// os INFO, que nunca aparecem, e a linha prometeria achados inexistentes.
	total := 0
	for _, fd := range r.Findings {
		if fd.Sev != check.SevInfo {
			total++
		}
	}
	n := 0
	for _, fd := range r.Findings {
		if fd.Sev == check.SevInfo {
			continue
		}
		if n >= maxWtfLinhas {
			fmt.Fprintf(w, "   … e mais %d achados — `aletheia scan -v`\n\n", total-n)
			return
		}
		n++

		fmt.Fprintln(w, pad(fmt.Sprintf("%s %-12s %s",
			fd.Sev.Mark(), Safe(fd.Subject), Safe(fd.Title)), 74)+"§"+Safe(fd.Ref))

		// Só o crítico ganha evidência: o wtf decide POR ONDE COMEÇAR, e
		// detalhar o aviso rouba a tela do que precisa de ação agora.
		if fd.Sev != check.SevCritical {
			continue
		}
		for i, ev := range fd.Evidence {
			if i >= 2 {
				break
			}
			fmt.Fprintln(w, "             "+Safe(ev))
		}
		// O passo irreversível — e só ele. O resto é trabalho do scan.
		if fd.Irreversible {
			for _, ns := range fd.NextSteps {
				if strings.HasPrefix(ns, "sudo ") {
					fmt.Fprintln(w, "             → "+Safe(ns))
					break
				}
			}
		}
	}
	fmt.Fprintln(w)
}

// writeWtfGaps cabe em UMA linha, e é a linha que impede a tela inteira de ser
// lida como "host limpo".
//
// Os motivos de check vêm juntos, não em blocos separados: "não estamos como
// root" aparece como NÃO VERIFICADO em uns e como PARCIAL em outros, e listar
// os dois gasta a linha repetindo a mesma frase.
//
// Lacuna de COLETA não entra na mesma soma: ela já vem prefixada pelo coletor
// ("proc: …"), e resumir por prefixo produziria "net: 1 · proc: 4" — que não
// informa nada. Vira contagem, e o detalhe fica com o scan.
func writeWtfGaps(w io.Writer, r *check.Report) {
	c := r.Coverage
	motivos := append(reasonsOf(c.NotChecked), partialReasons(c)...)

	var parts []string
	if len(motivos) > 0 {
		// Recorte por largura: um motivo de cobertura é uma frase inteira no
		// scan, e aqui ele divide a linha com os outros.
		parts = append(parts, clip(summarize(motivos, 2), 60))
	}
	if n := len(c.CollectorGaps); n > 0 {
		parts = append(parts, "coleta: "+strconv.Itoa(n)+" lacunas")
	}
	if len(parts) == 0 {
		return
	}
	fmt.Fprintln(w, "não verificado: "+Safe(strings.Join(parts, " · "))+
		"  —  `aletheia scan` detalha")
}

func partialReasons(c check.Coverage) []string {
	var out []string
	for _, p := range c.Partial {
		out = append(out, p.Reasons...)
	}
	return out
}

// writeWtfResult é obrigatório e sempre diz que isto NÃO foi varredura. É o
// comando com maior risco de ser lido como "host limpo".
func writeWtfResult(w io.Writer, r *check.Report, elapsed time.Duration, sobra int) {
	fmt.Fprintf(w, "RESULT: %s — %d checks em %s.", r.Verdict(), r.Coverage.Total, dur(elapsed))
	if sobra > 0 {
		fmt.Fprintf(w, " Isto NÃO é varredura: rode `aletheia scan` (+%d checks)", sobra)
	} else {
		// Enquanto o catálogo couber inteiro no orçamento, mandar rodar o scan
		// seria pedir para repetir exatamente o mesmo trabalho.
		fmt.Fprint(w, " Triagem rápida, não varredura de disco nem de persistência")
	}
	fmt.Fprintln(w)
}

// Oneline é uma linha por host, para triagem de FROTA (SPEC 6.1). Com dezenas
// de hosts, responde por onde começar — que é a decisão mais cara do início de
// um incidente de frota (runbook §23).
//
// O hostname NÃO entra: quem varre a frota já sabe em qual host mandou rodar, e
// prefixa a linha com ele.
func Oneline(w io.Writer, r *check.Report) {
	tokens := onelineTokens(r)
	if len(tokens) == 0 {
		tokens = []string{"—"}
	}
	line := fmt.Sprintf("%-10s %s", r.Verdict(), strings.Join(tokens, " "))
	// A cobertura entra na linha SEMPRE que estiver degradada. Sem ela, um host
	// onde metade não rodou aparece na frota igual a um host varrido inteiro —
	// e é exatamente esse host que precisa de atenção primeiro.
	if r.Coverage.Incomplete() {
		line += fmt.Sprintf("  [cobertura %d/%d]", r.Coverage.Complete, r.Coverage.Total)
	}
	fmt.Fprintln(w, Safe(line))
}

func onelineTokens(r *check.Report) []string {
	var out []string
	for _, g := range r.Grouped() {
		first := g.First()
		if first.Sev == check.SevInfo {
			continue
		}
		name := first.ID
		if i := strings.LastIndexByte(name, '.'); i >= 0 {
			name = name[i+1:]
		}
		var subj []string
		for i, fd := range g.Findings {
			if i >= 3 {
				subj = append(subj, "+"+strconv.Itoa(g.N()-3))
				break
			}
			if v := subjectValue(fd.Subject); v != "" {
				subj = append(subj, v)
			}
		}
		if len(subj) > 0 {
			name += "(" + strings.Join(subj, ",") + ")"
		}
		out = append(out, name)
	}
	return out
}

// subjectValue tira o rótulo: "pid=6574" vira "6574". Numa linha por host, o
// rótulo repetido gasta a largura que os alvos precisam.
func subjectValue(s string) string {
	if i := strings.IndexByte(s, '='); i >= 0 {
		return s[i+1:]
	}
	return s
}

// clip corta por RUNE, não por byte: os motivos são em português e cortar no
// meio de um caractere multibyte produz lixo no terminal.
func clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

func dur(d time.Duration) string {
	if d < time.Second {
		return strconv.FormatInt(d.Milliseconds(), 10) + "ms"
	}
	return strconv.FormatFloat(d.Seconds(), 'f', 2, 64) + "s"
}
