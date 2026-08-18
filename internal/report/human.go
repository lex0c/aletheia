// Package report renderiza o resultado. Compactação é decisão de EXIBIÇÃO:
// o JSONL nunca é afetado pelo nível de verbosidade, senão a agregação de
// frota passaria a depender de qual flag o operador usou (SPEC 7.1).
package report

import (
	"fmt"
	"io"
	"sort"
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

	// Baseline descreve a referência usada, quando houve uma. Nil = nenhuma.
	Baseline *BaselineInfo

	// Janela descreve o recorte temporal, quando houve um, e o âncora derivado.
	Janela *JanelaInfo

	// IOC descreve a lista de indicadores usada, quando houve uma. Vazio =
	// nenhuma. É obrigatório dizer: uma varredura que procurou por dez
	// indicadores e uma que procurou por dois, de uma lista mal entendida,
	// terminam iguais no papel se ninguém contar quantos entraram.
	IOC *IOCInfo

	// Analise diz que este relatório NÃO descreve o host agora: descreve o
	// retrato que alguém tirou dele, em outro lugar e em outra hora. Nil = a
	// execução olhou o host de verdade.
	Analise *AnaliseInfo
}

// AnaliseInfo é o que o relatório precisa dizer quando os fatos vieram de um
// dump.
//
// Sem este bloco, um `analyze` de três dias atrás é visualmente idêntico a um
// `scan` de agora — mesmo cabeçalho, mesmo veredito, mesmo exit code. O
// operador leria "RESULT: OK" e concluiria que o host está limpo NESTE momento,
// que é uma afirmação que ninguém fez.
type AnaliseInfo struct {
	Arquivo     string
	ColetadoEm  string
	ColetadoPor string
	ColetaSHA   string

	AnalisadoPor string
	AnalisadoEm  string

	// Estranhas são capacidades que o dump declara e este binário não conhece:
	// a coleta é de uma versão MAIS NOVA, e há um eixo que esta análise ignorou.
	Estranhas []string
}

// JanelaInfo é o que o relatório precisa dizer sobre o recorte temporal.
//
// Existe pelo mesmo motivo do bloco de baseline, e com mais razão: a baseline
// REBAIXA achado, a janela o REMOVE. Quem remove precisa dizer o que removeu.
type JanelaInfo struct {
	Desde string
	Spec  string
	// Fora é quanto ficou de fora, e ForaTexto descreve por severidade.
	Fora        int
	ForaTexto   string
	MaisRecente string
	// SemData são os achados sem data, que FICARAM.
	SemData int

	// Ancora é a data de referência da investigação (§9), com a origem dela.
	Ancora       string
	AncoraOrigem string
	AncoraDe     string
}

// IOCInfo é o que o relatório precisa dizer sobre a lista de indicadores.
type IOCInfo struct {
	Arquivo string
	Total   int
	Resumo  string
	// Avisos são as linhas da lista que o leitor NÃO entendeu.
	Avisos []string
}

// BaselineInfo é o que o relatório precisa dizer sobre a referência usada.
//
// Uma baseline REBAIXA achado, e autoridade que rebaixa precisa ser examinável:
// de onde veio, de quando, quantos achados calou e por que se deve ou não
// confiar nela. Sem isso o operador lê um relatório mais limpo sem saber que
// alguém limpou.
type BaselineInfo struct {
	Host       string
	CapturedAt string
	Conhecidos int
	Rebaixados int
	// SemChave conta os achados que não puderam ser comparados com a baseline.
	// Eles não são novos nem conhecidos: são indiferenciáveis, e dizer o número
	// é o que impede a comparação de parecer completa.
	SemChave  int
	Ressalvas []string
}

// Human escreve o relatório de decisão: uma linha por GRUPO de achado, bloco
// de ação, rodapé de cobertura. ~18 linhas independentemente do tamanho do
// incidente.
func Human(w io.Writer, r *check.Report, f *facts.Facts, e *env.Env, o Options) {
	writeHeader(w, f, e)
	writeAnalise(w, o.Analise)
	writeBaseline(w, o.Baseline)
	writeJanela(w, o.Janela)
	writeIOC(w, o.IOC)

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

	// Safe também na versão da ferramenta: num `analyze`, ela vem do DUMP —
	// que é dado do alvo, e portanto escolhido por quem controlava o host.
	fmt.Fprintf(w, "relógio %s · %s · modo %s · aletheia %s\n",
		e.Clock, e.Now.Format("2006-01-02T15:04:05Z"), e.Source,
		Safe(nz(e.ToolVersion, "dev")))
	fmt.Fprintln(w)
}

// writeAnalise avisa, antes de qualquer achado, que o relatório descreve um
// RETRATO e não o host de agora.
//
// A linha que importa é a última: a cobertura é a da coleta. É ela que impede a
// leitura errada de um `analyze` rodado numa estação com root sobre um dump
// feito sem root — os números são os de lá, e melhorá-los aqui seria afirmar
// que alguém olhou o que ninguém olhou.
func writeAnalise(w io.Writer, a *AnaliseInfo) {
	if a == nil {
		return
	}
	fmt.Fprintf(w, "ANÁLISE DE COLETA · %s\n", Safe(a.Arquivo))
	fmt.Fprintf(w, "  coletado em %s por %s\n",
		Safe(nz(a.ColetadoEm, "data ilegível no dump")), Safe(nz(a.ColetadoPor, "ferramenta não declarada")))
	if a.ColetaSHA != "" {
		fmt.Fprintf(w, "  binário da coleta sha256=%s\n", Safe(a.ColetaSHA))
	}
	fmt.Fprintf(w, "  analisado em %s por %s\n", Safe(a.AnalisadoEm), Safe(a.AnalisadoPor))
	for _, c := range a.Estranhas {
		fmt.Fprintf(w, "  ⚠ a coleta declarou a capacidade %q, que esta versão não conhece:\n"+
			"    há um eixo aqui que ESTA análise ignorou — use a versão que coletou\n", Safe(c))
	}
	fmt.Fprintln(w, "  nada foi olhado agora: os fatos e a COBERTURA são os da coleta")
	fmt.Fprintln(w)
}

// maxSinaisPorGrupo é o teto de linhas de um alvo correlacionado no resumo. O
// que passa disso vira uma linha com a contagem, e nunca desaparece.
const maxSinaisPorGrupo = 8

// sinal é uma linha do bloco de um alvo, com quantos achados idênticos ela
// representa.
type sinal struct {
	fd check.Finding
	n  int
}

// sinaisDoGrupo junta o que é REPETIÇÃO dentro do bloco de um alvo.
//
// O caso apareceu no primeiro host real: o `adb` escuta em duas portas, o check
// de listener emitiu dois achados de mesmo ID e mesmo pid, e o bloco imprimiu
// duas linhas idênticas — o que distingue as duas está na evidência, não no
// título. Solto, isso já vinha compactado como "2×"; dentro do grupo voltava a
// ser texto repetido sem motivo aparente, que faz o operador procurar uma
// diferença que a linha não mostra.
//
// A contagem fica, porque duas portas não são uma. Some só a duplicata visual.
func sinaisDoGrupo(g check.SubjectGroup) []sinal {
	var out []sinal
	pos := map[string]int{}
	for _, fd := range g.Findings {
		k := fd.ID + "\x00" + fd.Subject
		if i, ok := pos[k]; ok {
			out[i].n++
			continue
		}
		pos[k] = len(out)
		out = append(out, sinal{fd: fd, n: 1})
	}
	return out
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
		sinais := sinaisDoGrupo(g)
		for i, e := range sinais {
			// Antes do ator, um grupo só reunia achados do MESMO sujeito e o
			// teto era o número de checks. Agora um binário acusado reúne todos
			// os processos que o executam, e um interpretador modificado com
			// quarenta processos imprimiria quarenta linhas numa seção que
			// existe para caber na tela. O corte diz quanto sobrou e onde ver:
			// truncar em silêncio é a forma de mentir que esta ferramenta não
			// pode ter.
			//
			// As duas contas são sobre as LINHAS JÁ COMPACTADAS, e não sobre o
			// total bruto de achados. Misturar as duas escalas dizia "e mais
			// 14" onde faltavam 5: as oito linhas impressas podem representar
			// mais de oito achados, e a diferença ia toda para o número errado.
			if i == maxSinaisPorGrupo && len(sinais) > maxSinaisPorGrupo+1 {
				resta := 0
				for _, s := range sinais[maxSinaisPorGrupo:] {
					resta += s.n
				}
				fmt.Fprintf(w, "     · … e mais %d sinal(is) no mesmo alvo — `-v` mostra todos\n", resta)
				break
			}
			fd := e.fd
			line := "     · "
			if e.n > 1 {
				line += strconv.Itoa(e.n) + "× "
			}
			line += Safe(fd.Title) + marcaNovo(fd)
			// Quando o grupo se formou por ATOR, o sujeito próprio do achado é
			// outra coisa — `pid=17`, `sshd.service` —, e é ELE que o operador
			// usa no passo seguinte. Perdê-lo dentro do bloco trocaria uma
			// história por um alvo que ninguém consegue seguir.
			if fd.Ator != "" && fd.Subject != "" {
				line += " (" + Safe(fd.Subject) + ")"
			}
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
		line := fmt.Sprintf("%s %-13s %s%s", first.Sev.Mark(), Safe(subj),
			Safe(first.Title), marcaNovo(first))
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
// summarize agrupa as razões pela CAUSA e conta quantos checks cada uma
// degradou.
//
// A causa é o que vem antes do primeiro ":", que nestas mensagens é separador
// de rótulo: "não estamos como root: environ, dono de socket …" agrupa com
// qualquer outra que comece igual, e o operador lê UMA causa com peso em vez de
// quarenta e oito linhas quase iguais.
//
// O corte era no primeiro ":" OU "(" — e o parêntese chega cedo demais em
// português. "2 arquivo(s) com dono de pacote NÃO puderam ser comparados por
// hash (…)" virava a categoria "2 arquivo", com contagem ao lado: uma linha que
// não se lê, na seção que é a promessa central desta ferramenta. Só o ":"
// separa rótulo; o parêntese cai dentro da palavra.
func summarize(reasons []string, max int) string {
	count := map[string]int{}
	var ordem []string
	for _, r := range reasons {
		causa := r
		if i := strings.IndexByte(causa, ':'); i > 0 {
			causa = strings.TrimSpace(causa[:i])
		}
		if _, ok := count[causa]; !ok {
			ordem = append(ordem, causa)
		}
		count[causa]++
	}
	// A razão que degradou MAIS checks primeiro: é ela que o operador resolve
	// para recuperar mais cobertura de uma vez. Empate pelo texto, para que
	// duas execuções idênticas saiam iguais.
	sort.SliceStable(ordem, func(i, j int) bool {
		if count[ordem[i]] != count[ordem[j]] {
			return count[ordem[i]] > count[ordem[j]]
		}
		return ordem[i] < ordem[j]
	})

	var parts []string
	for i, s := range ordem {
		if i >= max {
			parts = append(parts, "… (+"+strconv.Itoa(len(ordem)-max)+" outras — `-v` lista cada uma)")
			break
		}
		p := corta(s, 52)
		if count[s] > 1 {
			p = strconv.Itoa(count[s]) + "× " + p
		}
		parts = append(parts, p)
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

// corta limita a n colunas, por RUNE: o texto é em português e cortar por byte
// parte um acento no meio e emite lixo no terminal. Devolve "" quando não sobra
// espaço nenhum — melhor perder o pedaço do que estourar a linha que o chamador
// prometeu.
func corta(s string, n int) string {
	if n <= 1 {
		return ""
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
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

// writeBaseline declara a referência usada, e é a primeira coisa depois do
// cabeçalho de propósito: o resto do relatório foi medido contra ela.
func writeBaseline(w io.Writer, b *BaselineInfo) {
	if b == nil {
		return
	}
	fmt.Fprintf(w, "BASELINE    %s · capturada em %s · %d achados conhecidos · %d rebaixados aqui\n",
		Safe(nz(b.Host, "?")), Safe(b.CapturedAt), b.Conhecidos, b.Rebaixados)
	if b.Rebaixados > 0 {
		fmt.Fprintln(w, "            o que já estava lá desceu um nível e CONTINUA abaixo:")
		fmt.Fprintln(w, "            estar na baseline diz que não é novo, não que é legítimo")
	}
	if b.SemChave > 0 {
		fmt.Fprintf(w, "            ⚠ %d achado(s) SEM chave estável: não são novos "+
			"nem conhecidos\n", b.SemChave)
		fmt.Fprintln(w, "            a comparação não os alcança, e por isso eles "+
			"NÃO levam a marca ✳NOVO")
	}
	for _, m := range b.Ressalvas {
		fmt.Fprintf(w, "            ⚠ %s\n", Safe(m))
	}
	fmt.Fprintln(w)
}

// writeJanela declara o recorte e o âncora.
//
// A linha que mais importa aqui é a do que ficou FORA: um crítico removido por
// uma janela mal escolhida é a diferença entre "host limpo" e "host onde eu
// mandei não olhar". E a dos SEM DATA vem junto porque explica a assimetria —
// eles ficaram, e ficaram de propósito.
func writeJanela(w io.Writer, j *JanelaInfo) {
	if j == nil {
		return
	}
	if j.Desde != "" {
		fmt.Fprintf(w, "JANELA      desde %s (--since %s)\n", Safe(j.Desde), Safe(j.Spec))
		if j.Fora > 0 {
			fmt.Fprintf(w, "            %d achado(s) FORA da janela: %s\n", j.Fora, Safe(j.ForaTexto))
			if j.MaisRecente != "" {
				fmt.Fprintf(w, "            o mais recente deles é de %s\n", Safe(j.MaisRecente))
			}
		}
		if j.SemData > 0 {
			fmt.Fprintf(w, "            %d achado(s) SEM data foram MANTIDOS: descartá-los "+
				"seria esconder por ignorância, não por escolha\n", j.SemData)
		}
	}
	if j.Ancora != "" {
		fmt.Fprintf(w, "ÂNCORA      %s · %s\n", Safe(j.Ancora), Safe(j.AncoraOrigem))
		if j.AncoraDe != "" {
			fmt.Fprintf(w, "            de %s\n", Safe(j.AncoraDe))
		}
	}
	fmt.Fprintln(w)
}

// writeIOC declara a lista usada, pelo mesmo motivo do bloco de baseline: quem
// muda o resultado da execução precisa ser examinável.
//
// O número é o que importa. Uma lista de quarenta linhas que produziu dois
// indicadores — porque a chave estava escrita errada — deixa a varredura com
// cara de limpa, e o operador conclui que o incidente não chegou neste host.
func writeIOC(w io.Writer, i *IOCInfo) {
	if i == nil {
		return
	}
	fmt.Fprintf(w, "INDICADORES %s · %d carregado(s): %s\n",
		Safe(i.Arquivo), i.Total, Safe(i.Resumo))
	for _, a := range i.Avisos {
		fmt.Fprintf(w, "            ⚠ NÃO entendido: %s\n", Safe(a))
	}
	fmt.Fprintln(w)
}

// marcaNovo destaca o achado AUSENTE da baseline.
//
// Quando há uma referência, esta é a informação mais valiosa da execução: tudo
// o que já era conhecido desceu de nível, e o que sobra em cima é o que mudou
// desde a captura. Sem a marca, o operador teria de comparar dois relatórios
// para descobrir o que a ferramenta já sabe.
//
// Fora de uma comparação a marca não aparece: sem baseline TUDO seria novo, e
// uma marca que está em toda linha não distingue nada.
func marcaNovo(fd check.Finding) string {
	if fd.Novo {
		return " ✳NOVO"
	}
	return ""
}
