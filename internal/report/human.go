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

	// Largura é a largura do terminal de saída em colunas (0 = desconhecida,
	// pipe/arquivo). A lista de foco quebra em duas linhas num TTY estreito.
	Largura int

	// Coverage mostra a SEÇÃO de cobertura (as causas e os gaps de coleta). Por
	// padrão ela fica oculta — mas o NÚMERO (cobertura X/Y) continua no resumo
	// do topo e alimenta o veredito INCOMPLETE e o "não prova host limpo". A
	// invariante "não olhei ≠ não há" vive no número; só o detalhe é opcional.
	Coverage bool

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
	t := temaPara(o.Color)
	writeHeader(w, t, f, e)
	writeAnalise(w, o.Analise)
	writeBaseline(w, o.Baseline)
	writeJanela(w, o.Janela)
	writeIOC(w, o.IOC)

	// O CORPO é a lista de decisão: veredito, uma linha por entidade que precisa
	// de atenção (id local, entidade, o que é — sem §ref, sem prosa), o contexto
	// resumido e o que fazer AGORA. O operador escaneia, não lê.
	// A SEÇÃO de cobertura sai com --coverage OU com -vv (o "mostra tudo"). O -v
	// sozinho NÃO a liga — ele é evidência por achado, um eixo diferente. O
	// número fica sempre no resumo: o default é enxuto sem esconder a invariante.
	mostrarCob := o.Coverage || o.Verbose >= 2
	writeSumario(w, t, r, mostrarCob)
	itens, _ := itensDeFoco(r)
	writeFoco(w, t, itens, o.Largura)
	writeContext(w, t, r)
	writeNextSteps(w, t, r)

	// O DETALHE — evidência por entidade — é do investigador, e só sai no -v,
	// abaixo da régua. O default fica escaneável.
	if o.Verbose > 0 {
		if len(r.Findings) > 0 {
			fmt.Fprintln(w, t.regua())
			fmt.Fprintln(w)
		}
		writeVerbose(w, t, r, o)
	}

	if mostrarCob {
		writeCoverage(w, t, r, o)
	}
	writeResult(w, t, r)
}

func writeHeader(w io.Writer, t Tema, f *facts.Facts, e *env.Env) {
	h := f.Host
	// O HOSTNAME é a identidade — a primeira pergunta do operador ("que host é
	// este?"). Vem em NEGRITO; kernel, OS e uptime são contexto e saem
	// esmaecidos. O load é contexto também, mas vira SINAL quando alto (>1.5×
	// cpu): aí sai em amarelo, porque é o rastro nº 1 de minerador — e SEMPRE
	// com o número de cpus, que 8.02 é catástrofe em 2 cpu e normal em 16.
	var ctx []string
	if h.Kernel != "" {
		ctx = append(ctx, Safe(h.Kernel))
	}
	if h.OS != "" {
		ctx = append(ctx, Safe(h.OS))
	}
	if h.Virt != "" {
		ctx = append(ctx, Safe(h.Virt))
	}
	if h.Uptime != "" {
		ctx = append(ctx, "up "+Safe(h.Uptime))
	}
	linha := t.negrito(Safe(nz(h.Hostname, "host-desconhecido")))
	if len(ctx) > 0 {
		linha += t.fraco(" · " + strings.Join(ctx, " · "))
	}
	if h.Load1 > 0 || h.NumCPU > 0 {
		lc := fmt.Sprintf("load %.2f (%d cpu%s)", h.Load1, h.NumCPU, cotaStr(h))
		if h.NumCPU > 0 && h.Load1 > float64(h.NumCPU)*1.5 {
			linha += " · " + t.pintaSev(check.SevWarn, lc+" ⚠")
		} else {
			linha += t.fraco(" · " + lc)
		}
	}
	fmt.Fprintln(w, linha)

	// A linha de meta — relógio, instante, modo, versão — é toda secundária.
	// Safe na versão: num `analyze` ela vem do DUMP, dado escolhido por quem
	// controlava o host.
	fmt.Fprintln(w, t.fraco(fmt.Sprintf("relógio %s · %s · modo %s · aletheia %s",
		e.Clock, e.Now.Format("2006-01-02T15:04:05Z"), e.Source,
		Safe(nz(e.ToolVersion, "dev")))))
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

// grouped compacta por ID: "8× exe em local suspeito" no lugar de oito linhas.
// É a outra metade da leitura — o mesmo check em muitos alvos, contra muitos
// checks no mesmo alvo.
// Tetos do detalhe -v: alvos por check e linhas de evidência por alvo. O que
// passa vira contagem, nunca some. -vv não corta.
const (
	maxMembros   = 6
	maxEvidencia = 2
)

// writeVerbose é o detalhe do INVESTIGADOR: agrupado por check (o mesmo tipo em
// N alvos vira UM bloco, não N), com os fatos de cada alvo — não a prosa. O
// título pedagógico, o §ref e os falsos-positivos saem daqui: o -v mostra O QUE
// e ONDE; o -vv acrescenta a explicação para a auditoria a fundo.
// nextStepsComuns devolve os NextSteps presentes em TODOS os membros do grupo —
// a ação GENÉRICA do check. O que NÃO está aqui é específico de um alvo (o
// `cp /path` daquele arquivo) e precisa sair por membro: senão o -v mostra N
// alvos mas só o comando de preservação do primeiro, e os outros se perdem.
func nextStepsComuns(fs []check.Finding) map[string]bool {
	if len(fs) == 0 {
		return nil
	}
	cont := map[string]int{}
	for _, fd := range fs {
		visto := map[string]bool{}
		for _, ns := range fd.NextSteps {
			if !visto[ns] {
				visto[ns] = true
				cont[ns]++
			}
		}
	}
	comum := map[string]bool{}
	for ns, n := range cont {
		if n == len(fs) {
			comum[ns] = true
		}
	}
	return comum
}

func writeVerbose(w io.Writer, t Tema, r *check.Report, o Options) {
	// ids locais na mesma ordem do topo, para o operador cruzar "olha o W3".
	_, idPorFinding := itensDeFoco(r)

	var lastSev check.Severity = -1
	for _, g := range check.GroupByIDSev(r.Findings) {
		first := g.First()
		if first.Sev == check.SevInfo && o.Verbose < 2 {
			continue
		}
		if first.Sev != lastSev {
			fmt.Fprintln(w, t.pintaSev(first.Sev, "== "+first.Sev.String()+" =="))
			fmt.Fprintln(w)
			lastSev = first.Sev
		}
		cab := t.pintaSev(first.Sev, t.etiqueta(first.Sev)) + "  " + t.negrito(Safe(first.ID))
		if g.N() > 1 {
			cab += t.fraco(" ×" + strconv.Itoa(g.N()))
		}
		if first.Downgraded {
			cab += t.fraco(" rebaixado")
		}
		fmt.Fprintln(w, cab)

		comum := nextStepsComuns(g.Findings)
		for i, fd := range g.Findings {
			if i >= maxMembros && o.Verbose < 2 && g.N() > maxMembros+1 {
				fmt.Fprintf(w, "   %s\n", t.fraco("… +"+strconv.Itoa(g.N()-i)+" iguais (use -vv)"))
				break
			}
			linha := "   " + Safe(nz(fd.Subject, fd.Title))
			if id, ok := idPorFinding[chaveFinding(fd)]; ok {
				linha = "   [" + id + "] " + Safe(nz(fd.Subject, fd.Title))
			}
			fmt.Fprintln(w, linha)
			for j, ev := range fd.Evidence {
				if j >= maxEvidencia && o.Verbose < 2 {
					fmt.Fprintf(w, "       %s\n", t.fraco("…"))
					break
				}
				fmt.Fprintln(w, "       "+Safe(ev))
			}
			// Ação ESPECÍFICA daquele alvo (o `cp /path` do arquivo), sob o
			// membro. O genérico do check sai depois, uma vez.
			for _, ns := range fd.NextSteps {
				if !comum[ns] {
					fmt.Fprintln(w, "       "+t.fraco("-> "+Safe(ns)))
				}
			}
		}
		// A AÇÃO GENÉRICA do check (o mesmo texto em todo membro) sai uma vez, na
		// ordem do primeiro. FP só no -vv.
		for _, ns := range first.NextSteps {
			if comum[ns] {
				fmt.Fprintln(w, t.fraco("   -> "+Safe(ns)))
			}
		}
		if o.Verbose >= 2 && len(first.FalsePositives) > 0 {
			fmt.Fprintln(w, "   "+t.fraco("FP: "+Safe(strings.Join(first.FalsePositives, " · "))))
		}
		fmt.Fprintln(w)
	}
}

// writeNextSteps adapta: com crítico, é a ordem do runbook §19; só com aviso,
// vira "revise antes de agir"; sem nada, some.
func writeNextSteps(w io.Writer, t Tema, r *check.Report) {
	// O bloco verboso de ação saiu da view. Fica SÓ a salvaguarda que a pressa
	// destrói: preservar a amostra ANTES de agir. Um memfd/binário apagado tem
	// UMA cópia e ela some no kill; um eBPF órfão some no REBOOT. Os passos, por
	// achado, estão no -v.
	//
	// O gatilho é o CAMPO Irreversible, e SÓ ele — não o texto do comando. Casar
	// por "sudo " (a versão anterior) calava justamente o kernel.bpf_unowned,
	// cujos passos são "guarde AGORA/bpftool/NÃO reinicie", nenhum começando com
	// sudo: o achado sumia no reboot e a salvaguarda não aparecia. FN.
	if len(r.Irreversible()) == 0 {
		return
	}
	fmt.Fprintln(w, t.negrito("preserve ANTES de agir")+
		t.fraco(" — há passo irreversível; aletheia help"))
	fmt.Fprintln(w)
}

// maxLacunasCompactas é o teto de lacunas de coleta listadas no modo de
// decisão. O que passa vira contagem, com o ponteiro para -v — nunca some.

// maxCausas é o teto de causas de lacuna listadas no modo de decisão.
const maxCausas = 5

func writeCoverage(w io.Writer, t Tema, r *check.Report, o Options) {
	c := r.Coverage
	nPartial, nNot := len(c.Partial), len(c.NotChecked)

	// Cabeçalho terse: só o que não é zero.
	cab := fmt.Sprintf("%s  %d/%d completos", t.negrito("COBERTURA"), c.Complete, c.Total)
	if nPartial > 0 {
		cab += fmt.Sprintf(" · %d parciais", nPartial)
	}
	if nNot > 0 {
		cab += fmt.Sprintf(" · %d não verificados", nNot)
	}
	fmt.Fprintln(w, cab)

	// -v: agrupado, não uma parede. parcial inverte para CAUSA -> checks; coleta
	// agrupa por coletor e colapsa a cláusula que se repete. Ver cobertura.go.
	if o.Verbose > 0 {
		writeCoberturaDetalhe(w, t, c, o.Verbose)
		fmt.Fprintln(w)
		return
	}

	// Default: agrupa por CAUSA RAIZ, ordenada por IMPACTO (quantos checks cada
	// uma degrada). O operador vê ONDE a cobertura é fraca e a alavanca para
	// fechá-la — não 26 linhas de detalhe por check.
	impacto := map[string]int{}
	var ordem []string
	acumula := func(txt string) {
		chave := causaCurta(txt)
		if chave == "" {
			return
		}
		if _, ok := impacto[chave]; !ok {
			ordem = append(ordem, chave)
		}
		impacto[chave]++
	}
	for _, p := range c.Partial {
		for _, rz := range dedupe(p.Reasons) {
			acumula(rz)
		}
	}
	for _, nc := range c.NotChecked {
		acumula(nc.Reason)
	}
	for _, g := range c.CollectorGaps {
		acumula(g)
	}
	sort.SliceStable(ordem, func(i, j int) bool { return impacto[ordem[i]] > impacto[ordem[j]] })

	lim := len(ordem)
	if lim > maxCausas {
		lim = maxCausas
	}
	temRoot := false
	for _, causa := range ordem[:lim] {
		n := impacto[causa]
		prefixo := "     ·"
		if n > 0 {
			prefixo = fmt.Sprintf("  %2d×  ", n)
		}
		fmt.Fprintf(w, "%s %s\n", t.fraco(prefixo), t.fraco(Safe(causa)))
		if mencionaRoot(causa) {
			temRoot = true
		}
	}
	if lim < len(ordem) {
		fmt.Fprintf(w, "  %s\n", t.fraco(fmt.Sprintf("… +%d causas — -v detalha", len(ordem)-lim)))
	}
	if temRoot {
		fmt.Fprintln(w, "  "+t.fraco("→ rode como root para recuperar boa parte"))
	}
	fmt.Fprintln(w)
}

// causaCurta reduz um motivo de lacuna à sua raiz escaneável: cortado no
// comprimento. O "o quê" fica no começo do motivo e o "porquê" pedagógico no
// fim — o corte naturalmente para perto do fim do "o quê".
func causaCurta(s string) string {
	return corta(strings.TrimSpace(s), 72)
}

func mencionaRoot(s string) bool {
	l := strings.ToLower(s)
	return strings.Contains(l, "root") || strings.Contains(l, "cap_") ||
		strings.Contains(l, "permiss") || strings.Contains(l, "privilég")
}

func writeResult(w io.Writer, t Tema, r *check.Report) {
	crit, warn, manual, _ := r.Counts()
	v := r.Verdict()
	// Mesma cor do veredito do topo: OK verde, WARNING amarelo, CRITICAL
	// vermelho. Só em TTY — em arquivo/pipe sai "RESULT: X" cru, e a unicidade
	// dessa linha (uma só, no fim) continua sendo a invariante anti-forja.
	vc := t.pintaSev(sevDoVerdict(v), v)
	if v == "OK" {
		vc = t.verde(v)
	}
	fmt.Fprintf(w, "RESULT: %s", vc)

	switch v {
	case "OK":
		fmt.Fprintf(w, " — %d/%d checks. Nenhum indicador coberto disparou.\n", r.Coverage.Complete, r.Coverage.Total)
		fmt.Fprintln(w, "        Isto NÃO prova que o host está limpo.")
	case "INCOMPLETE":
		miss := r.Coverage.Total - r.Coverage.Complete
		switch {
		case miss > 0:
			fmt.Fprintf(w, " — 0 achados, mas %d checks não cobriram o que deveriam.\n", miss)
		default:
			fmt.Fprintf(w, " — 0 achados, mas a coleta não conseguiu ler tudo (%d lacunas).\n",
				len(r.Coverage.CollectorGaps))
		}
		fmt.Fprintln(w, "        Isto NÃO é o mesmo que host limpo.")
	default:
		// A contagem já saiu no sumário do topo; aqui a linha fecha o veredito
		// sem repeti-la. (crit/warn/manual ficam para o -v da automação via JSONL.)
		fmt.Fprintln(w)
	}
	_ = crit
	_ = warn
	_ = manual

	if len(r.TrustBroken) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "CONFIANÇA REBAIXADA — achados vindos de binário do host não valem como prova:")
		for _, t := range dedupe(r.TrustBroken) {
			fmt.Fprintln(w, "  · "+Safe(t))
		}
	}
	// O bloco do KERNEL vem por último e é o mais forte que este relatório
	// imprime: ele não rebaixa achado, ele invalida AUSÊNCIA. Depois dele,
	// "nenhum outro processo oculto" deixa de ser uma frase que se possa dizer.
	if len(r.KernelTrustBroken) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "════ O KERNEL SE CONTRADISSE ══════════════════════════════════════")
		for _, t := range r.KernelTrustBroken {
			fmt.Fprintln(w, "  · "+Safe(t))
		}
		fmt.Fprintln(w)
		fmt.Fprintln(w, "  Os ACHADOS acima continuam valendo — valem mais, aliás: alguém teve")
		fmt.Fprintln(w, "  trabalho de esconder algo. O que deixou de valer é a AUSÊNCIA de")
		fmt.Fprintln(w, "  achado em todo o resto: quem responderia já demonstrou responder o")
		fmt.Fprintln(w, "  que quer. Cada check silencioso foi movido para cobertura parcial.")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "  Daqui em diante nenhuma conclusão NEGATIVA deste host vale sobre este")
		fmt.Fprintln(w, "  host. Varra a IMAGEM de fora (`aletheia scan --root`), onde o kernel")
		fmt.Fprintln(w, "  é o seu, e adquira a memória pelo hipervisor se ele existir.")
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
