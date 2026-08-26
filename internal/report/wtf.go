package report

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/lex0c/aletheia/internal/activity"
	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

// maxWtfLinhas mantém a promessa de UMA TELA. O que não couber vira uma linha
// dizendo quanto ficou de fora — nunca corte silencioso.
const maxWtfLinhas = 8

// janelaDeAtividade é o recorte do bloco de atividade. Vinte e quatro horas é o
// que o operador quer dizer quando pergunta "o que aconteceu aqui?" no começo
// de um plantão, e é curto o bastante para o número caber numa linha.
const janelaDeAtividade = 24 * time.Hour

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
func Wtf(w io.Writer, r *check.Report, f *facts.Facts, e *env.Env, elapsed time.Duration, catalogo int, bl *BaselineInfo, cor bool) {
	t := temaPara(cor)
	writeWtfHeader(w, t, f, e)
	// O bloco de ATIVIDADE vem antes dos achados, e é de propósito: ele é o
	// DENOMINADOR. "47 falhas seguidas de sucesso" é uma frase diferente num
	// host que recebeu 12.000 tentativas e num que recebeu 50, e quem lê o
	// achado primeiro já decidiu antes de ver o contexto.
	//
	// A janela é FIXA em 24h e não tem flag. O `--since` do scan já significa
	// outra coisa — ele recorta o RELATÓRIO —, e dar dois sentidos à mesma flag
	// custa mais do que a flag vale. Quem quer outra janela tem destino
	// nomeado, que é o `activity`.
	atv := activity.Resumir(f, e.Now, janelaDeAtividade)
	writeAtividade(w, t, atv, e.Now)
	writeBaseline(w, bl)

	sobra := catalogo - r.Coverage.Total

	if len(r.Findings) == 0 {
		fmt.Fprintln(w, t.verde(fmt.Sprintf("✓ nenhum indicador decisivo em %d checks (%s)",
			r.Coverage.Total, dur(elapsed))))
		fmt.Fprintln(w, t.fraco("  isto NÃO significa host limpo."+maisChecks(sobra)))
		fmt.Fprintln(w)
	} else {
		writeWtfFindings(w, t, r)
	}

	writeWtfGaps(w, t, r)
	// O destino nomeado do que não coube. O `wtf` decide POR ONDE COMEÇAR e
	// cabe numa tela; quem quer outra janela, outra conta ou a linha do tempo
	// inteira tem um comando para isso, e mandar o operador adivinhar qual
	// seria desperdiçar a única linha que ele lê depois do veredito.
	if atv.Coletado() {
		fmt.Fprintln(w, t.fraco("atividade em detalhe: `aletheia activity --since 24h`"))
	}
	writeWtfResult(w, t, r, elapsed, sobra)
}

func maisChecks(sobra int) string {
	if sobra <= 0 {
		return ""
	}
	return " Para o resto: aletheia scan (+" + strconv.Itoa(sobra) + " checks)"
}

func writeWtfHeader(w io.Writer, t Tema, f *facts.Facts, e *env.Env) {
	h := f.Host
	// Mesma hierarquia do scan: hostname em NEGRITO (a identidade), kernel/virt/
	// uptime em cinza (contexto). O load é contexto até ficar alto — aí é o
	// rastro nº 1 de minerador e sai em amarelo. Sempre com o nº de cpus: 8.02
	// é catástrofe em 2 e rotina em 16.
	var ctx []string
	if h.Kernel != "" {
		ctx = append(ctx, Safe(h.Kernel))
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
	if h.NumCPU > 0 {
		lc := fmt.Sprintf("load %.2f %.2f %.2f (%d cpu%s)",
			h.Load1, h.Load5, h.Load15, h.NumCPU, cotaStr(h))
		if h.Load1 > float64(h.NumCPU)*1.5 {
			linha += " · " + t.pintaSev(check.SevWarn, lc+" ⚠")
		} else {
			linha += t.fraco(" · " + lc)
		}
	}
	fmt.Fprintln(w, linha)

	// Relógio primeiro: sem ele, todo horário abaixo é frágil. Linha secundária.
	fmt.Fprintln(w, t.fraco(fmt.Sprintf("relógio %s · %s · %s",
		e.Clock, e.Now.Format("2006-01-02T15:04:05Z"), contagens(f))))
	fmt.Fprintln(w)
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

func writeWtfFindings(w io.Writer, t Tema, r *check.Report) {
	// Alvo com mais de um sinal vira UMA linha com a contagem. Numa tela só, é
	// a diferença entre "por onde começo" e uma lista para rolar.
	grupos, resto := r.Correlate()

	// O teto vale para as DUAS listas somadas: são a mesma tela. Contar só os
	// avulsos deixava vinte alvos correlacionados imprimirem vinte linhas, e o
	// comando existe para caber numa tela.
	linhas := 0
	for _, g := range grupos {
		if linhas >= maxWtfLinhas {
			break
		}
		linhas++
		// O `pad` alinha e NÃO corta. Com o alvo virando um caminho inteiro e
		// três títulos atrás dele, a linha passou de duzentas colunas — e este
		// comando promete UMA TELA. O corte é no resumo, que é a parte
		// recuperável: `scan` imprime os títulos por extenso.
		//
		// O caminho pode sozinho estourar o orçamento — `/home/deploy/.local/
		// share/app/versions/1.2.3/bin/daemon` tem 60 colunas —, e aí não sobra
		// resumo nenhum. Nesse caso o `: ` sai junto: dois-pontos sem nada
		// depois parece saída truncada por defeito. As seções continuam ali, e
		// são elas que dizem o que olhar.
		mark := g.Sev().Mark()
		cab := fmt.Sprintf("%s %-12s %d sinais", mark, Safe(g.Subject), len(g.Findings))
		if s := corta(Safe(resumoTitulos(g)), 70-len([]rune(cab))); s != "" {
			cab += ": " + s
		}
		// A marca colore por severidade sem quebrar o alinhamento: o pad conta o
		// texto PLANO, e a cor entra depois, trocando o prefixo. O §ref recua
		// para cinza (é atalho de lookup, não a decisão).
		linha := t.pintaSev(g.Sev(), mark) + strings.TrimPrefix(pad(cab, 72), mark) +
			t.fraco("§"+strings.Join(g.Refs(), " §"))
		fmt.Fprintln(w, linha)
	}

	// O denominador conta só o que SERIA impresso: usar len(r.Findings) incluiria
	// os INFO, que nunca aparecem, e a linha prometeria achados inexistentes.
	total := 0
	for _, fd := range resto {
		if fd.Sev != check.SevInfo {
			total++
		}
	}
	n := 0
	for _, fd := range resto {
		if fd.Sev == check.SevInfo {
			continue
		}
		if linhas >= maxWtfLinhas {
			fmt.Fprintf(w, "   … e mais %d achados — `aletheia scan -v`\n\n",
				(total-n)+(len(grupos)-min(len(grupos), linhas)))
			return
		}
		linhas++
		n++

		mark := fd.Sev.Mark()
		plano := pad(fmt.Sprintf("%s %-12s %s", mark, Safe(fd.Subject), Safe(fd.Title)), 74)
		fmt.Fprintln(w, t.pintaSev(fd.Sev, mark)+strings.TrimPrefix(plano, mark)+t.fraco("§"+Safe(fd.Ref)))

		// Só o crítico ganha evidência: o wtf decide POR ONDE COMEÇAR, e
		// detalhar o aviso rouba a tela do que precisa de ação agora.
		if fd.Sev != check.SevCritical {
			continue
		}
		for i, ev := range fd.Evidence {
			if i >= 2 {
				break
			}
			fmt.Fprintln(w, "             "+t.fraco(Safe(ev)))
		}
		// O passo irreversível — e só ele. O resto é trabalho do scan.
		//
		// O gatilho é o CAMPO Irreversible, nunca o texto do comando. Casar por
		// prefixo "sudo " é o mesmo defeito que human.go documenta ter
		// corrigido ("calava justamente o kernel.bpf_unowned"), e ele continuou
		// vivo aqui: kernel.bpf_unowned, cross.bpf_hidden e o trampolim são
		// todos CRITICAL + Irreversible, e nenhum passo deles começa com
		// `sudo` — o primeiro é um `bpftool prog dump` ou um `cp` do pin. O
		// resultado era o wtf imprimir o achado e engolir o "guarde AGORA, o
		// programa some no próximo boot", que é a única razão de o campo
		// existir.
		if fd.Irreversible && len(fd.NextSteps) > 0 {
			fmt.Fprintln(w, "             "+t.fraco("→ "+Safe(primeiroPassoAcionavel(fd.NextSteps))))
		}
	}
	fmt.Fprintln(w)
}

// primeiroPassoAcionavel devolve o passo que o operador deve EXECUTAR primeiro.
//
// A convenção dos checks é abrir com a PROIBIÇÃO ("NÃO mate antes de
// preservar", "NÃO reinicie o host antes de decidir") e pôr a ação logo em
// seguida. O wtf tem uma linha só por achado, e ela rende mais gasta na ação:
// a proibição sozinha não diz o que fazer, e a ação já carrega a urgência.
//
// Quando todo passo é proibição, sai a primeira mesmo assim — melhor a
// proibição que o silêncio.
func primeiroPassoAcionavel(ns []string) string {
	for _, s := range ns {
		if !strings.HasPrefix(s, "NÃO ") {
			return s
		}
	}
	return ns[0]
}

// resumoTitulos encurta os títulos para caber na linha: no wtf o que decide é
// QUANTOS sinais e de que natureza, não a redação de cada um.
func resumoTitulos(g check.SubjectGroup) string {
	var out []string
	for i, fd := range g.Findings {
		if i >= 3 {
			out = append(out, "…")
			break
		}
		t := fd.Title
		if i := strings.IndexAny(t, ":,"); i > 0 {
			t = t[:i]
		}
		out = append(out, t)
	}
	return strings.Join(out, " · ")
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
func writeWtfGaps(w io.Writer, t Tema, r *check.Report) {
	c := r.Coverage
	// Só as LACUNAS: escopo não degradou cobertura, e citá-lo aqui gastaria a
	// única linha de lacuna do wtf com um mecanismo que este host nunca terá.
	lacunas, _ := c.NaoVerificados()
	motivos := append(reasonsOf(lacunas), partialReasons(c)...)

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
	// Linha secundária, mas NÃO opcional: é ela que impede a tela de ser lida
	// como "host limpo". Cinza, sem sumir.
	fmt.Fprintln(w, t.fraco("não verificado: "+Safe(strings.Join(parts, " · "))+
		"  —  `aletheia scan` detalha"))
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
func writeWtfResult(w io.Writer, t Tema, r *check.Report, elapsed time.Duration, sobra int) {
	v := r.Verdict()
	vc := t.pintaSev(sevDoVerdict(v), v)
	if v == "OK" {
		vc = t.verde(v)
	}
	fmt.Fprintf(w, "RESULT: %s — %d checks em %s.", vc, r.Coverage.Total, dur(elapsed))
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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func dur(d time.Duration) string {
	if d < time.Second {
		return strconv.FormatInt(d.Milliseconds(), 10) + "ms"
	}
	return strconv.FormatFloat(d.Seconds(), 'f', 2, 64) + "s"
}
