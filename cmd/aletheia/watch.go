package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/lex0c/aletheia/internal/baseline"
	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
	"github.com/lex0c/aletheia/internal/report"
)

// watch: o eixo do TEMPO, que é o que um retrato não tem.
//
// Toda esta ferramenta é um retrato — ela pergunta "o que está acontecendo
// AGORA" e responde bem. O que ela não pode responder é o que não está
// acontecendo agora, e um adversário competente sabe disso: o implante que
// acorda às 03:00, roda por quarenta segundos e sai não existe para nenhuma
// varredura feita às 14:00. Nenhum check novo resolve isso, porque não é
// lacuna de técnica — é propriedade do modelo.
//
// O `watch` roda o MESMO scan em ciclo e reporta só o que MUDOU.
//
// # Por que a coleta é completa em cada ciclo
//
// Medido neste host: coleta completa 1487ms, e a parte volátil — /proc, rede,
// cross-view — 164ms. Um ciclo volátil é nove vezes mais barato, e a tentação
// de usá-lo é óbvia.
//
// Ele foi descartado. Rodar os checks sobre fatos parciais faz um check que lê
// unit encontrar zero units e reportar "nada encontrado", quando o certo é
// "não olhei". É exatamente a mentira que esta ferramenta existe para não
// contar, e ela não pode entrar por uma otimização de custo. Aproveitar o ciclo
// barato exigiria declarar, em cada um dos setenta checks, de quais coletores
// ele depende — setenta chances de errar em silêncio, e o erro sai como falso
// negativo.
//
// Completo a cada 60s custa 2,5% de uma CPU. É pago.
//
// # O valor está no DIFF
//
// Um laço de shell com `scan` já roda de novo. O que ele não faz é calar o que
// já foi visto: sessenta ciclos de um host com treze avisos são setecentas e
// oitenta linhas onde havia treze fatos, e o achado novo — o único que
// importa — nasce enterrado. Aqui o ciclo 0 é o retrato, e o resto é delta.

const (
	// A AMOSTRA é barata (164ms) e por isso pode ser frequente: é ela que pega
	// o beacon curto e o processo efêmero.
	watchIntervaloPadrao = 5 * time.Second
	watchIntervaloMinimo = 1 * time.Second
	// A varredura COMPLETA custa ~1,5s e roda no ritmo que cabe.
	watchCompletoPadrao = 60 * time.Second
	watchCompletoMinimo = 5 * time.Second
)

// evento é o que muda entre dois ciclos.
type evento struct {
	Kind   string // novo | voltou | sumiu
	Fd     check.Finding
	Quando time.Time
}

func runWatch(args []string) int {
	fs := flag.NewFlagSet("watch", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var (
		intervalo = fs.Duration("interval", watchIntervaloPadrao, "tempo entre AMOSTRAS (/proc e sockets)")
		completo  = fs.Duration("full", watchCompletoPadrao, "tempo entre varreduras COMPLETAS")
		durante   = fs.Duration("for", 0, "duração total (0 = até Ctrl-C)")
		only      = fs.String("only", "", "grupos, separados por vírgula")
		mode      = fs.String("mode", "", "auto | manual")
		jsonOut   = fs.String("json", "", "escrever JSONL em FILE ('-' = stdout)")
		base      = fs.String("baseline", "", "começar com a baseline em FILE já conhecida")
	)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	if err := fs.Parse(args); err != nil {
		return 3
	}

	if *intervalo < watchIntervaloMinimo {
		fmt.Fprintf(os.Stderr, "--interval mínimo é %s\n", watchIntervaloMinimo)
		return 3
	}
	// A varredura completa custa ~1,5s. Pedi-la mais rápido que isso faz os
	// ciclos se encavalarem e o host passa a rodar a ferramenta o tempo todo —
	// recusar é melhor que aceitar e não cumprir.
	if *completo < watchCompletoMinimo {
		fmt.Fprintf(os.Stderr, "--full mínimo é %s: a coleta completa leva mais de um segundo, "+
			"e ciclos mais curtos se encavalam\n", watchCompletoMinimo)
		return 3
	}
	if *completo < *intervalo {
		fmt.Fprintf(os.Stderr, "--full (%s) não pode ser menor que --interval (%s)\n",
			*completo, *intervalo)
		return 3
	}
	if *mode != "" && *mode != "auto" && *mode != "manual" {
		fmt.Fprintln(os.Stderr, "--mode aceita apenas: auto, manual")
		return 3
	}

	sel := check.Selection{Mode: *mode}
	if *only != "" {
		sel.Groups = strings.Split(*only, ",")
		if unknown := check.UnknownGroups(sel.Groups); len(unknown) > 0 {
			fmt.Fprintf(os.Stderr, "grupo inexistente em --only: %s\n", strings.Join(unknown, ", "))
			fmt.Fprintf(os.Stderr, "grupos com checks registrados: %s\n", strings.Join(check.Groups(), " "))
			return 3
		}
	}
	selected := check.Select(sel)
	if len(selected) == 0 {
		fmt.Fprintln(os.Stderr, "nenhum check corresponde à seleção")
		return 3
	}

	// O JSONL vai para stdout e o texto para stderr, como no scan: misturar os
	// dois faz `watch --json - > out.jsonl` produzir arquivo inválido.
	humano := io.Writer(os.Stdout)
	var jw *os.File
	if *jsonOut != "" {
		humano = os.Stderr
		if *jsonOut == "-" {
			jw = os.Stdout
		} else {
			fh, err := openJSONOut(*jsonOut)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 3
			}
			defer fh.Close()
			jw = fh
		}
	}

	// Ctrl-C não pode matar o processo direto: o resumo é metade do valor, e
	// quem roda isto por uma hora vai encerrar com Ctrl-C.
	parar := make(chan os.Signal, 1)
	signal.Notify(parar, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(parar)

	w := &vigia{
		selected: selected,
		humano:   humano,
		jsonW:    jw,
		visto:    map[string]check.Finding{},
		presente: map[string]bool{},
		am:       novoAmostrador(),
	}

	if code := w.carregarBaseline(*base); code != 0 {
		return code
	}

	inicio := time.Now()
	// DUAS cadências, e são cadências porque medem coisas diferentes.
	//
	//	amostra   /proc e sockets, 164ms — pega o beacon de 2s e o processo
	//	          efêmero, que é o que nenhum retrato alcança
	//	completa  os 70 checks, 1,5s — pega tudo o mais, no ritmo que ela cabe
	tickAmostra := time.NewTicker(*intervalo)
	defer tickAmostra.Stop()
	tickCompleto := time.NewTicker(*completo)
	defer tickCompleto.Stop()

	w.intervalo, w.completo = *intervalo, *completo
	w.ciclo(true)
	w.amostra()
	for {
		if *durante > 0 && time.Since(inicio) >= *durante {
			break
		}
		select {
		case <-parar:
			fmt.Fprintln(humano)
			w.resumo(time.Since(inicio), "interrompido")
			return w.exit()
		case <-tickAmostra.C:
			w.amostra()
		case <-tickCompleto.C:
			w.ciclo(false)
		}
	}
	w.resumo(time.Since(inicio), "concluído")
	return w.exit()
}

// vigia guarda o que já foi visto entre ciclos.
type vigia struct {
	selected []check.Check
	humano   io.Writer
	jsonW    *os.File

	// visto é tudo que JÁ apareceu alguma vez, com o achado. Ele responde
	// "isto é novidade?".
	visto map[string]check.Finding
	// presente é o que estava no ciclo ANTERIOR. Ele responde "isto sumiu?" e
	// "isto voltou?" — e as duas perguntas são diferentes de "é novo".
	presente map[string]bool

	am        *amostrador
	intervalo time.Duration
	completo  time.Duration
	// ultimoCompleto é o Facts da última varredura completa. O amostrador o usa
	// para NOMEAR o gatilho quando mede um período: ele vê o ritmo de fora e
	// não sabe de onde vem; a coleta completa sabe quais agendamentos existem.
	ultimoCompleto *facts.Facts

	ciclos    int
	amostras  int
	eventos   []evento
	pior      check.Severity
	cobertura string
	// semChave conta o que não pôde ser diferenciado entre ciclos.
	semChave int
	// coberturaFalhou fica ligado no PRIMEIRO ciclo que não cobriu tudo, e não
	// desliga: se a vigília ficou cega às 03:00, o exit não pode dizer que a
	// noite foi tranquila só porque o último ciclo enxergou.
	coberturaFalhou bool
}

func (w *vigia) carregarBaseline(caminho string) int {
	if caminho == "" {
		return 0
	}
	bl, err := baseline.Carregar(caminho)
	if err != nil {
		fmt.Fprintf(os.Stderr, "--baseline: %v\n", err)
		return 3
	}
	// A baseline entra como JÁ VISTO: o que ela conhece não é novidade, e é
	// para isso que ela existe. Não entra em `presente` — o primeiro ciclo é
	// quem diz o que está aqui agora.
	for _, k := range bl.Keys {
		w.visto[k] = check.Finding{}
	}
	fmt.Fprintf(w.humano, "baseline: %d achados conhecidos de %s\n\n", len(bl.Keys), bl.Host)
	return 0
}

// ciclo roda uma varredura completa e reporta o que mudou.
func (w *vigia) ciclo(primeiro bool) {
	e := env.Probe(env.Options{Version: version})
	defer e.Close()
	f := facts.Collect(e)
	r := check.Run(w.selected, f, e)
	collectorGaps(r, f)
	w.ciclos++
	w.ultimoCompleto = f

	agora := e.Now
	atual := map[string]bool{}
	var semChave int

	for _, fd := range r.Findings {
		if fd.Sev == check.SevInfo {
			continue
		}
		// A severidade conta ANTES da chave.
		//
		// Um achado sem chave estável não pode ser comparado entre ciclos, mas
		// ele existe — e o `continue` abaixo o tirava do laço antes de ele
		// tocar em w.pior. Um CRITICAL indiferenciável saía da vigília com exit
		// 0: o achado aparecia na tela e não chegava ao código de saída, que é
		// por onde o resto do mundo lê esta ferramenta.
		if fd.Sev > w.pior {
			w.pior = fd.Sev
		}

		k := chaveDeVigia(f, fd)
		if k == "" {
			// Sem chave estável não dá para dizer se é novo. Contar e declarar
			// é a única resposta honesta: silenciar viraria falso negativo, e
			// reimprimir a cada ciclo afogaria o que importa.
			semChave++
			continue
		}
		// Duas ocorrências da MESMA chave dentro de um ciclo são repetição, não
		// mudança. Sem esta linha o `adb`, que escuta em duas portas, saía como
		// "novo" na primeira e "VOLTOU" na segunda — dentro do mesmo segundo.
		if atual[k] {
			continue
		}
		atual[k] = true

		// O ciclo 0 é a REFERÊNCIA, e nada nele é mudança. Registrá-lo como
		// evento fazia o resumo dizer "APARECEU — não estava aqui quando a
		// vigília começou" sobre exatamente as coisas que estavam aqui quando
		// ela começou.
		if primeiro {
			w.visto[k] = fd
			continue
		}

		if _, jaViu := w.visto[k]; !jaViu {
			w.registra(evento{Kind: "novo", Fd: fd, Quando: agora})
		} else if !w.presente[k] {
			// VOLTOU não é o mesmo que novo, e é mais interessante: algo que
			// aparece, some e reaparece está sendo executado por um GATILHO —
			// que é a forma exata do implante agendado, e o motivo deste comando.
			w.registra(evento{Kind: "voltou", Fd: fd, Quando: agora})
		}
		w.visto[k] = fd
	}

	for k := range w.presente {
		if !atual[k] {
			w.registra(evento{Kind: "sumiu", Fd: w.visto[k], Quando: agora})
		}
	}
	w.presente = atual
	// A quantidade de achados indiferenciáveis mudando é evento: se ela sobe, a
	// vigília passou a enxergar menos, e o silêncio dela vale menos.
	if !primeiro && semChave != w.semChave {
		fmt.Fprintf(w.humano, "%s  ⚠ achados sem chave estável: %d → %d — "+
			"esses não podem ser comparados entre ciclos\n",
			agora.Format("15:04:05"), w.semChave, semChave)
	}
	w.semChave = semChave

	if r.Coverage.Incomplete() {
		w.coberturaFalhou = true
	}
	cob := fmt.Sprintf("%d/%d", r.Coverage.Complete, r.Coverage.Total)
	if len(r.Coverage.CollectorGaps) > 0 {
		cob += fmt.Sprintf(" (+%d lacunas de coleta)", len(r.Coverage.CollectorGaps))
	}

	if primeiro {
		// O ciclo 0 é o RETRATO: relatório inteiro, como um scan. Sem ele o
		// operador não sabe de onde partiu, e um delta sem ponto de partida não
		// significa nada.
		report.Human(w.humano, r, f, e, report.Options{})
		w.cobertura = cob
		fmt.Fprintf(w.humano, "vigiando em duas cadências — amostra de /proc e sockets a cada %s, "+
			"varredura completa a cada %s. Só o que MUDAR aparece daqui\n", w.intervalo, w.completo)
		if semChave > 0 {
			fmt.Fprintf(w.humano, "%d achado(s) sem chave estável (exe ilegível): "+
				"não é possível dizer se mudam entre ciclos\n", semChave)
		}
		fmt.Fprintln(w.humano)
		w.emiteJSON(r, f, e)
		return
	}

	// A cobertura mudando no meio da vigília é evento por si: se um coletor
	// parou de conseguir ler, os ciclos seguintes comparam menos coisa, e o
	// silêncio deles não significa mais o mesmo.
	if cob != w.cobertura {
		fmt.Fprintf(w.humano, "%s  ⚠ COBERTURA MUDOU: %s → %s — o silêncio dos "+
			"próximos ciclos vale menos que o dos anteriores\n",
			agora.Format("15:04:05"), w.cobertura, cob)
		w.cobertura = cob
	}
}

// amostra roda a coleta barata e imprime o que mudou desde a anterior.
func (w *vigia) amostra() {
	e := env.Probe(env.Options{Version: version})
	defer e.Close()
	f := facts.CollectVolatile(e)
	w.amostras++
	for _, l := range w.am.amostra(f, w.ultimoCompleto, e.Now) {
		fmt.Fprintln(w.humano, l)
	}
}

func (w *vigia) registra(ev evento) {
	w.eventos = append(w.eventos, ev)

	marca := map[string]string{"novo": "＋", "voltou": "↻", "sumiu": "－"}[ev.Kind]
	nome := ev.Fd.Subject
	if ev.Fd.Ator != "" {
		nome = ev.Fd.Ator
	}
	fmt.Fprintf(w.humano, "%s %s %s %-12s %s §%s\n",
		ev.Quando.Format("15:04:05"), marca, ev.Fd.Sev.Mark(),
		report.Safe(nome), report.Safe(ev.Fd.Title), ev.Fd.Ref)

	if w.jsonW != nil {
		// encoding/json e não %q: o verbo de Go escapa para um literal de GO,
		// não de JSON. Rune inválido vira \xNN, que nenhum parser de JSON
		// aceita — e Subject e Title vêm do ALVO, onde o byte inválido é
		// escolha de quem controlava o host. Uma linha inválida no meio do
		// JSONL quebra o consumidor no lugar onde ele mais precisa funcionar.
		linha, err := json.Marshal(map[string]string{
			"ts":      ev.Quando.UTC().Format(time.RFC3339),
			"event":   ev.Kind,
			"id":      ev.Fd.ID,
			"ref":     ev.Fd.Ref,
			"sev":     ev.Fd.Sev.String(),
			"subject": ev.Fd.Subject,
			"title":   ev.Fd.Title,
		})
		if err == nil {
			fmt.Fprintf(w.jsonW, "%s\n", linha)
		}
	}
}

func (w *vigia) emiteJSON(r *check.Report, f *facts.Facts, e *env.Env) {
	if w.jsonW == nil {
		return
	}
	if err := report.JSONL(w.jsonW, r, f, e, nil, nil, nil); err != nil {
		fmt.Fprintf(os.Stderr, "erro ao escrever JSONL: %v\n", err)
	}
}

func (w *vigia) resumo(decorrido time.Duration, motivo string) {
	fmt.Fprintf(w.humano, "\nVIGÍLIA %s — %d varredura(s) completa(s) e %d amostra(s) em %s\n",
		motivo, w.ciclos, w.amostras, decorrido.Round(time.Second))
	fmt.Fprint(w.humano, w.am.resumo(w.intervalo))

	if len(w.eventos) == 0 {
		fmt.Fprintf(w.humano, "nada mudou. Isto NÃO prova que nada aconteceu: "+
			"o que roda e sai entre dois ciclos não é visto por nenhum dos dois — "+
			"o intervalo é o tamanho do buraco.\n")
		return
	}

	// Agrupado por tipo, porque as três perguntas são diferentes: o que
	// apareceu, o que voltou (gatilho!) e o que saiu de cena.
	for _, kind := range []string{"novo", "voltou", "sumiu"} {
		var linhas []string
		for _, ev := range w.eventos {
			if ev.Kind != kind {
				continue
			}
			nome := ev.Fd.Subject
			if ev.Fd.Ator != "" {
				nome = ev.Fd.Ator
			}
			linhas = append(linhas, fmt.Sprintf("  %s %s %s §%s",
				ev.Quando.Format("15:04:05"), report.Safe(nome),
				report.Safe(ev.Fd.Title), ev.Fd.Ref))
		}
		if len(linhas) == 0 {
			continue
		}
		sort.Strings(linhas)
		fmt.Fprintf(w.humano, "\n%s (%d)\n", rotuloEvento(kind), len(linhas))
		for _, l := range linhas {
			fmt.Fprintln(w.humano, l)
		}
	}
	fmt.Fprintln(w.humano)
}

func rotuloEvento(k string) string {
	switch k {
	case "novo":
		return "APARECEU — não estava aqui quando a vigília começou"
	case "voltou":
		return "VOLTOU — sumiu e reapareceu: é a forma de algo executado por gatilho"
	default:
		return "SUMIU — estava aqui e não está mais; o processo pode ter terminado"
	}
}

// exit devolve o código pela PIOR severidade que apareceu durante a vigília, e
// não pelo estado do último ciclo.
//
// A diferença é o ponto do comando: um implante que rodou às 03:00 e saiu não
// está no último ciclo, e um exit 0 ali diria que a noite foi tranquila.
func (w *vigia) exit() int {
	switch {
	case w.pior >= check.SevCritical:
		return 2
	case w.pior >= check.SevWarn:
		return 1
	case w.coberturaFalhou:
		// A mesma regra do `scan` (SPEC 7.9): zero exige achado nenhum E
		// cobertura completa. Faltava aqui — uma vigília de oito horas que
		// nunca conseguiu ler /proc de ninguém terminava com exit 0, que é a
		// ferramenta dizendo "olhei a noite toda e não vi nada" sobre uma noite
		// em que ela não olhou.
		return 1
	}
	return 0
}

// chaveDeVigia identifica um achado entre ciclos.
//
// Usa a mesma chave da baseline: `pid=N` não serve, porque o número é reusado e
// o mesmo pid pode ser outro programa dez minutos depois. O que identifica é o
// exe.
func chaveDeVigia(f *facts.Facts, fd check.Finding) string {
	if fd.Ator != "" {
		return fd.ID + "|" + fd.Ator
	}
	return baseline.Chave(f, fd)
}
