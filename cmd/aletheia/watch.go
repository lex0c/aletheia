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
	//
	// Mas o PRIMEIRO Ctrl-C, e não mais que um: se o ciclo em curso estiver
	// preso numa coleta lenta, quem quer sair não pode ficar refém dela. O
	// segundo sinal força a saída na hora. Sem isto o segundo Ctrl-C caía num
	// buffer cheio e sumia — e o operador ficava sem conseguir encerrar.
	sinais := make(chan os.Signal, 2)
	signal.Notify(sinais, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sinais)
	parar := make(chan struct{})
	go func() {
		<-sinais // primeiro: para com resumo, no fim do ciclo
		close(parar)
		<-sinais // segundo: força a saída, mesmo no meio de uma coleta
		fmt.Fprint(os.Stderr, "\r\033[K\ninterrompido à força\n")
		os.Exit(130)
	}()

	w := &vigia{
		selected: selected,
		humano:   humano,
		jsonW:    jw,
		visto:    map[string]check.Finding{},
		presente: map[string]bool{},
		eventos:  novoRegistro(),
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
	//	completa  a varredura completa, 1,5s — pega tudo o mais, no ritmo que ela cabe
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

	// jsonQuebrado marca que alguma linha do JSONL não pôde ser gravada. O
	// arquivo deixa de ser um registro completo, e isso precisa aparecer no
	// exit code — ver escreveJSON e exit.
	jsonQuebrado bool

	ciclos   int
	amostras int
	// eventos é CONTAGEM mais exemplos, e não a lista inteira.
	//
	// Ela era um slice que crescia a cada transição, numa vigília que `--for 0`
	// deixa indefinida. Um host que produz identidade nova continuamente —
	// /tmp/x-1, /tmp/x-2, ... — fazia a memória e o tempo do resumo final
	// crescerem sem teto, no comando cujo caso de uso é justamente ficar horas
	// ligado. O evento já FOI emitido quando aconteceu, no humano e no JSONL:
	// guardá-lo de novo só serve ao resumo, e o resumo não fica melhor com dez
	// mil linhas.
	eventos   registroDeEventos
	pior      check.Severity
	cobertura string
	// semChave conta o que não pôde ser diferenciado entre ciclos.
	semChave int
	// coberturaFalhou fica ligado no PRIMEIRO ciclo que não cobriu tudo, e não
	// desliga: se a vigília ficou cega às 03:00, o exit não pode dizer que a
	// noite foi tranquila só porque o último ciclo enxergou.
	coberturaFalhou bool

	// estadoEsgotado marca que o conjunto de identidades encheu, e com ele a
	// vigília PERDEU a capacidade de distinguir "novo" de "já visto".
	//
	// É a mesma família de coberturaFalhou e jsonQuebrado: uma coisa que a
	// ferramenta sabe que deixou de conseguir fazer, e que não pode terminar em
	// exit 0.
	estadoEsgotado bool
	// naoClassificadas conta as OBSERVAÇÕES cuja novidade não pôde ser decidida
	// depois disso. Não é contagem de identidades distintas: distingui-las
	// exigiria guardá-las, que é exatamente o que o teto impede.
	naoClassificadas int
}

// maxIdentidadesVigiadas é o teto do conjunto que responde "isto é novidade?".
//
// Cada identidade custa a chave mais um check.Finding (232 bytes), então
// cinquenta mil são cerca de 15 MB — e cinquenta mil achados DISTINTOS num só
// host é ordens de grandeza acima de qualquer varredura real, onde a conta fica
// em dezenas.
//
// Ele não existe para hosts reais: existe porque `watch --for 0` é indefinido
// por desenho, e um alvo que cria identidade nova a cada ciclo fazia o conjunto
// crescer enquanto o comando estivesse ligado.
const maxIdentidadesVigiadas = 50_000

// maxExemplosPorTipo limita o que o resumo IMPRIME de cada tipo de transição. A
// contagem continua exata; o que fica limitado é a lista, porque um resumo de
// dez mil linhas não é lido por ninguém.
const maxExemplosPorTipo = 100

// registroDeEventos guarda contagem exata e exemplos limitados.
type registroDeEventos struct {
	total    map[string]int
	exemplos map[string][]string
}

func novoRegistro() registroDeEventos {
	return registroDeEventos{total: map[string]int{}, exemplos: map[string][]string{}}
}

func (r *registroDeEventos) anota(kind, linha string) {
	if r.total == nil {
		*r = novoRegistro()
	}
	r.total[kind]++
	if len(r.exemplos[kind]) < maxExemplosPorTipo {
		r.exemplos[kind] = append(r.exemplos[kind], linha)
	}
}

func (r *registroDeEventos) vazio() bool {
	for _, n := range r.total {
		if n > 0 {
			return false
		}
	}
	return true
}

// lembra guarda a identidade e diz se ela COUBE no orçamento.
//
// Uma chave que já está lá é sempre atualizada — isso não faz o conjunto
// crescer. Uma chave nova só entra se houver espaço; sem espaço, a resposta é
// não, e quem chama para de emitir veredito de novidade sobre ela.
//
// Não é um LRU de propósito. Descartar a identidade mais antiga faria a
// pergunta "isto é novo?" voltar a ser respondida — com "sim", sobre algo que a
// vigília já tinha visto e esqueceu. Um teto que transforma a resposta certa em
// resposta errada é pior que um teto que recusa a responder.
func (w *vigia) lembra(k string, fd check.Finding) bool {
	if _, ja := w.visto[k]; ja {
		w.visto[k] = fd
		return true
	}
	if len(w.visto) >= maxIdentidadesVigiadas {
		w.naoClassificadas++
		if !w.estadoEsgotado {
			w.estadoEsgotado = true
			agora := time.Now()
			fmt.Fprintf(w.humano, "%s  ⚠ ESTADO ESGOTADO: %d identidades vigiadas, "+
				"que é o teto.\n   A partir daqui a vigília não consegue mais dizer "+
				"se um achado é NOVO ou se já tinha aparecido — os achados continuam "+
				"sendo avaliados e continuam pesando no exit, o que se perdeu é o "+
				"delta.\n", agora.Format("15:04:05"), maxIdentidadesVigiadas)
			w.escreveJSON(map[string]string{
				"ts":    agora.UTC().Format(time.RFC3339),
				"event": "estado_esgotado",
				"title": "o conjunto de identidades vigiadas encheu: novidade não " +
					"pode mais ser determinada",
			})
		}
		return false
	}
	w.visto[k] = fd
	return true
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
			w.lembra(k, fd)
			continue
		}

		// jaViu é lido ANTES de lembrar: lembra() insere, e perguntar depois
		// responderia sempre que sim.
		_, jaViu := w.visto[k]
		if !w.lembra(k, fd) {
			// Orçamento de identidades esgotado. NÃO emitir veredito é a
			// resposta certa: "novo" sairia verdadeiro na primeira vez e
			// falso em todas as seguintes, porque sem guardar a chave não há
			// como saber que ela já apareceu. Um delta que se repete a cada
			// ciclo afoga o delta que importa.
			//
			// O achado em si já contou para w.pior lá em cima, então o exit
			// continua enxergando a severidade dele.
			continue
		}
		if !jaViu {
			w.registra(evento{Kind: "novo", Fd: fd, Quando: agora})
		} else if !w.presente[k] {
			// VOLTOU não é o mesmo que novo, e é mais interessante: algo que
			// aparece, some e reaparece está sendo executado por um GATILHO —
			// que é a forma exata do implante agendado, e o motivo deste comando.
			w.registra(evento{Kind: "voltou", Fd: fd, Quando: agora})
		}
	}

	for k := range w.presente {
		if atual[k] {
			continue
		}
		// A identidade que não coube no orçamento está em `presente` — ela foi
		// vista no ciclo anterior — e NÃO está em `visto`, porque o teto a
		// recusou. Emitir "sumiu" com o que o mapa devolve ali seria uma linha
		// de achado VAZIO: sem título, sem referência, sem assunto.
		//
		// E não é só cosmético: dizer que algo sumiu é uma afirmação sobre ele
		// ter estado lá, e é exatamente essa afirmação que o esgotamento tirou.
		fd, conhecida := w.visto[k]
		if !conhecida {
			w.naoClassificadas++
			continue
		}
		w.registra(evento{Kind: "sumiu", Fd: fd, Quando: agora})
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
		fmt.Fprintln(w.humano, l.Texto)
		// O que o amostrador vê precisa chegar ao exit code e ao JSONL. Ele é a
		// ÚNICA fonte de alguns achados — a conexão de 2 s que se repete a cada
		// 10 min não aparece em varredura completa nenhuma —, e enquanto ele só
		// imprimia, `watch --json` saía 0 com o arquivo vazio sobre eles.
		if l.Sev > w.pior {
			w.pior = l.Sev
		}
		w.escreveJSON(map[string]string{
			"ts":      e.Now.UTC().Format(time.RFC3339),
			"event":   "amostra",
			"id":      l.ID,
			"sev":     l.Sev.String(),
			"subject": l.Assunto,
			"title":   l.Texto,
		})
	}
}

func (w *vigia) registra(ev evento) {
	marca := map[string]string{"novo": "＋", "voltou": "↻", "sumiu": "－"}[ev.Kind]
	nome := ev.Fd.Subject
	if ev.Fd.Ator != "" {
		nome = ev.Fd.Ator
	}
	// A linha do resumo é montada AQUI, e o evento não é guardado.
	//
	// Guardar o check.Finding inteiro para reformatá-lo no fim era o que fazia
	// a memória crescer com a duração da vigília. A linha é o que o resumo
	// precisa, e ela é curta.
	w.eventos.anota(ev.Kind, fmt.Sprintf("  %s %s %s §%s",
		ev.Quando.Format("15:04:05"), report.Safe(nome),
		report.Safe(ev.Fd.Title), ev.Fd.Ref))

	fmt.Fprintf(w.humano, "%s %s %s %-12s %s §%s\n",
		ev.Quando.Format("15:04:05"), marca, ev.Fd.Sev.Mark(),
		report.Safe(nome), report.Safe(ev.Fd.Title), ev.Fd.Ref)

	w.escreveJSON(map[string]string{
		"ts":      ev.Quando.UTC().Format(time.RFC3339),
		"event":   ev.Kind,
		"id":      ev.Fd.ID,
		"ref":     ev.Fd.Ref,
		"sev":     ev.Fd.Sev.String(),
		"subject": ev.Fd.Subject,
		"title":   ev.Fd.Title,
	})
}

// escreveJSON emite UMA linha do JSONL e CONFERE que ela saiu.
//
// encoding/json e não %q: o verbo de Go escapa para um literal de GO, não de
// JSON. Rune inválido vira \xNN, que nenhum parser de JSON aceita — e Subject e
// Title vêm do ALVO, onde o byte inválido é escolha de quem controlava o host.
// Uma linha inválida no meio do JSONL quebra o consumidor no lugar onde ele
// mais precisa funcionar.
//
// E o erro de escrita não é descartado: numa vigília de oito horas com a
// partição enchendo às 03:00, as linhas seguintes — inclusive o ＋ do implante —
// deixavam de ser gravadas sem uma palavra, e o exit continuava vindo da
// severidade vista em MEMÓRIA. O arquivo que a frota consome ficava truncado
// exatamente onde a informação apareceu.
func (w *vigia) escreveJSON(campos map[string]string) {
	if w.jsonW == nil {
		return
	}
	linha, err := json.Marshal(campos)
	if err == nil {
		_, err = fmt.Fprintf(w.jsonW, "%s\n", linha)
	}
	w.erroDeJSON(err)
}

// erroDeJSON é o ÚNICO ponto que marca o JSONL como quebrado.
//
// Havia dois caminhos de escrita e só um deles marcava. O relatório inicial —
// o ciclo 0, que é o retrato inteiro — imprimia o erro no stderr e seguia com
// jsonQuebrado em false. A sequência que sai disso é a pior possível:
//
//	a primeira escrita falha       o arquivo já nasce truncado
//	as seguintes funcionam         nada mais falha
//	jsonQuebrado continua false    exit() não tem o que reportar
//	a vigília termina 0            "olhei a noite toda e não vi nada"
//
// sobre um registro que a ferramenta SABE estar incompleto. É a mesma razão
// pela qual coberturaFalhou existe, entrando por uma porta que não passava por
// ela — e um erro de escrita no relatório inicial não é hipótese: é a partição
// enchendo às 03:00, que é justamente quando a vigília importa.
func (w *vigia) erroDeJSON(err error) {
	if err == nil || w.jsonQuebrado {
		return
	}
	w.jsonQuebrado = true
	fmt.Fprintf(os.Stderr, "watch: o JSONL parou de ser gravado (%v): "+
		"o arquivo está INCOMPLETO a partir daqui\n", err)
}

func (w *vigia) emiteJSON(r *check.Report, f *facts.Facts, e *env.Env) {
	if w.jsonW == nil {
		return
	}
	w.erroDeJSON(report.JSONL(w.jsonW, r, f, e, nil, nil, nil))
}

func (w *vigia) resumo(decorrido time.Duration, motivo string) {
	fmt.Fprintf(w.humano, "\nVIGÍLIA %s — %d varredura(s) completa(s) e %d amostra(s) em %s\n",
		motivo, w.ciclos, w.amostras, decorrido.Round(time.Second))
	fmt.Fprint(w.humano, w.am.resumo(w.intervalo))

	if w.estadoEsgotado {
		// ANTES da lista, porque muda como ela deve ser lida.
		fmt.Fprintf(w.humano, "\n⚠ o conjunto de identidades encheu (%d) e %d "+
			"observação(ões) ficaram SEM classificação de novidade.\n"+
			"  A lista abaixo é o que a vigília conseguiu classificar, e não o que "+
			"aconteceu. Os achados em si continuam contando para o resultado.\n",
			maxIdentidadesVigiadas, w.naoClassificadas)
	}

	if w.eventos.vazio() {
		fmt.Fprintf(w.humano, "nada mudou. Isto NÃO prova que nada aconteceu: "+
			"o que roda e sai entre dois ciclos não é visto por nenhum dos dois — "+
			"o intervalo é o tamanho do buraco.\n")
		return
	}

	// Agrupado por tipo, porque as três perguntas são diferentes: o que
	// apareceu, o que voltou (gatilho!) e o que saiu de cena.
	for _, kind := range []string{"novo", "voltou", "sumiu"} {
		total := w.eventos.total[kind]
		if total == 0 {
			continue
		}
		linhas := append([]string(nil), w.eventos.exemplos[kind]...)
		sort.Strings(linhas)
		fmt.Fprintf(w.humano, "\n%s (%d)\n", rotuloEvento(kind), total)
		for _, l := range linhas {
			fmt.Fprintln(w.humano, l)
		}
		// A CONTAGEM é exata e a LISTA não: dizer quantas ficaram de fora
		// impede que o tamanho da lista seja lido como o tamanho do que houve.
		if n := total - len(linhas); n > 0 {
			fmt.Fprintf(w.humano, "  … e mais %d não listada(s): o resumo mostra "+
				"as %d primeiras de cada tipo. O JSONL tem todas.\n",
				n, maxExemplosPorTipo)
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
	case w.jsonQuebrado:
		// Pela mesma razão: o JSONL é o produto que a frota consome, e um
		// arquivo truncado com exit 0 é a ferramenta afirmando completude sobre
		// um registro que ela sabe estar incompleto.
		return 1
	case w.estadoEsgotado:
		// E pela mesma razão de novo. O comando existe para responder "o que
		// MUDOU", e a partir do teto ele deixou de conseguir responder isso
		// para parte do que viu. Terminar em zero seria dizer "nada mudou"
		// quando a resposta honesta é "não sei mais dizer".
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
