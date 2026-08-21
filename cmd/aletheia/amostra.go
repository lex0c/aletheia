package main

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/facts"
	"github.com/lex0c/aletheia/internal/redact"
	"github.com/lex0c/aletheia/internal/report"
)

// O amostrador do `watch` — SPEC 6.2.
//
// Dois casos que nenhum retrato pega, por construção:
//
//	beacon intermitente   conexão que dura 2s a cada 10 min está ausente de
//	                      99,7% dos retratos possíveis
//	processo efêmero      nasce, executa e morre entre duas varreduras
//
// O ciclo de scan completo do `watch` não alcança nenhum dos dois: ele custa
// 1,5s e por isso não roda de cinco em cinco segundos. Este amostrador custa
// 164ms — /proc e sockets, nada de filesystem — e é o que permite o intervalo
// curto.
//
// # O que ele mede que um retrato não pode medir
//
// Aparecer não é o sinal; REAPARECER é. Um serviço legítimo fica de pé. Um
// implante agendado nasce, faz o que veio fazer, morre, e volta no próximo
// disparo — e o intervalo entre as voltas é o gatilho, medido de fora:
//
//	delta quase constante   automação. Humano não é pontual
//	delta que casa com um   e aí a ferramenta não só diz que há automação:
//	`*/N` de cron ou um     ela diz QUEM dispara, cruzando com o que a coleta
//	OnUnitActiveSec         completa já leu
//
// # O que ele NÃO pega, e precisa dizer
//
// Amostragem por polling perde o que dura menos que o intervalo. Um processo de
// 200ms entre duas amostras de 5s não existiu para esta ferramenta. Detecção
// contínua de verdade se instala ANTES do incidente, com eBPF; isto é o
// substituto para quando isso não existe — que é o caso comum.

// minAparicoesParaPeriodo é quantas voltas antes de afirmar periodicidade. Com
// duas há UM intervalo, e um intervalo não é um padrão — é uma coincidência.
const minAparicoesParaPeriodo = 3

// Tetos do estado do amostrador. O `watch` é o comando feito para rodar
// `--for 8h`, e nada aqui era podado — nem `destinos`, nem `aparicoes`, nem
// `jaFalouDoPeriodo`.
//
// Quem escolhe o tamanho desse estado é o HOST VIGIADO: uma varredura de saída
// produz centenas de peers ESTAB distintos por amostra, e a `--interval 5s` por
// 8h são 5760 amostras. A ferramenta de triagem morria por OOM causado pelo
// comprometimento que ela existe para observar.
const (
	// maxDestinos é o teto de peers acompanhados. Ao atingi-lo, os novos são
	// CONTADOS e não acompanhados — e a contagem sai no resumo, porque um
	// número alto aqui já é o achado.
	//
	// A conta que fixa o número: cada destino guarda até maxAparicoes instantes
	// de 24 bytes, então o pior caso é 20000 × 64 × 24 ≈ 31 MB, mais o mapa.
	// Um host legítimo fica três ordens de grandeza abaixo disso.
	maxDestinos = 20000

	// maxAparicoes é a janela deslizante do histórico de um destino. A
	// periodicidade se julga pelos intervalos RECENTES: guardar as 5760 voltas
	// de uma vigília de 8h não melhora a conclusão e faz concluiPeriodo
	// reconstruir `deltas` sobre o histórico inteiro a cada volta — O(n²) por
	// destino, ~16M operações num peer que pisca a cada amostra.
	maxAparicoes = 64
)

// toleranciaPeriodo é o quanto os intervalos podem variar e ainda serem
// chamados de constantes. Amostragem por polling já introduz jitter do tamanho
// do próprio intervalo, então um piso apertado demais nunca dispararia.
const toleranciaPeriodo = 0.25

// amostrador guarda o que viu entre amostras.
type amostrador struct {
	// pids que estavam na amostra anterior, com o que identifica cada um.
	pids map[int]facts.Process
	// destinos remotos, com o instante de cada REAPARIÇÃO.
	destinos map[string]*ritmo
	// jaFalouDoPeriodo evita repetir a mesma conclusão a cada volta.
	jaFalouDoPeriodo map[string]bool
	amostras         int

	// destinosDescartados conta os peers que não couberam no teto. Sai no
	// resumo: silenciar o corte diria "acompanhei tudo" sobre uma vigília que
	// parou de acompanhar.
	destinosDescartados int
}

// ritmo é o histórico de aparições de um destino.
type ritmo struct {
	presente bool
	// aparicoes é a JANELA das últimas voltas, não o histórico inteiro — ver
	// maxAparicoes.
	aparicoes []time.Time
	// vistas é a contagem TOTAL de reaparições, que a janela não guarda. Ela
	// entra na frase do achado: "repete a cada ~5s em 500 aparições" é
	// evidência muito mais forte que "em 64", e dizer 64 porque foi só o que
	// coube na janela seria subdeclarar o que se observou.
	vistas int
	exe    string
}

func novoAmostrador() *amostrador {
	return &amostrador{
		pids:             map[int]facts.Process{},
		destinos:         map[string]*ritmo{},
		jaFalouDoPeriodo: map[string]bool{},
	}
}

// amostra compara com a anterior e devolve as linhas do que mudou.
//
// `completo` é o último Facts da varredura completa, usado só para nomear o
// gatilho quando um período é medido. Pode ser nil.
func (a *amostrador) amostra(f *facts.Facts, completo *facts.Facts, agora time.Time) []linhaAmostra {
	var out []linhaAmostra
	primeira := a.amostras == 0
	a.amostras++

	// --- processos ---------------------------------------------------------
	atuais := map[int]facts.Process{}
	for i := range f.Processes {
		p := &f.Processes[i]
		if p.Self {
			continue
		}
		atuais[p.PID] = *p
		if primeira {
			continue
		}
		if _, tinha := a.pids[p.PID]; !tinha {
			out = append(out, linhaAmostra{
				Sev: check.SevInfo, ID: "watch.process_new",
				Assunto: "pid=" + strconv.Itoa(p.PID),
				Texto: fmt.Sprintf("%s ＋ processo pid=%d %s%s%s%s",
					agora.Format("15:04:05"), p.PID, report.Safe(exeOuComm(p)),
					argvDe(p), cgroupDe(p), paiDe(p, atuais, a.pids)),
			})
		}
	}
	if !primeira {
		for pid, p := range a.pids {
			if _, ainda := atuais[pid]; !ainda {
				out = append(out, linhaAmostra{
					Sev: check.SevInfo, ID: "watch.process_gone",
					Assunto: "pid=" + strconv.Itoa(pid),
					Texto: fmt.Sprintf("%s － processo pid=%d %s terminou",
						agora.Format("15:04:05"), pid, report.Safe(exeOuComm(&p))),
				})
			}
		}
	}
	a.pids = atuais

	// --- destinos remotos --------------------------------------------------
	vistos := map[string]bool{}
	for i := range f.Sockets {
		s := &f.Sockets[i]
		// SÓ o que SAI daqui.
		//
		// A conexão de ENTRADA é o outro lado de uma conversa que alguém abriu
		// conosco, e o "destino" dela é a porta efêmera do cliente — número
		// diferente a cada vez. Contá-las faz cada requisição virar um destino
		// novo, e num servidor com tráfego a tela vira uma lista de portas
		// aleatórias com o beacon enterrado no meio. Apareceu no primeiro
		// cenário: o próprio listener do rig gerava uma linha por conexão.
		//
		// E é o corte certo pelo que se procura: beacon é o host FALANDO com
		// alguém, não alguém falando com o host.
		if s.Dir != facts.DirOut || s.State != "ESTAB" || s.Peer() == "" {
			continue
		}
		chave := s.Peer()
		vistos[chave] = true
		r := a.destinos[chave]
		if r == nil {
			if len(a.destinos) >= maxDestinos {
				a.destinosDescartados++
				continue
			}
			r = &ritmo{}
			a.destinos[chave] = r
		}
		if e := exeDoSocket(f, s); e != "" {
			r.exe = e
		}
		if r.presente {
			continue // já estava: não é volta
		}
		r.presente = true
		r.vistas++
		r.aparicoes = append(r.aparicoes, agora)
		if len(r.aparicoes) > maxAparicoes {
			// Janela deslizante: descarta a volta mais antiga em vez de crescer.
			r.aparicoes = append(r.aparicoes[:0], r.aparicoes[1:]...)
		}
		if primeira {
			continue
		}
		// r.vistas, e não len(r.aparicoes): a janela deslizante nunca deixa o
		// slice passar de maxAparicoes, mas ela também não volta a 1 — só que
		// depender do comprimento aqui amarra "é a primeira vez" a uma estrutura
		// que existe por razão de memória. A contagem total é quem responde.
		if r.vistas == 1 {
			out = append(out, linhaAmostra{
				Sev: check.SevInfo, ID: "watch.peer_new", Assunto: chave,
				Texto: fmt.Sprintf("%s ＋ conexão %s%s",
					agora.Format("15:04:05"), report.Safe(chave), porQuem(r)),
			})
		} else {
			d := agora.Sub(r.aparicoes[len(r.aparicoes)-2])
			out = append(out, linhaAmostra{
				Sev: check.SevInfo, ID: "watch.peer_back", Assunto: chave,
				Texto: fmt.Sprintf("%s ↻ conexão %s%s — voltou depois de %s",
					agora.Format("15:04:05"), report.Safe(chave), porQuem(r), d.Round(time.Second)),
			})
		}
		if l := a.concluiPeriodo(chave, r, completo); l.Texto != "" {
			out = append(out, l)
		}
	}
	for chave, r := range a.destinos {
		if r.presente && !vistos[chave] {
			r.presente = false
		}
	}
	return out
}

// linhaAmostra é o que o amostrador produz.
//
// O texto é o que o humano lê; a severidade, o id e o assunto são o que o exit
// code e o JSONL precisam. Enquanto isto era []string, o amostrador DETECTAVA e
// não conseguia reportar: nada em w.amostra tocava w.pior, w.eventos ou w.jsonW,
// então `watch --for 8h --json f.jsonl` achava o beacon, imprimia a linha em
// stderr e saía 0 com o arquivo sem uma única linha vinda daqui.
type linhaAmostra struct {
	Texto   string
	Sev     check.Severity
	ID      string
	Assunto string
}

// concluiPeriodo afirma periodicidade, uma vez só por destino.
func (a *amostrador) concluiPeriodo(chave string, r *ritmo, completo *facts.Facts) linhaAmostra {
	if a.jaFalouDoPeriodo[chave] || len(r.aparicoes) < minAparicoesParaPeriodo {
		return linhaAmostra{}
	}
	var deltas []float64
	for i := 1; i < len(r.aparicoes); i++ {
		deltas = append(deltas, r.aparicoes[i].Sub(r.aparicoes[i-1]).Seconds())
	}
	media, ok := constante(deltas)
	if !ok {
		// Irregular é conclusão também, e é a oposta: humano, não automação.
		// Não vira linha para não competir com o achado.
		//
		// Com a janela CHEIA a conclusão já está formada, e insistir só
		// reconstrói `deltas` inteiro a cada volta — o O(n²) por destino. Um
		// peer com jitter irregular nunca marcava, e era exatamente ele que
		// pagava o laço para sempre.
		if len(r.aparicoes) >= maxAparicoes {
			a.jaFalouDoPeriodo[chave] = true
		}
		return linhaAmostra{}
	}
	a.jaFalouDoPeriodo[chave] = true

	l := fmt.Sprintf("           ⏱ %s repete a cada ~%s em %d aparições: "+
		"intervalo constante é AUTOMAÇÃO, não pessoa",
		report.Safe(chave), time.Duration(media*float64(time.Second)).Round(time.Second),
		r.vistas)
	if quem := gatilhoComPeriodo(completo, media); quem != "" {
		l += "\n           ⏱ e casa com um gatilho já lido nesta máquina: " + report.Safe(quem)
	}
	// AVISO, e não informação: período constante é o discriminador entre
	// automação e pessoa, e é o único achado que só este comando produz — a
	// varredura completa de 60 s não vê a conexão de 2 s que se repete. Sem
	// severidade ele não chegava ao exit code nem ao JSONL, e a frota lia "host
	// limpo" exatamente sobre ele.
	return linhaAmostra{
		Sev: check.SevWarn, ID: "watch.beacon", Assunto: chave, Texto: l,
	}
}

// constante diz se os intervalos são regulares o bastante para se chamarem um
// período, e devolve a média.
func constante(d []float64) (float64, bool) {
	if len(d) == 0 {
		return 0, false
	}
	var soma float64
	for _, x := range d {
		soma += x
	}
	media := soma / float64(len(d))
	if media <= 0 {
		return 0, false
	}
	for _, x := range d {
		if math.Abs(x-media)/media > toleranciaPeriodo {
			return 0, false
		}
	}
	return media, true
}

// gatilhoComPeriodo procura, no que a varredura completa já leu, um agendamento
// com o mesmo período.
//
// É o pulo do gato das duas cadências juntas: o amostrador mede o ritmo DE
// FORA, sem saber de onde vem, e a coleta completa sabe quais gatilhos existem.
// Cruzar os dois transforma "há automação" em "é este cron aqui".
func gatilhoComPeriodo(f *facts.Facts, seg float64) string {
	if f == nil || seg <= 0 {
		return ""
	}
	casa := func(alvo float64) bool {
		return alvo > 0 && math.Abs(alvo-seg)/seg <= toleranciaPeriodo
	}
	for i := range f.Cron {
		c := &f.Cron[i]
		if casa(float64(c.IntervalSec)) {
			return "cron " + c.File + ":" + strconv.Itoa(c.Line) + " (" + c.Schedule + ")"
		}
	}
	for i := range f.Units {
		u := &f.Units[i]
		if u.OnUnitActiveSec == "" {
			continue
		}
		d, err := time.ParseDuration(u.OnUnitActiveSec)
		if err == nil && casa(d.Seconds()) {
			return "timer " + u.Name + " (OnUnitActiveSec=" + u.OnUnitActiveSec + ")"
		}
	}
	return ""
}

func exeOuComm(p *facts.Process) string {
	if p.Exe != "" {
		return p.Exe
	}
	if p.Comm != "" {
		return "[" + p.Comm + "]"
	}
	return "?"
}

// paiDe nomeia quem gerou o processo, porque "apareceu um /bin/sh" e "o cron
// gerou um /bin/sh" são fatos diferentes.
func paiDe(p *facts.Process, atuais, antes map[int]facts.Process) string {
	if p.PPID == 0 {
		return ""
	}
	pai, ok := atuais[p.PPID]
	if !ok {
		pai, ok = antes[p.PPID]
	}
	if !ok {
		return " (pai pid=" + strconv.Itoa(p.PPID) + ", já saiu)"
	}
	return " ← " + report.Safe(exeOuComm(&pai))
}

// argvDe mostra os argumentos, porque o mesmo binário faz coisas diferentes
// conforme como foi chamado: `curl url` e `curl url | sh` são o mesmo exe.
//
// O cmdline VAZIO com exe presente é sinal por si — é assim que um processo que
// se apagou do `ps` aparece —, e por isso ele é dito e não omitido.
func argvDe(p *facts.Process) string {
	if p.CmdlineEmpty {
		return " [cmdline VAZIO]"
	}
	if len(p.Argv) < 2 {
		return ""
	}
	// Redigir ANTES do corte de 60 colunas, como linhaCurta já faz. report.Safe
	// sanitiza controle e não redige nada: este era o único consumidor de argv
	// que não passava por redact.Cmdline — e é o que roda por HORAS com a saída
	// sendo capturada. Um `watch` aberto durante o backup noturno punha
	// `mysqldump -u root -pS3cr3t` na tela e no log do operador.
	args := strings.Join(redact.Cmdline(p.Argv)[1:], " ")
	if len(args) > 60 {
		args = args[:59] + "…"
	}
	return " " + report.Safe(args)
}

// cgroupDe diz de qual contêiner ou unit o processo veio. Num host com docker,
// é a diferença entre "apareceu um processo" e "apareceu um processo FORA de
// qualquer contêiner".
func cgroupDe(p *facts.Process) string {
	if p.Cgroup == "" {
		return ""
	}
	c := p.Cgroup
	if i := strings.LastIndexByte(c, '/'); i >= 0 && i < len(c)-1 {
		c = c[i+1:]
	}
	if len(c) > 32 {
		c = c[:31] + "…"
	}
	return " {" + report.Safe(c) + "}"
}

func porQuem(r *ritmo) string {
	if r.exe == "" {
		return ""
	}
	return " por " + report.Safe(r.exe)
}

func exeDoSocket(f *facts.Facts, s *facts.Socket) string {
	if s.PID == 0 {
		return ""
	}
	if p := f.ProcessByPID(s.PID); p != nil {
		return exeOuComm(p)
	}
	return ""
}

// resumoDeAmostragem é o rodapé obrigatório: dizer o que a amostragem NÃO pega
// é parte do resultado, não ressalva de rodapé.
func (a *amostrador) resumo(intervalo time.Duration) string {
	var b strings.Builder
	fmt.Fprintf(&b, "amostragem: %d amostras a cada %s\n", a.amostras, intervalo)

	var periodicos []string
	for chave := range a.jaFalouDoPeriodo {
		periodicos = append(periodicos, chave)
	}
	if len(periodicos) > 0 {
		sort.Strings(periodicos)
		fmt.Fprintf(&b, "destinos com ritmo constante: %s\n", strings.Join(periodicos, " "))
	}
	if a.destinosDescartados > 0 {
		// O corte é DITO. Uma vigília que parou de acompanhar destinos e cala
		// sobre isso relata "nenhum ritmo constante" sobre o que não olhou — e
		// o número alto aqui já é, por si, o sinal de varredura de saída.
		fmt.Fprintf(&b, "ATENÇÃO: o teto de %d destinos acompanhados foi atingido e "+
			"%d aparição(ões) de destinos novos NÃO foram acompanhadas — esse "+
			"volume de peers distintos já é, por si, comportamento de varredura\n",
			maxDestinos, a.destinosDescartados)
	}
	fmt.Fprintf(&b, "o que dura menos que %s pode não ter sido amostrado: "+
		"polling perde processo muito curto, e detecção contínua de verdade se "+
		"instala ANTES do incidente (eBPF)\n", intervalo)
	return b.String()
}
