package checks

import (
	"sort"
	"strconv"
	"strings"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
	"github.com/lex0c/aletheia/internal/kbpf"
)

func init() {
	check.Register(bpfSemDono)
	check.Register(bpfInventario)
	check.Register(bpfOculto)
}

// bpfSemDono — runbook §35, SPEC fase 8.
//
// # O que este check pergunta
//
// Um programa eBPF continua carregado enquanto alguém o segurar. Quando
// ninguém que se possa nomear o segura, ele está lá porque um carregador o
// deixou e foi embora — e essa é a forma do implante que vive no kernel.
//
// A pergunta NÃO é "há eBPF neste host?". Há em todo host com systemd moderno,
// e num nó de Kubernetes há dezenas. É "quem segura este programa?", e os
// detentores possíveis são conhecidos:
//
//	descritor aberto   um processo o carregou e o mantém — o caso de toda
//	                   ferramenta com libbpf, e o mais comum de todos
//	perf_event         anexo legado de kprobe: perguntado ao kernel por
//	                   BPF_TASK_FD_QUERY, senão bpftrace viraria achado
//	pin no bpffs       persistência DECLARADA, com caminho e data
//	link               anexo moderno, enumerável
//	tail call          o programa é alvo de um prog_array, e é o mapa que o segura
//
// Nenhum dos cinco, num tipo cuja fixação deveria ser visível: é achado.
//
// # O tipo decide se a pergunta é respondível
//
// Programa de tc, de xdp e de cgroup é segurado por interface e por cgroup —
// coisas que se leem por netlink e por BPF_PROG_QUERY, e esta ferramenta não
// faz nem uma nem outra. Ali a ausência de dono não significa nada, e acusar
// produziria achado em todo host com cilium. Esses viram LACUNA declarada, não
// achado (ver kbpf.FixacaoDe).
var bpfSemDono = check.Check{
	ID:       "kernel.bpf_unowned",
	Ref:      "35",
	Title:    "programa eBPF carregado no kernel sem nenhum dono visível",
	Group:    "kernel",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive,
	Requires: env.CapProcfs,
	Optional: env.CapRoot,
	Wtf:      true,
	FalsePositives: []string{
		"FERRAMENTA QUE JÁ TERMINOU: um programa carregado por algo que morreu " +
			"logo depois pode ser visto no intervalo entre o carregamento e a " +
			"liberação. A janela é de milissegundos, mas existe — repetir a " +
			"varredura resolve, porque implante persiste e corrida não",
		"ANEXO POR SOCKET não é legível daqui: um programa de socket_filter ou " +
			"de sk_reuseport preso por setsockopt fica sem dono aparente, e " +
			"servidor que usa reuseport com eBPF (dnsdist, haproxy) produz " +
			"exatamente esta forma — legitimamente",
		"tc, xdp, cgroup e struct_ops NÃO entram aqui: quem os segura exigiria " +
			"netlink e BPF_PROG_QUERY, e o que a ferramenta faz com eles é " +
			"declarar a lacuna em vez de acusar",
		"varredura de DENTRO de contêiner não produz achado nenhum aqui, mesmo " +
			"quando a enumeração funciona: o espaço de ids do eBPF é global e os " +
			"donos estão fora do namespace de PID, então TODO programa do host " +
			"apareceria órfão",
		"LIMITE que vale mais que o check: se o kernel estiver comprometido, é " +
			"ele quem responde a esta enumeração. Ausência não prova nada; " +
			"presença prova muito",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		if !f.BPF.Enumerado {
			if f.BPF.Lacuna {
				r.Partial = append(r.Partial, f.BPF.Motivo)
			}
			return r
		}

		// De DENTRO de um contêiner privilegiado a enumeração funciona e a
		// atribuição não: o espaço de ids do eBPF é global — são os programas do
		// HOST que aparecem —, e os processos que os seguram estão fora deste
		// namespace de PID. Todo programa do host sai sem dono.
		//
		// Isto não é hipótese: um cenário com SYS_ADMIN produziu 46 programas
		// não atribuíveis e um crítico contra um programa perfeitamente
		// legítimo da máquina que rodava a suíte. Onde a pergunta não pode ser
		// respondida, a resposta é declarar — nunca acusar.
		if f.Host.EmContainer {
			r.Partial = append(r.Partial, "esta varredura roda DENTRO de um contêiner: "+
				"os "+strconv.Itoa(len(f.BPF.Programas))+" programa(s) eBPF enumerados "+
				"são do kernel do HOST, e quem os segura está fora deste namespace de "+
				"PID — sem dono visível aqui não significa nada. Varra o host")
			return r
		}

		naoAtribuiveis := map[kbpf.Fixacao]int{}
		for i := range f.BPF.Programas {
			p := &f.BPF.Programas[i]
			if !p.SemDonoVisivel() {
				continue
			}
			fix := kbpf.FixacaoDe(p.TipoNum)
			if fix != kbpf.FixVisivel && fix != kbpf.FixSocket {
				naoAtribuiveis[fix]++
				continue
			}

			sev := check.SevWarn
			if kbpf.Intercepta(p.TipoNum) {
				sev = check.SevCritical
			}

			ev := []string{
				"programa id=" + strconv.Itoa(int(p.ID)) + " tipo=" + p.Tipo +
					" nome=" + nz(p.Nome, "(sem nome)") + " tag=" + nz(p.Tag, "?"),
				"nenhum processo tem descritor aberto para ele, não há pin no " +
					"bpffs, não há link e nenhum prog_array o alcança",
			}
			if p.CarregadoUTC != "" {
				ev = append(ev, "carregado em "+p.CarregadoUTC+" (UTC), por uid "+
					strconv.Itoa(int(p.UID)))
			} else {
				ev = append(ev, "carregado por uid "+strconv.Itoa(int(p.UID))+
					"; o instante não pôde ser datado")
			}
			if m := fix.Motivo(); m != "" {
				ev = append(ev, m)
			}
			// O detentor de um filtro de socket é um SOCKET, e socket não diz o
			// que carrega. Mas a lista de quem tem socket de captura neste host
			// é curta e agora é lida (§2.6): em vez de mandar o operador
			// procurar, o achado nomeia os candidatos.
			candidatos := detentoresCandidatos(f, fix)
			if len(candidatos) > 0 {
				ev = append(ev, "candidatos a detentor, entre os processos que têm "+
					"socket de captura: "+strings.Join(corta(candidatos, 6), " · ")+
					" — é candidato, não prova: o kernel não diz qual socket carrega "+
					"qual programa")
			} else if fix == kbpf.FixSocket {
				ev = append(ev, "e NÃO há socket de captura visível neste host: ou o "+
					"detentor é um socket comum, ou ele está fora do alcance desta "+
					"varredura")
			}
			if kbpf.Intercepta(p.TipoNum) {
				ev = append(ev, "o tipo deste programa OBSERVA ou ALTERA a execução do "+
					"kernel: é a família usada para esconder arquivo, ler credencial "+
					"em trânsito e receber comando sem abrir porta")
			}

			fd := self.F(sev, "bpf prog id="+strconv.Itoa(int(p.ID)), "", ev...)
			fd.Quando, fd.QuandoFonte = p.CarregadoUTC, "carga do programa eBPF"
			// Um programa eBPF não tem arquivo: ele existe só na memória do
			// kernel e some no reboot. Se ninguém guardar agora, não há o que
			// analisar depois.
			fd.Irreversible = true
			passos := []string{
				"guarde AGORA o que identifica o programa — id, tag e tipo saem " +
					"deste relatório, e o programa some no próximo boot",
				"`bpftool prog dump xlated id " + strconv.Itoa(int(p.ID)) +
					"` mostra o bytecode, quando houver bpftool no host",
			}
			if len(candidatos) > 0 {
				passos = append(passos, "comece pelos candidatos acima: `sudo ls -l "+
					"/proc/<pid>/exe` e `sudo ls -l /proc/<pid>/fd` de cada um "+
					"(runbook §3.8)")
			} else {
				passos = append(passos, "procure quem o segura: um processo com socket "+
					"aberto que não explique o que faz (runbook §3.8)")
			}
			fd.NextSteps = append(passos,
				"NÃO reinicie o host antes de decidir: o reboot é o que apaga a "+
					"única cópia desta evidência")
			r.Findings = append(r.Findings, fd)
		}

		// O que não se sabe atribuir vira LACUNA, com o número junto: sem o
		// número, "não verifiquei" não diz o tamanho do que ficou de fora.
		fixOrdenada := make([]kbpf.Fixacao, 0, len(naoAtribuiveis))
		for fix := range naoAtribuiveis {
			fixOrdenada = append(fixOrdenada, fix)
		}
		sort.Slice(fixOrdenada, func(i, j int) bool { return fixOrdenada[i] < fixOrdenada[j] })
		for _, fix := range fixOrdenada {
			r.Partial = append(r.Partial, strconv.Itoa(naoAtribuiveis[fix])+
				" programa(s) eBPF sem dono visível não foram atribuídos: "+fix.Motivo())
		}
		if f.BPF.Cortado {
			r.Partial = append(r.Partial, "a enumeração de eBPF bateu no teto: "+
				"a lista não é o total")
		}
		r.Partial = append(r.Partial, f.Partial["bpf"]...)
		return r
	},
}

// bpfInventario — runbook §35.
//
// Não é achado: é o QUADRO. A §35 manda perguntar o que está instrumentando o
// kernel, e até aqui a ferramenta não tinha como responder — `bpftool` não está
// instalado na maioria dos servidores, e sem ele ninguém sabe dizer se as
// quatorze coisas carregadas ali são do agente de observabilidade ou não.
//
// Sai como UM achado, não um por programa: num nó de Kubernetes são dezenas, e
// dezenas de linhas idênticas afogam o relatório inteiro.
var bpfInventario = check.Check{
	ID:       "kernel.bpf_inventory",
	Ref:      "35",
	Title:    "o que está instrumentando este kernel por eBPF",
	Group:    "kernel",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive,
	Requires: env.CapProcfs,
	Optional: env.CapRoot,
	Wtf:      false, // é contexto para investigar, não indicador de incêndio
	FalsePositives: []string{
		"não é achado: é o quadro que a §35 manda montar. systemd moderno, " +
			"cilium, falco, tetragon, bpftrace e agente comercial carregam " +
			"programa eBPF por desenho — o que a ferramenta não sabe é quais " +
			"deles este time reconhece",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result

		if !f.BPF.Enumerado {
			if f.BPF.Lacuna {
				r.Partial = append(r.Partial, f.BPF.Motivo)
				return r
			}
			if f.BPF.Motivo == "" {
				return r
			}
			// Não é lacuna de cobertura e mesmo assim precisa ser DITO: um
			// silêncio aqui seria a ferramenta deixando o operador achar que
			// olhou. É o caso do contêiner, cujo kernel é do host.
			r.Findings = append(r.Findings, self.F(check.SevInfo, "eBPF",
				"o eBPF deste kernel não foi enumerado", f.BPF.Motivo))
			return r
		}
		if len(f.BPF.Programas) == 0 {
			return r
		}

		porTipo := map[string]int{}
		porDono := map[string]int{}
		porMecanismo := map[string]int{}
		semDono := 0
		for _, p := range f.BPF.Programas {
			porTipo[p.Tipo]++
			if len(p.Donos) == 0 {
				semDono++
			}
			for _, d := range p.Donos {
				porDono[nz(d.Comm, "pid "+strconv.Itoa(d.PID))]++
				porMecanismo[mecanismoDeDono(d.Como)]++
			}
			if len(p.Pins) > 0 {
				porMecanismo["pin no bpffs"]++
			}
			if len(p.Anexos) > 0 {
				porMecanismo["link"]++
			}
			if p.TailCall {
				porMecanismo["tail call"]++
			}
		}

		ev := []string{
			strconv.Itoa(len(f.BPF.Programas)) + " programa(s) carregado(s), " +
				strconv.Itoa(len(f.BPF.Links)) + " anexo(s) e " +
				strconv.Itoa(f.BPF.Pins) + " pin(s) no bpffs",
			"por tipo: " + resumoContado(porTipo, 8),
		}
		if len(porDono) > 0 {
			ev = append(ev, "quem os segura: "+resumoContado(porDono, 8))
		}
		// O MECANISMO é o que explica por que um programa sem processo dono não
		// virou achado: pin, link, tail call e anexo por perf_event são donos
		// legítimos, e cada um deles é uma resposta diferente à mesma pergunta.
		if len(porMecanismo) > 0 {
			ev = append(ev, "como estão presos: "+resumoContado(porMecanismo, 8))
		}
		if semDono > 0 {
			ev = append(ev, strconv.Itoa(semDono)+" sem processo dono — pin, link "+
				"ou anexo legado respondem por eles")
		}
		ev = append(ev, "a ferramenta não sabe quais destes o time reconhece: "+
			"esse é o trabalho humano que a §35 pede")
		if f.Host.EmContainer {
			// O espaço de ids é global: de dentro de um contêiner o que se
			// enumera é o kernel do host. Sem esta linha o operador leria a
			// lista como se fosse do contêiner.
			ev = append(ev, "esta varredura roda DENTRO de um contêiner: estes "+
				"programas são do kernel do HOST, e quem os segura está fora "+
				"deste namespace de PID")
		}

		fd := self.F(check.SevManual, "eBPF", "", ev...)
		fd.NextSteps = []string{
			"confirme com o time cada nome desta lista que ninguém reconhecer",
			"a lista completa, com id, tag e data de carga, está no JSONL " +
				"(`--json`) — ela some no próximo boot",
		}
		r.Findings = append(r.Findings, fd)
		if f.BPF.Cortado {
			r.Partial = append(r.Partial, "a enumeração de eBPF bateu no teto: "+
				"a lista não é o total")
		}
		return r
	},
}

// bpfOculto — runbook §32, §35.
//
// A mesma pergunta do cross.hidden_pid, aplicada ao kernel: o que estou vendo é
// TUDO que existe? Duas rotas, e as duas comparam fontes independentes.
//
//	citado e não listado   um descritor de processo, um pin ou um link aponta
//	                       para um id que a enumeração não devolveu. Perguntar
//	                       pelo id usa outro caminho no kernel (idr_find) que a
//	                       listagem (idr_get_next), e esconder dos dois de forma
//	                       consistente é mais difícil
//	trampolim sem programa o ftrace mostra que há trampolim de eBPF interceptando
//	                       função de kernel, e a enumeração não devolve NENHUM
//	                       programa dos tipos que usam trampolim
var bpfOculto = check.Check{
	ID:       "cross.bpf_hidden",
	Ref:      "35",
	Title:    "programa eBPF existe e não aparece na enumeração do kernel",
	Group:    "kernel",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive,
	Requires: env.CapProcfs,
	Optional: env.CapRoot,
	Wtf:      true,
	FalsePositives: []string{
		"corrida NÃO produz este achado: o coletor reenumera e pergunta pelo id " +
			"um a um — quem nasceu entre as leituras aparece na segunda, e quem " +
			"morreu não responde. Só sobra o que existe e não é listado",
		"a segunda rota tem um caso legítimo: struct_ops também usa trampolim, e " +
			"por isso ele conta junto de tracing, lsm e ext ao decidir se há " +
			"programa que explique o trampolim",
		"LIMITE: as duas fontes desta comparação vêm do MESMO kernel. Se ele " +
			"estiver comprometido, pode mentir nas duas de forma consistente",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		if !f.BPF.Enumerado {
			if f.BPF.Lacuna {
				r.Partial = append(r.Partial, f.BPF.Motivo)
			}
			return r
		}

		for _, id := range f.BPF.Ocultos {
			fd := self.F(check.SevCritical, "bpf prog id="+strconv.Itoa(int(id)), "", []string{
				"o id " + strconv.Itoa(int(id)) + " é citado por um descritor aberto, " +
					"por um pin ou por um link, e a enumeração do kernel não o devolve",
				"perguntar pelo id e pedir a lista são caminhos diferentes dentro " +
					"do kernel: divergir significa que um deles foi manipulado",
				"é a mesma forma do PID que responde a stat e não aparece na " +
					"listagem de /proc (runbook §32)",
			}...)
			fd.Irreversible = true
			fd.NextSteps = []string{
				"a partir daqui, NADA que dependa deste kernel vale como prova: " +
					"analise a imagem DE FORA (runbook §35.6)",
				"guarde o id e o processo que o cita antes de qualquer outra coisa",
			}
			r.Findings = append(r.Findings, fd)
		}

		if simbolos := trampolimSemPrograma(f); len(simbolos) > 0 {
			fd := self.F(check.SevCritical, "trampolim de eBPF", "", []string{
				strconv.Itoa(len(simbolos)) + " função(ões) do kernel interceptada(s) " +
					"por trampolim de eBPF: " + strings.Join(corta(simbolos, 6), " "),
				"e a enumeração não devolve NENHUM programa dos tipos que usam " +
					"trampolim (tracing, lsm, ext, struct_ops)",
				"o trampolim é criado pelo kernel para um programa que existe: " +
					"a lista de programas está omitindo alguém",
			}...)
			fd.Irreversible = true
			fd.NextSteps = []string{
				"`cat /sys/kernel/tracing/enabled_functions` guardado agora é a " +
					"prova: ela some no reboot",
				"analise a imagem DE FORA: o kernel deste host não é fonte " +
					"confiável (runbook §35.6)",
			}
			r.Findings = append(r.Findings, fd)
		}
		return r
	},
}

// trampolimSemPrograma é a segunda rota: duas interfaces do kernel sobre o
// MESMO fato. O ftrace mostra o trampolim; a bpf(2) deveria mostrar o programa
// que o justifica.
func trampolimSemPrograma(f *facts.Facts) []string {
	var simbolos []string
	for _, h := range f.Ftrace {
		if strings.Contains(h.Callback, "bpf_trampoline") {
			simbolos = append(simbolos, h.Simbolo)
		}
	}
	if len(simbolos) == 0 {
		return nil
	}
	for _, p := range f.BPF.Programas {
		switch p.TipoNum {
		case kbpf.ProgTracing, kbpf.ProgLSM, kbpf.ProgExt, kbpf.ProgStructOps:
			return nil // há quem explique o trampolim
		}
	}
	return simbolos
}

// detentoresCandidatos lista os processos que PODEM estar segurando um
// programa preso a socket.
//
// Vale só para a fixação por socket: para os outros tipos o detentor é outra
// coisa, e oferecer candidato ali confundiria em vez de ajudar. E é candidato
// mesmo — o kernel não expõe qual socket carrega qual programa, e afirmar mais
// que isso seria inventar a ligação que falta.
func detentoresCandidatos(f *facts.Facts, fix kbpf.Fixacao) []string {
	if fix != kbpf.FixSocket {
		return nil
	}
	var out []string
	visto := map[string]bool{}
	for _, s := range f.SocketsBrutos {
		// Socket inerte não recebe pacote e não pode ser o detentor: oferecê-lo
		// como candidato mandaria o operador investigar o runtime de contêiner.
		if s.Inerte() {
			continue
		}
		rot := "dono não identificado"
		if s.PID > 0 {
			rot = nz(s.Comm, "?") + " (pid=" + strconv.Itoa(s.PID) + ")"
		}
		if visto[rot] {
			continue
		}
		visto[rot] = true
		out = append(out, rot)
	}
	return out
}

// mecanismoDeDono reduz o "como" ao mecanismo, sem o detalhe do caso: a
// evidência do inventário conta FORMAS, e o detalhe de cada programa está no
// JSONL. "perf_event kprobe em sys_execve" vira "perf_event kprobe".
func mecanismoDeDono(como string) string {
	if strings.HasPrefix(como, "descritor aberto") {
		return "descritor aberto"
	}
	campos := strings.Fields(como)
	if len(campos) >= 2 {
		return campos[0] + " " + campos[1]
	}
	return nz(como, "?")
}

// resumoContado imprime "systemd(3) · cilium-agent(12)", ordenado por
// quantidade e cortado no teto.
func resumoContado(m map[string]int, max int) string {
	type par struct {
		k string
		n int
	}
	ps := make([]par, 0, len(m))
	for k, n := range m {
		ps = append(ps, par{k, n})
	}
	sort.Slice(ps, func(i, j int) bool {
		if ps[i].n != ps[j].n {
			return ps[i].n > ps[j].n
		}
		return ps[i].k < ps[j].k
	})
	var out []string
	for i, p := range ps {
		if i >= max {
			out = append(out, "…")
			break
		}
		out = append(out, p.k+"("+strconv.Itoa(p.n)+")")
	}
	return strings.Join(out, " · ")
}

func corta(ss []string, max int) []string {
	if len(ss) <= max {
		return ss
	}
	return append(ss[:max:max], "…")
}
