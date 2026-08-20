package checks

import (
	"strconv"
	"strings"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

func init() {
	check.Register(pidOculto)
	check.Register(threadOculta)
	check.Register(moduloDivergente)
	check.Register(socketDivergente)
}

// socketDivergente — runbook §35.5.
//
// # As duas visões, e por que elas são independentes
//
// Tudo que esta ferramenta sabe de conexão vem de /proc/net/tcp e das três
// tabelas irmãs. É UMA fonte, servida por uma função do kernel — `tcp4_seq_show`
// — que um rootkit intercepta para sumir com a própria conexão. Não é hipótese:
// é o hook que o catálogo de ftrace desta ferramenta procura pelo nome, porque
// é o que os implantes conhecidos usam.
//
// O NETLINK_INET_DIAG responde a mesma pergunta por outro caminho de código: o
// kernel percorre as tabelas de hash de socket e devolve mensagem, sem passar
// pelo `seq_show`. Esconder das duas exige interceptar duas coisas diferentes,
// de forma consistente — que é justamente o que é difícil.
//
// # Só uma direção é achado
//
//	no netlink e NÃO em /proc   a tabela que o `ss` e o `netstat` leem omitiu
//	                            uma conexão que o kernel entrega quando
//	                            perguntado de outro jeito
//	em /proc e NÃO no netlink   o socket fechou entre as duas leituras. É
//	                            rotina, e não é reportado
//
// # CRITICAL, e por que ele invalida as ausências desta execução
//
// O achado aqui não é "vi algo estranho": é a demonstração de que a interface
// que responde por conexão deu duas respostas incompatíveis sobre si mesma.
// Depois disso, "não encontrei nada" em qualquer outro check deixa de valer —
// quem responderia já mostrou que responde o que quer (ver engine.go).
var socketDivergente = check.Check{
	ID:       "cross.socket_view",
	Ref:      "35.5",
	Title:    "socket que o netlink mostra e /proc/net não",
	Group:    "kernel",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive,
	Requires: env.CapProcfs | env.CapNetlink,
	Optional: env.CapRoot,
	Wtf:      true,
	FalsePositives: []string{
		"CORRIDA de socket recém-nascido NÃO produz este achado: o candidato é " +
			"reconfirmado contra uma SEGUNDA leitura de /proc/net e um SEGUNDO " +
			"dump por netlink, e só sobrevive quem aparece nos dois dumps e em " +
			"nenhuma das duas leituras",
		"FALHA DE LEITURA nunca vira CRITICAL: as quatro testemunhas (/proc e " +
			"netlink, 1ª e 2ª passada) têm de ser OBSERVADAS. Qualquer uma que " +
			"não leia torna o candidato INCONCLUSIVO e vira cobertura parcial — " +
			"um kernelBreaker não pode nascer de uma cegueira da própria ferramenta",
		"protocolo cujo dump por netlink FALHOU ou foi PULADO não é comparado " +
			"com /proc — udp_diag é módulo separado do tcp_diag, e a consulta só " +
			"acontece onde o handler já está carregado (senão autocarregaria)",
		"a comparação é por INODE quando ele existe (ESTAB, LISTEN) — o que " +
			"impede SO_REUSEPORT de colapsar vários sockets da mesma tupla numa " +
			"entrada só — e cai para tupla+estado só em TIME-WAIT/SYN-RECV, onde " +
			"o inode é zero nas duas visões",
		"LIMITE que vale mais que o check: se o kernel estiver comprometido no " +
			"nível certo, as duas visões mentem juntas. Ausência de divergência " +
			"não prova nada; presença prova muito",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		if !f.Cross.SocketDiagLido {
			motivo := f.Cross.SocketDiagMotivo
			if motivo == "" {
				motivo = "a enumeração por netlink não foi feita"
			}
			r.Partial = append(r.Partial, "a tabela de conexões NÃO foi confrontada "+
				"com uma segunda visão: "+motivo)
			return r
		}
		for _, s := range f.Cross.SocketOcultos {
			ev := []string{
				s.Proto + " " + s.Local + " → " + nz(s.Peer, "(sem par)") +
					" estado=" + s.Estado,
				"o netlink entrega este socket e /proc/net não o lista: as duas " +
					"visões vêm do MESMO kernel e discordam",
				"uid=" + strconv.FormatUint(uint64(s.UID), 10),
			}
			if s.Inode != 0 {
				ev = append(ev, "socket:["+strconv.FormatUint(uint64(s.Inode), 10)+
					"] — é por este inode que o dono é encontrado nos fds")
			} else {
				ev = append(ev, "sem inode: o socket não pertence mais a processo "+
					"nenhum (TIME-WAIT ou SYN-RECV), e não há fd para procurar")
			}
			ev = append(ev, "as duas visões enxergaram "+
				strconv.Itoa(f.Cross.SocketDiag)+" (netlink) e "+
				strconv.Itoa(f.Cross.SocketProc)+" (/proc/net) sockets comparáveis")

			fd := self.F(check.SevCritical, s.Proto+" "+s.Local, "", ev...)
			fd.NextSteps = []string{
				"o `ss`, o `netstat` e esta ferramenta leem a tabela que OMITIU " +
					"isto: trate toda ausência desta execução como não-resposta",
			}
			if s.Inode != 0 {
				fd.NextSteps = append(fd.NextSteps,
					"ache o dono pelo inode: sudo ls -l /proc/*/fd 2>/dev/null | grep "+
						check.Arg("socket:["+strconv.FormatUint(uint64(s.Inode), 10)+"]"))
			}
			fd.NextSteps = append(fd.NextSteps,
				"confira se há hook nas funções que servem /proc/net: o achado de "+
					"kernel.ftrace_hook em tcp4_seq_show explica exatamente esta divergência",
				"capture o tráfego antes de mexer: "+preservarPcap(e, s.PeerIP()))
			r.Findings = append(r.Findings, fd)
		}
		if f.Cross.SocketDiagCortado {
			r.Partial = append(r.Partial, "o dump por netlink bateu no teto de "+
				"mensagens: a comparação NÃO cobriu todas as conexões")
		}
		return r
	},
}

// pidOculto — runbook §32, §35.
//
// A pergunta que este check faz é diferente de todos os outros do catálogo. Os
// demais perguntam "isto que estou vendo é suspeito?". Este pergunta "o que
// estou vendo é TUDO que existe?".
//
// Um rootkit de userland reescreve `readdir()` e some com o processo da
// listagem de /proc — mas o `stat()` num caminho direto passa por outro caminho
// de código, e esconder dos dois de forma consistente é mais difícil.
//
// Duas formas de achar, e a primeira é a mais precisa:
//
//	ppid       um processo VISÍVEL declara um pai que não aparece na lista. Um
//	           stat resolve sem corrida: se o pai existe, a LISTAGEM mentiu
//	sondagem   PID que responde a stat sem estar na listagem
var pidOculto = check.Check{
	ID:       "cross.hidden_pid",
	Ref:      "35",
	Title:    "processo responde direto mas não aparece na listagem de /proc",
	Group:    "kernel",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive,
	Requires: env.CapProcfs,
	Optional: env.CapRoot,
	Wtf:      true,
	FalsePositives: []string{
		"corrida de nascimento NÃO produz mais este achado: o coletor relista " +
			"/proc depois da sondagem, e quem nasceu no intervalo aparece na " +
			"segunda listagem e é descartado. Foi o que fazia um guest de kernel " +
			"3.18 acusar as threads de kernel nascidas durante o boot",
		"hidepid não causa isto: sob hidepid o processo some das DUAS vias, e o " +
			"que degrada é a cobertura, não a comparação",
		"LIMITE que vale mais que o check: se o KERNEL estiver comprometido, as " +
			"duas fontes mentem juntas. Ausência de divergência não prova nada — " +
			"presença prova muito",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		for _, h := range f.Cross.Hidden {
			viaPPID := strings.HasPrefix(h.Como, "ppid")
			sev := check.SevWarn
			ev := []string{
				"pid=" + strconv.Itoa(h.PID) + " comm=" + nz(h.Comm, "?"),
				h.Como,
			}
			if viaPPID {
				// Esta via não tem corrida: o filho existe AGORA e declara o pai.
				sev = check.SevCritical
				ev = append(ev, "um processo visível declara este PID como pai, e ele "+
					"responde a stat: a LISTAGEM de /proc é que o omitiu")
			} else {
				ev = append(ev, "pode ser processo nascido entre a listagem e a "+
					"sondagem — o que dá sinal é a quantidade, não o caso isolado")
			}
			ev = append(ev, "sondagem foi até pid "+strconv.Itoa(f.Cross.ProbeAte)+
				" (pid_max="+strconv.Itoa(f.Cross.PidMax)+")")

			fd := self.F(sev, "pid="+strconv.Itoa(h.PID), "", ev...)
			fd.Irreversible = true
			fd.NextSteps = []string{
				"leia direto, sem passar por listagem: " +
					"sudo cat /proc/" + strconv.Itoa(h.PID) + "/status /proc/" +
					strconv.Itoa(h.PID) + "/cmdline",
				preservarPID(e, h.PID),
				"ocultação de processo é a assinatura do rootkit: a partir daqui, " +
					"analise a imagem DE FORA",
			}
			r.Findings = append(r.Findings, fd)
		}
		// ModFtraceDiff NÃO é processado aqui: módulo escondido é achado de
		// `moduloDivergente` (cross.module_view), não de PID oculto. Havia um
		// loop duplicado nesta função que fazia um módulo virar cross.hidden_pid
		// — semanticamente errado, e com efeito colateral grave: cross.hidden_pid
		// é kernelBreaker, e o relatório passava a acusar "um PID responde a
		// /proc" sem PID oculto nenhum ter existido. O teste exercitava
		// moduloDivergente direto e não via a duplicação global.
		r.Partial = append(r.Partial, f.Partial["cross"]...)
		return r
	},
}

// threadOculta — runbook §35.
//
// O status DECLARA quantas threads o processo tem; o diretório de tarefas
// MOSTRA quantas existem. São caminhos diferentes no kernel, e esconder uma
// thread exige mentir nos dois.
var threadOculta = check.Check{
	ID:       "cross.thread_count",
	Ref:      "35",
	Title:    "contagem de threads diverge entre o status e o diretório de tarefas",
	Group:    "kernel",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive,
	Requires: env.CapProcfs,
	Optional: env.CapRoot,
	Wtf:      true,
	FalsePositives: []string{
		"thread que MORRE entre as duas leituras produz exatamente esta forma, " +
			"e runtime com pool (Go, JVM, Node) faz isso o tempo todo. Por isso " +
			"o coletor relê e só reporta o que PERSISTE — mas um processo em " +
			"encolhimento rápido e contínuo ainda pode escapar",
		"a direção oposta — diretório com mais entradas que o status declara — " +
			"não é reportada: é só a ordem de leitura, com uma thread nascendo " +
			"no intervalo",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		for _, d := range f.Cross.Threads {
			// O coletor já filtrou direção e confirmou por releitura; aqui só
			// resta o que sobreviveu às duas.
			p := f.ProcessByPID(d.PID)
			nome := "?"
			if p != nil {
				nome = p.Comm
			}
			fd := self.F(check.SevWarn, "pid="+strconv.Itoa(d.PID), "", []string{
				"status declara " + strconv.Itoa(d.Status) + " threads, o diretório " +
					"de tarefas mostra " + strconv.Itoa(d.Task),
				"comm=" + nome,
				"são caminhos diferentes no kernel: esconder uma thread exige " +
					"mentir nos dois",
			}...)
			fd.NextSteps = []string{
				"sudo ls /proc/" + strconv.Itoa(d.PID) + "/task && " +
					"grep Threads /proc/" + strconv.Itoa(d.PID) + "/status",
			}
			r.Findings = append(r.Findings, fd)
		}
		return r
	},
}

// moduloDivergente — runbook §7.12, §35.3.
//
// O kernel expõe a lista de módulos por duas interfaces. Um LKM que se remove
// da lista encadeada para sumir do /proc/modules costuma esquecer do sysfs — e
// o contrário também acontece.
//
// Duas comparações alimentam este check. A primeira é /proc/modules × sysfs,
// só na direção "carregado no /proc e ausente do sysfs" — a oposta é ruído,
// porque módulo embutido no kernel aparece no sysfs e nunca no /proc/modules.
//
// A segunda cobre o ponto cego da primeira: um LKM que faz list_del some do
// /proc/modules mas fica no sysfs, e ali é indistinguível de um builtin. O
// ftrace desfaz o empate — a função rastreável do módulo continua anotada com o
// nome dele mesmo depois do list_del, e builtin não leva anotação de módulo.
var moduloDivergente = check.Check{
	ID:       "cross.module_view",
	Ref:      "35.3",
	Title:    "módulo aparece numa interface do kernel e não na outra",
	Group:    "kernel",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive,
	Requires: env.CapProcfs,
	Optional: env.CapRoot,
	Wtf:      true,
	FalsePositives: []string{
		"nome com hífen e com sublinhado é o MESMO módulo, e a normalização já " +
			"cuida disso. Divergência real aqui é rara",
		"a direção oposta — presente no sysfs e ausente do /proc/modules — é " +
			"módulo EMBUTIDO no kernel, e não é reportada",
		"a comparação com o ftrace só reporta tag presente no ftrace e ausente " +
			"do /proc/modules; o contrário — módulo sem função rastreável, que " +
			"não aparece no ftrace — é normal e não é achado",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		for _, d := range f.Cross.ModDiff {
			fd := self.F(check.SevCritical, d, "", []string{
				d,
				"as duas interfaces expõem a MESMA informação: divergir significa " +
					"que uma delas foi manipulada",
				"é a forma do LKM que se desencadeia da lista para sumir",
			}...)
			fd.NextSteps = []string{
				"compare com um kernel do mesmo pacote em host limpo",
				"a partir daqui, resultado vindo deste host não vale como prova: " +
					"analise a imagem DE FORA",
			}
			r.Findings = append(r.Findings, fd)
		}
		for _, d := range f.Cross.ModFtraceDiff {
			fd := self.F(check.SevCritical, d, "", []string{
				d,
				"o ftrace registra a função rastreável de um módulo no " +
					"CARREGAMENTO e só a libera no descarregamento real: um módulo " +
					"que se desencadeia da lista para sumir do /proc/modules não " +
					"limpa esse registro",
				"e é a interface que o crossview de sysfs não alcança — ali o " +
					"módulo escondido é indistinguível de um embutido no kernel",
			}...)
			fd.NextSteps = []string{
				"`grep \"[<nome>]\" /sys/kernel/tracing/available_filter_functions` " +
					"lista as funções que o módulo escondido ainda expõe",
				"a partir daqui, resultado vindo deste host não vale como prova: " +
					"analise a imagem DE FORA",
			}
			r.Findings = append(r.Findings, fd)
		}
		r.Partial = append(r.Partial, f.Partial["cross"]...)
		return r
	},
}
