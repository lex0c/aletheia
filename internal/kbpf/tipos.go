package kbpf

import "strconv"

// Tipos de programa (enum bpf_prog_type). O número é ABI e não muda; o nome é
// como a documentação e o bpftool o chamam, para o achado ser pesquisável.
const (
	ProgSocketFilter          = 1
	ProgKprobe                = 2
	ProgSchedCls              = 3
	ProgSchedAct              = 4
	ProgTracepoint            = 5
	ProgXDP                   = 6
	ProgPerfEvent             = 7
	ProgCgroupSkb             = 8
	ProgCgroupSock            = 9
	ProgLwtIn                 = 10
	ProgLwtOut                = 11
	ProgLwtXmit               = 12
	ProgSockOps               = 13
	ProgSkSkb                 = 14
	ProgCgroupDevice          = 15
	ProgSkMsg                 = 16
	ProgRawTracepoint         = 17
	ProgCgroupSockAddr        = 18
	ProgLwtSeg6Local          = 19
	ProgLircMode2             = 20
	ProgSkReuseport           = 21
	ProgFlowDissector         = 22
	ProgCgroupSysctl          = 23
	ProgRawTracepointWritable = 24
	ProgCgroupSockopt         = 25
	ProgTracing               = 26
	ProgStructOps             = 27
	ProgExt                   = 28
	ProgLSM                   = 29
	ProgSkLookup              = 30
	ProgSyscall               = 31
	ProgNetfilter             = 32
)

var nomesDePrograma = map[uint32]string{
	ProgSocketFilter: "socket_filter", ProgKprobe: "kprobe",
	ProgSchedCls: "sched_cls", ProgSchedAct: "sched_act",
	ProgTracepoint: "tracepoint", ProgXDP: "xdp", ProgPerfEvent: "perf_event",
	ProgCgroupSkb: "cgroup_skb", ProgCgroupSock: "cgroup_sock",
	ProgLwtIn: "lwt_in", ProgLwtOut: "lwt_out", ProgLwtXmit: "lwt_xmit",
	ProgSockOps: "sock_ops", ProgSkSkb: "sk_skb",
	ProgCgroupDevice: "cgroup_device", ProgSkMsg: "sk_msg",
	ProgRawTracepoint: "raw_tracepoint", ProgCgroupSockAddr: "cgroup_sock_addr",
	ProgLwtSeg6Local: "lwt_seg6local", ProgLircMode2: "lirc_mode2",
	ProgSkReuseport: "sk_reuseport", ProgFlowDissector: "flow_dissector",
	ProgCgroupSysctl: "cgroup_sysctl", ProgRawTracepointWritable: "raw_tracepoint_writable",
	ProgCgroupSockopt: "cgroup_sockopt", ProgTracing: "tracing",
	ProgStructOps: "struct_ops", ProgExt: "ext", ProgLSM: "lsm",
	ProgSkLookup: "sk_lookup", ProgSyscall: "syscall", ProgNetfilter: "netfilter",
}

// TipoPrograma nomeia o tipo. Tipo DESCONHECIDO sai com o número, não com um
// palpite: um kernel mais novo que este binário tem tipos que ele não conhece,
// e inventar nome ali seria mentir sobre o que se está olhando.
func TipoPrograma(t uint32) string {
	if n, ok := nomesDePrograma[t]; ok {
		return n
	}
	return "tipo_" + strconv.Itoa(int(t))
}

// Tipos de link (enum bpf_link_type).
const (
	LinkRawTracepoint = 1
	LinkTracing       = 2
	LinkCgroup        = 3
	LinkIter          = 4
	LinkNetns         = 5
	LinkXDP           = 6
	LinkPerfEvent     = 7
	LinkKprobeMulti   = 8
	LinkStructOps     = 9
	LinkNetfilter     = 10
	LinkTCX           = 11
	LinkUprobeMulti   = 12
	LinkNetkit        = 13
	LinkSockmap       = 14
)

var nomesDeLink = map[uint32]string{
	LinkRawTracepoint: "raw_tracepoint", LinkTracing: "tracing",
	LinkCgroup: "cgroup", LinkIter: "iter", LinkNetns: "netns",
	LinkXDP: "xdp", LinkPerfEvent: "perf_event", LinkKprobeMulti: "kprobe_multi",
	LinkStructOps: "struct_ops", LinkNetfilter: "netfilter", LinkTCX: "tcx",
	LinkUprobeMulti: "uprobe_multi", LinkNetkit: "netkit", LinkSockmap: "sockmap",
}

func TipoLink(t uint32) string {
	if n, ok := nomesDeLink[t]; ok {
		return n
	}
	return "link_" + strconv.Itoa(int(t))
}

// MapProgArray é o tipo de mapa que guarda ID de programa (tail call).
const MapProgArray = 3

// Fixacao responde a pergunta que decide TODO o falso positivo deste assunto:
// se ninguém que esta ferramenta enxerga segura o programa, isso é uma
// anomalia ou é só o limite da ferramenta?
//
// Um programa eBPF continua carregado enquanto ALGUÉM o segurar. Os detentores
// possíveis são cinco, e só quatro deles são legíveis a partir de um retrato:
//
//	descritor aberto   /proc/<pid>/fd — visível
//	pin no bpffs       arquivo — visível
//	link               enumerável pela bpf(2) — visível
//	tail call          entrada de prog_array — visível, com leitura de mapa
//	anexo LEGADO       tc/xdp por netlink, cgroup por BPF_PROG_ATTACH, socket
//	                   por setsockopt — INVISÍVEL daqui
//
// Acusar sem saber disso produziria achado em todo host com cilium, com
// systemd moderno ou com qualquer coisa que use tc — e é exatamente o tipo de
// ruído que faz o operador parar de ler a saída.
type Fixacao int

const (
	// FixVisivel: se este programa existe, um dos quatro detentores legíveis
	// deveria aparecer. Nenhum aparecer é a anomalia.
	FixVisivel Fixacao = iota
	// FixSocket: preso a um socket por setsockopt. O socket é de algum
	// processo, e o descritor do PROGRAMA pode ter sido fechado logo depois —
	// que é exatamente a forma do BPFDoor.
	FixSocket
	// FixNetlink: tc, xdp e roteamento. Quem segura é a interface, e ler isso
	// exige netlink, que esta ferramenta ainda não fala.
	FixNetlink
	// FixCgroup: anexo por cgroup sem link. Exigiria BPF_PROG_QUERY em cada
	// cgroup da árvore.
	FixCgroup
	// FixMapa: struct_ops e sockmap são segurados por um MAPA.
	FixMapa
	// FixDesconhecida: tipo que este binário não conhece — kernel mais novo que
	// ele. Não se acusa o que não se sabe interpretar.
	FixDesconhecida
)

// Motivo explica por que a ferramenta não consegue nomear o detentor. Vazio
// para FixVisivel, que é o caso em que ela consegue.
func (f Fixacao) Motivo() string {
	switch f {
	case FixSocket:
		return "programa deste tipo é preso a um SOCKET por setsockopt, e o " +
			"descritor do programa pode ter sido fechado depois: o socket " +
			"segura, e ele pertence a algum processo"
	case FixNetlink:
		return "programa deste tipo é anexado a uma INTERFACE (tc, xdp). O XDP " +
			"de cada link e os FILTROS de tc são lidos por netlink quando a " +
			"capacidade existe, e nenhum deles casou com este programa; o que " +
			"continua sem leitura é a AÇÃO de tc (act_bpf), que pendura " +
			"programa dentro do filtro"
	case FixCgroup:
		return "programa deste tipo é anexado a um CGROUP: a ferramenta percorre " +
			"a árvore de cgroups por BPF_PROG_QUERY (attached), e o que aparece " +
			"ali recebe o ponto de anexação. O que resta sem leitura é o anexo " +
			"EFETIVO herdado e os cgroups que o teto ou a permissão não alcançou"
	case FixMapa:
		return "programa deste tipo é segurado por um MAPA (struct_ops, " +
			"sockmap), e o conteúdo desses mapas não foi lido"
	case FixDesconhecida:
		return "tipo de programa que este binário não conhece — o kernel é mais " +
			"novo que ele: não dá para afirmar como este programa está preso"
	}
	return ""
}

var fixacaoPorTipo = map[uint32]Fixacao{
	ProgKprobe:                FixVisivel,
	ProgTracepoint:            FixVisivel,
	ProgPerfEvent:             FixVisivel,
	ProgRawTracepoint:         FixVisivel,
	ProgRawTracepointWritable: FixVisivel,
	ProgTracing:               FixVisivel,
	ProgLSM:                   FixVisivel,
	ProgExt:                   FixVisivel,
	ProgSyscall:               FixVisivel,
	ProgSkLookup:              FixVisivel,

	ProgSocketFilter: FixSocket,
	ProgSkReuseport:  FixSocket,

	ProgSchedCls:      FixNetlink,
	ProgSchedAct:      FixNetlink,
	ProgXDP:           FixNetlink,
	ProgLwtIn:         FixNetlink,
	ProgLwtOut:        FixNetlink,
	ProgLwtXmit:       FixNetlink,
	ProgLwtSeg6Local:  FixNetlink,
	ProgNetfilter:     FixNetlink,
	ProgFlowDissector: FixNetlink,

	ProgCgroupSkb:      FixCgroup,
	ProgCgroupSock:     FixCgroup,
	ProgCgroupSockAddr: FixCgroup,
	ProgCgroupDevice:   FixCgroup,
	ProgCgroupSysctl:   FixCgroup,
	ProgCgroupSockopt:  FixCgroup,
	ProgSockOps:        FixCgroup,

	ProgStructOps: FixMapa,
	ProgSkSkb:     FixMapa,
	ProgSkMsg:     FixMapa,
}

// FixacaoDe classifica o tipo. O padrão é FixDesconhecida, e não FixVisivel:
// diante de um tipo que não está na tabela, o certo é declarar ignorância em
// vez de acusar.
func FixacaoDe(tipo uint32) Fixacao {
	if f, ok := fixacaoPorTipo[tipo]; ok {
		return f
	}
	return FixDesconhecida
}

// Intercepta diz se o tipo serve para OBSERVAR ou ALTERAR a execução do
// kernel — a família que um implante usa para esconder arquivo, roubar
// credencial em trânsito ou receber comando. É o eixo de severidade: um
// programa de rastreamento sem dono é outra conversa que um de estatística.
func Intercepta(tipo uint32) bool {
	switch tipo {
	case ProgKprobe, ProgTracepoint, ProgRawTracepoint, ProgRawTracepointWritable,
		ProgTracing, ProgLSM, ProgPerfEvent, ProgExt, ProgSocketFilter:
		return true
	}
	return false
}
