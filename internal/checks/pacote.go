package checks

import (
	"sort"
	"strconv"
	"strings"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

func init() { check.Register(socketDeCaptura) }

// socketDeCaptura — runbook §2.6.
//
// # A pergunta que nenhum outro check faz
//
// Todo o resto da leitura de rede desta ferramenta é sobre CONEXÃO: quem fala
// com quem, em que porta, em que direção. Um socket AF_PACKET não é conexão —
// ele recebe da interface o que passa por ela, inclusive o que não é
// endereçado àquele processo, e não abre porta nenhuma. Para a tabela de
// conexões, quem tem um deles não tem rede.
//
// É o mecanismo do sniffer, e é como uma credencial em texto claro sai de um
// host sem que nada apareça em /proc/net/tcp.
//
// # Por que é inventário e não acusação
//
// A população legítima é real e comum. Medido num desktop com wifi: três
// sockets AF_PACKET, todos de root, com protocolo de GESTÃO DE REDE — ARP,
// EAPOL e TDLS —, mais um raw6 de ICMPv6. É o wpa_supplicant e o cliente de
// DHCP fazendo o trabalho deles, e num servidor a lista costuma ser menor.
//
// O que separa isso de um sniffer é o NOME de quem segura, e reconhecer nome é
// trabalho de quem opera o host. O juízo objetivo desta ferramenta fica em
// outro lugar: no cruzamento com o programa eBPF órfão (`kernel.bpf_unowned`),
// onde a existência do socket deixa de ser contexto e vira o detentor
// procurado.
var socketDeCaptura = check.Check{
	ID:       "net.packet_socket",
	Ref:      "2.6",
	Title:    "quem consegue ler o tráfego deste host",
	Group:    "net",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive,
	Requires: env.CapProcfs,
	Optional: env.CapRoot,
	Wtf:      false, // é contexto para investigar, não indicador de incêndio
	FalsePositives: []string{
		"não é achado: é o quadro que a §2.6 manda montar. Cliente de DHCP, " +
			"wpa_supplicant, NetworkManager e ferramenta de diagnóstico usam " +
			"exatamente isto — num desktop com wifi são três, sempre de root",
		"ETH_P_ALL não é assinatura de sniffer sozinho: o cliente de DHCP da ISC " +
			"pede TODO o tráfego e filtra por cima, e o tcpdump do próprio " +
			"respondedor produz a mesma linha",
		"modo promíscuo tem dono legítimo em qualquer host com contêiner ou VM: " +
			"a ponte precisa dele para entregar quadro a quem não é o dono do MAC",
		"sem root o DONO não é identificável, e a lista sai sem nome — o que " +
			"degrada é a cobertura, não a leitura",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		if len(f.SocketsBrutos) == 0 {
			r.Partial = append(r.Partial, f.Partial["pacote"]...)
			return r
		}

		// Agrupado por DETENTOR: um processo com quatro sockets é um fato, não
		// quatro. Quem não pôde ser identificado cai num grupo próprio, e o
		// grupo diz isso em voz alta.
		type grupo struct {
			pid    int
			comm   string
			socks  []facts.SocketBruto
			amplo  bool
			ifaces map[string]bool
		}
		por := map[int]*grupo{}
		var ordem []int
		for _, s := range f.SocketsBrutos {
			// Socket que não está enganchado no caminho de recepção não lê nada,
			// e a §2.6 pergunta por quem LÊ. Todo contêiner tem um desses,
			// deixado pelo runtime ao montar o namespace — reportá-lo faria a
			// ferramenta falar em toda varredura de contêiner, com o dono
			// eternamente fora de alcance.
			if s.Inerte() {
				continue
			}
			g := por[s.PID]
			if g == nil {
				g = &grupo{pid: s.PID, comm: s.Comm, ifaces: map[string]bool{}}
				por[s.PID] = g
				ordem = append(ordem, s.PID)
			}
			g.socks = append(g.socks, s)
			g.amplo = g.amplo || s.TodoTrafego()
			if s.IfaceNome != "" {
				g.ifaces[s.IfaceNome] = true
			}
		}
		sort.Ints(ordem)

		promiscuas := interfacesPromiscuas(f)

		for _, pid := range ordem {
			g := por[pid]
			var desc []string
			for _, s := range g.socks {
				d := s.Familia + ":" + s.Proto
				if s.IfaceNome != "" {
					d += " em " + s.IfaceNome
				}
				if s.Tipo == "SOCK_RAW" {
					d += " (quadro inteiro)"
				}
				desc = append(desc, d)
			}

			sujeito := "pid=" + strconv.Itoa(pid)
			ev := []string{strconv.Itoa(len(g.socks)) + " socket(s): " + strings.Join(corta(desc, 6), " · ")}
			if pid == 0 {
				sujeito = "dono não identificado"
				ev = append(ev, "o processo dono NÃO foi identificado: sem root, o "+
					"descritor de processo alheio é ilegível. Os sockets existem e "+
					"quem os segura não pôde ser nomeado")
			} else {
				ev = append(ev, "processo: "+nz(g.comm, "?")+" (uid do socket: "+
					strconv.Itoa(g.socks[0].UID)+")")
			}
			if g.amplo {
				ev = append(ev, "um deles pede TODO o tráfego (ETH_P_ALL): recebe o "+
					"que passa pela interface, e não só o que é endereçado a este host")
			}
			if len(promiscuas) > 0 {
				ev = append(ev, "e há interface em modo PROMÍSCUO: "+
					strings.Join(promiscuas, " · ")+" — contexto, não achado: ponte de "+
					"contêiner e de VM ligam isso por desenho")
			}
			ev = append(ev, "a ferramenta não sabe quais destes o time reconhece: "+
				"gerenciador de rede e cliente de DHCP usam o mesmo mecanismo")

			fd := self.F(check.SevManual, sujeito, "", ev...)
			fd.NextSteps = []string{
				"confirme com o time cada processo desta lista que ninguém reconhecer",
				"um socket de captura não abre porta: ele NÃO aparece em `ss -tulpn` " +
					"nem na tabela de conexões deste relatório",
			}
			if pid > 0 {
				fd.NextSteps = append(fd.NextSteps,
					"sudo ls -l /proc/"+strconv.Itoa(pid)+"/exe && sudo cat /proc/"+
						strconv.Itoa(pid)+"/cmdline | tr '\\0' ' '")
			}
			r.Findings = append(r.Findings, fd)
		}
		r.Partial = append(r.Partial, f.Partial["pacote"]...)
		return r
	},
}

func interfacesPromiscuas(f *facts.Facts) []string {
	var out []string
	for _, i := range f.Interfaces {
		if i.Promisc {
			out = append(out, i.Nome)
		}
	}
	return out
}
