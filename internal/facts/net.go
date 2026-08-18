package facts

import (
	"encoding/binary"
	"encoding/hex"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/lex0c/aletheia/internal/env"
)

// Direction diz QUEM iniciou a conexão, e é a informação que separa um proxy
// reverso legítimo de um pivô (runbook §12.2):
//
//	proxy   ENTRADA externa  +  saída interna
//	pivô    SAÍDA   externa  +  saída interna
//
// Sem ela, o check de pivô dispara em todo nginx que serve tráfego público.
//
// O kernel NÃO registra quem iniciou a conexão: /proc/net/tcp não tem esse
// campo. A direção é INFERIDA comparando a porta local com a tabela de LISTEN —
// mesma inferência que se faz à mão com ss. O limite disso, para quem for
// mexer aqui:
//
//	falso NEGATIVO   um implante que amarre a porta de origem numa porta que
//	                 também está em LISTEN aparece como entrada, e o shell
//	                 reverso deixa de ser reconhecido. Exige SO_REUSEADDR e
//	                 conhecimento do host; é caro, mas é possível.
//	falso POSITIVO   serviço cujo listener foi fechado depois do accept: a
//	                 conexão aceita passa a parecer saída.
//
// Não há fonte melhor sem conntrack ou eBPF. Trocar a inferência por faixa de
// porta efêmera seria pior: é chute, e o implante escolhe a porta.
type Direction string

const (
	DirIn      Direction = "in"  // alguém conectou em nós
	DirOut     Direction = "out" // nós conectamos em alguém
	DirListen  Direction = "listen"
	DirUnknown Direction = "unknown"
)

// Scope classifica o peer. Público significa "fora da rede local" — é o que
// distingue canal com operador de tráfego interno.
type Scope string

const (
	ScopeLoopback Scope = "loopback"
	ScopePrivate  Scope = "private"
	ScopePublic   Scope = "public"
)

// Socket é uma entrada da tabela de conexões, já resolvida.
type Socket struct {
	Proto string `json:"proto"` // tcp | tcp6
	State string `json:"state"` // ESTAB | LISTEN | …

	LocalIP   string `json:"local_ip"`
	LocalPort int    `json:"local_port"`
	PeerIP    string `json:"peer_ip,omitempty"`
	PeerPort  int    `json:"peer_port,omitempty"`

	Inode uint64 `json:"inode"`
	UID   int    `json:"uid"`

	Dir       Direction `json:"dir"`
	PeerScope Scope     `json:"peer_scope,omitempty"`

	// PID vem do join com os fds já coletados. Zero significa dono
	// desconhecido — tipicamente falta de permissão, não ausência de dono.
	PID  int    `json:"pid,omitempty"`
	Comm string `json:"comm,omitempty"`
}

func (s Socket) Peer() string {
	if s.PeerIP == "" {
		return ""
	}
	return net.JoinHostPort(s.PeerIP, strconv.Itoa(s.PeerPort))
}

func (s Socket) Local() string {
	return net.JoinHostPort(s.LocalIP, strconv.Itoa(s.LocalPort))
}

// tcpStates mapeia o campo st de /proc/net/tcp.
var tcpStates = map[string]string{
	"01": "ESTAB", "02": "SYN-SENT", "03": "SYN-RECV", "04": "FIN-WAIT1",
	"05": "FIN-WAIT2", "06": "TIME-WAIT", "07": "CLOSE", "08": "CLOSE-WAIT",
	"09": "LAST-ACK", "0A": "LISTEN", "0B": "CLOSING",
}

func collectSockets(f *Facts, e *env.Env) {
	var socks []Socket
	for _, src := range []struct{ path, proto string }{
		{"/proc/net/tcp", "tcp"},
		{"/proc/net/tcp6", "tcp6"},
		// UDP não é opcional: C2 por DNS e beacon por UDP não aparecem em
		// tabela de TCP nenhuma, e ler só TCP fazia os checks de rede
		// reportarem cobertura COMPLETA tendo ignorado metade da pilha.
		{"/proc/net/udp", "udp"},
		{"/proc/net/udp6", "udp6"},
	} {
		body, ok := readTrim(src.path)
		if !ok {
			// A variante v6 ausente é normal em host sem IPv6; a v4 não é.
			if src.proto == "tcp" || src.proto == "udp" {
				f.partial("net", src.path+" ilegível: nenhuma conexão desse protocolo foi avaliada")
			}
			continue
		}
		socks = append(socks, parseTCPTable(body, src.proto)...)
	}

	// A direção sai de uma comparação, não de heurística de faixa de porta:
	// se a porta local também está em LISTEN, a conexão veio de FORA.
	listening := map[int]bool{}
	for _, s := range socks {
		if s.State == "LISTEN" {
			listening[s.LocalPort] = true
		}
	}
	for i := range socks {
		s := &socks[i]
		switch {
		case isUDP(s.Proto):
			// UDP não tem LISTEN nem handshake, então a comparação com a tabela
			// de escuta não se aplica. Sem peer, o socket está só ligado a uma
			// porta — é o equivalente funcional de um listener. Com peer, o
			// processo chamou connect().
			//
			// LIMITE, e ele importa: implante que usa sendto() sem connect()
			// NÃO expõe o destino aqui. A porta local aparece, o peer não.
			if s.PeerIP == "" {
				s.Dir = DirListen
			} else {
				s.Dir = DirOut
			}
		case s.State == "LISTEN":
			s.Dir = DirListen
		case listening[s.LocalPort]:
			s.Dir = DirIn
		case s.PeerIP != "":
			s.Dir = DirOut
		default:
			s.Dir = DirUnknown
		}
		s.PeerScope = scopeOf(s.PeerIP)
	}

	// Join com os fds já coletados: o dono do socket sai do inode.
	byInode := map[uint64]*Socket{}
	for i := range socks {
		byInode[socks[i].Inode] = &socks[i]
	}
	var orphan int
	for i := range f.Processes {
		p := &f.Processes[i]
		for _, fd := range p.FDs {
			if !fd.Socket {
				continue
			}
			if s, ok := byInode[fd.SocketInode]; ok {
				s.PID, s.Comm = p.PID, p.Comm
			}
		}
	}
	for i := range socks {
		if socks[i].PID == 0 {
			orphan++
		}
	}
	if orphan > 0 && !e.Has(env.CapRoot) {
		f.partial("net", strconv.Itoa(orphan)+" de "+strconv.Itoa(len(socks))+
			" sockets sem dono identificado (sem root, /proc/<pid>/fd de processo alheio "+
			"é ilegível): pivô e reverse shell não puderam ser avaliados neles")
	}

	sort.Slice(socks, func(i, j int) bool { return socks[i].Inode < socks[j].Inode })
	f.Sockets = socks
}

// parseTCPTable lê /proc/net/tcp{,6}. Campos: sl local rem st tx:rx tr:tm
// retrnsmt uid timeout inode …
func parseTCPTable(body, proto string) []Socket {
	var out []Socket
	for i, ln := range strings.Split(body, "\n") {
		if i == 0 { // cabeçalho
			continue
		}
		fs := strings.Fields(ln)
		if len(fs) < 10 {
			continue
		}
		lip, lport, ok := parseHexAddr(fs[1])
		if !ok {
			continue
		}
		rip, rport, ok := parseHexAddr(fs[2])
		if !ok {
			continue
		}
		state, ok := tcpStates[strings.ToUpper(fs[3])]
		if !ok {
			state = "?" + fs[3]
		}
		uid, _ := strconv.Atoi(fs[7])
		inode, _ := strconv.ParseUint(fs[9], 10, 64)

		s := Socket{
			Proto: proto, State: state,
			LocalIP: lip, LocalPort: lport,
			Inode: inode, UID: uid,
		}
		// Peer zerado significa socket sem destino: LISTEN em TCP, e UDP
		// apenas ligado a uma porta.
		if state != "LISTEN" && !(rport == 0 && isUnspecifiedIP(rip)) {
			s.PeerIP, s.PeerPort = rip, rport
		}
		out = append(out, s)
	}
	return out
}

// parseHexAddr decodifica "0100007F:1F90". O endereço vem em hex com cada
// palavra de 32 bits em ordem de HOST — em x86 isso é little-endian, e ignorar
// a inversão faz 127.0.0.1 virar 1.0.0.127.
func parseHexAddr(s string) (ip string, port int, ok bool) {
	h, p, found := strings.Cut(s, ":")
	if !found {
		return "", 0, false
	}
	pn, err := strconv.ParseUint(p, 16, 32)
	if err != nil {
		return "", 0, false
	}
	raw, err := hex.DecodeString(h)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return "", 0, false
	}
	for i := 0; i+4 <= len(raw); i += 4 {
		w := binary.BigEndian.Uint32(raw[i : i+4])
		binary.LittleEndian.PutUint32(raw[i:i+4], w)
	}
	return net.IP(raw).String(), int(pn), true
}

// scopeOf classifica o peer. É deliberadamente conservador: o que não é
// comprovadamente loopback ou privado conta como público, porque errar para
// "público" gera revisão humana e errar para "privado" esconde o canal com o
// operador.
func scopeOf(s string) Scope {
	if s == "" {
		return ""
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return ScopePublic
	}
	switch {
	case ip.IsLoopback(), ip.IsUnspecified():
		return ScopeLoopback
	case ip.IsPrivate(), ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
		return ScopePrivate
	case isCGNAT(ip):
		// 100.64/10 é espaço de operadora, mas em nuvem aparece como rede
		// interna (metadata, mesh). Tratar como público geraria ruído.
		return ScopePrivate
	default:
		return ScopePublic
	}
}

func isUDP(proto string) bool { return strings.HasPrefix(proto, "udp") }

// isUnspecifiedIP reconhece 0.0.0.0 e :: — "endereço nenhum".
func isUnspecifiedIP(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.IsUnspecified()
}

// IsExposedLocal diz se um endereço LOCAL de escuta está exposto para fora da
// máquina.
//
// É a pergunta espelhada do scopeOf, e a resposta para 0.0.0.0 é OPOSTA: como
// peer, "endereço nenhum" não é destino externo; como endereço local de escuta,
// 0.0.0.0 significa TODAS as interfaces — o caso mais exposto que existe.
// Manter as duas perguntas em funções separadas é o que impede alguém de
// "unificar" as duas e inverter uma delas.
func IsExposedLocal(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ip != ""
	}
	return !parsed.IsLoopback()
}

func isCGNAT(ip net.IP) bool {
	v4 := ip.To4()
	return v4 != nil && v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127
}

// LimitesDeRede são os tetos que decidem quando a PRÓXIMA conexão falha.
//
// Existem pela mesma razão do RLIMIT_NPROC no censo de processos: contar
// conexão é fácil, e sozinho não diz nada. O que responde "por que o connect
// está falhando" é a contagem CONTRA o teto — e os dois tetos abaixo são os
// que produzem as duas falhas que o operador encontra no meio do incidente:
//
//	nf_conntrack cheio    o kernel DERRUBA pacote e escreve "table full" no
//	                      dmesg. O sintoma é perda intermitente que não
//	                      aparece em log de aplicação nenhum
//	porta efêmera acaba   connect() falha com EADDRNOTAVAIL, e TIME-WAIT é o
//	                      que come a faixa: cada conexão fechada segura a
//	                      porta por 60s
type LimitesDeRede struct {
	// Conntrack só existe quando o módulo está carregado — em host sem
	// firewall nem NAT ele não está, e isso é resposta e não lacuna.
	ConntrackCount int  `json:"conntrack_count,omitempty"`
	ConntrackMax   int  `json:"conntrack_max,omitempty"`
	ConntrackLido  bool `json:"conntrack_read,omitempty"`

	// A faixa de porta efêmera é o teto de conexões de SAÍDA simultâneas por
	// par (ip de origem, ip:porta de destino).
	PortaEfemeraMin int  `json:"ephemeral_port_min,omitempty"`
	PortaEfemeraMax int  `json:"ephemeral_port_max,omitempty"`
	FaixaLida       bool `json:"ephemeral_range_read,omitempty"`
}

// FaixaEfemera é quantas portas de origem existem. Zero quando não foi lida —
// e zero NÃO pode ser tratado como "não há portas".
func (l LimitesDeRede) FaixaEfemera() int {
	if !l.FaixaLida || l.PortaEfemeraMax < l.PortaEfemeraMin {
		return 0
	}
	return l.PortaEfemeraMax - l.PortaEfemeraMin + 1
}

func collectLimitesDeRede(f *Facts, e *env.Env) {
	l := &f.LimitesRede
	// O conntrack mudou de lugar entre kernels: sondar os dois evita depender
	// de versão.
	for _, p := range []string{
		"/proc/sys/net/netfilter/nf_conntrack_count",
		"/proc/sys/nf_conntrack_count",
	} {
		b, err := e.ReadFile(p)
		if err != nil {
			continue
		}
		if n, ok := inteiroDe(string(b)); ok {
			l.ConntrackCount, l.ConntrackLido = n, true
			break
		}
	}
	if l.ConntrackLido {
		for _, p := range []string{
			"/proc/sys/net/netfilter/nf_conntrack_max",
			"/proc/sys/nf_conntrack_max",
		} {
			b, err := e.ReadFile(p)
			if err != nil {
				continue
			}
			if n, ok := inteiroDe(string(b)); ok {
				l.ConntrackMax = n
				break
			}
		}
	}

	if b, err := e.ReadFile("/proc/sys/net/ipv4/ip_local_port_range"); err == nil {
		campos := strings.Fields(string(b))
		if len(campos) == 2 {
			min, ok1 := inteiroDe(campos[0])
			max, ok2 := inteiroDe(campos[1])
			if ok1 && ok2 {
				l.PortaEfemeraMin, l.PortaEfemeraMax, l.FaixaLida = min, max, true
			}
		}
	}
}

func inteiroDe(s string) (int, bool) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, false
	}
	return n, true
}
