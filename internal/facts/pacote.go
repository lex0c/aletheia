package facts

import (
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/lex0c/aletheia/internal/env"
)

// Sockets que leem PACOTE, não conexão (runbook §2.6).
//
// # O ponto cego que isto fecha
//
// A ferramenta lê /proc/net/tcp e /proc/net/udp, e um socket AF_PACKET não
// aparece em nenhum dos dois. Quem tem um deles lê o tráfego da interface
// inteira — inclusive o que não é endereçado a ele — e não abre porta nenhuma:
// para toda a tabela de conexões, aquele processo não tem rede.
//
// É o mecanismo do sniffer, e é a outra metade do implante que a fase 8 achou:
// um programa eBPF de socket_filter órfão continua vivo porque um SOCKET o
// segura, e o socket é de alguém. Sem esta leitura, o achado terminava em
// "procure quem o segura"; com ela, ele nomeia os candidatos.
//
// # A população legítima, medida
//
// Num desktop com wifi: três sockets AF_PACKET, todos de root, com protocolos
// de GESTÃO DE REDE — ARP, EAPOL (802.1X) e TDLS —, mais um raw6 de ICMPv6. É
// o wpa_supplicant e o cliente de DHCP fazendo o trabalho deles.
//
// Por isso este coletor alimenta um INVENTÁRIO, e não uma acusação: o que
// separa o sniffer do gerenciador de rede é o nome de quem segura, e isso é
// reconhecimento humano. O juízo objetivo fica na correlação com o eBPF órfão.

// SocketBruto é um socket que recebe pacote sem passar pela pilha de conexão.
type SocketBruto struct {
	// Familia distingue de onde ele veio: packet (camada 2) ou raw (camada 3).
	Familia string `json:"family"`
	// Proto é o nome quando conhecido, senão o número em hexadecimal.
	Proto    string `json:"proto"`
	ProtoNum int    `json:"proto_num"`
	// Tipo só existe em AF_PACKET: SOCK_RAW vê o quadro inteiro, SOCK_DGRAM
	// recebe o pacote já sem o cabeçalho de enlace.
	Tipo string `json:"type,omitempty"`

	// Ativo é a coluna R do /proc/net/packet: o socket está ENGANCHADO no
	// caminho de recepção. Um AF_PACKET criado e nunca ligado a protocolo
	// nenhum não recebe quadro algum, e a distinção não é cosmética — ver
	// Inerte.
	Ativo bool `json:"active,omitempty"`

	Iface     int    `json:"ifindex,omitempty"`
	IfaceNome string `json:"iface,omitempty"`

	Inode uint64 `json:"inode"`
	UID   int    `json:"uid"`

	// PID vem do join com os fds já coletados. Zero significa dono
	// DESCONHECIDO — sem root, o fd de processo alheio é ilegível — e não
	// ausência de dono.
	PID  int    `json:"pid,omitempty"`
	Comm string `json:"comm,omitempty"`
	Exe  string `json:"exe,omitempty"`
}

// TodoTrafego responde se este socket vê o que não é dele. É o discriminador
// entre "gerenciador de rede falando o protocolo dele" e "alguém escutando o
// fio inteiro".
func (s SocketBruto) TodoTrafego() bool {
	// ETH_P_ALL, e SÓ ele: o kernel entrega todos os quadros. É o que o tcpdump
	// pede — e também o que o cliente de DHCP da ISC pede, com um filtro por
	// cima. Protocolo ZERO é o oposto disso: não recebe nada.
	return s.Familia == "packet" && s.ProtoNum == 0x0003
}

// Inerte diz que este socket NÃO recebe pacote nenhum.
//
// Medido: todo contêiner Debian recém-criado tem um AF_PACKET com protocolo
// 0000, sem interface e com a coluna de running em zero — o runtime o cria ao
// montar o namespace de rede e o dono vive fora do contêiner. Ele não lê nada,
// e reportá-lo faria a ferramenta acusar "alguém pode ler o tráfego" em toda
// varredura de contêiner, com o dono eternamente não identificado.
//
// A distinção é do kernel, não minha: sem enganchar no caminho de recepção,
// nenhum quadro chega ao socket.
func (s SocketBruto) Inerte() bool {
	return s.Familia == "packet" && !s.Ativo
}

// Interface é o retrato de uma interface de rede, para o que o socket sozinho
// não conta.
type Interface struct {
	Nome     string `json:"name"`
	Index    int    `json:"ifindex"`
	Promisc  bool   `json:"promisc,omitempty"`
	Flags    uint64 `json:"-"`
	Ativa    bool   `json:"up,omitempty"`
	Loopback bool   `json:"loopback,omitempty"`
}

const (
	iffUp       = 0x1
	iffLoopback = 0x8
	iffPromisc  = 0x100
)

func collectSocketsBrutos(f *Facts, e *env.Env) {
	f.Interfaces = lerInterfaces()
	porIndice := map[int]string{}
	for _, i := range f.Interfaces {
		porIndice[i.Index] = i.Nome
	}

	// AUSENTE não é ILEGÍVEL, e a distinção custou três cenários de VM antes de
	// ser implementada como está escrita aqui.
	//
	//	não existe    kernel sem CONFIG_PACKET — os dois kernels legados da
	//	              suíte são assim. Não há socket de pacote para achar,
	//	              porque o kernel não sabe criar um. Não é lacuna
	//	existe e não abre  aí sim: a interface está lá e não pôde ser lida
	//
	// Tratar as duas igual fazia todo guest de kernel antigo sair com cobertura
	// degradada por uma capacidade que aquele kernel não tem — a mesma confusão
	// que o coletor de ftrace já tinha resolvido do outro lado.
	var out []SocketBruto
	body, err := readTrimErr("/proc/net/packet")
	switch {
	case err == nil:
		out = append(out, parsePacketTable(body)...)
	case os.IsNotExist(err):
		// kernel sem suporte a AF_PACKET: nada a enumerar
	default:
		f.partial("pacote", "/proc/net/packet existe e não pôde ser lido: sockets "+
			"de captura de pacote não foram enumerados")
	}
	for _, src := range []struct{ path, fam string }{
		{"/proc/net/raw", "raw"},
		{"/proc/net/raw6", "raw6"},
	} {
		if body, ok := readTrim(src.path); ok {
			out = append(out, parseRawTable(body, src.fam)...)
		}
	}
	if len(out) == 0 {
		return
	}

	for i := range out {
		out[i].IfaceNome = porIndice[out[i].Iface]
	}

	// Join com os fds já coletados, igual ao dos sockets de conexão: o dono
	// sai do inode.
	byInode := map[uint64]*SocketBruto{}
	for i := range out {
		byInode[out[i].Inode] = &out[i]
	}
	for i := range f.Processes {
		p := &f.Processes[i]
		for _, fd := range p.FDs {
			if !fd.Socket {
				continue
			}
			if s, ok := byInode[fd.SocketInode]; ok {
				s.PID, s.Comm, s.Exe = p.PID, p.Comm, p.Exe
			}
		}
	}

	// A conta de "sem dono" é sobre o que CAPTURA. Um socket inerte não lê
	// tráfego, e degradar a cobertura por não saber o dono dele seria declarar
	// uma lacuna que não existe.
	semDono, capturam := 0, 0
	for i := range out {
		if out[i].Inerte() {
			continue
		}
		capturam++
		if out[i].PID == 0 {
			semDono++
		}
	}
	if semDono > 0 {
		motivo := "não foi possível identificar o processo dono"
		if !e.Has(env.CapRoot) {
			motivo = "sem root, /proc/<pid>/fd de processo alheio é ilegível"
		}
		f.partial("pacote", strconv.Itoa(semDono)+" de "+strconv.Itoa(capturam)+
			" sockets de pacote/raw sem dono identificado ("+motivo+"): quem "+
			"lê o tráfego deste host não pôde ser nomeado")
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Inode < out[j].Inode })
	f.SocketsBrutos = out
}

// parsePacketTable lê /proc/net/packet. Os campos:
//
//	sk               RefCnt Type Proto  Iface R Rmem   User   Inode
//	000000009c3b8d6e 3      2    0806   3     1 0      0      26822
//
// Proto vem em hexadecimal SEM prefixo, e é o ETH_P_* que o socket pediu.
func parsePacketTable(body string) []SocketBruto {
	var out []SocketBruto
	for _, ln := range strings.Split(body, "\n") {
		cs := strings.Fields(ln)
		if len(cs) < 9 || cs[0] == "sk" {
			continue
		}
		proto, err := strconv.ParseUint(cs[3], 16, 32)
		if err != nil {
			continue
		}
		inode, err := strconv.ParseUint(cs[8], 10, 64)
		if err != nil {
			continue
		}
		s := SocketBruto{
			Familia:  "packet",
			ProtoNum: int(proto),
			Proto:    nomeEtherType(int(proto)),
			Inode:    inode,
		}
		s.Iface, _ = strconv.Atoi(cs[4])
		s.UID, _ = strconv.Atoi(cs[7])
		s.Ativo = cs[5] == "1"
		switch cs[2] {
		case "3":
			s.Tipo = "SOCK_RAW" // vê o quadro inteiro, com cabeçalho de enlace
		case "2":
			s.Tipo = "SOCK_DGRAM"
		}
		out = append(out, s)
	}
	return out
}

// parseRawTable lê /proc/net/raw{,6}, que têm o MESMO layout de colunas do
// /proc/net/tcp — com uma diferença que decide a leitura: o que ocuparia a
// porta local é o número do PROTOCOLO IP.
//
//	sl  local_address rem_address st tx:rx tr:tm retrnsmt uid timeout inode …
//	247: 000…000:003A 000…000:0000 07 …                     0       0 26828 …
func parseRawTable(body, familia string) []SocketBruto {
	var out []SocketBruto
	for _, ln := range strings.Split(body, "\n") {
		cs := strings.Fields(ln)
		if len(cs) < 10 || !strings.HasSuffix(cs[0], ":") {
			continue
		}
		_, proto, ok := strings.Cut(cs[1], ":")
		if !ok {
			continue
		}
		n, err := strconv.ParseUint(proto, 16, 32)
		if err != nil {
			continue
		}
		inode, err := strconv.ParseUint(cs[9], 10, 64)
		if err != nil {
			continue
		}
		// Socket raw não tem coluna de running: ele recebe o protocolo dele
		// desde que exista.
		s := SocketBruto{
			Familia:  familia,
			ProtoNum: int(n),
			Proto:    nomeProtoIP(int(n)),
			Inode:    inode,
			Ativo:    true,
		}
		s.UID, _ = strconv.Atoi(cs[7])
		out = append(out, s)
	}
	return out
}

// lerInterfaces devolve as interfaces e as flags delas. O modo promíscuo é o
// que um sniffer costuma ligar — e o que uma ponte de contêiner liga
// legitimamente, o que faz dele contexto e não achado.
func lerInterfaces() []Interface {
	ents, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return nil
	}
	var out []Interface
	for _, ent := range ents {
		i := Interface{Nome: ent.Name()}
		if s, ok := readTrim("/sys/class/net/" + ent.Name() + "/ifindex"); ok {
			i.Index, _ = strconv.Atoi(s)
		}
		if s, ok := readTrim("/sys/class/net/" + ent.Name() + "/flags"); ok {
			v, err := strconv.ParseUint(strings.TrimPrefix(s, "0x"), 16, 64)
			if err == nil {
				i.Flags = v
				i.Promisc = v&iffPromisc != 0
				i.Ativa = v&iffUp != 0
				i.Loopback = v&iffLoopback != 0
			}
		}
		out = append(out, i)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Index < out[b].Index })
	return out
}

// nomeEtherType nomeia o que o socket pediu para receber. A lista é curta de
// propósito: são os que aparecem em host real, e o resto sai em hexadecimal —
// número desconhecido nunca vira palpite.
func nomeEtherType(n int) string {
	switch n {
	case 0x0000:
		return "nenhum (bind sem protocolo)"
	case 0x0003:
		return "ETH_P_ALL (TODO o tráfego)"
	case 0x0800:
		return "IPv4"
	case 0x0806:
		return "ARP"
	case 0x8035:
		return "RARP"
	case 0x86dd:
		return "IPv6"
	case 0x888e:
		return "EAPOL (802.1X)"
	case 0x8863, 0x8864:
		return "PPPoE"
	case 0x88cc:
		return "LLDP"
	case 0x890d:
		return "TDLS"
	}
	return "0x" + strconv.FormatInt(int64(n), 16)
}

func nomeProtoIP(n int) string {
	switch n {
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 41:
		return "IPv6"
	case 47:
		return "GRE"
	case 50:
		return "ESP"
	case 58:
		return "ICMPv6"
	case 89:
		return "OSPF"
	case 255:
		return "RAW (todos)"
	}
	return "proto " + strconv.Itoa(n)
}
