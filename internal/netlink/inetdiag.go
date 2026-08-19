package netlink

import (
	"net"
	"strconv"
	"syscall"
)

// A consulta de SOCKET pelo netlink (runbook §35).
//
// É a segunda visão da mesma tabela que /proc/net/tcp mostra, e ela vale
// justamente por NÃO ser a mesma: o /proc é servido por `tcp4_seq_show`, e este
// caminho é servido por `inet_diag_dump`. Um rootkit que intercepte só o
// primeiro — que é o normal, porque é o que o `netstat` lê — fica visível aqui.
//
// A grafia das estruturas é ABI do kernel desde o 3.3 e não muda. Elas são
// montadas byte a byte de propósito: uma struct de Go com os mesmos campos
// mudaria de tamanho por causa de alinhamento em 32 bits, e o kernel leria
// outro campo sem que nada reclamasse — o mesmo defeito que o pacote kbpf
// documenta e testa por tamanho.

const (
	// SOCK_DIAG_BY_FAMILY: o único tipo de mensagem que este pacote manda.
	sockDiagByFamily = 20

	tamReqInet = 56 // inet_diag_req_v2
	tamMsgInet = 72 // inet_diag_msg

	// todosOsEstados pede TODA conexão. O filtro por estado existe na ABI e
	// não é usado: um estado a menos aqui vira uma divergência inventada lá na
	// comparação, porque /proc/net não filtra nada.
	todosOsEstados = 0xffffffff
)

// As famílias e protocolos, exportados para que quem chama não precise
// importar syscall só para dizer "TCP sobre IPv4".
const (
	FamiliaIPv4 = syscall.AF_INET
	FamiliaIPv6 = syscall.AF_INET6
	ProtoTCP    = syscall.IPPROTO_TCP
	ProtoUDP    = syscall.IPPROTO_UDP
)

// SocketInet é uma entrada da tabela, já decodificada.
type SocketInet struct {
	// Proto é a mesma grafia que o coletor de /proc/net usa — tcp, tcp6, udp,
	// udp6 —, porque as duas visões são comparadas por ela.
	Proto  string
	Estado uint8

	LocalIP    string
	LocalPorta int
	PeerIP     string
	PeerPorta  int

	// Inode é a chave que liga o socket ao descritor de um processo. Vale ZERO
	// em TIME-WAIT e em SYN-RECV: ali o socket não pertence mais a ninguém, e
	// tratar o zero como identidade juntaria todos eles num só.
	Inode uint32
	UID   uint32
}

func (s SocketInet) Local() string {
	return net.JoinHostPort(s.LocalIP, strconv.Itoa(s.LocalPorta))
}

func (s SocketInet) Peer() string {
	if s.PeerIP == "" {
		return ""
	}
	return net.JoinHostPort(s.PeerIP, strconv.Itoa(s.PeerPorta))
}

// SocketsInet enumera uma família e um protocolo, entregando um socket de cada
// vez. Um host grande tem centenas de milhares deles.
func SocketsInet(c *Conexao, familia, protocolo uint8, fn func(SocketInet) error) error {
	return c.Dump(sockDiagByFamily, reqInet(familia, protocolo, todosOsEstados), func(dados []byte) error {
		s, ok := decodificarInet(dados, familia, protocolo)
		if !ok {
			// Mensagem menor que a estrutura: kernel mais novo com layout
			// diferente, ou resposta truncada. Ignorar UMA é melhor que
			// interpretar bytes de outro campo como endereço.
			return nil
		}
		return fn(s)
	})
}

// reqInet monta o inet_diag_req_v2:
//
//	0  sdiag_family    1 byte
//	1  sdiag_protocol  1 byte
//	2  idiag_ext       1 byte   nenhuma extensão: não queremos memória nem congestão
//	3  pad             1 byte
//	4  idiag_states    4 bytes  ordem NATIVA
//	8  id             48 bytes  zerado: sem filtro por endereço
//
// O TAMANHO é contrato: o kernel valida o comprimento da mensagem, e um campo
// a mais ou a menos aqui vira EINVAL — ou, pior, faz o kernel ler o estado a
// partir do byte errado e devolver um conjunto de sockets que ninguém pediu.
func reqInet(familia, protocolo uint8, estados uint32) []byte {
	req := make([]byte, tamReqInet)
	req[0] = familia
	req[1] = protocolo
	ordemNativa.PutUint32(req[4:8], estados)
	return req
}

// decodificarInet lê o inet_diag_msg. Os deslocamentos são a estrutura do
// kernel, e estão escritos por extenso porque é assim que dá para conferir com
// o header sem executar nada:
//
//	 0  família        1 byte
//	 1  estado         1 byte
//	 2  timer          1 byte
//	 3  retrans        1 byte
//	 4  sport          2 bytes  BIG-ENDIAN
//	 6  dport          2 bytes  BIG-ENDIAN
//	 8  src           16 bytes  ordem de rede
//	24  dst           16 bytes  ordem de rede
//	40  if             4 bytes
//	44  cookie         8 bytes
//	52  expires        4 bytes
//	56  rqueue         4 bytes
//	60  wqueue         4 bytes
//	64  uid            4 bytes
//	68  inode          4 bytes
func decodificarInet(b []byte, familia, protocolo uint8) (SocketInet, bool) {
	if len(b) < tamMsgInet {
		return SocketInet{}, false
	}
	s := SocketInet{
		Proto:  nomeDeProto(familia, protocolo),
		Estado: b[1],
		// A PORTA é big-endian mesmo em máquina little-endian: é __be16 na
		// estrutura. Lê-la na ordem nativa faz a porta 80 virar 20480, e o
		// achado sai apontando para um serviço que não existe.
		LocalPorta: int(b[4])<<8 | int(b[5]),
		PeerPorta:  int(b[6])<<8 | int(b[7]),
		UID:        ordemNativa.Uint32(b[64:68]),
		Inode:      ordemNativa.Uint32(b[68:72]),
	}
	s.LocalIP = enderecoDe(b[8:24], familia)
	// Peer zerado significa socket sem destino: um LISTEN, ou um UDP apenas
	// ligado a uma porta. É a mesma regra do coletor de /proc/net, e precisa
	// ser a mesma ou as duas visões divergiriam por formatação.
	// A decisão sai dos BYTES, e a string só é formatada quando o peer é
	// guardado. O caminho anterior formatava o endereço com net.IP.String() e
	// depois REPARSEAVA a string com net.ParseIP só para perguntar
	// IsUnspecified() — nas 300 mil mensagens que maxMensagens prevê, eram
	// ~900 mil alocações e 300 mil parses para responder o que os bytes crus
	// já dizem.
	if !(s.PeerPorta == 0 && bytesNaoEspecificados(b[24:40], familia)) {
		s.PeerIP = enderecoDe(b[24:40], familia)
	}
	return s, true
}

// enderecoDe converte os bytes crus. Em IPv4 só os quatro primeiros valem — o
// resto do campo é lixo do kernel, e incluí-lo produziria um endereço v6
// inventado.
func enderecoDe(b []byte, familia uint8) string {
	if familia == FamiliaIPv4 {
		return net.IP(b[:4]).String()
	}
	return net.IP(b[:16]).String()
}

// bytesNaoEspecificados diz se o endereço cru é o "sem destino" (0.0.0.0 ou ::)
// sem passar por string nenhuma. O recorte por família é o mesmo de enderecoDe:
// em IPv4 só os quatro primeiros bytes valem, o resto do campo é lixo do
// kernel.
func bytesNaoEspecificados(b []byte, familia uint8) bool {
	n := 16
	if familia == FamiliaIPv4 {
		n = 4
	}
	for _, c := range b[:n] {
		if c != 0 {
			return false
		}
	}
	return true
}

func nomeDeProto(familia, protocolo uint8) string {
	nome := "tcp"
	if protocolo == ProtoUDP {
		nome = "udp"
	}
	if familia == FamiliaIPv6 {
		nome += "6"
	}
	return nome
}

// Sonda responde se a enumeração de socket por netlink é POSSÍVEL neste host, e
// quando não é diz por quê — é essa frase que vai para o rodapé de cobertura.
//
// Recebe a família e o protocolo porque o CHAMADOR é quem sabe qual handler de
// diagnóstico já está carregado: sondar TCP num host onde só o udp_diag existe
// dispararia o autoload que a política de não-intrusão evita. Ver
// env.diagProtocolosSeguros.
//
// A consulta é a de verdade com o filtro de estado ZERADO: percorre o caminho
// inteiro do kernel e não devolve socket nenhum. É o que separa "a interface
// responde" de "a interface existe", sem pagar por um dump completo.
func Sonda(familia, protocolo uint8) error {
	c, err := Abrir(syscall.NETLINK_INET_DIAG)
	if err != nil {
		return err
	}
	defer c.Fechar()
	return c.Dump(sockDiagByFamily, reqInet(familia, protocolo, 0), func([]byte) error { return nil })
}
