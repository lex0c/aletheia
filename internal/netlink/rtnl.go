package netlink

import (
	"strconv"
	"syscall"
)

// Onde um programa eBPF de REDE fica preso (runbook §35, SPEC fase 8).
//
// # A pergunta que faltava
//
// Um programa eBPF continua carregado enquanto alguém o segura. A enumeração
// por bpf(2) resolve quatro detentores — descritor aberto, pin no bpffs, link e
// tail call — e não alcança o quinto: tc e XDP prendem o programa a uma
// INTERFACE, e quem sabe disso é o rtnetlink.
//
// Sem esta parte, todo programa de tc ou de XDP aparecia como "sem dono
// visível" e virava lacuna declarada. Num nó com cilium ou com qualquer coisa
// que use tc, é a maioria deles — e uma lacuna desse tamanho é indistinguível
// de não ter olhado.
//
// # O que fica de fora, e está declarado
//
// A AÇÃO de tc (act_bpf) também carrega programa, pendurada dentro do filtro.
// Aqui é lido o filtro (cls_bpf), que é a forma que um implante de rede usa
// para interceptar pacote. Quem estiver dentro de uma ação não é resolvido, e
// isso vira lacuna — não silêncio.

// Números de ABI do kernel. Como os comandos da bpf(2) no pacote kbpf, eles não
// mudam: estão em if_link.h e pkt_cls.h desde que existem.
const (
	iflaXDP        = 43 // IFLA_XDP, um bloco aninhado
	iflaXDPProgID  = 4  // IFLA_XDP_PROG_ID
	iflaXDPAtached = 2  // IFLA_XDP_ATTACHED

	tcaKind    = 1 // TCA_KIND: o nome do classificador, "bpf" nos que interessam
	tcaOptions = 2 // TCA_OPTIONS: bloco aninhado, específico do classificador

	tcaBPFName = 7  // TCA_BPF_NAME
	tcaBPFTag  = 10 // TCA_BPF_TAG
	tcaBPFID   = 11 // TCA_BPF_ID

	tamIfInfomsg = 16 // struct ifinfomsg
	tamTcmsg     = 20 // struct tcmsg

	// Os pais que o clsact expõe. É por eles que se sabe se o programa vê o
	// pacote ENTRANDO ou SAINDO — e a diferença decide se ele pode exfiltrar
	// ou se pode receber comando.
	pariIngress = 0xFFFFFFF2 // TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_INGRESS)
	pariEgress  = 0xFFFFFFF3 // TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_EGRESS)
)

// Atributo é um TLV de netlink.
type Atributo struct {
	Tipo  uint16
	Dados []byte
}

// atributos decodifica a sequência de TLV que vem depois do cabeçalho fixo.
//
// O alinhamento é de QUATRO bytes e o comprimento declarado NÃO o inclui:
// avançar por nla_len cru desalinha a leitura no primeiro atributo de tamanho
// ímpar, e a partir dali todo atributo é lido a partir do byte errado — sem
// erro, com dados plausíveis.
func atributos(b []byte) []Atributo {
	var out []Atributo
	for len(b) >= 4 {
		tam := int(ordemNativa.Uint16(b[0:2]))
		tipo := ordemNativa.Uint16(b[2:4])
		if tam < 4 || tam > len(b) {
			return out
		}
		out = append(out, Atributo{
			// Os dois bits altos do tipo são marcadores (aninhado, ordem de
			// rede), não fazem parte do número.
			Tipo:  tipo & 0x3FFF,
			Dados: b[4:tam],
		})
		avanco := (tam + 3) &^ 3
		if avanco > len(b) {
			return out
		}
		b = b[avanco:]
	}
	return out
}

func atributo(as []Atributo, tipo uint16) ([]byte, bool) {
	for _, a := range as {
		if a.Tipo == tipo {
			return a.Dados, true
		}
	}
	return nil, false
}

func u32De(b []byte) (uint32, bool) {
	if len(b) < 4 {
		return 0, false
	}
	return ordemNativa.Uint32(b[:4]), true
}

func stringDe(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// Interface é o que a enumeração de links devolve, com o programa de XDP que
// estiver preso nela.
type Interface struct {
	Indice int
	Nome   string
	// XDPProgID é o programa preso ao caminho de recepção da placa. Zero
	// significa nenhum — e é o normal.
	XDPProgID uint32
}

// Interfaces enumera os links e o XDP de cada um.
func Interfaces(c *Conexao) ([]Interface, error) {
	req := make([]byte, tamIfInfomsg)
	req[0] = syscall.AF_UNSPEC
	var out []Interface
	err := c.Dump(syscall.RTM_GETLINK, req, func(dados []byte) error {
		if i, ok := decodificarLink(dados); ok {
			out = append(out, i)
		}
		return nil
	})
	return out, err
}

// decodificarLink lê a resposta de RTM_GETLINK: o ifinfomsg fixo e, depois
// dele, os atributos.
//
//	0  ifi_family    1 byte
//	1  __ifi_pad     1 byte
//	2  ifi_type      2 bytes
//	4  ifi_index     4 bytes   ordem NATIVA, com SINAL
//	8  ifi_flags     4 bytes
//	12 ifi_change    4 bytes
func decodificarLink(dados []byte) (Interface, bool) {
	if len(dados) < tamIfInfomsg {
		return Interface{}, false
	}
	i := Interface{Indice: int(int32(ordemNativa.Uint32(dados[4:8])))}
	as := atributos(dados[tamIfInfomsg:])
	if b, ok := atributo(as, syscall.IFLA_IFNAME); ok {
		i.Nome = stringDe(b)
	}
	if b, ok := atributo(as, iflaXDP); ok {
		// O bloco de XDP é ANINHADO. O PROG_ID é o que interessa; o ATTACHED
		// só diz em que modo (driver, genérico, hardware), e ler o bloco como
		// se fosse plano devolveria o modo no lugar do id do programa.
		if id, ok := atributo(atributos(b), iflaXDPProgID); ok {
			i.XDPProgID, _ = u32De(id)
		}
	}
	return i, true
}

// FiltroTC é um classificador de tc que carrega um programa eBPF.
type FiltroTC struct {
	Interface string
	// Direcao é "ingress", "egress" ou a grafia crua do pai quando é outro
	// ponto. A distinção importa: no ingress o programa vê o que CHEGA — é
	// onde mora um gatilho de C2 —, e no egress vê o que sai.
	Direcao string
	ProgID  uint32
	Nome    string
}

// FiltrosBPF lê os filtros de UMA interface e devolve os que são cls_bpf.
//
// Por interface, e não de uma vez: o dump de filtro é por dispositivo, e o
// kernel não oferece "todos os filtros da máquina" — é o mesmo laço que o `tc`
// faz quando alguém escreve `tc filter show dev X`.
func FiltrosBPF(c *Conexao, iface Interface) ([]FiltroTC, error) {
	req := make([]byte, tamTcmsg)
	ordemNativa.PutUint32(req[4:8], uint32(iface.Indice))
	// Pai ZERADO: o kernel percorre todos os qdiscs do dispositivo. Fixar o
	// clsact aqui perderia o ingress legado, que é outro pai.
	var out []FiltroTC
	err := c.Dump(syscall.RTM_GETTFILTER, req, func(dados []byte) error {
		if f, ok := decodificarFiltro(dados, iface.Nome); ok {
			out = append(out, f)
		}
		return nil
	})
	return out, err
}

// decodificarFiltro lê a resposta de RTM_GETTFILTER. O cabeçalho é o tcmsg:
//
//	0  tcm_family    1 byte
//	4  tcm_ifindex   4 bytes
//	8  tcm_handle    4 bytes
//	12 tcm_parent    4 bytes   é ele que diz ingress ou egress
//	16 tcm_info      4 bytes
//
// Só o classificador "bpf" interessa: um dispositivo tem filtros de todo tipo,
// e os outros não carregam programa nenhum.
func decodificarFiltro(dados []byte, iface string) (FiltroTC, bool) {
	if len(dados) < tamTcmsg {
		return FiltroTC{}, false
	}
	as := atributos(dados[tamTcmsg:])
	kind, ok := atributo(as, tcaKind)
	if !ok || stringDe(kind) != "bpf" {
		return FiltroTC{}, false
	}
	opts, ok := atributo(as, tcaOptions)
	if !ok {
		return FiltroTC{}, false
	}
	f := FiltroTC{
		Interface: iface,
		Direcao:   direcaoDoPai(ordemNativa.Uint32(dados[12:16])),
	}
	sub := atributos(opts)
	if b, ok := atributo(sub, tcaBPFID); ok {
		f.ProgID, _ = u32De(b)
	}
	if b, ok := atributo(sub, tcaBPFName); ok {
		f.Nome = stringDe(b)
	}
	// Sem id não há o que atribuir: um filtro bpf da forma ANTIGA carrega o
	// bytecode embutido e não tem programa no espaço de ids para casar.
	if f.ProgID == 0 {
		return FiltroTC{}, false
	}
	return f, true
}

func direcaoDoPai(pai uint32) string {
	switch pai {
	case pariIngress:
		return "ingress"
	case pariEgress:
		return "egress"
	}
	return "parent=" + strconv.FormatUint(uint64(pai), 16)
}
