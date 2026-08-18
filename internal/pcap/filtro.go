package pcap

import (
	"errors"
	"net/netip"
	"strconv"
	"strings"
)

// Filtro é o que o operador pediu para capturar.
//
// O conjunto é FECHADO — endereço, porta e protocolo — e isso é escolha, não
// falta de tempo. Aceitar a linguagem de filtro do tcpdump ("tcp port 443 and
// not net 10.0.0.0/8") significaria implementar um compilador, e um compilador
// com defeito produz captura errada em silêncio. Estas três perguntas cobrem o
// que um incidente faz: "o que este IP conversa com o host", "o que sai por esta
// porta", "que ICMP está passando".
//
// As condições combinam por E. Nenhuma condição = capture tudo, e isso precisa
// ser pedido explicitamente (ver `Vazio`): tráfego bruto de um host de produção
// carrega credencial em claro de terceiros que não são parte do incidente.
type Filtro struct {
	// Host casa como ORIGEM ou DESTINO. Endereço, não rede: máscara é a porta
	// de entrada para o compilador que este filtro não quer ser.
	Host netip.Addr
	// Porta casa origem ou destino, em TCP e em UDP.
	Porta int
	// Proto é "tcp", "udp" ou "icmp".
	Proto string
}

// Vazio diz que nada foi pedido — o que significa capturar TUDO que passa.
func (f Filtro) Vazio() bool {
	return !f.Host.IsValid() && f.Porta == 0 && f.Proto == ""
}

// Descricao é o que vai para o manifesto e para a tela. Uma captura cujo
// critério não está escrito ao lado dela é um arquivo que ninguém sabe
// interpretar seis meses depois.
func (f Filtro) Descricao() string {
	if f.Vazio() {
		return "TUDO o que passa na interface (sem filtro)"
	}
	var p []string
	if f.Host.IsValid() {
		p = append(p, "host "+f.Host.String())
	}
	if f.Porta != 0 {
		p = append(p, "porta "+strconv.Itoa(f.Porta))
	}
	if f.Proto != "" {
		p = append(p, "protocolo "+f.Proto)
	}
	return strings.Join(p, " E ")
}

// ProtoValido recusa o que não sabe decidir. Aceitar "sctp" e depois nunca casar
// produziria uma captura vazia com cara de resposta.
func ProtoValido(s string) error {
	switch s {
	case "", "tcp", "udp", "icmp":
		return nil
	}
	return errors.New("--proto aceita apenas tcp, udp ou icmp")
}

const (
	protoICMP   = 1
	protoTCP    = 6
	protoUDP    = 17
	protoICMPv6 = 58
)

// Casa decide se o pacote entra no arquivo.
//
// Devolve DOIS booleanos, e o segundo é o que mantém a ferramenta honesta:
//
//	casa      o pacote satisfaz o que foi pedido
//	entendi   o pacote foi decodificado até onde o filtro precisava
//
// Um quadro que não foi entendido — protocolo de enlace incomum, cabeçalho de
// extensão IPv6 que este parser não anda, pacote truncado pelo snaplen antes da
// porta — NÃO entra no arquivo e é CONTADO. Sem essa contagem, "não capturei
// nada daquele IP" seria indistinguível de "não consegui olhar dentro dos
// pacotes", que é a confusão que esta ferramenta existe para não cometer.
func (f Filtro) Casa(tipoEnlace uint32, pkt []byte) (casa, entendi bool) {
	if f.Vazio() {
		return true, true
	}
	carga, etherType, ok := semEnlace(tipoEnlace, pkt)
	if !ok {
		return false, false
	}
	return f.casaIP(etherType, carga)
}

// semEnlace pula o cabeçalho de enlace e devolve o que vem depois, junto do
// tipo do protocolo de rede.
func semEnlace(tipoEnlace uint32, pkt []byte) (carga []byte, etherType uint16, ok bool) {
	switch tipoEnlace {
	case LinkRaw:
		// Sem enlace: o primeiro nibble diz a versão do IP.
		if len(pkt) < 1 {
			return nil, 0, false
		}
		switch pkt[0] >> 4 {
		case 4:
			return pkt, 0x0800, true
		case 6:
			return pkt, 0x86DD, true
		}
		return nil, 0, false

	case LinkEthernet:
		// Quadro menor que o cabeçalho de enlace é truncado de verdade: aí sim
		// não dá para decidir nada sobre ele.
		if len(pkt) < 14 {
			return nil, 0, false
		}
		et := uint16(pkt[12])<<8 | uint16(pkt[13])
		off := 14
		// VLAN: o quadro carrega uma etiqueta de 4 bytes antes do tipo real.
		// Duas etiquetas empilhadas (QinQ) acontecem em rede de operadora.
		for i := 0; i < 2 && (et == 0x8100 || et == 0x88A8); i++ {
			if len(pkt) < off+4 {
				return nil, 0, false
			}
			et = uint16(pkt[off+2])<<8 | uint16(pkt[off+3])
			off += 4
		}
		return pkt[off:], et, true
	}
	return nil, 0, false
}

func (f Filtro) casaIP(etherType uint16, b []byte) (casa, entendi bool) {
	var src, dst netip.Addr
	var proto uint8
	var resto []byte

	switch etherType {
	case 0x0800: // IPv4
		if len(b) < 20 {
			return false, false
		}
		ihl := int(b[0]&0x0F) * 4
		if ihl < 20 || len(b) < ihl {
			return false, false
		}
		proto = b[9]
		src = netip.AddrFrom4([4]byte(b[12:16]))
		dst = netip.AddrFrom4([4]byte(b[16:20]))
		// Fragmento que não é o primeiro não tem cabeçalho de transporte: a
		// porta não está ali, e fingir que está casaria pelo lixo seguinte.
		fragOff := (uint16(b[6]&0x1F)<<8 | uint16(b[7])) * 8
		if fragOff > 0 {
			if f.Porta != 0 {
				return false, false
			}
			resto = nil
		} else {
			resto = b[ihl:]
		}

	case 0x86DD: // IPv6
		if len(b) < 40 {
			return false, false
		}
		proto = b[6]
		src = netip.AddrFrom16([16]byte(b[8:24]))
		dst = netip.AddrFrom16([16]byte(b[24:40]))
		resto = b[40:]
		// Cabeçalho de extensão: este parser não anda a cadeia. Quando a porta
		// importa, o pacote sai como NÃO ENTENDIDO em vez de casar por acaso.
		if extensaoIPv6(proto) {
			if f.Porta != 0 || f.Proto != "" {
				return false, false
			}
			resto = nil
		}

	default:
		// QUADRO QUE NÃO É IP: ARP, LLDP, STP, 802.1X. Ele foi entendido — só
		// não é do tipo que um filtro de host/porta/protocolo alcança. Contar
		// isso como "não consegui decodificar" fazia TODA captura filtrada num
		// segmento Ethernet real terminar com lacuna declarada e exit 1, e
		// afogava o sinal que existe para denunciar truncamento de verdade.
		return false, true
	}

	if f.Host.IsValid() && f.Host != src && f.Host != dst {
		return false, true
	}
	if f.Proto != "" && !protoCasa(f.Proto, proto) {
		return false, true
	}
	if f.Porta != 0 {
		if proto != protoTCP && proto != protoUDP {
			return false, true
		}
		// A porta está nos 4 primeiros bytes de TCP e de UDP, na mesma ordem.
		if len(resto) < 4 {
			return false, false // truncado pelo snaplen: não dá para decidir
		}
		sp := int(resto[0])<<8 | int(resto[1])
		dp := int(resto[2])<<8 | int(resto[3])
		if f.Porta != sp && f.Porta != dp {
			return false, true
		}
	}
	return true, true
}

func protoCasa(nome string, n uint8) bool {
	switch nome {
	case "tcp":
		return n == protoTCP
	case "udp":
		return n == protoUDP
	case "icmp":
		return n == protoICMP || n == protoICMPv6
	}
	return false
}

func extensaoIPv6(n uint8) bool {
	switch n {
	case 0, 43, 44, 50, 51, 60, 135:
		return true
	}
	return false
}
