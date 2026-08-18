package pcap

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func fHost(s string) Filtro { return Filtro{Host: netip.MustParseAddr(s)} }

// O filtro decide o que ENTRA no arquivo, e as duas direções de erro custam
// coisas diferentes: largo demais grava tráfego de terceiros que não são parte
// do incidente; estreito demais perde a evidência e a captura sai vazia com cara
// de resposta.
func TestFiltroPorHostOlhaAsDuasPontas(t *testing.T) {
	f := fHost("51.91.190.241")
	casos := []struct {
		nome      string
		pkt       []byte
		queroCasa bool
	}{
		{"alvo como ORIGEM", quadro(alvo, local, protoTCP, 443, 51000), true},
		{"alvo como DESTINO", quadro(local, alvo, protoTCP, 51000, 443), true},
		{"conversa de terceiros", quadro(local, outro, protoTCP, 51000, 443), false},
	}
	for _, c := range casos {
		casa, entendi := f.Casa(LinkEthernet, c.pkt)
		if !entendi {
			t.Errorf("%s: quadro comum não foi entendido", c.nome)
		}
		if casa != c.queroCasa {
			t.Errorf("%s: casa = %v, queria %v", c.nome, casa, c.queroCasa)
		}
	}
}

func TestFiltroPorPortaEProtocolo(t *testing.T) {
	tcp443 := quadro(local, alvo, protoTCP, 51000, 443)
	udp53 := quadro(local, alvo, protoUDP, 51000, 53)
	icmp := quadro(local, alvo, protoICMP, 0, 0)

	casos := []struct {
		nome  string
		f     Filtro
		pkt   []byte
		quero bool
	}{
		{"porta no destino", Filtro{Porta: 443}, tcp443, true},
		{"porta na origem", Filtro{Porta: 51000}, tcp443, true},
		{"porta de outra conversa", Filtro{Porta: 22}, tcp443, false},
		{"a porta vale em UDP também", Filtro{Porta: 53}, udp53, true},
		{"proto tcp", Filtro{Proto: "tcp"}, tcp443, true},
		{"proto udp não casa tcp", Filtro{Proto: "udp"}, tcp443, false},
		{"proto icmp", Filtro{Proto: "icmp"}, icmp, true},
		{"icmp não tem porta", Filtro{Porta: 443}, icmp, false},
		// As condições combinam por E: o host certo na porta errada fica fora.
		{"host E porta, os dois", Filtro{Host: netip.MustParseAddr("51.91.190.241"), Porta: 443}, tcp443, true},
		{"host certo, porta errada", Filtro{Host: netip.MustParseAddr("51.91.190.241"), Porta: 22}, tcp443, false},
	}
	for _, c := range casos {
		if casa, _ := c.f.Casa(LinkEthernet, c.pkt); casa != c.quero {
			t.Errorf("%s: casa = %v, queria %v", c.nome, casa, c.quero)
		}
	}
}

// Filtro vazio é "grave tudo", e é o único caso em que um quadro que o parser
// não entende ainda entra no arquivo: não há pergunta a responder sobre ele.
func TestSemFiltroTudoEntra(t *testing.T) {
	var f Filtro
	if !f.Vazio() {
		t.Fatal("Filtro{} precisa ser vazio")
	}
	for _, pkt := range [][]byte{
		quadro(local, outro, protoTCP, 1, 2),
		{0x00, 0x01}, // nem quadro é
	} {
		casa, entendi := f.Casa(LinkEthernet, pkt)
		if !casa || !entendi {
			t.Errorf("sem filtro tudo entra: casa=%v entendi=%v", casa, entendi)
		}
	}
}

// "Não entendi" É DIFERENTE de "não casou", e a separação é o que impede a
// captura de dizer "não vi tráfego daquele IP" quando o que houve foi não
// conseguir olhar dentro dos pacotes.
func TestOQueNaoFoiEntendidoNaoViraNaoCasou(t *testing.T) {
	f := fHost("51.91.190.241")
	casos := map[string][]byte{
		"quadro curto demais":     {0x00, 0x01, 0x02},
		"ethertype desconhecido":  append(make([]byte, 12), 0x88, 0xCC, 0x01),
		"IPv4 com IHL impossível": quadroComIHL(3),
		"IPv4 sem cabeçalho todo": quadro(alvo, local, protoTCP, 1, 2)[:20],
	}
	for nome, pkt := range casos {
		casa, entendi := f.Casa(LinkEthernet, pkt)
		if entendi {
			t.Errorf("%s: foi dado como entendido", nome)
		}
		if casa {
			t.Errorf("%s: não pode CASAR o que não foi decodificado", nome)
		}
	}
}

func quadroComIHL(ihl byte) []byte {
	p := quadro(alvo, local, protoTCP, 443, 51000)
	p[14] = 0x40 | ihl
	return p
}

// VLAN é o caso que quebra um parser ingênuo: a etiqueta empurra o IP quatro
// bytes para frente, e quem lê o EtherType no lugar fixo conclui que não é IP.
func TestQuadroComEtiquetaVLAN(t *testing.T) {
	base := quadro(alvo, local, protoTCP, 443, 51000)
	comVLAN := make([]byte, 0, len(base)+4)
	comVLAN = append(comVLAN, base[:12]...)
	comVLAN = append(comVLAN, 0x81, 0x00, 0x00, 0x64) // etiqueta, VLAN 100
	comVLAN = append(comVLAN, base[12:]...)

	f := fHost("51.91.190.241")
	if casa, entendi := f.Casa(LinkEthernet, comVLAN); !casa || !entendi {
		t.Errorf("quadro com VLAN: casa=%v entendi=%v", casa, entendi)
	}
	if casa, _ := (Filtro{Porta: 443}).Casa(LinkEthernet, comVLAN); !casa {
		t.Error("a porta precisa ser achada depois da etiqueta")
	}
}

// Fragmento que não é o primeiro NÃO carrega cabeçalho de transporte. Ler a
// porta ali casaria contra o payload — quatro bytes de dado que por acaso valem
// o número pedido.
func TestFragmentoIntermediarioNaoTemPorta(t *testing.T) {
	p := quadro(local, alvo, protoTCP, 51000, 443)
	binary.BigEndian.PutUint16(p[14+6:], 185) // offset de fragmento != 0
	if _, entendi := (Filtro{Porta: 443}).Casa(LinkEthernet, p); entendi {
		t.Error("fragmento sem cabeçalho de transporte não pode ser dado como entendido")
	}
	// Sem pergunta sobre porta, o fragmento ainda casa por endereço.
	if casa, entendi := fHost("51.91.190.241").Casa(LinkEthernet, p); !casa || !entendi {
		t.Errorf("por endereço o fragmento vale: casa=%v entendi=%v", casa, entendi)
	}
}

func TestIPv6(t *testing.T) {
	p := make([]byte, 14+40+8)
	p[12], p[13] = 0x86, 0xDD
	ip := p[14:]
	ip[0] = 0x60
	ip[6] = protoTCP
	src := netip.MustParseAddr("2001:db8::1").As16()
	dst := netip.MustParseAddr("2001:db8::2").As16()
	copy(ip[8:24], src[:])
	copy(ip[24:40], dst[:])
	binary.BigEndian.PutUint16(p[54:], 51000)
	binary.BigEndian.PutUint16(p[56:], 443)

	if casa, entendi := fHost("2001:db8::2").Casa(LinkEthernet, p); !casa || !entendi {
		t.Errorf("IPv6 por endereço: casa=%v entendi=%v", casa, entendi)
	}
	if casa, _ := (Filtro{Porta: 443}).Casa(LinkEthernet, p); !casa {
		t.Error("IPv6 por porta")
	}
	// Cabeçalho de extensão: este parser não anda a cadeia, e quando a pergunta
	// depende do que vem depois dela a resposta é "não entendi".
	ip[6] = 44 // fragment header
	if _, entendi := (Filtro{Porta: 443}).Casa(LinkEthernet, p); entendi {
		t.Error("cadeia de extensão não andada não pode ser dada como entendida")
	}
}

// Enlace RAW (tun): não há cabeçalho ethernet, o pacote começa no IP.
func TestEnlaceRawComecaNoIP(t *testing.T) {
	p := quadro(alvo, local, protoTCP, 443, 51000)[14:]
	if casa, entendi := fHost("51.91.190.241").Casa(LinkRaw, p); !casa || !entendi {
		t.Errorf("DLT_RAW: casa=%v entendi=%v", casa, entendi)
	}
	// E o mesmo pacote lido como ethernet é lixo — é por isso que rotular o
	// arquivo errado é pior que não escrever.
	if _, entendi := fHost("51.91.190.241").Casa(LinkEthernet, p); entendi {
		t.Error("um pacote RAW lido como ethernet não pode ser dado como entendido")
	}
}

func TestDescricaoDizOQueFoiPedido(t *testing.T) {
	if d := (Filtro{}).Descricao(); d != "TUDO o que passa na interface (sem filtro)" {
		t.Errorf("Descricao vazia = %q", d)
	}
	f := Filtro{Host: netip.MustParseAddr("10.0.0.5"), Porta: 443, Proto: "tcp"}
	if d := f.Descricao(); d != "host 10.0.0.5 E porta 443 E protocolo tcp" {
		t.Errorf("Descricao = %q", d)
	}
}

func TestProtoValidoRecusaOQueNaoSabeDecidir(t *testing.T) {
	for _, ok := range []string{"", "tcp", "udp", "icmp"} {
		if err := ProtoValido(ok); err != nil {
			t.Errorf("%q deveria ser aceito", ok)
		}
	}
	for _, ruim := range []string{"sctp", "TCP", "ip", "qualquer"} {
		if err := ProtoValido(ruim); err == nil {
			t.Errorf("%q deveria ser recusado: aceitar e nunca casar produz "+
				"captura vazia com cara de resposta", ruim)
		}
	}
}
