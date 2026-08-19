package netlink

import (
	"net"
	"testing"
)

// msgInet monta um inet_diag_msg como o kernel o entrega, para que o teste
// exercite o DESLOCAMENTO de cada campo — que é o que quebra em silêncio.
func msgInet(familia, estado uint8, sport, dport int, src, dst net.IP, uid, inode uint32) []byte {
	b := make([]byte, tamMsgInet)
	b[0] = familia
	b[1] = estado
	// __be16: byte alto primeiro, independentemente da máquina.
	b[4], b[5] = byte(sport>>8), byte(sport)
	b[6], b[7] = byte(dport>>8), byte(dport)
	// O kernel escreve o endereço v4 nos PRIMEIROS quatro bytes do campo, e não
	// na forma mapeada em v6: `idiag_src[0]` é o endereço inteiro. Escrever
	// To16() aqui produziria zeros nos quatro bytes que o decodificador lê — e
	// o teste passaria a medir o próprio engano.
	copy(b[8:24], enderecoCru(src, familia))
	copy(b[24:40], enderecoCru(dst, familia))
	ordemNativa.PutUint32(b[64:68], uid)
	ordemNativa.PutUint32(b[68:72], inode)
	return b
}

func enderecoCru(ip net.IP, familia uint8) []byte {
	if familia == FamiliaIPv4 {
		return ip.To4()
	}
	return ip.To16()
}

// A PORTA é big-endian na estrutura, mesmo em máquina little-endian. Lida na
// ordem nativa, a porta 80 vira 20480 — e o achado sai apontando para um
// serviço que não existe, com toda a aparência de estar certo.
func TestDecodificarInetLePortaEmOrdemDeRede(t *testing.T) {
	b := msgInet(FamiliaIPv4, 10, 80, 0, net.ParseIP("127.0.0.1"), net.IPv4zero, 0, 4242)
	s, ok := decodificarInet(b, FamiliaIPv4, ProtoTCP)
	if !ok {
		t.Fatal("mensagem do tamanho certo não foi decodificada")
	}
	if s.LocalPorta != 80 {
		t.Errorf("porta = %d, quer 80 (20480 é o sinal de leitura na ordem nativa)", s.LocalPorta)
	}
	if s.LocalIP != "127.0.0.1" {
		t.Errorf("ip = %q", s.LocalIP)
	}
	if s.Inode != 4242 {
		t.Errorf("inode = %d", s.Inode)
	}
}

// Em IPv4 só os quatro primeiros bytes do campo valem. Ler os dezesseis
// produziria um endereço v6 inventado, e ele NUNCA casaria com o que /proc
// mostra — cada conexão do host viraria uma divergência.
func TestDecodificarInetIgnoraOLixoAlemDeQuatroBytesEmIPv4(t *testing.T) {
	b := msgInet(FamiliaIPv4, 1, 1234, 443, net.ParseIP("10.0.0.5"), net.ParseIP("1.2.3.4"), 0, 1)
	for i := 12; i < 24; i++ { // lixo depois dos 4 bytes úteis do src
		b[i] = 0xAA
	}
	s, _ := decodificarInet(b, FamiliaIPv4, ProtoTCP)
	if s.LocalIP != "10.0.0.5" {
		t.Errorf("ip = %q, quer 10.0.0.5", s.LocalIP)
	}
	if s.PeerIP != "1.2.3.4" || s.PeerPorta != 443 {
		t.Errorf("par = %s:%d", s.PeerIP, s.PeerPorta)
	}
}

func TestDecodificarInetLeIPv6(t *testing.T) {
	ip := net.ParseIP("2001:db8::1")
	b := msgInet(FamiliaIPv6, 1, 5555, 443, ip, net.ParseIP("2001:db8::2"), 0, 7)
	s, _ := decodificarInet(b, FamiliaIPv6, ProtoTCP)
	if s.LocalIP != "2001:db8::1" || s.PeerIP != "2001:db8::2" {
		t.Errorf("v6 = %s → %s", s.LocalIP, s.PeerIP)
	}
	if s.Proto != "tcp6" {
		t.Errorf("proto = %q, quer tcp6", s.Proto)
	}
}

// Um LISTEN não tem par. Preencher o campo com "0.0.0.0:0" faria a chave da
// comparação divergir da que /proc produz para o mesmo socket — e a divergência
// seria da ferramenta, não do host.
func TestDecodificarInetDeixaParVazioEmListen(t *testing.T) {
	b := msgInet(FamiliaIPv4, 10, 22, 0, net.ParseIP("0.0.0.0"), net.IPv4zero, 0, 9)
	s, _ := decodificarInet(b, FamiliaIPv4, ProtoTCP)
	if s.PeerIP != "" {
		t.Errorf("par = %q, quer vazio", s.PeerIP)
	}
}

// Mensagem menor que a estrutura é kernel com layout diferente ou resposta
// truncada. Interpretá-la leria bytes de outro campo como endereço.
func TestDecodificarInetRecusaMensagemCurta(t *testing.T) {
	if _, ok := decodificarInet(make([]byte, tamMsgInet-1), FamiliaIPv4, ProtoTCP); ok {
		t.Error("mensagem curta não pode ser decodificada")
	}
}

// O nome do protocolo é a metade da CHAVE que compara as duas visões. Errar
// aqui faz todo socket daquele protocolo parecer oculto.
func TestNomeDeProtoCobreAsQuatroCombinacoes(t *testing.T) {
	casos := []struct {
		fam, proto uint8
		quer       string
	}{
		{FamiliaIPv4, ProtoTCP, "tcp"},
		{FamiliaIPv6, ProtoTCP, "tcp6"},
		{FamiliaIPv4, ProtoUDP, "udp"},
		{FamiliaIPv6, ProtoUDP, "udp6"},
	}
	for _, c := range casos {
		if got := nomeDeProto(c.fam, c.proto); got != c.quer {
			t.Errorf("fam=%d proto=%d → %q, quer %q", c.fam, c.proto, got, c.quer)
		}
	}
}

// O TAMANHO da consulta é contrato com o kernel: um byte a mais ou a menos vira
// EINVAL, ou faz o kernel ler o filtro de estado a partir do byte errado e
// devolver um conjunto de sockets que ninguém pediu.
func TestReqInetTemOLayoutDoKernel(t *testing.T) {
	req := reqInet(FamiliaIPv6, ProtoUDP, 0xffffffff)
	if len(req) != 56 {
		t.Fatalf("tamanho = %d, quer 56 (inet_diag_req_v2)", len(req))
	}
	if req[0] != FamiliaIPv6 || req[1] != ProtoUDP {
		t.Errorf("família/protocolo = %d/%d", req[0], req[1])
	}
	if req[2] != 0 {
		t.Error("idiag_ext precisa ficar zerado: extensão pedida é resposta maior sem uso")
	}
	if got := ordemNativa.Uint32(req[4:8]); got != 0xffffffff {
		t.Errorf("idiag_states = %#x", got)
	}
	// O sockid zerado é o que significa "sem filtro por endereço".
	for i := 8; i < 56; i++ {
		if req[i] != 0 {
			t.Fatalf("byte %d do sockid = %#x, quer 0", i, req[i])
		}
	}
}
