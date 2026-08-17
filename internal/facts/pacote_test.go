package facts

import "testing"

// O dado é REAL: saiu do /proc/net/packet de um desktop com wifi. Três sockets,
// todos de root, todos de gestão de rede — é a população legítima que decide se
// esta leitura vira inventário ou vira ruído.
const packetDeDesktopComWifi = `sk               RefCnt Type Proto  Iface R Rmem   User   Inode
000000009c3b8d6e 3      2    890d   3     1 0      0      22897
00000000055f0b97 3      2    888e   0     1 0      0      22924
00000000d79d6e6b 3      2    0806   3     1 0      0      26822
`

func TestParsePacketTable(t *testing.T) {
	socks := parsePacketTable(packetDeDesktopComWifi)
	if len(socks) != 3 {
		t.Fatalf("sockets = %d, queria 3: %+v", len(socks), socks)
	}
	// O protocolo vem em HEXADECIMAL sem prefixo. Lê-lo como decimal daria
	// 890 em vez de 0x890d, e o nome sairia errado sem nada falhar.
	if socks[0].ProtoNum != 0x890d || socks[0].Proto != "TDLS" {
		t.Errorf("primeiro socket = %+v", socks[0])
	}
	if socks[1].Proto != "EAPOL (802.1X)" || socks[1].Iface != 0 {
		t.Errorf("segundo socket = %+v", socks[1])
	}
	if socks[2].Proto != "ARP" || socks[2].Inode != 26822 || socks[2].Iface != 3 {
		t.Errorf("terceiro socket = %+v", socks[2])
	}
	for _, s := range socks {
		if s.Tipo != "SOCK_DGRAM" {
			t.Errorf("tipo de %d = %q, queria SOCK_DGRAM", s.Inode, s.Tipo)
		}
		if s.TodoTrafego() {
			t.Errorf("socket de gestão de rede (%s) NÃO vê todo o tráfego", s.Proto)
		}
	}
}

// ETH_P_ALL é o que separa "o gerenciador de rede falando o protocolo dele" de
// "alguém escutando o fio inteiro" — e é a única distinção objetiva que este
// coletor faz.
func TestPacketTodoTrafego(t *testing.T) {
	socks := parsePacketTable(`sk               RefCnt Type Proto  Iface R Rmem   User   Inode
0000000000000001 3      3    0003   2     1 0      0      777
0000000000000002 3      3    0800   2     1 0      0      778
`)
	if len(socks) != 2 {
		t.Fatalf("sockets = %d", len(socks))
	}
	if !socks[0].TodoTrafego() || socks[0].Proto != "ETH_P_ALL (TODO o tráfego)" {
		t.Errorf("ETH_P_ALL não reconhecido: %+v", socks[0])
	}
	if socks[0].Tipo != "SOCK_RAW" {
		t.Errorf("tipo = %q, queria SOCK_RAW (vê o quadro inteiro)", socks[0].Tipo)
	}
	if socks[1].TodoTrafego() {
		t.Error("IPv4 é um protocolo específico: não é captura ampla")
	}
}

// O /proc/net/raw tem o layout do /proc/net/tcp, com uma diferença que decide a
// leitura: o campo que pareceria porta é o número do PROTOCOLO IP.
func TestParseRawTable(t *testing.T) {
	raw6 := `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
 247: 00000000000000000000000000000000:003A 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 26828 2 00000000a86134c1 0
`
	socks := parseRawTable(raw6, "raw6")
	if len(socks) != 1 {
		t.Fatalf("sockets = %d: %+v", len(socks), socks)
	}
	s := socks[0]
	if s.ProtoNum != 58 || s.Proto != "ICMPv6" {
		t.Errorf("protocolo = %d/%q, queria 58/ICMPv6", s.ProtoNum, s.Proto)
	}
	if s.Inode != 26828 || s.UID != 0 || s.Familia != "raw6" {
		t.Errorf("socket = %+v", s)
	}
	// Cabeçalho e linha truncada não podem virar socket: um socket inventado
	// aqui vira um "dono não identificado" no relatório.
	if n := len(parseRawTable("sl local rem\nlixo\n", "raw")); n != 0 {
		t.Errorf("linhas inválidas viraram %d sockets", n)
	}
}

// Protocolo que esta tabela não conhece sai em hexadecimal, nunca como palpite:
// o operador precisa poder pesquisar o número.
func TestNomeDeProtocoloDesconhecido(t *testing.T) {
	if got := nomeEtherType(0x1234); got != "0x1234" {
		t.Errorf("nomeEtherType(0x1234) = %q", got)
	}
	if got := nomeProtoIP(200); got != "proto 200" {
		t.Errorf("nomeProtoIP(200) = %q", got)
	}
}

// E este dado é do outro lado da medição: todo contêiner Debian recém-criado
// tem UM socket AF_PACKET, criado pelo runtime ao montar o namespace de rede.
// Protocolo zero, sem interface, e a coluna de running em ZERO — ele não recebe
// quadro nenhum, e o dono dele vive fora do contêiner.
//
// Sem esta distinção a ferramenta acusaria "alguém pode ler o tráfego" em toda
// varredura de contêiner, com o dono eternamente não identificado. Foi o que a
// suíte inteira pegou, em quarenta cenários de uma vez.
const packetDeContainerRecemCriado = `sk               RefCnt Type Proto  Iface R Rmem   User   Inode
0000000044ba1276 2      2    0000   0     0 0      0      15015108
`

func TestSocketInerteDeContainer(t *testing.T) {
	socks := parsePacketTable(packetDeContainerRecemCriado)
	if len(socks) != 1 {
		t.Fatalf("sockets = %d", len(socks))
	}
	s := socks[0]
	if s.Ativo {
		t.Error("a coluna R está em zero: o socket NÃO está enganchado na recepção")
	}
	if !s.Inerte() {
		t.Error("socket sem protocolo e sem enganche não lê nada: é inerte")
	}
	if s.TodoTrafego() {
		t.Error("protocolo ZERO é o oposto de ETH_P_ALL: não recebe nada")
	}
	// E o do desktop, que ESTÁ enganchado, não pode cair na mesma regra.
	for _, v := range parsePacketTable(packetDeDesktopComWifi) {
		if v.Inerte() {
			t.Errorf("socket ativo de gestão de rede virou inerte: %+v", v)
		}
	}
}
