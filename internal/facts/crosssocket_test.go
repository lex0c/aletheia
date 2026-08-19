package facts

import (
	"fmt"
	"io/fs"
	"strings"
	"syscall"
	"testing"

	"github.com/lex0c/aletheia/internal/netlink"
)

const cabecalhoProcNet = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"

// A CHAVE precisa sair idêntica das duas visões para o MESMO socket. Se
// divergir — um endereço v4 mapeado escrito de dois jeitos, um par vazio
// preenchido de um lado só, o inode lido do campo errado —, toda conexão do
// host viraria socket oculto e o check nasceria como uma máquina de FP crítico.
//
// Este é o teste que sustenta o check inteiro.
func TestChaveDeSocketEhAMesmaNasDuasVisoes(t *testing.T) {
	casos := []struct {
		nome     string
		linha    string
		proto    string
		nlIP     string
		nlPorta  int
		nlPeer   string
		nlPeerPt int
		nlEstado uint8
	}{
		{
			nome:  "tcp v4 estabelecido",
			linha: "   0: 0100007F:1F90 0200000A:01BB 01 00:00 00:00 00 1000 0 4242 1",
			proto: "tcp",
			nlIP:  "127.0.0.1", nlPorta: 8080, nlPeer: "10.0.0.2", nlPeerPt: 443, nlEstado: 1,
		},
		{
			nome:  "tcp v4 em escuta",
			linha: "   1: 00000000:0016 00000000:0000 0A 00:00 00:00 00 0 0 111 1",
			proto: "tcp",
			nlIP:  "0.0.0.0", nlPorta: 22, nlEstado: 10,
		},
		{
			nome:  "tcp6 nativo",
			linha: "   0: B80D0120000000000000000001000000:1F90 00000000000000000000000000000000:0000 0A 00:00 00:00 00 0 0 55 1",
			proto: "tcp6",
			nlIP:  "2001:db8::1", nlPorta: 8080, nlEstado: 10,
		},
		{
			// v4 mapeado em v6: /proc escreve por palavras de 32 bits na ordem
			// do HOST, o netlink entrega bytes em ordem de rede, e os dois têm
			// de chegar em "127.0.0.1". A chave por inode não exercita isso, por
			// isso o teste também confere o IP parseado diretamente.
			nome:  "tcp6 com endereço v4 mapeado",
			linha: "   0: 0000000000000000FFFF00000100007F:0050 00000000000000000000000000000000:0000 0A 00:00 00:00 00 0 0 66 1",
			proto: "tcp6",
			nlIP:  "127.0.0.1", nlPorta: 80, nlEstado: 10,
		},
	}
	for _, c := range casos {
		t.Run(c.nome, func(t *testing.T) {
			socks := parseTCPTable(cabecalhoProcNet+"\n"+c.linha, c.proto)
			if len(socks) != 1 {
				t.Fatalf("a linha de /proc não foi entendida: %+v", socks)
			}
			pr := socks[0]
			// O IP e a porta parseados do /proc têm de bater com o que o netlink
			// entrega — é a consistência de FORMATAÇÃO que a chave sem inode
			// dependeria, e que o inode não deve mascarar.
			if pr.LocalIP != c.nlIP || pr.LocalPort != c.nlPorta {
				t.Errorf("/proc parseou %s:%d, netlink diz %s:%d", pr.LocalIP, pr.LocalPort, c.nlIP, c.nlPorta)
			}
			// Com o inode igual dos dois lados (é o MESMO socket), as chaves têm
			// de coincidir — e chaveDiag tem de ler o inode do campo certo.
			nl := netlink.SocketInet{
				Proto: c.proto, LocalIP: c.nlIP, LocalPorta: c.nlPorta,
				PeerIP: c.nlPeer, PeerPorta: c.nlPeerPt, Estado: c.nlEstado, Inode: uint32(pr.Inode),
			}
			if chaveProc(&pr) != chaveDiag(nl) {
				t.Errorf("chaves diferentes para o mesmo socket:\n  /proc:   %s\n  netlink: %s",
					chaveProc(&pr), chaveDiag(nl))
			}
		})
	}
}

// O inode fecha o falso NEGATIVO de multiplicidade: SO_REUSEPORT põe vários
// sockets na MESMA tupla, cada um com inode próprio. Colapsá-los numa chave só
// esconderia a divergência de quem escondesse UM deles de /proc.
func TestChavePorInodeNaoColapsaReuseport(t *testing.T) {
	a := Socket{Proto: "tcp", LocalIP: "0.0.0.0", LocalPort: 443, State: "LISTEN", Inode: 10}
	b := Socket{Proto: "tcp", LocalIP: "0.0.0.0", LocalPort: 443, State: "LISTEN", Inode: 11}
	if chaveProc(&a) == chaveProc(&b) {
		t.Error("dois sockets SO_REUSEPORT na mesma tupla colapsaram numa chave só")
	}
}

// Sem inode — TIME-WAIT e SYN-RECV — a chave cai para tupla+estado, e o estado
// faz parte dela: um TIME-WAIT e um SYN-RECV na mesma tupla NÃO são o mesmo
// socket.
func TestChaveSemInodeUsaTuplaEEstado(t *testing.T) {
	tw := Socket{Proto: "tcp", LocalIP: "1.2.3.4", LocalPort: 5, PeerIP: "6.7.8.9", PeerPort: 10, State: "TIME-WAIT", Inode: 0}
	sr := Socket{Proto: "tcp", LocalIP: "1.2.3.4", LocalPort: 5, PeerIP: "6.7.8.9", PeerPort: 10, State: "SYN-RECV", Inode: 0}
	if chaveProc(&tw) == chaveProc(&sr) {
		t.Error("estados diferentes na mesma tupla não podem colapsar")
	}
	// E o mesmo estado na mesma tupla casa entre as visões.
	nl := netlink.SocketInet{Proto: "tcp", LocalIP: "1.2.3.4", LocalPorta: 5, PeerIP: "6.7.8.9", PeerPorta: 10, Estado: 6}
	if chaveProc(&tw) != chaveDiag(nl) {
		t.Errorf("tupla+estado sem inode não casou:\n  %s\n  %s", chaveProc(&tw), chaveDiag(nl))
	}
}

// A regra que sustenta o kernelBreaker: sem as QUATRO testemunhas observadas, o
// candidato é INCONCLUSIVO — nunca CRITICAL. Converter "não reli" em "reli e
// continuava ausente" seria a ferramenta quebrando a própria tese, agravada por
// o resultado invalidar as ausências de toda a execução.
func TestClassificarOcultoExigeAsQuatroTestemunhas(t *testing.T) {
	base := observacao{procOK1: true, procOK2: true, diagOK1: true, diagOK2: true, emProc2: false, emDiag2: true}
	if classificarOculto(base) != ocultoConfirmado {
		t.Fatal("com as quatro observadas, ausente no proc2 e presente no diag2 é oculto")
	}
	for _, mut := range []func(*observacao){
		func(o *observacao) { o.procOK1 = false },
		func(o *observacao) { o.procOK2 = false },
		func(o *observacao) { o.diagOK1 = false },
		func(o *observacao) { o.diagOK2 = false },
	} {
		o := base
		mut(&o)
		if got := classificarOculto(o); got != ocultoInconclusivo {
			t.Errorf("uma testemunha faltando tem de dar INCONCLUSIVO, deu %v", got)
		}
	}
}

// A corrida: um socket que reapareceu em /proc nasceu no intervalo; um que
// sumiu do netlink fechou. Nenhum dos dois é oculto.
func TestClassificarOcultoDescartaCorrida(t *testing.T) {
	obs := observacao{procOK1: true, procOK2: true, diagOK1: true, diagOK2: true}
	nasceu := obs
	nasceu.emProc2, nasceu.emDiag2 = true, true // reapareceu em /proc
	if classificarOculto(nasceu) != ocultoCorrida {
		t.Error("socket que reapareceu em /proc é recém-nascido, não oculto")
	}
	morreu := obs
	morreu.emProc2, morreu.emDiag2 = false, false // sumiu do netlink
	if classificarOculto(morreu) != ocultoCorrida {
		t.Error("socket que sumiu do netlink fechou, não é oculto")
	}
}

// lerProcNet devolve o SUCESSO por protocolo, e é ele que separa ausência de
// lacuna. Um protocolo não pedido não vira "não lido" — simplesmente não entra.
func TestLerProcNetSoTentaOsProtocolosPedidos(t *testing.T) {
	// Só tcp é pedido; os arquivos reais deste host respondem por ele. O ponto
	// é que udp NÃO aparece em lidos por não ter sido pedido.
	_, lidos := lerProcNet(map[string]bool{"tcp": true})
	if _, pediuUDP := lidos["udp"]; pediuUDP {
		t.Error("udp não foi pedido e não pode aparecer em lidos")
	}
}

// As duas visões precisam chamar o mesmo estado pelo mesmo nome. Se
// divergirem, o mesmo socket aparece no relatório com dois nomes e o operador
// perde a única correspondência que tem entre as duas tabelas.
func TestNomeDeEstadoBateComATabelaDeProc(t *testing.T) {
	for n := uint8(1); n <= 11; n++ {
		hex := strings.ToUpper(fmt.Sprintf("%02X", n))
		if quer, ok := tcpStates[hex]; ok {
			if got := nomeDeEstado(n); got != quer {
				t.Errorf("estado %d: netlink diz %q e /proc diz %q", n, got, quer)
			}
		}
	}
	if got := nomeDeEstado(99); got != "?99" {
		t.Errorf("estado desconhecido = %q", got)
	}
}

// ENOENT em /proc/net não é lacuna: a tabela não existir (IPv6 desligado) é
// ausência de protocolo, e contá-la como "não lido" criaria um buraco de
// cobertura em todo host sem IPv6. EACCES e EIO SÃO lacuna.
func TestProcNetLidoTrataAusenciaComoVazio(t *testing.T) {
	if !procNetLido(nil) {
		t.Error("leitura OK conta como lido")
	}
	if !procNetLido(fs.ErrNotExist) {
		t.Error("tabela ausente (ENOENT) conta como lido-e-vazio, não lacuna")
	}
	if procNetLido(syscall.EACCES) {
		t.Error("EACCES é LACUNA: o protocolo não pode contar como lido")
	}
	if procNetLido(syscall.EIO) {
		t.Error("EIO é LACUNA")
	}
}
