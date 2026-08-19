package facts

import (
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/netlink"
)

const cabecalhoProcNet = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"

// A CHAVE precisa sair idêntica das duas visões. Se ela divergir por
// formatação — um endereço v4 mapeado escrito de dois jeitos, um par vazio
// preenchido de um lado só —, TODA conexão do host vira socket oculto e o check
// nasce como uma máquina de falso positivo crítico.
//
// Este é o teste que sustenta o check inteiro.
func TestChaveDeSocketEhAMesmaNasDuasVisoes(t *testing.T) {
	casos := []struct {
		nome  string
		linha string
		proto string
		nl    netlink.SocketInet
	}{
		{
			nome:  "tcp v4 estabelecido",
			linha: "   0: 0100007F:1F90 0200000A:01BB 01 00:00 00:00 00 1000 0 4242 1",
			proto: "tcp",
			nl: netlink.SocketInet{Proto: "tcp", LocalIP: "127.0.0.1", LocalPorta: 8080,
				PeerIP: "10.0.0.2", PeerPorta: 443},
		},
		{
			// LISTEN não tem par nas duas visões. Preencher "0.0.0.0:0" de um
			// lado só faria toda porta de escuta parecer oculta.
			nome:  "tcp v4 em escuta",
			linha: "   1: 00000000:0016 00000000:0000 0A 00:00 00:00 00 0 0 111 1",
			proto: "tcp",
			nl:    netlink.SocketInet{Proto: "tcp", LocalIP: "0.0.0.0", LocalPorta: 22},
		},
		{
			nome:  "tcp6 nativo",
			linha: "   0: B80D0120000000000000000001000000:1F90 00000000000000000000000000000000:0000 0A 00:00 00:00 00 0 0 55 1",
			proto: "tcp6",
			nl:    netlink.SocketInet{Proto: "tcp6", LocalIP: "2001:db8::1", LocalPorta: 8080},
		},
		{
			// O caso mais traiçoeiro: v4 mapeado em v6. O /proc escreve por
			// palavras de 32 bits na ordem do HOST, o netlink entrega os bytes
			// em ordem de rede, e os dois têm de chegar em "127.0.0.1".
			nome:  "tcp6 com endereço v4 mapeado",
			linha: "   0: 0000000000000000FFFF00000100007F:0050 00000000000000000000000000000000:0000 0A 00:00 00:00 00 0 0 66 1",
			proto: "tcp6",
			nl:    netlink.SocketInet{Proto: "tcp6", LocalIP: "127.0.0.1", LocalPorta: 80},
		},
	}
	for _, c := range casos {
		t.Run(c.nome, func(t *testing.T) {
			socks := parseTCPTable(cabecalhoProcNet+"\n"+c.linha, c.proto)
			if len(socks) != 1 {
				t.Fatalf("a linha de /proc não foi entendida: %+v", socks)
			}
			p := socks[0]
			doProc := chaveDeSocket(p.Proto, p.LocalIP, p.LocalPort, p.PeerIP, p.PeerPort)
			doNetlink := chaveDeSocket(c.nl.Proto, c.nl.LocalIP, c.nl.LocalPorta, c.nl.PeerIP, c.nl.PeerPorta)
			if doProc != doNetlink {
				t.Errorf("as duas visões produzem chaves diferentes para o MESMO socket:\n"+
					"  /proc:   %s\n  netlink: %s", doProc, doNetlink)
			}
		})
	}
}

// Um endereço v4 mapeado tem 40 dígitos hex nesta grafia; a de cima veio do
// kernel. Se o parser mudar, este teste explica por que a comparação quebrou.
func TestChaveNaoDependeDaGrafiaDoEndereco(t *testing.T) {
	a := chaveDeSocket("tcp", "127.0.0.1", 80, "", 0)
	b := chaveDeSocket("tcp", net.ParseIP("127.0.0.1").String(), 80, "", 0)
	if a != b {
		t.Errorf("%q != %q", a, b)
	}
}

// Só uma direção é achado. O socket que fechou entre uma leitura e outra
// aparece em /proc e não no netlink, e reportá-lo encheria de ruído todo host
// movimentado.
func TestSomenteNoDiagIgnoraOQueSoEstaEmProc(t *testing.T) {
	diag := map[string]netlink.SocketInet{
		"tcp|1.1.1.1:1|2.2.2.2:2": {Proto: "tcp"},
		"tcp|3.3.3.3:3|4.4.4.4:4": {Proto: "tcp"},
	}
	proc := map[string]bool{
		"tcp|3.3.3.3:3|4.4.4.4:4": true,
		"tcp|9.9.9.9:9|8.8.8.8:8": true, // só em /proc: não é achado
	}
	out := somenteNoDiag(diag, proc)
	if len(out) != 1 {
		t.Fatalf("candidatos = %v, quer 1", out)
	}
	if _, ok := out["tcp|1.1.1.1:1|2.2.2.2:2"]; !ok {
		t.Errorf("candidato errado: %v", out)
	}
}

// A corrida: um socket nascido entre a leitura de /proc e o dump tem a forma
// EXATA de um socket escondido. Sem a reconfirmação, todo host com tráfego
// produziria achado crítico — e crítico falso é como um relatório inteiro passa
// a ser ignorado.
func TestReconfirmarDescartaSocketNascidoNaCorrida(t *testing.T) {
	cands := map[string]netlink.SocketInet{
		"tcp|nasceu": {Proto: "tcp"},
		"tcp|morreu": {Proto: "tcp"},
		"tcp|oculto": {Proto: "tcp"},
	}
	procDeNovo := map[string]bool{"tcp|nasceu": true} // apareceu na 2ª leitura
	diagDeNovo := map[string]netlink.SocketInet{      // "morreu" sumiu do 2º dump
		"tcp|nasceu": {}, "tcp|oculto": {},
	}
	out := reconfirmar(cands, procDeNovo, diagDeNovo)
	if len(out) != 1 {
		t.Fatalf("sobreviventes = %v, quer só o oculto", out)
	}
	if _, ok := out["tcp|oculto"]; !ok {
		t.Errorf("sobrevivente errado: %v", out)
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
	// Estado que este binário não conhece não pode virar nome bonito: um
	// kernel mais novo tem estados que ele não conhece, e inventar um nome
	// esconderia isso.
	if got := nomeDeEstado(99); got != "?99" {
		t.Errorf("estado desconhecido = %q", got)
	}
}
