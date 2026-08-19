package facts

import (
	"net"
	"strconv"
	"syscall"

	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/netlink"
)

// A terceira visão cruzada do kernel: /proc/net × NETLINK_INET_DIAG.
//
// # Por que ela existe
//
// O coletor de rede lê /proc/net/tcp e as três tabelas irmãs. É UMA fonte, e é
// a que um rootkit de kernel intercepta primeiro: um hook em `tcp4_seq_show`
// some com a conexão da tabela e não toca em mais nada. O catálogo de hooks de
// ftrace desta ferramenta já procura essa função pelo nome — o que faltava era
// a segunda visão para confrontar com a primeira.
//
// O netlink não passa pelo `seq_show`. O kernel percorre as tabelas de hash e
// responde por mensagem, por outro caminho de código. Esconder das duas exige
// interceptar as duas.
//
// # A direção da comparação, e por que só uma vale
//
//	no netlink e NÃO em /proc   ACHADO: a tabela que o operador lê omitiu algo
//	                            que o kernel entrega quando perguntado de outro
//	                            jeito
//	em /proc e NÃO no netlink   RUÍDO: o socket fechou entre uma leitura e a
//	                            outra, ou o dump daquele protocolo falhou
//
// # A corrida, e como ela é eliminada
//
// Um socket nascido entre a leitura de /proc e o dump aparece só no dump —
// idêntico a um socket escondido. A resposta é a mesma da sondagem de PID
// oculto: reconfirmar. O candidato só vira achado se sobreviver a uma SEGUNDA
// leitura de /proc e a um SEGUNDO dump. Um socket que existe nos dois dumps e
// em nenhuma das duas leituras de /proc não é corrida.
//
// # O custo que esta consulta pode ter, e ele é declarado
//
// Perguntar ao sock_diag pode fazer o kernel carregar sozinho o módulo de
// diagnóstico (tcp_diag, udp_diag) — é o que acontece quando o `ss` roda pela
// primeira vez. Carregar módulo é o kernel EXECUTANDO /proc/sys/kernel/modprobe
// como root, e um host com esse caminho sequestrado transformaria esta consulta
// no gatilho do implante que a própria ferramenta denuncia. Por isso a
// capacidade de netlink é negada quando aquele caminho não é o de fábrica (ver
// env.Probe), e nada aqui roda.

// SocketOculto é um socket que o netlink mostra e /proc/net não.
type SocketOculto struct {
	Proto  string `json:"proto"`
	Local  string `json:"local"`
	Peer   string `json:"peer,omitempty"`
	Estado string `json:"state"`
	// Inode vale ZERO em TIME-WAIT e SYN-RECV — ali o socket não pertence mais
	// a processo nenhum, e não há descritor para procurar.
	Inode uint32 `json:"inode,omitempty"`
	UID   uint32 `json:"uid"`
}

// PeerIP é só o endereço do par, sem a porta. É o que um filtro de captura
// aceita, e é por isso que ele existe separado do Peer: `--host 1.2.3.4:443`
// não filtra nada.
func (s SocketOculto) PeerIP() string {
	if s.Peer == "" {
		return ""
	}
	h, _, err := net.SplitHostPort(s.Peer)
	if err != nil {
		return ""
	}
	return h
}

// estadosDiag traduz o estado numérico do netlink. São os mesmos números do
// campo `st` de /proc/net/tcp, e a tradução é a mesma tabela — se as duas
// divergissem, o relatório mostraria o mesmo socket com dois nomes.
var estadosDiag = map[uint8]string{
	1: "ESTAB", 2: "SYN-SENT", 3: "SYN-RECV", 4: "FIN-WAIT1",
	5: "FIN-WAIT2", 6: "TIME-WAIT", 7: "CLOSE", 8: "CLOSE-WAIT",
	9: "LAST-ACK", 10: "LISTEN", 11: "CLOSING",
}

func nomeDeEstado(e uint8) string {
	if s, ok := estadosDiag[e]; ok {
		return s
	}
	return "?" + strconv.Itoa(int(e))
}

// chaveDeSocket é a identidade usada na comparação.
//
// É a TUPLA, e não o inode, por um motivo que o inode não resolve: sockets em
// TIME-WAIT e em SYN-RECV têm inode zero nas duas visões, e comparar por inode
// juntaria todos eles num único socket — a divergência sumiria dentro da
// colisão.
func chaveDeSocket(proto, lip string, lport int, pip string, pport int) string {
	return proto + "|" + net.JoinHostPort(lip, strconv.Itoa(lport)) +
		"|" + net.JoinHostPort(pip, strconv.Itoa(pport))
}

func collectCrossSockets(f *Facts, e *env.Env) {
	if !e.Has(env.CapNetlink) {
		f.Cross.SocketDiagMotivo = e.Reason(env.CapNetlink)
		return
	}
	c, err := netlink.Abrir(syscall.NETLINK_INET_DIAG)
	if err != nil {
		f.Cross.SocketDiagMotivo = err.Error()
		f.partial("net", "enumeração de socket por netlink indisponível ("+err.Error()+
			"): a tabela de conexões NÃO pôde ser confrontada com uma segunda visão")
		return
	}
	defer c.Fechar()

	diag, familias, cortado := dumpDiag(f, c)
	if len(familias) == 0 {
		return // dumpDiag já declarou o porquê
	}
	f.Cross.SocketDiagLido = true
	f.Cross.SocketDiag = len(diag)
	f.Cross.SocketDiagCortado = cortado

	// O que /proc entregou, restrito aos protocolos cujo dump FUNCIONOU.
	// Comparar com um protocolo que o netlink não respondeu produziria
	// divergência em toda conexão dele — invertida, e por culpa nossa.
	proc := map[string]bool{}
	for i := range f.Sockets {
		s := &f.Sockets[i]
		if familias[s.Proto] {
			proc[chaveDeSocket(s.Proto, s.LocalIP, s.LocalPort, s.PeerIP, s.PeerPort)] = true
		}
	}
	f.Cross.SocketProc = len(proc)

	candidatos := somenteNoDiag(diag, proc)
	if len(candidatos) == 0 {
		return
	}

	// Reconfirmação, dois passos, e só quando há candidato: as duas releituras
	// custam, e num host onde as visões concordam — que é o normal — elas nunca
	// acontecem.
	segundo, _, _ := dumpDiag(nil, c)
	candidatos = reconfirmar(candidatos, chavesDeProcNet(familias), segundo)

	for _, s := range candidatos {
		f.Cross.SocketOcultos = append(f.Cross.SocketOcultos, SocketOculto{
			Proto: s.Proto, Local: s.Local(), Peer: s.Peer(),
			Estado: nomeDeEstado(s.Estado), Inode: s.Inode, UID: s.UID,
		})
	}
}

// somenteNoDiag é a diferença entre as duas visões, e a direção importa.
//
// Só "está no netlink e não em /proc" é achado. O contrário — em /proc e não no
// netlink — é o socket que fechou entre uma leitura e a outra, e reportá-lo
// encheria todo host movimentado de divergência inventada.
func somenteNoDiag(diag map[string]netlink.SocketInet, proc map[string]bool) map[string]netlink.SocketInet {
	out := map[string]netlink.SocketInet{}
	for chave, s := range diag {
		if !proc[chave] {
			out[chave] = s
		}
	}
	return out
}

// reconfirmar elimina a corrida, e é o que separa este check de um gerador de
// ruído.
//
// Um socket nascido ENTRE a leitura de /proc e o dump aparece só no dump — a
// forma exata de um socket escondido. Sobrevive quem cumpre as duas condições:
//
//	continua AUSENTE numa segunda leitura de /proc  (não é socket novo)
//	continua PRESENTE num segundo dump por netlink  (não é socket que morreu)
//
// É a mesma resposta que a sondagem de PID oculto dá para o mesmo problema:
// relistar depois, e descartar quem apareceu.
func reconfirmar(cands map[string]netlink.SocketInet, procDeNovo map[string]bool,
	diagDeNovo map[string]netlink.SocketInet) map[string]netlink.SocketInet {
	out := map[string]netlink.SocketInet{}
	for chave, s := range cands {
		if procDeNovo[chave] {
			continue
		}
		if _, aindaEsta := diagDeNovo[chave]; !aindaEsta {
			continue
		}
		out[chave] = s
	}
	return out
}

// dumpDiag enumera as quatro combinações de família e protocolo. Devolve o que
// veio, QUAIS protocolos responderam, e se algum teto foi atingido.
//
// O conjunto de protocolos que responderam não é detalhe: udp_diag é um módulo
// separado do tcp_diag em boa parte das distribuições, e um host onde só o
// segundo existe compararia UDP contra o vazio.
func dumpDiag(f *Facts, c *netlink.Conexao) (map[string]netlink.SocketInet, map[string]bool, bool) {
	out := map[string]netlink.SocketInet{}
	familias := map[string]bool{}
	cortado := false
	for _, fam := range []uint8{netlink.FamiliaIPv4, netlink.FamiliaIPv6} {
		for _, proto := range []uint8{netlink.ProtoTCP, netlink.ProtoUDP} {
			var nome string
			err := netlink.SocketsInet(c, fam, proto, func(s netlink.SocketInet) error {
				nome = s.Proto
				out[chaveDeSocket(s.Proto, s.LocalIP, s.LocalPorta, s.PeerIP, s.PeerPorta)] = s
				return nil
			})
			if err == netlink.ErrCortado {
				cortado = true
			} else if err != nil {
				if f != nil {
					f.partial("net", "netlink não enumerou "+nomeDeFamilia(fam, proto)+
						" ("+err.Error()+"): esse protocolo NÃO foi confrontado com /proc/net")
				}
				continue
			}
			// Um dump legítimo pode não devolver socket nenhum, e nesse caso o
			// nome não foi preenchido pelo callback. Ele responde à pergunta
			// "este protocolo foi comparado?", que é diferente de "havia
			// socket nele".
			if nome == "" {
				nome = nomeDeFamilia(fam, proto)
			}
			familias[nome] = true
		}
	}
	return out, familias, cortado
}

func nomeDeFamilia(fam, proto uint8) string {
	nome := "tcp"
	if proto == netlink.ProtoUDP {
		nome = "udp"
	}
	if fam == netlink.FamiliaIPv6 {
		nome += "6"
	}
	return nome
}

// chavesDeProcNet relê as tabelas de /proc/net. É a SEGUNDA leitura da
// reconfirmação: entre ela e a primeira o socket recém-nascido já apareceu.
func chavesDeProcNet(familias map[string]bool) map[string]bool {
	out := map[string]bool{}
	for _, src := range []struct{ path, proto string }{
		{"/proc/net/tcp", "tcp"}, {"/proc/net/tcp6", "tcp6"},
		{"/proc/net/udp", "udp"}, {"/proc/net/udp6", "udp6"},
	} {
		if !familias[src.proto] {
			continue
		}
		body, ok := readTrim(src.path)
		if !ok {
			continue
		}
		for _, s := range parseTCPTable(body, src.proto) {
			out[chaveDeSocket(s.Proto, s.LocalIP, s.LocalPort, s.PeerIP, s.PeerPort)] = true
		}
	}
	return out
}
