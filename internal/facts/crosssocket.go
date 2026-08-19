package facts

import (
	"errors"
	"io/fs"
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

// chaveDeSocket é a identidade usada na comparação, e ela tem DOIS regimes.
//
// Com inode, a chave é o inode: é a identidade EXATA do socket, e casa entre
// /proc e netlink. Isso fecha o falso NEGATIVO de multiplicidade — vários
// sockets na MESMA tupla por SO_REUSEPORT deixam de colapsar numa entrada só,
// então esconder UM de /proc enquanto o outro aparece continua divergindo.
//
// Sem inode — TIME-WAIT e SYN-RECV têm inode zero nas duas visões — a tupla
// mais o ESTADO é o melhor que existe. O resíduo de multiplicidade sobra só
// nesses estados efêmeros, onde implante não mora.
func chaveDeSocket(proto string, inode uint64, lip string, lport int, pip string, pport int, estado string) string {
	if inode != 0 {
		return proto + "#" + strconv.FormatUint(inode, 10)
	}
	return proto + "|" + net.JoinHostPort(lip, strconv.Itoa(lport)) +
		"|" + net.JoinHostPort(pip, strconv.Itoa(pport)) + "|" + estado
}

// chaveProc e chaveDiag montam a chave a partir de cada uma das duas visões,
// para que a grafia do estado (que decide a chave sem inode) saia da MESMA
// tabela dos dois lados.
func chaveProc(s *Socket) string {
	return chaveDeSocket(s.Proto, s.Inode, s.LocalIP, s.LocalPort, s.PeerIP, s.PeerPort, s.State)
}

func chaveDiag(s netlink.SocketInet) string {
	return chaveDeSocket(s.Proto, uint64(s.Inode), s.LocalIP, s.LocalPorta, s.PeerIP, s.PeerPorta, nomeDeEstado(s.Estado))
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

	seguros := e.DiagSeguros

	diag1, diagOK1, cortado := dumpDiag(f, c, seguros)
	if len(diagOK1) == 0 {
		return // dumpDiag já declarou o porquê (nenhum protocolo consultável)
	}
	f.Cross.SocketDiagLido = true
	f.Cross.SocketDiag = len(diag1)
	f.Cross.SocketDiagCortado = cortado

	// 1ª leitura de /proc, restrita aos protocolos que o netlink respondeu, com
	// o SUCESSO por protocolo — não só as chaves. Sem esse sucesso, "o socket
	// não está em /proc" não se distingue de "não consegui ler /proc", e essa
	// distinção é a tese inteira da ferramenta.
	proc1, procOK1 := lerProcNet(diagOK1)
	f.Cross.SocketProc = len(proc1)

	// Protocolo que o netlink respondeu mas /proc não pôde ser LIDO: não é
	// comparável, e a ausência de um socket nele NÃO pode virar achado.
	for proto := range diagOK1 {
		if !procOK1[proto] {
			f.partial("net", "/proc/net/"+proto+" não pôde ser lido: as conexões de "+
				proto+" NÃO foram confrontadas com o netlink")
		}
	}

	// Candidatos: no diag, ausentes do /proc — SÓ para protocolos em que a 1ª
	// leitura de /proc foi de fato OBSERVADA.
	candidatos := map[string]netlink.SocketInet{}
	for chave, sk := range diag1 {
		if !procOK1[sk.Proto] {
			continue
		}
		if !proc1[chave] {
			candidatos[chave] = sk
		}
	}
	if len(candidatos) == 0 {
		return
	}

	// Reconfirmação, e só quando há candidato: as releituras custam, e num host
	// onde as visões concordam — o normal — elas nunca acontecem.
	//
	// As QUATRO testemunhas têm de ser observadas: /proc e netlink, 1ª e 2ª
	// passada. Se qualquer uma falhar, o candidato é INCONCLUSIVO, nunca
	// CRITICAL — este check é kernelBreaker, e formar um a partir de "não
	// consegui reler" seria a ferramenta quebrando a própria confiança do
	// kernel por uma falha de leitura dela mesma.
	proc2, procOK2 := lerProcNet(diagOK1)
	diag2, diagOK2, _ := dumpDiag(nil, c, seguros)

	var inconclusivos int
	for chave, sk := range candidatos {
		_, emDiag2 := diag2[chave]
		switch classificarOculto(observacao{
			procOK1: procOK1[sk.Proto], procOK2: procOK2[sk.Proto],
			diagOK1: diagOK1[sk.Proto], diagOK2: diagOK2[sk.Proto],
			emProc2: proc2[chave], emDiag2: emDiag2,
		}) {
		case ocultoInconclusivo:
			inconclusivos++
		case ocultoConfirmado:
			f.Cross.SocketOcultos = append(f.Cross.SocketOcultos, SocketOculto{
				Proto: sk.Proto, Local: sk.Local(), Peer: sk.Peer(),
				Estado: nomeDeEstado(sk.Estado), Inode: sk.Inode, UID: sk.UID,
			})
		}
	}
	if inconclusivos > 0 {
		f.partial("net", strconv.Itoa(inconclusivos)+" socket(s) candidatos a oculto NÃO "+
			"puderam ser reconfirmados: uma das quatro leituras (/proc ou netlink, 1ª ou 2ª "+
			"passada) falhou, e sem as quatro observadas a divergência fica INCONCLUSIVA — "+
			"não vira CRITICAL")
	}
}

// observacao são as seis testemunhas de UM candidato a socket oculto.
type observacao struct {
	procOK1, procOK2 bool // a leitura de /proc foi observada em cada passada?
	diagOK1, diagOK2 bool // o dump de netlink foi observado em cada passada?
	emProc2          bool // o socket REapareceu em /proc na 2ª passada?
	emDiag2          bool // o socket CONTINUA no netlink na 2ª passada?
}

type resultadoOculto int

const (
	ocultoConfirmado   resultadoOculto = iota // oculto de verdade
	ocultoCorrida                             // socket nasceu ou morreu: descartar
	ocultoInconclusivo                        // uma leitura falhou: nem confirma nem descarta
)

// classificarOculto decide, e a regra é deliberadamente severa por causa do
// peso do achado.
//
// Sem as quatro fontes observadas, INCONCLUSIVO — porque a alternativa é
// converter "não reli" em "reli e continuava ausente", que é exatamente a
// confusão que a ferramenta existe para não cometer, agravada aqui por o
// resultado ser um kernelBreaker.
func classificarOculto(o observacao) resultadoOculto {
	if !(o.procOK1 && o.procOK2 && o.diagOK1 && o.diagOK2) {
		return ocultoInconclusivo
	}
	if o.emProc2 { // reapareceu em /proc: socket recém-nascido, não oculto
		return ocultoCorrida
	}
	if !o.emDiag2 { // sumiu do netlink: socket que fechou, não oculto
		return ocultoCorrida
	}
	return ocultoConfirmado
}

// lerProcNet lê as tabelas de /proc/net dos protocolos pedidos, devolvendo as
// chaves e o SUCESSO por protocolo — a distinção que separa ausência de lacuna.
//
// ENOENT conta como leitura BEM-SUCEDIDA e vazia: a tabela não existir (IPv6
// desligado) é ausência de protocolo, consistente com o dump vazio do diag, e
// não uma falha. EACCES/EIO deixam o protocolo como NÃO lido, e ele não é
// comparado.
func lerProcNet(protos map[string]bool) (map[string]bool, map[string]bool) {
	chaves := map[string]bool{}
	lidos := map[string]bool{}
	for _, src := range []struct{ path, proto string }{
		{"/proc/net/tcp", "tcp"}, {"/proc/net/tcp6", "tcp6"},
		{"/proc/net/udp", "udp"}, {"/proc/net/udp6", "udp6"},
	} {
		if !protos[src.proto] {
			continue
		}
		body, err := readTrimErr(src.path)
		if !procNetLido(err) {
			continue // EACCES/EIO: LACUNA. O protocolo fica NÃO lido.
		}
		lidos[src.proto] = true
		if err == nil {
			for _, sk := range parseTCPTable(body, src.proto) {
				chaves[chaveProc(&sk)] = true
			}
		}
	}
	return chaves, lidos
}

// procNetLido diz, a partir do erro de leitura de /proc/net/<proto>, se o
// protocolo conta como LIDO.
//
// ENOENT — a tabela não existe, ex. IPv6 desligado — conta como lido e VAZIO:
// é ausência de protocolo, consistente com o dump vazio do diag, e transformá-la
// em lacuna criaria um buraco de cobertura em todo host sem IPv6. EACCES e EIO
// são lacuna de verdade, e deixam o protocolo fora da comparação.
func procNetLido(err error) bool {
	return err == nil || errors.Is(err, fs.ErrNotExist)
}

// dumpDiag enumera as quatro combinações de família e protocolo. Devolve o que
// veio, QUAIS protocolos responderam, e se algum teto foi atingido.
//
// O conjunto de protocolos que responderam não é detalhe: udp_diag é um módulo
// separado do tcp_diag em boa parte das distribuições, e um host onde só o
// segundo existe compararia UDP contra o vazio.
func dumpDiag(f *Facts, c *netlink.Conexao, seguros map[string]bool) (map[string]netlink.SocketInet, map[string]bool, bool) {
	out := map[string]netlink.SocketInet{}
	lidos := map[string]bool{}
	cortado := false
	for _, fam := range []uint8{netlink.FamiliaIPv4, netlink.FamiliaIPv6} {
		for _, proto := range []uint8{netlink.ProtoTCP, netlink.ProtoUDP} {
			nomeP := nomeDeFamilia(fam, proto)
			// Protocolo cujo handler NÃO está carregado é PULADO — consultá-lo
			// autocarregaria o módulo, e a política é não alterar o host. É
			// lacuna declarada, não falha.
			if !seguros[nomeP] {
				if f != nil {
					f.partial("net", "netlink NÃO consultou "+nomeP+": o módulo de "+
						"diagnóstico não está carregado, e consultar autocarregaria "+
						"(request_module). Use --allow-kernel-autoload para incluí-lo")
				}
				continue
			}
			err := netlink.SocketsInet(c, fam, proto, func(s netlink.SocketInet) error {
				out[chaveDiag(s)] = s
				return nil
			})
			if err == netlink.ErrCortado {
				cortado = true
			} else if err != nil {
				if f != nil {
					f.partial("net", "netlink não enumerou "+nomeP+" ("+err.Error()+
						"): esse protocolo NÃO foi confrontado com /proc/net")
				}
				continue
			}
			// Sucesso, com ou sem socket: o protocolo FOI comparado. A pergunta
			// é "consegui olhar?", diferente de "havia socket?".
			lidos[nomeP] = true
		}
	}
	return out, lidos, cortado
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
