package pcap

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// Opcoes é o que a captura precisa saber. Tudo tem teto: uma coleta que enche o
// disco do respondedor no meio do incidente é pior que uma coleta parcial
// declarada — a mesma regra do dump de memória.
type Opcoes struct {
	Iface    string
	Filtro   Filtro
	Duracao  time.Duration
	Snaplen  int   // 0 = pacote inteiro
	MaxBytes int64 // teto do arquivo

	// Parar interrompe a captura antes do prazo. É o Ctrl-C: o arquivo é
	// finalizado com o que já foi capturado, nunca descartado.
	Parar <-chan struct{}
}

// Estatisticas é o que a captura conta sobre si mesma.
//
// `Descartados` vem do PRÓPRIO KERNEL (PACKET_STATISTICS), e é o número que
// decide se este arquivo é evidência completa. Uma captura que perdeu pacote e
// não diz isso mente por omissão: o operador conclui "não houve tráfego" onde o
// certo é "não coube no buffer".
type Estatisticas struct {
	VistosPeloKernel int // tudo que o socket recebeu
	Descartados      int // o que o kernel jogou fora por falta de buffer
	Gravados         int
	Filtrados        int // vistos, não casaram o filtro
	NaoEntendidos    int // não deram para decodificar até onde o filtro precisa
	Truncados        int // cortados pelo snaplen
	// Duplicados são as cópias de TRANSMISSÃO descartadas na loopback. Ver o
	// laço de captura: ali o mesmo quadro chega duas vezes.
	Duplicados  int
	Bytes       int64
	Inicio, Fim time.Time

	// SemRelogioDoKernel diz que o horário de cada pacote é o da LEITURA, e não
	// o da chegada. A diferença é de microssegundos a milissegundos, e importa
	// quando a pergunta é ordem de eventos.
	SemRelogioDoKernel bool
	// Motivo de a captura ter parado.
	Parou string
}

// Interface é o que o /sys diz sobre a placa antes de tentar capturar.
type Interface struct {
	Nome       string
	Index      int
	TipoARP    int
	TipoEnlace uint32
	Ativa      bool
	Promiscua  bool
	// Loopback muda o que se grava: ali cada quadro é entregue DUAS vezes.
	Loopback bool
}

// ARPHRD → tipo de enlace do pcap.
//
// O mapa é curto e o resto é RECUSA. Escrever um pcap rotulado errado é pior que
// não escrever: o Wireshark decodifica com confiança total a partir do byte
// errado, e a análise sai limpa e falsa.
const (
	arphrdEther    = 1
	arphrdLoopback = 772
	arphrdNone     = 65534 // tun em modo IP: o pacote começa no IP
)

// AbrirInterface lê o que o /sys sabe. Falhar aqui é falhar antes de abrir
// socket nenhum.
func AbrirInterface(nome string) (Interface, error) {
	i := Interface{Nome: nome}
	base := "/sys/class/net/" + nome + "/"
	if fi, err := os.Stat(base); err != nil || !fi.IsDir() {
		return i, fmt.Errorf("interface %q não existe neste host (veja /sys/class/net)", nome)
	}
	i.Index = int(numeroDe(base+"ifindex", 10))
	i.TipoARP = int(numeroDe(base+"type", 10))
	if f := numeroDe(base+"flags", 16); f != 0 {
		i.Ativa = f&0x1 != 0
		i.Promiscua = f&0x100 != 0
	}
	switch i.TipoARP {
	case arphrdEther, arphrdLoopback:
		i.TipoEnlace = LinkEthernet
		i.Loopback = i.TipoARP == arphrdLoopback
	case arphrdNone:
		i.TipoEnlace = LinkRaw
	default:
		return i, fmt.Errorf("interface %q é do tipo ARPHRD %d, que este escritor "+
			"não sabe rotular. Um pcap com o rótulo errado é decodificado com "+
			"confiança total a partir do byte errado — recusar é a resposta certa",
			nome, i.TipoARP)
	}
	if i.Index == 0 {
		return i, fmt.Errorf("interface %q sem ifindex legível", nome)
	}
	return i, nil
}

func numeroDe(p string, base int) uint64 {
	b, err := os.ReadFile(p)
	if err != nil {
		return 0
	}
	s := strings.TrimSpace(string(b))
	s = strings.TrimPrefix(s, "0x")
	n, _ := strconv.ParseUint(s, base, 64)
	return n
}

const (
	ethPAll          = 0x0003
	solPacket        = 263
	packetStatistics = 6
	rcvbufAlvo       = 8 << 20 // reduz o descarte do kernel sob rajada
	esperaPorPacote  = 250 * time.Millisecond
	pacoteSaindo     = 4 // PACKET_OUTGOING
)

var ErrSemPrivilegio = errors.New("abrir socket de captura exige CAP_NET_RAW: " +
	"rode como root")

// Capturar abre o socket, escreve o pcap e devolve o que aconteceu.
//
// O socket é AF_PACKET SOCK_RAW, sem modo promíscuo. Isso é decisão, não
// omissão: ligar o promiscuous mode ALTERA o estado da interface — uma
// ferramenta read-only não faz isso —, é visível para quem estiver olhando, e a
// própria §2.6 trata interface promíscua como achado. Sem promíscuo se vê o
// tráfego DESTE host, que é o que um incidente pergunta.
func Capturar(w io.Writer, h hash.Hash, iface Interface, o Opcoes) (Estatisticas, error) {
	st := Estatisticas{Inicio: time.Now().UTC()}

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(ethPAll)))
	if err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			return st, ErrSemPrivilegio
		}
		return st, fmt.Errorf("socket AF_PACKET: %w", err)
	}
	defer syscall.Close(fd)

	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{
		Protocol: htons(ethPAll), Ifindex: iface.Index,
	}); err != nil {
		return st, fmt.Errorf("bind em %s: %w", iface.Nome, err)
	}

	// Buffer grande primeiro: o descarte do kernel acontece entre o fio e a
	// nossa leitura, e é o único dado que esta captura não consegue recuperar.
	_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, rcvbufAlvo)
	// Horário do KERNEL por pacote. Se não vier, o horário é o da leitura — e
	// isso sai declarado, não presumido.
	semRelogio := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TIMESTAMP, 1) != nil
	// Sem isto, um recvmsg numa rede quieta bloqueia para sempre e o Ctrl-C não
	// é visto até chegar um pacote.
	espera := syscall.NsecToTimeval(int64(esperaPorPacote))
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &espera)

	snap := o.Snaplen
	if snap <= 0 {
		snap = 262144 // "pacote inteiro": o teto do próprio AF_PACKET
	}
	esc, err := NovoEscritor(w, h, uint32(snap), iface.TipoEnlace)
	if err != nil {
		return st, err
	}

	buf := make([]byte, snap)
	oob := make([]byte, 128)
	prazo := time.Now().Add(o.Duracao)

	for {
		select {
		case <-o.Parar:
			st.Parou = "interrompido pelo operador: o arquivo tem o que foi capturado até aqui"
		default:
		}
		if st.Parou == "" && time.Now().After(prazo) {
			st.Parou = "prazo de " + o.Duracao.String() + " cumprido"
		}
		if st.Parou == "" && o.MaxBytes > 0 && esc.Bytes >= o.MaxBytes {
			st.Parou = fmt.Sprintf("teto de %d MB atingido: o tráfego SEGUINTE não "+
				"foi capturado. Suba --max-bytes se precisar dele", o.MaxBytes>>20)
		}
		if st.Parou != "" {
			break
		}

		n, oobn, _, de, err := syscall.Recvmsg(fd, buf, oob, 0)
		if err != nil {
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EINTR) {
				continue // sem pacote na janela de espera: volta a conferir prazo
			}
			st.Parou = "erro de leitura: " + err.Error()
			break
		}
		if n <= 0 {
			continue
		}
		st.VistosPeloKernel++

		// NA LOOPBACK O MESMO QUADRO CHEGA DUAS VEZES: uma na transmissão
		// (PACKET_OUTGOING) e outra na recepção, porque ali as duas pontas são
		// esta máquina. Gravar as duas DOBRA a contagem de pacotes e de bytes, e
		// qualquer análise de volume ou de ritmo sai errada — foi medido contra o
		// tcpdump, que grava três quadros de um handshake onde nós gravávamos seis.
		//
		// A cópia descartada é a de transmissão, e só na loopback: numa placa de
		// verdade o que este host ENVIA aparece exclusivamente como
		// PACKET_OUTGOING, e descartá-lo perderia metade da conversa.
		if iface.Loopback {
			if sll, ok := de.(*syscall.SockaddrLinklayer); ok && sll.Pkttype == pacoteSaindo {
				st.Duplicados++
				continue
			}
		}

		quando, doKernel := horario(oob[:oobn])
		if !doKernel {
			semRelogio = true
		}

		casa, entendi := o.Filtro.Casa(iface.TipoEnlace, buf[:n])
		switch {
		case !entendi:
			st.NaoEntendidos++
			continue
		case !casa:
			st.Filtrados++
			continue
		}

		// `n` é o que foi COPIADO; o tamanho original vem do próprio recvmsg
		// quando o snaplen corta — o AF_PACKET devolve o tamanho real do quadro
		// só via MSG_TRUNC, então o que se sabe aqui é que o corte aconteceu.
		original := n
		if n == snap {
			st.Truncados++
		}
		if err := esc.Pacote(quando, buf[:n], original); err != nil {
			st.Parou = "erro de escrita: " + err.Error()
			break
		}
		st.Gravados++
	}

	st.Fim = time.Now().UTC()
	st.Bytes = esc.Bytes
	st.SemRelogioDoKernel = semRelogio

	// As estatísticas do kernel por último: a leitura ZERA os contadores, então
	// ela acontece uma vez só, no fim.
	if p, d, err := estatisticasDoKernel(fd); err == nil {
		st.VistosPeloKernel = p
		st.Descartados = d
	}
	return st, nil
}

// horario devolve o instante do pacote. O do kernel é melhor: é quando o quadro
// CHEGOU, e não quando este processo conseguiu lê-lo.
func horario(oob []byte) (time.Time, bool) {
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return time.Now().UTC(), false
	}
	for _, m := range msgs {
		if m.Header.Level != syscall.SOL_SOCKET || m.Header.Type != syscall.SCM_TIMESTAMP {
			continue
		}
		var tv syscall.Timeval
		if len(m.Data) < int(unsafe.Sizeof(tv)) {
			continue
		}
		tv = *(*syscall.Timeval)(unsafe.Pointer(&m.Data[0]))
		return time.Unix(int64(tv.Sec), int64(tv.Usec)*1000).UTC(), true
	}
	return time.Now().UTC(), false
}

// estatisticasDoKernel lê PACKET_STATISTICS. É um getsockopt de ESTRUTURA, que
// a stdlib não expõe — daí a syscall crua, com o número por arquitetura.
func estatisticasDoKernel(fd int) (pacotes, descartes int, err error) {
	var b [8]byte
	if err := getsockoptBytes(fd, solPacket, packetStatistics, b[:]); err != nil {
		return 0, 0, err
	}
	le := binary.NativeEndian
	return int(le.Uint32(b[0:])), int(le.Uint32(b[4:])), nil
}

func htons(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return binary.NativeEndian.Uint16(b[:])
}
