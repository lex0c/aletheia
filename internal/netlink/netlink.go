// Package netlink fala com o kernel pela interface que o `ss` e o `ip` usam,
// sem chamar nenhum dos dois.
//
// # Por que isto existe
//
// Quase tudo que esta ferramenta sabe sobre rede vem de /proc/net. É uma fonte
// só, e é a fonte que um rootkit de kernel intercepta primeiro: um hook em
// `tcp4_seq_show` some com a conexão da tabela sem tocar em mais nada — o
// próprio catálogo de hooks de ftrace desta ferramenta procura exatamente essa
// função.
//
// O netlink é o OUTRO caminho para o mesmo fato. Ele não passa pelo
// `seq_show`: o kernel percorre as tabelas de hash de socket e responde por
// mensagem. Esconder das duas visões exige interceptar dois caminhos de código
// diferentes, e é isso que torna a comparação valiosa.
//
// # O que este pacote NÃO faz
//
// Só LÊ. Nenhuma mensagem daqui cria, altera ou remove estado: os tipos usados
// são de consulta, e não há um único `RTM_NEW*` neste código. É a mesma regra
// do pacote kbpf, pelo mesmo motivo (SPEC 10).
package netlink

import (
	"encoding/binary"
	"errors"
	"strconv"
	"syscall"
	"time"
	"unsafe"
)

// ordemNativa é a ordem de bytes do HOST. O cabeçalho netlink e os campos
// `__u32` das mensagens vão nela; só endereço e porta são big-endian, e esses
// estão marcados um a um lá em inetdiag.go.
//
// Detectada em vez de assumida porque um cabeçalho montado na ordem errada não
// quebra a compilação: o kernel devolve EINVAL, ou pior, lê um comprimento
// absurdo — e o defeito aparece só na arquitetura que ninguém testou.
var ordemNativa = func() binary.ByteOrder {
	x := uint16(1)
	if *(*byte)(unsafe.Pointer(&x)) == 1 {
		return binary.LittleEndian
	}
	return binary.BigEndian
}()

// Tetos. Um dump de socket num balanceador devolve centenas de milhares de
// mensagens; o teto existe para o caso patológico e para o kernel que responde
// sem parar. Bater nele é CORTE DECLARADO, nunca silêncio.
const (
	maxMensagens = 300000
	tamBuffer    = 64 * 1024
	prazoTotal   = 10 * time.Second
	prazoLeitura = 3 * time.Second
)

// ErrCortado diz que o teto foi atingido: o que veio é válido, e não é tudo.
var ErrCortado = errors.New("dump cortado no teto de mensagens: a enumeração NÃO é completa")

// Erro é a falha com a frase que vai para o rodapé de cobertura. A distinção
// entre "este kernel não faz isso" e "não me deixaram" decide se a lacuna é
// permanente ou se basta rodar como root.
type Erro struct {
	Motivo string
	Errno  syscall.Errno
	// SemMecanismo marca o kernel que não OFERECE a interface. Não é lacuna de
	// leitura: não há o que ler, e dizer "não verifiquei" ali seria prometer
	// uma verificação que não existe neste host.
	SemMecanismo bool
}

func (e *Erro) Error() string { return e.Motivo }

// Conexao é um socket netlink aberto. Não é seguro para uso concorrente: a
// sequência é por conexão, e duas goroutinas dividindo uma leriam a resposta
// uma da outra.
type Conexao struct {
	fd  int
	seq uint32
}

// Abrir cria o socket. O protocolo é a família netlink — NETLINK_INET_DIAG
// para socket, NETLINK_ROUTE para interface e qdisc.
func Abrir(protocolo int) (*Conexao, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK,
		syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, protocolo)
	if err != nil {
		return nil, traduzir(err, "abrir socket netlink")
	}
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		syscall.Close(fd)
		return nil, traduzir(err, "bind do socket netlink")
	}
	// Sem prazo, um kernel que para de responder trava a coleta inteira — e
	// esta ferramenta roda em host sob incidente, que é onde isso acontece.
	tv := syscall.NsecToTimeval(int64(prazoLeitura))
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
	return &Conexao{fd: fd}, nil
}

func (c *Conexao) Fechar() {
	if c != nil && c.fd >= 0 {
		syscall.Close(c.fd)
		c.fd = -1
	}
}

// Dump manda uma consulta e entrega CADA mensagem da resposta ao callback.
//
// Por callback, e não por slice devolvido, pela mesma razão que o maps é lido
// em fluxo: um host com cem mil conexões produziria dezenas de megabytes de
// payload cru para que o chamador guardasse quatro campos de cada um.
func (c *Conexao) Dump(tipo uint16, req []byte, fn func(dados []byte) error) error {
	c.seq++
	seq := c.seq

	msg := make([]byte, syscall.NLMSG_HDRLEN+len(req))
	ordemNativa.PutUint32(msg[0:4], uint32(len(msg)))
	ordemNativa.PutUint16(msg[4:6], tipo)
	ordemNativa.PutUint16(msg[6:8], syscall.NLM_F_REQUEST|syscall.NLM_F_DUMP)
	ordemNativa.PutUint32(msg[8:12], seq)
	ordemNativa.PutUint32(msg[12:16], 0) // pid 0 = o kernel escolhe
	copy(msg[syscall.NLMSG_HDRLEN:], req)

	if err := syscall.Sendto(c.fd, msg, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return traduzir(err, "enviar consulta netlink")
	}

	buf := make([]byte, tamBuffer)
	limite := time.Now().Add(prazoTotal)
	vistas := 0
	for {
		if time.Now().After(limite) {
			return ErrCortado
		}
		n, _, err := syscall.Recvfrom(c.fd, buf, 0)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			return traduzir(err, "ler resposta netlink")
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return &Erro{Motivo: "resposta netlink ilegível: " + err.Error()}
		}
		for i := range msgs {
			m := &msgs[i]
			// Resposta de OUTRA consulta na mesma conexão. Não deveria
			// acontecer com uso sequencial, e processá-la misturaria dois
			// dumps sem que nada reclamasse.
			if m.Header.Seq != seq {
				continue
			}
			switch m.Header.Type {
			case syscall.NLMSG_DONE:
				// O errno de encerramento do dump vem NO PAYLOAD do DONE:
				// netlink_dump copia nlk->dump_done_errno para o corpo da
				// mensagem (net/netlink/af_netlink.c). Um dump que ABORTOU no
				// meio não vira NLMSG_ERROR — ele termina em DONE com código
				// negativo. Tratar isso como sucesso fazia um host sem
				// tcp_diag carregável (onde __inet_diag_dump devolve -ENOENT
				// depois de o netlink_dump_start ter sucedido) declarar a
				// capacidade PRESENTE e entregar zero sockets sem erro — e a
				// visão cruzada lia esse zero como fato.
				if len(m.Data) >= 4 {
					if code := int32(ordemNativa.Uint32(m.Data[0:4])); code < 0 {
						return traduzir(syscall.Errno(-code), "dump netlink")
					}
				}
				return nil
			case syscall.NLMSG_ERROR:
				if len(m.Data) < 4 {
					return &Erro{Motivo: "netlink devolveu erro sem código"}
				}
				code := int32(ordemNativa.Uint32(m.Data[0:4]))
				if code == 0 {
					return nil // ACK: fim sem erro
				}
				return traduzir(syscall.Errno(-code), "consulta netlink")
			case syscall.NLMSG_NOOP:
				continue
			}
			vistas++
			if vistas > maxMensagens {
				return ErrCortado
			}
			if err := fn(m.Data); err != nil {
				return err
			}
		}
	}
}

// traduzir transforma o errno na frase que o operador lê. Os "não" são
// diferentes e a diferença decide o que fazer: um pede root, outro diz que
// este kernel não tem o mecanismo, e um terceiro diz que o módulo do
// subsistema não está disponível.
func traduzir(err error, oque string) error {
	errno, ok := err.(syscall.Errno)
	if !ok {
		return &Erro{Motivo: oque + ": " + err.Error()}
	}
	switch errno {
	case syscall.EPERM, syscall.EACCES:
		return &Erro{
			Motivo: oque + ": permissão negada — rode como root",
			Errno:  errno,
		}
	case syscall.EPROTONOSUPPORT, syscall.EAFNOSUPPORT:
		return &Erro{
			Motivo: oque + ": este kernel não oferece esta família de netlink " +
				"(compilado sem o subsistema)",
			Errno:        errno,
			SemMecanismo: true,
		}
	case syscall.ENOENT:
		// sock_diag responde ENOENT quando o módulo daquela família/protocolo
		// não está disponível — tcp_diag e udp_diag são módulos separados em
		// boa parte das distribuições.
		return &Erro{
			Motivo: oque + ": o kernel não tem o módulo de diagnóstico desta " +
				"família carregável (ENOENT)",
			Errno:        errno,
			SemMecanismo: true,
		}
	case syscall.EINVAL, syscall.ENOSYS:
		return &Erro{
			Motivo: oque + ": este kernel não entende a consulta — anterior ao " +
				"3.3, quando o sock_diag ganhou a forma atual",
			Errno:        errno,
			SemMecanismo: true,
		}
	// EAGAIN e EWOULDBLOCK são o MESMO valor no Linux; listar os dois não
	// compila, e o que interessa aqui é que o prazo de leitura estourou.
	case syscall.EAGAIN:
		return &Erro{
			Motivo: oque + ": o kernel não respondeu dentro de " +
				strconv.Itoa(int(prazoLeitura/time.Second)) + "s",
			Errno: errno,
		}
	}
	return &Erro{Motivo: oque + ": " + errno.Error(), Errno: errno}
}
