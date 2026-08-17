// Command helper cria, em qualquer distribuição, as situações que shell não
// consegue montar sozinho.
//
// Por que ele existe: `exec -a` é builtin do bash, e as imagens da matriz usam
// dash (debian) ou busybox ash (alpine) — nenhuma das duas tem. E memfd_create
// não tem primitiva de shell nenhuma. Um helper ESTÁTICO resolve os dois de uma
// vez e roda idêntico em toda imagem, inclusive sem libc — o que de quebra
// demonstra a mesma propriedade que justificou escrever a CLI em Go.
//
// Ele NÃO faz nada malicioso: renomeia o próprio argv e executa a partir de um
// descritor anônimo. São as FORMAS que a ferramenta precisa reconhecer, sem
// nenhum comportamento de implante.
package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"syscall"
	"time"
	"unsafe"
)

const usage = `helper — monta situações para a suíte de cenários

  helper argv0 <argv0-falso> <programa> [args...]
      executa <programa> com argv[0] arbitrário — o que exec -a faria (runbook §7.1)

  helper memfd <programa> [args...]
      copia <programa> para um descritor anônimo e executa DE LÁ. O processo
      resultante tem /proc/<pid>/exe apontando para /memfd: — execução fileless,
      sem que o binário jamais exista em disco (runbook §3.16)

  helper sleep <segundos>
      apenas dorme. Existe porque o /bin/sleep do Alpine é o BUSYBOX, que
      despacha pelo argv[0]: renomeá-lo faz o busybox procurar um applet
      inexistente e sair. Um alvo próprio, estático e sem despacho por nome
      funciona igual em toda imagem da matriz.

  helper listen <ip:porta>
      escuta e mantém aceitas as conexões. É o "outro lado" dos cenários de rede.

  helper connect <ip:porta> [ip:porta...]
      conecta em cada endereço e MANTÉM tudo aberto. Duas saídas — uma externa e
      uma interna — são a forma de pivô (runbook §12.2).

  helper revshell <ip:porta>
      conecta e duplica o socket sobre fd 0, 1 e 2. É a assinatura ESTRUTURAL de
      shell reverso (runbook §17) — sem executar shell nenhum: só a forma.

  helper accept <ip:porta>
      escuta, aceita UMA conexão e duplica o socket ACEITO sobre fd 0, 1 e 2,
      mantendo o socket de escuta aberto. É a forma da ativação por socket do
      systemd — idêntica à de cima, exceto pela DIREÇÃO. Existe para provar que
      a ferramenta não confunde as duas.

  helper proxy <ip:porta-escuta> <ip:porta-backend>
      aceita conexão de fora e abre outra para o backend. É a forma do proxy
      reverso: entrada externa + saída interna. Não pode ser lida como pivô.
`

func main() {
	if len(os.Args) < 3 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	switch os.Args[1] {
	case "sleep":
		var n int
		fmt.Sscanf(os.Args[2], "%d", &n)
		time.Sleep(time.Duration(n) * time.Second)
		return

	case "argv0":
		// helper argv0 "[kworker/9:2]" /bin/sleep 300
		if len(os.Args) < 4 {
			fmt.Fprint(os.Stderr, usage)
			os.Exit(2)
		}
		fake, prog := os.Args[2], os.Args[3]
		argv := append([]string{fake}, os.Args[4:]...)
		die(syscall.Exec(prog, argv, os.Environ()))

	case "memfd":
		prog := os.Args[2]
		die(memfdExec(prog, os.Args[3:]))

	case "listen":
		ln := mustListen(os.Args[2])
		go acceptForever(ln)
		hold()

	case "connect":
		for _, addr := range os.Args[2:] {
			keep(mustDial(addr))
		}
		hold()

	case "revshell":
		// A forma da §17: o processo SAI e amarra os três descritores padrão no
		// socket. Nenhum shell é executado — o que a ferramenta reconhece é a
		// estrutura, não o programa.
		c := mustDial(os.Args[2])
		die(dupOntoStdio(c))
		hold()

	case "accept":
		// Mesma estrutura, direção oposta: é assim que systemd (StandardInput=
		// socket) e inetd entregam a conexão. O socket de ESCUTA fica aberto,
		// como num serviço de verdade — é ele que permite classificar a conexão
		// aceita como de ENTRADA.
		ln := mustListen(os.Args[2])
		c, err := ln.Accept()
		die(err)
		keep(ln)
		die(dupOntoStdio(c))
		hold()

	case "proxy":
		// Entrada externa + saída interna: proxy reverso. Tem os dois lados
		// como um pivô e NÃO é um — a direção é a diferença inteira.
		if len(os.Args) < 4 {
			fmt.Fprint(os.Stderr, usage)
			os.Exit(2)
		}
		ln := mustListen(os.Args[2])
		c, err := ln.Accept()
		die(err)
		keep(ln, c, mustDial(os.Args[3]))
		hold()

	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
}

// memfdExec reproduz a técnica da §3.16: o binário vai para memória anônima e
// é executado de lá, então nunca existe caminho em disco para o find achar, nem
// inode para o hash comparar.
func memfdExec(prog string, args []string) error {
	data, err := os.ReadFile(prog)
	if err != nil {
		return err
	}

	name, err := syscall.BytePtrFromString("aletheia-test")
	if err != nil {
		return err
	}
	fd, _, errno := syscall.Syscall(sysMemfdCreate,
		uintptr(unsafe.Pointer(name)), 0, 0)
	if errno != 0 {
		return fmt.Errorf("memfd_create: %w", errno)
	}
	f := os.NewFile(fd, "memfd")
	if _, err := f.Write(data); err != nil {
		return err
	}

	path := fmt.Sprintf("/proc/self/fd/%d", f.Fd())
	argv := append([]string{prog}, args...)
	return syscall.Exec(path, argv, os.Environ())
}

// alive segura tudo que precisa continuar aberto: um socket coletado pelo GC
// some da tabela de conexões, e o cenário viraria falso negativo silencioso.
var alive []io.Closer

func keep(cs ...io.Closer) { alive = append(alive, cs...) }

func hold() {
	time.Sleep(300 * time.Second)
	runtime.KeepAlive(alive)
}

func mustListen(addr string) net.Listener {
	ln, err := net.Listen("tcp", addr)
	die(err)
	return ln
}

func mustDial(addr string) net.Conn {
	c, err := net.Dial("tcp", addr)
	die(err)
	return c
}

func acceptForever(ln net.Listener) {
	keep(ln)
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		keep(c)
	}
}

// dupOntoStdio põe o MESMO socket em fd 0, 1 e 2 — a assinatura que a
// ferramenta procura. Dup3 e não Dup2: Dup2 não existe em linux/arm64.
func dupOntoStdio(c net.Conn) error {
	sc, ok := c.(interface {
		SyscallConn() (syscall.RawConn, error)
	})
	if !ok {
		return fmt.Errorf("conexão sem SyscallConn")
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return err
	}
	var dupErr error
	err = raw.Control(func(fd uintptr) {
		for n := 0; n < 3; n++ {
			if e := syscall.Dup3(int(fd), n, 0); e != nil {
				dupErr = e
				return
			}
		}
	})
	if err != nil {
		return err
	}
	// A conexão original precisa sobreviver: fechá-la fecha o socket, e os três
	// descritores duplicados apontariam para nada.
	keep(c)
	return dupErr
}

func die(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "helper:", err)
		os.Exit(1)
	}
}
