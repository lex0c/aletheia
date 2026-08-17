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
	"os"
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

func die(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "helper:", err)
		os.Exit(1)
	}
}
