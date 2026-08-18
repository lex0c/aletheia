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
	"os/exec"
	"runtime"
	"strconv"
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

  helper caps <uid>
      larga o uid de root MANTENDO capability. É como capability substitui o
      SUID (runbook §3.7): o processo aparece como usuário comum e tem poder de
      root. Não precisa de setcap nem de libcap — só de PR_SET_KEEPCAPS.

  helper trace
      inicia um filho sob PTRACE_TRACEME e o mantém traçado. A relação pai/filho
      é o que satisfaz ptrace_scope=1, que é o padrão da maioria das distros.

  helper pty <uid> <programa> [args...]
      abre um pseudoterminal, larga o privilégio para <uid> e executa o
      programa com o terminal em fd 0, 1 e 2. É a forma de uma sessão
      interativa — que é o que uma conta de serviço nunca deveria ter (§3.2).

  helper spawn <programa> [args...]
      inicia um FILHO e o mantém. Serve para montar linhagem: um processo com
      nome de daemon gerando um shell é a cadeia da §3.2, e ela não existe
      sem pai e filho de verdade.

  helper rwx
      mapeia uma região ANÔNIMA gravável e executável e a mantém. É a assinatura
      que o malfind procura (runbook §3.10) — sem escrever código nela: só a forma.

  helper proxy <ip:porta-escuta> <ip:porta-backend>
      aceita conexão de fora e abre outra para o backend. É a forma do proxy
      reverso: entrada externa + saída interna. Não pode ser lida como pivô.

  helper bpf socket <nome>
      carrega um programa eBPF mínimo, ANEXA a um socket e FECHA o descritor do
      programa. Ninguém mais tem descritor, não há pin e não há link: quem
      segura é o socket. É a forma do implante em eBPF (runbook §35), sem
      nenhum comportamento dele — o programa devolve zero e termina.

  helper bpf hold <nome>
      carrega e MANTÉM o descritor aberto. É o que toda ferramenta com libbpf
      faz, e é o caso que NÃO pode virar achado.

  helper bpf pin <caminho> <nome>
      carrega e prende no bpffs. O pin é um dono visível.

  helper bpf tracepoint <evento> <nome>
      caminho LEGADO: perf_event_open no tracepoint e o programa pendurado por
      ioctl, sem link nenhum. É como bpftrace e agente com libbpf antiga
      anexam, e é o falso positivo que o BPF_TASK_FD_QUERY existe para evitar.

  helper bpf cgroup <caminho-do-cgroup> <nome>
      anexa por BPF_PROG_ATTACH e SAI. Não deixa descritor, pin nem link: quem
      segura é o CGROUP. É como o systemd aplica controle por unit, e é a
      população legítima que não pode virar achado.

  helper bpf tailcall <nome>
      deixa o programa preso a um prog_array e segura o MAPA. É como cilium
      encadeia o datapath: o programa não tem descritor próprio.

  helper bpf pacote <nome>
      a forma COMPLETA do BPFDoor: socket AF_PACKET com ETH_P_ALL, filtro eBPF
      anexado e o descritor do programa fechado. Não abre porta nenhuma.

  helper pacote
      só o socket AF_PACKET, sem programa: é o gerenciador de rede. O mecanismo
      é o mesmo, e não há implante — existe para provar que a leitura da §2.6
      não vira acusação sozinha.
`

func main() {
	// O mínimo é o subcomando: `trace` não leva argumento nenhum. Cada caso
	// confere o que precisa.
	need(2)

	switch os.Args[1] {
	case "sleep":
		need(3)
		var n int
		fmt.Sscanf(os.Args[2], "%d", &n)
		time.Sleep(time.Duration(n) * time.Second)
		return

	case "argv0":
		// helper argv0 "[kworker/9:2]" /bin/sleep 300
		need(4)
		fake, prog := os.Args[2], os.Args[3]
		argv := append([]string{fake}, os.Args[4:]...)
		die(syscall.Exec(prog, argv, os.Environ()))

	case "memfd":
		need(3)
		prog := os.Args[2]
		die(memfdExec(prog, os.Args[3:]))

	case "listen":
		need(3)
		ln := mustListen(os.Args[2])
		go acceptForever(ln)
		hold()

	case "connect":
		need(3)
		for _, addr := range os.Args[2:] {
			keep(mustDial(addr))
		}
		hold()

	case "revshell":
		// A forma da §17: o processo SAI e amarra os três descritores padrão no
		// socket. Nenhum shell é executado — o que a ferramenta reconhece é a
		// estrutura, não o programa.
		need(3)
		c := mustDial(os.Args[2])
		die(dupOntoStdio(c))
		hold()

	case "accept-fecha":
		// A mesma entrega de conexão do inetd, com uma diferença: o socket de
		// ESCUTA é fechado depois do accept.
		//
		// É o que derruba a inferência de direção. O kernel não registra em
		// /proc/net/tcp quem iniciou a conexão; a ferramenta deduz olhando se a
		// porta local também está em LISTEN. Sem o listener, uma conexão de
		// ENTRADA fica indistinguível de uma de saída — e a estrutura de
		// reverse shell (stdio no mesmo socket) passa a casar.
		need(3)
		ln := mustListen(os.Args[2])
		c, err := ln.Accept()
		die(err)
		die(ln.Close())
		die(dupOntoStdio(c))
		hold()

	case "accept":
		// Mesma estrutura, direção oposta: é assim que systemd (StandardInput=
		// socket) e inetd entregam a conexão. O socket de ESCUTA fica aberto,
		// como num serviço de verdade — é ele que permite classificar a conexão
		// aceita como de ENTRADA.
		need(3)
		ln := mustListen(os.Args[2])
		c, err := ln.Accept()
		die(err)
		keep(ln)
		die(dupOntoStdio(c))
		hold()

	case "caps":
		need(3)
		uid, err := strconv.Atoi(os.Args[2])
		die(err)
		die(keepCapsAsUser(uid))
		hold()

	case "trace":
		die(traceChild())
		hold()

	case "pty":
		need(4)
		uid, err := strconv.Atoi(os.Args[2])
		die(err)
		die(sessaoComPTY(uid, os.Args[3], os.Args[4:]))

	case "spawn":
		need(3)
		cmd := exec.Command(os.Args[2], os.Args[3:]...)
		die(cmd.Start())
		hold()

	case "setcap":
		// helper setcap /caminho 7      (7 = CAP_SETUID)
		//
		// Existe porque a imagem de teste não traz o `setcap` do libcap, e a
		// forma MODERNA de retenção de root — capability em xattr, sem bit
		// setuid nenhum — precisa ser plantável para ser testada.
		//
		// O formato é o vfs_cap_data do kernel, versão 2, little-endian: magic
		// com o bit EFETIVO ligado, seguido de permitted e inheritable em
		// metades baixa e alta.
		need(4)
		var bit uint
		fmt.Sscanf(os.Args[3], "%d", &bit)
		perm := uint64(1) << bit
		v := make([]byte, 20)
		put32(v[0:], 0x02000000|0x000001) // versão 2, efetivo
		put32(v[4:], uint32(perm))
		put32(v[12:], uint32(perm>>32))
		die(syscall.Setxattr(os.Args[2], "security.capability", v, 0))

	case "immutable":
		// helper immutable /caminho
		//
		// Não depende do `chattr`, que vem em pacotes diferentes por
		// distribuição. O número do ioctl DEPENDE DA ARQUITETURA: a macro é
		// _IOR('f', 1, long), e long tem 4 bytes em 32 bits.
		need(3)
		fh, err := os.OpenFile(os.Args[2], os.O_RDONLY, 0)
		die(err)
		get := uintptr(0x80000000 | (unsafe.Sizeof(int(0)) << 16) | ('f' << 8) | 1)
		set := uintptr(0x40000000 | (unsafe.Sizeof(int(0)) << 16) | ('f' << 8) | 2)
		var flags uint32
		if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fh.Fd(), get,
			uintptr(unsafe.Pointer(&flags))); errno != 0 {
			die(errno)
		}
		flags |= 0x00000010 // FS_IMMUTABLE_FL
		if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fh.Fd(), set,
			uintptr(unsafe.Pointer(&flags))); errno != 0 {
			die(errno)
		}
		fh.Close()

	case "utmp":
		// helper utmp /var/log/btmp 7 root 203.0.113.9 25
		//
		// Escreve registros no formato utmp: tipo, usuário, origem e quantos.
		// Existe porque plantar entrada de login de verdade exigiria sshd e
		// sessão — e o que está sob teste é a LEITURA do formato e o cruzamento
		// entre os dois arquivos, não o daemon que os escreve.
		need(7)
		var tipo, n int
		fmt.Sscanf(os.Args[3], "%d", &tipo)
		fmt.Sscanf(os.Args[6], "%d", &n)
		fh, err := os.OpenFile(os.Args[2], os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		die(err)
		for i := 0; i < n; i++ {
			r := make([]byte, 384)
			r[0], r[1] = byte(tipo), byte(tipo>>8)
			put32(r[4:], uint32(1000+i))
			copy(r[8:40], "pts/0")
			copy(r[44:76], os.Args[4])
			copy(r[76:332], os.Args[5])
			put32(r[340:], uint32(time.Now().Unix()))
			_, err := fh.Write(r)
			die(err)
		}
		die(fh.Close())

	case "ftrace":
		// helper ftrace /caminho/enabled_functions __x64_sys_getdents64 rootkit
		//
		// Escreve uma linha no formato do `enabled_functions`. O arquivo real
		// vive em /sys e não é gravável — o cenário monta um tmpfs por cima
		// para exercitar o parser e a decisão contra conteúdo realista.
		need(5)
		linha := fmt.Sprintf("%s (1) R   D   M \ttramp: ftrace_regs_caller+0x0/0x65 (%s_hook+0x0/0x20)",
			os.Args[3], os.Args[4])
		if os.Args[4] != "bpf" {
			linha += " [" + os.Args[4] + "]"
		} else {
			linha = fmt.Sprintf("%s (1) R   D   M \ttramp: ftrace_regs_caller+0x0/0x65 (bpf_trampoline_6442516084+0x0/0xee)",
				os.Args[3])
		}
		fh, err := os.OpenFile(os.Args[2], os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		die(err)
		_, err = fh.WriteString(linha + "\n")
		die(err)
		die(fh.Close())

	case "rwx":
		die(mapRWX())
		hold()

	case "vigia":
		// Um watch de inotify nos caminhos dados. É a forma do "removi e
		// voltou": quem recria o arquivo apagado precisa saber que ele sumiu, e
		// vigia o DIRETÓRIO, que sobrevive ao `rm`.
		need(3)
		die(vigiarArquivos(os.Args[2:]))
		hold()

	case "pacote":
		die(pacoteSemBPF())
		hold()

	case "bpf":
		need(4)
		switch os.Args[2] {
		case "socket":
			die(bpfNoSocket(os.Args[3]))
		case "hold":
			die(bpfSegura(os.Args[3]))
		case "pin":
			// SAI de propósito: quem segura o programa passa a ser só o pin, e
			// é isso que o cenário precisa demonstrar. Segurar o descritor aqui
			// provaria outra coisa.
			need(5)
			die(bpfPina(os.Args[3], os.Args[4]))
			return
		case "tracepoint":
			need(5)
			die(bpfNoTracepoint(os.Args[3], os.Args[4]))
		case "cgroup":
			// Também SAI: quem segura passa a ser o cgroup, e é isso que o
			// cenário precisa mostrar.
			need(5)
			die(bpfNoCgroup(os.Args[3], os.Args[4]))
			return
		case "tailcall":
			die(bpfNoTailCall(os.Args[3]))
		case "pacote":
			die(bpfNoSocketDePacote(os.Args[3]))
		default:
			fmt.Fprint(os.Stderr, usage)
			os.Exit(2)
		}
		hold()

	case "proxy":
		// Entrada externa + saída interna: proxy reverso. Tem os dois lados
		// como um pivô e NÃO é um — a direção é a diferença inteira.
		need(4)
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

// keepCapsAsUser reproduz o caminho da §3.7: PR_SET_KEEPCAPS preserva o
// conjunto PERMITIDO através do setuid, e o capset devolve ao EFETIVO o que
// interessa. O resultado é um processo com uid de usuário comum e poder de
// root — que é exatamente o que auditoria por UID não enxerga.
//
// As duas capabilities escolhidas estão no conjunto padrão do Docker, então o
// cenário roda sem --cap-add.
func keepCapsAsUser(uid int) error {
	const (
		prSetKeepCaps  = 8
		capVersion3    = 0x20080522
		capDACOverride = 1
		capSetUID      = 7
	)
	if _, _, e := syscall.RawSyscall(syscall.SYS_PRCTL, prSetKeepCaps, 1, 0); e != 0 {
		return fmt.Errorf("PR_SET_KEEPCAPS: %w", e)
	}
	if err := syscall.Setresgid(uid, uid, uid); err != nil {
		return fmt.Errorf("setresgid: %w", err)
	}
	if err := syscall.Setresuid(uid, uid, uid); err != nil {
		return fmt.Errorf("setresuid: %w", err)
	}
	// O setuid limpa o conjunto EFETIVO mesmo com KEEPCAPS; o permitido
	// sobrevive, e é dele que se reergue o efetivo.
	want := uint32(1<<capDACOverride | 1<<capSetUID)
	hdr := capHeader{version: capVersion3}
	data := [2]capData{{effective: want, permitted: want}}
	if _, _, e := syscall.RawSyscall(syscall.SYS_CAPSET,
		uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&data[0])), 0); e != 0 {
		return fmt.Errorf("capset: %w", e)
	}
	return nil
}

// capset não está no pacote syscall da biblioteca padrão — só em
// golang.org/x/sys. Como o helper é sem dependência (mesma regra do binário
// principal), as duas estruturas vêm à mão. Layout de <linux/capability.h>.
type capHeader struct {
	version uint32
	pid     int32
}

type capData struct {
	effective   uint32
	permitted   uint32
	inheritable uint32
}

// traceChild deixa um processo com TracerPid != 0. O filho é iniciado com
// PTRACE_TRACEME e depois liberado: fica RODANDO e traçado, que é a forma de
// injeção da §3.16 — e não um processo parado, que não pareceria nada.
func traceChild() error {
	// A thread que inicia o filho é a única que pode esperar por ele.
	runtime.LockOSThread()

	cmd := exec.Command(os.Args[0], "sleep", "300")
	cmd.SysProcAttr = &syscall.SysProcAttr{Ptrace: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	var ws syscall.WaitStatus
	if _, err := syscall.Wait4(cmd.Process.Pid, &ws, 0, nil); err != nil {
		return err
	}
	return syscall.PtraceCont(cmd.Process.Pid, 0)
}

// mapRWX cria a região que `MemoryDenyWriteExecute=yes` torna impossível
// (runbook §34.1): sem arquivo por trás, gravável e executável ao mesmo tempo.
func mapRWX() error {
	b, err := syscall.Mmap(-1, 0, 4096,
		syscall.PROT_READ|syscall.PROT_WRITE|syscall.PROT_EXEC,
		syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS)
	if err != nil {
		return fmt.Errorf("mmap rwx: %w", err)
	}
	rwx = b
	return nil
}

// rwx é global para o mapeamento não ser recolhido antes da varredura.
var rwx []byte

// sessaoComPTY monta o que o kernel considera uma sessão interativa: um
// pseudoterminal em fd 0, 1 e 2. Sem terminal de verdade o check não teria o
// que ver — e um terminal falso não é testável.
//
// Os números de ioctl vêm do asm-generic e valem para x86, arm e arm64, que são
// as arquiteturas que o helper constrói.
func sessaoComPTY(uid int, prog string, args []string) error {
	const (
		tiocsptlck = 0x40045431 // destrava o escravo
		tiocgptn   = 0x80045430 // devolve o número do escravo
	)
	mestre, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		return err
	}
	var zero int32
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, mestre.Fd(),
		tiocsptlck, uintptr(unsafe.Pointer(&zero))); e != 0 {
		return fmt.Errorf("destravar pty: %w", e)
	}
	var n int32
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, mestre.Fd(),
		tiocgptn, uintptr(unsafe.Pointer(&n))); e != 0 {
		return fmt.Errorf("número do pty: %w", e)
	}
	escravo, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR, 0)
	if err != nil {
		return err
	}
	keep(mestre, escravo)

	for fd := 0; fd < 3; fd++ {
		if err := syscall.Dup3(int(escravo.Fd()), fd, 0); err != nil {
			return err
		}
	}
	// O privilégio é largado ANTES do exec: o processo resultante roda com a
	// identidade da conta de serviço, que é o ponto do cenário.
	if err := syscall.Setresgid(uid, uid, uid); err != nil {
		return err
	}
	if err := syscall.Setresuid(uid, uid, uid); err != nil {
		return err
	}
	return syscall.Exec(prog, append([]string{prog}, args...), os.Environ())
}

func need(n int) {
	if len(os.Args) < n {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
}

func die(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "helper:", err)
		os.Exit(1)
	}
}

func put32(b []byte, v uint32) {
	b[0], b[1], b[2], b[3] = byte(v), byte(v>>8), byte(v>>16), byte(v>>24)
}

// vigiarArquivos abre um inotify e registra um watch por caminho. O descritor
// fica aberto enquanto o processo viver — é o que a varredura enxerga em
// /proc/<pid>/fdinfo.
func vigiarArquivos(caminhos []string) error {
	fd, err := syscall.InotifyInit1(0)
	if err != nil {
		return err
	}
	for _, c := range caminhos {
		// IN_CREATE|IN_DELETE|IN_MOVED_TO: exatamente o que interessa a quem
		// espera o arquivo sumir para recriá-lo.
		if _, err := syscall.InotifyAddWatch(fd, c, 0x100|0x200|0x80); err != nil {
			return err
		}
	}
	return nil
}
