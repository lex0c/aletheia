package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

// Plantio de eBPF, para os cenários da fase 8.
//
// O programa carregado é o menor programa VÁLIDO que existe: devolve zero e
// termina. Ele não lê pacote, não intercepta nada e não esconde coisa alguma —
// o que a ferramenta precisa reconhecer é a FORMA (existe algo carregado no
// kernel, e quem o segura não aparece), não o comportamento.
//
// Por que o helper carrega em vez de a suíte usar bpftool: bpftool não está nas
// imagens da matriz nem no initramfs do guest, e depender dele trocaria "o
// cenário planta" por "o cenário pula".
//
// A syscall vem à mão aqui pelo mesmo motivo do capset e do FS_IOC_GETFLAGS: o
// helper não tem dependência, e o pacote kbpf da ferramenta é deliberadamente
// SÓ LEITURA — carregar programa não pertence ao binário que varre.

const (
	bpfMapCreate     = 0
	bpfMapUpdateElem = 2
	bpfProgLoad      = 5
	bpfObjPin        = 6
	bpfProgAttach    = 8

	mapTipoProgArray = 3

	progTipoSocketFilter = 1
	progTipoTracepoint   = 5
	progTipoCgroupSkb    = 8

	soAttachBPF = 50

	// PERF_EVENT_IOC_ENABLE e _SET_BPF: _IO('$', 0) e _IOW('$', 8, __u32).
	perfIocEnable = 0x2400
	perfIocSetBPF = 0x40042408
)

// programaMinimo é `r0 = <retorno>; exit` — duas instruções de oito bytes.
//
// O formato de uma instrução é {u8 code, u8 dst:4|src:4, s16 off, s32 imm}.
// 0xb7 é BPF_ALU64|BPF_MOV|BPF_K (mover imediato para registrador) e 0x95 é
// BPF_JMP|BPF_EXIT.
//
// O retorno IMPORTA por tipo: num filtro de socket zero descarta o pacote (e o
// socket é do próprio helper, então não afeta ninguém), mas num programa de
// cgroup zero BLOQUEIA o tráfego do cgroup inteiro. Ali o cenário usa 1.
//
// O buffer é de pacote e reescrito antes de cada carga: o endereço dele entra
// na bpf_attr como inteiro, e um buffer local poderia mudar de lugar. O helper
// é sequencial, então reescrever é seguro.
var programaMinimo = []byte{
	0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // r0 = <imm>
	0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
}

// Os dois buffers são de PACOTE de propósito.
//
// O endereço deles entra na bpf_attr como INTEIRO, e um inteiro não é visto
// nem pelo coletor de lixo nem por quem move a pilha: um buffer local poderia
// mudar de lugar entre a montagem da struct e a syscall, e o kernel leria
// endereço velho. Alocação de pacote não se move.
var (
	licencaGPL     = []byte("GPL\x00")
	logVerificador = make([]byte, 4096)
	chaveDoMapa    = make([]byte, 4)
	valorDoMapa    = make([]byte, 4)
)

// carregaBPF devolve o descritor do programa carregado.
func carregaBPF(tipo uint32, nome string, retorno uint32) (int, error) {
	licenca, log := licencaGPL, logVerificador
	put32(programaMinimo[4:], retorno) // imm da primeira instrução

	var attr [72]byte
	put32(attr[0:], tipo)
	put32(attr[4:], uint32(len(programaMinimo)/8))
	put64(attr[8:], ponteiro(programaMinimo))
	put64(attr[16:], ponteiro(licenca))
	put32(attr[24:], 1) // log_level: sem ele, erro de verificador vem mudo
	put32(attr[28:], uint32(len(log)))
	put64(attr[32:], ponteiro(log))
	copy(attr[48:64], nome) // prog_name[16]

	fd, _, errno := syscall.Syscall(sysBPF, bpfProgLoad,
		uintptr(unsafe.Pointer(&attr[0])), uintptr(len(attr)))
	if errno != 0 {
		return -1, fmt.Errorf("BPF_PROG_LOAD: %w — verificador: %s",
			errno, strings.TrimRight(string(log), "\x00"))
	}
	return int(fd), nil
}

// pinaBPF prende o objeto no bpffs. É o que faz um programa sobreviver à saída
// de quem o carregou — e, para esta ferramenta, é um dono VISÍVEL.
func pinaBPF(fd int, caminho string) error {
	p, err := syscall.BytePtrFromString(caminho)
	if err != nil {
		return err
	}
	var attr [16]byte
	put64(attr[0:], uint64(uintptr(unsafe.Pointer(p))))
	put32(attr[8:], uint32(fd))

	_, _, errno := syscall.Syscall(sysBPF, bpfObjPin,
		uintptr(unsafe.Pointer(&attr[0])), uintptr(len(attr)))
	if errno != 0 {
		return fmt.Errorf("BPF_OBJ_PIN em %s: %w", caminho, errno)
	}
	return nil
}

// bpfNoSocket é a forma do implante que esta fase existe para reconhecer.
//
// Carrega, ANEXA a um socket e FECHA o descritor do programa. A partir daí não
// há descritor de programa em processo nenhum, não há pin e não há link: quem
// segura o programa é o SOCKET, e socket não diz o que carrega. O programa
// continua no kernel enquanto este processo viver.
//
// É a estrutura do BPFDoor, sem nenhum comportamento dele: o programa não lê
// pacote nem responde a gatilho — só existe.
func bpfNoSocket(nome string) error {
	progFD, err := carregaBPF(progTipoSocketFilter, nome, 0)
	if err != nil {
		return err
	}
	sock, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("socket: %w", err)
	}
	if err := syscall.SetsockoptInt(sock, syscall.SOL_SOCKET, soAttachBPF, progFD); err != nil {
		return fmt.Errorf("SO_ATTACH_BPF: %w", err)
	}
	// O descritor do PROGRAMA vai embora; o do socket fica. É esta linha que
	// separa "ferramenta de observação rodando" de "algo carregado e anônimo".
	if err := syscall.Close(progFD); err != nil {
		return err
	}
	guardaFD(sock)
	return nil
}

// bpfSegura carrega e MANTÉM o descritor aberto. É o caso legítimo: toda
// ferramenta baseada em libbpf faz isto, e a ferramenta precisa NÃO acusar.
func bpfSegura(nome string) error {
	fd, err := carregaBPF(progTipoSocketFilter, nome, 0)
	if err != nil {
		return err
	}
	guardaFD(fd)
	return nil
}

// bpfPina carrega e prende no bpffs, largando o descritor: o pin é o dono, e
// ele é visível.
func bpfPina(caminho, nome string) error {
	fd, err := carregaBPF(progTipoSocketFilter, nome, 0)
	if err != nil {
		return err
	}
	if err := pinaBPF(fd, caminho); err != nil {
		return err
	}
	return syscall.Close(fd)
}

// bpfNoTracepoint é o caminho LEGADO de anexação: perf_event_open no
// tracepoint, e o programa pendurado nele por ioctl. Não cria link nenhum, e o
// descritor que segura o programa é um perf_event — cujo fdinfo não cita o
// programa.
//
// É o falso positivo que existiria se a ferramenta não perguntasse ao kernel
// pelo BPF_TASK_FD_QUERY: bpftrace e agente com libbpf antiga produzem
// exatamente esta forma, e são legítimos.
func bpfNoTracepoint(evento, nome string) error {
	id, err := idDoTracepoint(evento)
	if err != nil {
		return err
	}
	progFD, err := carregaBPF(progTipoTracepoint, nome, 0)
	if err != nil {
		return err
	}

	// struct perf_event_attr: 128 bytes bastam para os campos que importam.
	//	@0  type          @4  size         @8  config (u64)
	//	@24 sample_type   @40 bits de flag
	var pa [128]byte
	put32(pa[0:], 2) // PERF_TYPE_TRACEPOINT
	put32(pa[4:], uint32(len(pa)))
	put64(pa[8:], uint64(id))
	put64(pa[16:], 1) // sample_period: um evento já basta
	put64(pa[24:], 1<<10 /* PERF_SAMPLE_RAW */)

	fd, _, errno := syscall.Syscall6(sysPerfEventOpen,
		uintptr(unsafe.Pointer(&pa[0])),
		uintptr(^uintptr(0)), // pid = -1: qualquer processo
		0,                    // cpu 0
		uintptr(^uintptr(0)), // group_fd = -1
		0, 0)
	if errno != 0 {
		return fmt.Errorf("perf_event_open(%s): %w", evento, errno)
	}
	perfFD := int(fd)

	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(perfFD),
		perfIocSetBPF, uintptr(progFD)); errno != 0 {
		return fmt.Errorf("PERF_EVENT_IOC_SET_BPF: %w", errno)
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(perfFD),
		perfIocEnable, 0); errno != 0 {
		return fmt.Errorf("PERF_EVENT_IOC_ENABLE: %w", errno)
	}
	// O descritor do programa é fechado de propósito: no caminho legado quem
	// segura é o perf_event, e é ISSO que a ferramenta precisa saber atribuir.
	if err := syscall.Close(progFD); err != nil {
		return err
	}
	guardaFD(perfFD)
	return nil
}

// bpfNoCgroup é a forma LEGÍTIMA mais comum em servidor moderno, e o falso
// positivo mais caro que este check poderia cometer.
//
// O anexo por cgroup sem link — `BPF_PROG_ATTACH` — não deixa descritor, não
// deixa pin e não deixa link: quem segura o programa é o CGROUP. É como o
// systemd aplica controle de dispositivo e de rede por unit, e num servidor
// são dezenas.
//
// A ferramenta não lê `BPF_PROG_QUERY` em cgroup, e é por isso que ela declara
// a lacuna em vez de acusar. Este cenário existe para provar a declaração.
func bpfNoCgroup(caminho, nome string) error {
	// Retorno 1: num programa de cgroup_skb, zero BLOQUEIA o tráfego do cgroup.
	progFD, err := carregaBPF(progTipoCgroupSkb, nome, 1)
	if err != nil {
		return err
	}
	dir, err := os.Open(caminho)
	if err != nil {
		return fmt.Errorf("abrir cgroup %s: %w", caminho, err)
	}

	var attr [16]byte
	put32(attr[0:], uint32(dir.Fd())) // target_fd: o cgroup
	put32(attr[4:], uint32(progFD))   // attach_bpf_fd
	put32(attr[8:], 0)                // BPF_CGROUP_INET_INGRESS

	if _, _, errno := syscall.Syscall(sysBPF, bpfProgAttach,
		uintptr(unsafe.Pointer(&attr[0])), uintptr(len(attr))); errno != 0 {
		return fmt.Errorf("BPF_PROG_ATTACH em %s: %w", caminho, errno)
	}
	// Os DOIS descritores vão embora: é o cgroup que segura daqui em diante.
	dir.Close()
	return syscall.Close(progFD)
}

// bpfNoTailCall deixa o programa vivo preso a um MAPA.
//
// É como cilium encadeia o datapath: um prog_array guarda os programas e a
// chamada salta de um para o outro. O programa fica sem descritor próprio, sem
// pin e sem link — quem o segura é a entrada do mapa, e o mapa é de alguém.
//
// Sem a leitura de prog_array, todo programa encadeado assim viraria achado.
func bpfNoTailCall(nome string) error {
	progFD, err := carregaBPF(progTipoSocketFilter, nome, 0)
	if err != nil {
		return err
	}
	mapFD, err := criaProgArray("tabela")
	if err != nil {
		return err
	}
	if err := atualizaMapa(mapFD, 0, uint32(progFD)); err != nil {
		return err
	}
	// O descritor do PROGRAMA some; o do mapa fica com este processo.
	if err := syscall.Close(progFD); err != nil {
		return err
	}
	guardaFD(mapFD)
	return nil
}

func criaProgArray(nome string) (int, error) {
	var attr [56]byte
	put32(attr[0:], mapTipoProgArray)
	put32(attr[4:], 4)  // key_size
	put32(attr[8:], 4)  // value_size: id de programa
	put32(attr[12:], 8) // max_entries
	copy(attr[28:44], nome)

	fd, _, errno := syscall.Syscall(sysBPF, bpfMapCreate,
		uintptr(unsafe.Pointer(&attr[0])), uintptr(len(attr)))
	if errno != 0 {
		return -1, fmt.Errorf("BPF_MAP_CREATE: %w", errno)
	}
	return int(fd), nil
}

// atualizaMapa escreve num prog_array. O VALOR que se escreve é o descritor do
// programa; o que se lê depois é o id dele — a assimetria é do kernel.
func atualizaMapa(mapFD int, chave, valor uint32) error {
	// De pacote pelo mesmo motivo da licença: o endereço vai para a bpf_attr
	// como inteiro, e inteiro não é visto por quem move a pilha.
	k, v := chaveDoMapa, valorDoMapa
	put32(k, chave)
	put32(v, valor)

	var attr [32]byte
	put32(attr[0:], uint32(mapFD))
	put64(attr[8:], ponteiro(k))
	put64(attr[16:], ponteiro(v))

	_, _, errno := syscall.Syscall(sysBPF, bpfMapUpdateElem,
		uintptr(unsafe.Pointer(&attr[0])), uintptr(len(attr)))
	if errno != 0 {
		return fmt.Errorf("BPF_MAP_UPDATE_ELEM: %w", errno)
	}
	return nil
}

func idDoTracepoint(evento string) (int, error) {
	for _, base := range []string{"/sys/kernel/tracing", "/sys/kernel/debug/tracing"} {
		b, err := os.ReadFile(base + "/events/" + evento + "/id")
		if err != nil {
			continue
		}
		return strconv.Atoi(strings.TrimSpace(string(b)))
	}
	return 0, fmt.Errorf("tracepoint %s: nenhum tracefs montado com o evento", evento)
}

// guardaFD impede que o descritor seja fechado: um socket recolhido leva o
// programa junto, e o cenário viraria falso negativo silencioso.
func guardaFD(fd int) { fdsVivos = append(fdsVivos, fd) }

var fdsVivos []int

func ponteiro(b []byte) uint64 {
	if len(b) == 0 {
		return 0
	}
	return uint64(uintptr(unsafe.Pointer(&b[0])))
}

func put64(b []byte, v uint64) {
	for i := 0; i < 8; i++ {
		b[i] = byte(v >> (8 * i))
	}
}
