// Package kbpf enumera o que está carregado no kernel pela própria syscall
// bpf(2) (runbook §35, SPEC fase 8).
//
// # Por que isto precisa existir
//
// Um programa eBPF é a forma FILELESS de morar dentro do kernel. Ele não tem
// arquivo em disco depois de carregado, não aparece em /proc/modules, não é um
// módulo, não deixa nome no filesystem — e intercepta syscall, lê pacote e
// altera retorno com a mesma força de um LKM. Todo o resto desta ferramenta
// pergunta "que arquivo é este?" e "que processo é este?"; nenhuma das duas
// perguntas alcança um programa que vive no kernel e cujo carregador já saiu.
//
// # Por que nativo, e não `bpftool`
//
// Pela mesma razão que a §24 é lida do disco e não do `dpkg -V`: o binário do
// host é justamente o que pode estar adulterado, e além disso `bpftool` não
// está instalado na maioria dos servidores — perguntar a ele transformaria
// "não verifiquei" em "não encontrei". A syscall é ABI estável desde 2015.
//
// # O que este pacote NÃO faz
//
// Não carrega programa, não anexa, não desanexa e não escreve em lugar nenhum:
// só as operações de LEITURA da bpf(2). A ferramenta é read-only (SPEC 10).
package kbpf

import (
	"encoding/binary"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

// Comandos da bpf(2). São ABI do kernel — o número nunca muda, e por isso
// podem ser literais aqui em vez de virem de header.
const (
	cmdMapLookupElem  = 1
	cmdObjGet         = 7
	cmdProgGetNextID  = 11
	cmdMapGetNextID   = 12
	cmdProgGetFDByID  = 13
	cmdMapGetFDByID   = 14
	cmdObjGetInfoByFD = 15
	cmdLinkGetFDByID  = 30
	cmdLinkGetNextID  = 31
)

// Tetos. Existem pelo mesmo motivo dos outros orçamentos desta base: um número
// alto é situação anormal, e a resposta certa é declarar o corte — nunca
// truncar em silêncio.
const (
	maxObjetos = 4096 // programas ou links enumerados por rodada
	maxTailKey = 1024 // entradas lidas de um prog_array
	maxLookups = 8192 // teto global de leituras de mapa
)

// ponteiro64 vive nos arquivos por arquitetura (sys_*.go), e não aqui, por um
// motivo que custou um defeito para aparecer.
//
// Um endereço na bpf_attr tem SEMPRE 64 bits, mesmo num host de 32 — o kernel
// declara os campos como __aligned_u64 justamente para a ABI não mudar com a
// arquitetura. A primeira versão tentou resolver isso com um preenchimento
// calculado em tempo de compilação, `[8 - unsafe.Sizeof(ponteiro)]byte`, que dá
// zero byte em 64 bits e quatro em 32. Parecia elegante e estava errado: em Go,
// campo de tamanho zero no FIM de uma struct ganha padding, e a struct saiu com
// dezesseis bytes em vez de oito. O deslocamento de todo campo seguinte mudou.
//
// Nada disso quebra a compilação. O que quebra é a leitura do mapa e a consulta
// de perf_event, em silêncio, devolvendo dados de outro campo — e foi o teste
// de LAYOUT que pegou, antes de qualquer execução.

func ptr(b []byte) ponteiro64 {
	if len(b) == 0 {
		return ponteiro64{}
	}
	return ponteiro64{p: unsafe.Pointer(&b[0])}
}

// As uniões da bpf_attr que esta ferramenta usa, com os campos na ordem exata
// do header do kernel. São tipos com nome — e não structs anônimas dentro das
// funções — para que o TAMANHO de cada uma seja verificável por teste em toda
// arquitetura: um campo fora de lugar em 32 bits não quebra a compilação, faz o
// kernel ler outro campo. É o mesmo eixo do FS_IOC_GETFLAGS, que já mordeu
// este projeto uma vez.
type (
	// BPF_*_GET_NEXT_ID
	attrProximoID struct {
		startID uint32
		nextID  uint32
		flags   uint32
	}
	// BPF_*_GET_FD_BY_ID
	attrFDPorID struct {
		id    uint32
		next  uint32
		flags uint32
	}
	// BPF_OBJ_GET_INFO_BY_FD
	attrInfo struct {
		fd      uint32
		tamanho uint32
		info    ponteiro64
	}
	// BPF_OBJ_GET
	attrObjGet struct {
		caminho ponteiro64
		fd      uint32
		flags   uint32
	}
	// BPF_MAP_LOOKUP_ELEM
	attrLookup struct {
		fd    uint32
		_     uint32
		chave ponteiro64
		valor ponteiro64
		flags uint64
	}
)

var le = binary.LittleEndian

// Programa é um programa eBPF carregado, como o kernel o descreve.
type Programa struct {
	ID       uint32
	TipoNum  uint32
	Tipo     string
	Nome     string // name[16] do bpf_prog_info: escolhido por quem carregou
	Tag      string // hash do bytecode, calculado pelo kernel
	UID      uint32 // created_by_uid
	CargaNS  uint64 // nanossegundos desde o boot
	NumMaps  uint32
	BTF      uint32
	Insns    uint32 // verified_insns; 0 em kernel antigo
	RunCnt   uint64 // só é contado com estatística ligada
	TamInfo  uint32 // quanto o kernel de fato preencheu
	SemDados bool   // info truncada: kernel antigo
}

// Link é um ANEXO: a ligação entre um programa e o ponto do kernel onde ele
// roda. Desde o 5.8 é o mecanismo padrão, e ele tem uma propriedade que decide
// vários checks — um link sem descritor aberto e sem pin se desfaz sozinho.
type Link struct {
	ID      uint32
	TipoNum uint32
	Tipo    string
	ProgID  uint32
	Alvo    string // o ponto de anexação, decodificado quando o kernel o expõe
}

// Objeto é o que um pin no bpffs aponta.
type Objeto struct {
	Classe string // prog | map | link
	ID     uint32
}

// Sonda responde se a enumeração é POSSÍVEL neste host, e quando não é diz por
// quê — é essa frase que vai para o rodapé de cobertura.
//
// Os três "não" são diferentes e a diferença importa:
//
//	ENOSYS         kernel sem bpf(2) — anterior ao 3.18
//	EINVAL         kernel sem BPF_PROG_GET_NEXT_ID — anterior ao 4.13
//	EPERM/EACCES   falta CAP_BPF/CAP_SYS_ADMIN: rode como root
//
// ENOENT é SUCESSO: significa que a iteração começou e não há programa nenhum
// carregado. Tratá-lo como falha faria todo host limpo reportar lacuna.
func Sonda() error {
	_, err := proximoID(cmdProgGetNextID, 0)
	if err == nil {
		return nil
	}
	errno, ok := err.(syscall.Errno)
	if !ok {
		return err
	}
	switch errno {
	case syscall.ENOENT:
		return nil
	case syscall.ENOSYS:
		// Kernel sem bpf(2) nenhum. Não há o que enumerar porque não há o que
		// carregar: um implante em eBPF é impossível aqui, e isto é ausência de
		// MECANISMO — não lacuna de leitura.
		//
		// E a frase NÃO afirma versão. A primeira dizia "anterior ao 3.18" e
		// saiu num guest de kernel 3.18 e noutro de 4.14 — os dois de uma
		// distribuição que compila sem CONFIG_BPF_SYSCALL. O que o errno prova é
		// que a syscall não existe AQUI; a versão é outra pergunta.
		return &ErroSonda{
			Motivo: "este kernel não tem a syscall bpf(2) — anterior ao 3.18, ou " +
				"compilado sem CONFIG_BPF_SYSCALL: não existe programa eBPF para enumerar",
			Errno:        errno,
			SemMecanismo: true,
		}
	case syscall.EINVAL:
		// 3.18 a 4.12: o kernel CARREGA programa e não oferece forma de listar
		// — o espaço de ids só apareceu no 4.13. É ponto cego do kernel, não
		// desta ferramenta, e por isso é lacuna declarada e permanente.
		return &ErroSonda{
			Motivo: "kernel sem BPF_PROG_GET_NEXT_ID (anterior ao 4.13): ele CARREGA " +
				"programa eBPF e não oferece forma de listar o que está carregado — " +
				"nem para esta ferramenta nem para nenhuma outra",
			Errno: errno,
		}
	case syscall.EPERM, syscall.EACCES:
		return &ErroSonda{
			Motivo: "sem CAP_BPF/CAP_SYS_ADMIN: os programas eBPF carregados não foram " +
				"enumerados — rode como root para respondê-lo",
			Errno: errno,
		}
	}
	return &ErroSonda{Motivo: "bpf(BPF_PROG_GET_NEXT_ID) falhou: " + errno.Error(), Errno: errno}
}

// ErroSonda carrega a frase pronta para o rodapé e a classificação que decide
// se aquilo conta como lacuna de cobertura.
type ErroSonda struct {
	Motivo string
	Errno  syscall.Errno
	// SemMecanismo diz que não há O QUE enumerar — diferente de "não me
	// deixaram olhar". A primeira não degrada cobertura; a segunda degrada.
	SemMecanismo bool
}

func (e *ErroSonda) Error() string { return e.Motivo }

// IDsDePrograma devolve só a lista de ids, sem ler a descrição de cada um. É a
// enumeração BARATA, usada para confirmar ocultação: quem foi citado por um
// descritor e não aparece aqui, duas vezes seguidas, não está sendo listado.
func IDsDePrograma() ([]uint32, bool, error) {
	return todosOsIDs(cmdProgGetNextID)
}

// Programas devolve todos os programas carregados. O bool diz se a enumeração
// foi CORTADA pelo teto — sem ele, "é isto que existe" seria mentira.
func Programas() ([]Programa, bool, error) {
	ids, cortou, err := IDsDePrograma()
	if err != nil {
		return nil, false, err
	}
	out := make([]Programa, 0, len(ids))
	for _, id := range ids {
		p, err := ProgramaPorID(id)
		if err != nil {
			// Sumiu entre a listagem e a leitura: é rotina, não lacuna. Um
			// programa carregado por ferramenta que terminou vive segundos.
			continue
		}
		out = append(out, p)
	}
	return out, cortou, nil
}

// ProgramaPorID lê a descrição de UM programa. Devolve erro quando ele não
// existe mais — e é essa distinção que separa corrida de ocultação.
func ProgramaPorID(id uint32) (Programa, error) {
	fd, err := fdPorID(cmdProgGetFDByID, id)
	if err != nil {
		return Programa{}, err
	}
	defer syscall.Close(fd)

	info, n, err := infoDoFD(fd, 256)
	if err != nil {
		return Programa{}, err
	}
	p := Programa{
		ID:      id,
		TipoNum: u32(info, n, 0),
		Tag:     hexOu(info, n, 8, 8),
		CargaNS: u64(info, n, 40),
		UID:     u32(info, n, 48),
		NumMaps: u32(info, n, 52),
		Nome:    cstr(info, n, 64, 16),
		BTF:     u32(info, n, 128),
		RunCnt:  u64(info, n, 200),
		Insns:   u32(info, n, 216),
		TamInfo: n,
	}
	// O id vem do kernel também; se ele discordar do que pedimos, o certo é
	// acreditar no kernel e registrar o que ele disse.
	if v := u32(info, n, 4); v != 0 {
		p.ID = v
	}
	p.Tipo = TipoPrograma(p.TipoNum)
	p.SemDados = n < 64
	return p, nil
}

// Existe responde se um id de programa ainda está carregado AGORA. É a
// confirmação sem corrida da visão cruzada: um id citado por descritor aberto
// que não apareceu na enumeração ou (a) morreu no intervalo, e então isto
// devolve false, ou (b) existe e não foi listado — que é ocultação.
func Existe(id uint32) bool {
	fd, err := fdPorID(cmdProgGetFDByID, id)
	if err != nil {
		return false
	}
	syscall.Close(fd)
	return true
}

// Links devolve os anexos vivos.
func Links() ([]Link, bool, error) {
	ids, cortou, err := todosOsIDs(cmdLinkGetNextID)
	if err != nil {
		// Kernel anterior ao 5.8 não tem link nenhum: não é lacuna de leitura,
		// é ausência do mecanismo. Quem chama distingue pelo errno.
		return nil, false, err
	}
	out := make([]Link, 0, len(ids))
	for _, id := range ids {
		l, err := linkPorID(id)
		if err != nil {
			continue
		}
		out = append(out, l)
	}
	return out, cortou, nil
}

func linkPorID(id uint32) (Link, error) {
	fd, err := fdPorID(cmdLinkGetFDByID, id)
	if err != nil {
		return Link{}, err
	}
	defer syscall.Close(fd)

	info, n, err := infoDoFD(fd, 256)
	if err != nil {
		return Link{}, err
	}
	l := Link{
		ID:      id,
		TipoNum: u32(info, n, 0),
		ProgID:  u32(info, n, 8),
	}
	if v := u32(info, n, 4); v != 0 {
		l.ID = v
	}
	l.Tipo = TipoLink(l.TipoNum)
	l.Alvo = alvoDoLink(fd, l.TipoNum, info, n)
	return l, nil
}

// alvoDoLink decodifica o PONTO de anexação. É a evidência que transforma
// "existe um programa de rastreamento" em "existe um programa em getdents64".
//
// Cada tipo guarda o alvo num membro diferente da união, e alguns o entregam
// por ponteiro: o kernel escreve o nome num buffer NOSSO, e isso exige uma
// segunda chamada com o ponteiro preenchido. Kernel que não conhece o campo
// simplesmente ignora o ponteiro, e o buffer volta vazio — por isso a decisão
// é sempre "veio nome? use; não veio? não invente".
func alvoDoLink(fd int, tipo uint32, info []byte, n uint32) string {
	switch tipo {
	case LinkRawTracepoint:
		if s := nomePorPonteiro(fd, 16, 24, 128); s != "" {
			return "tracepoint " + s
		}
	case LinkTracing:
		at := u32(info, n, 16)
		alvo := u32(info, n, 20)
		s := "attach_type=" + strconv.Itoa(int(at))
		if alvo != 0 {
			s += " alvo_btf_obj=" + strconv.Itoa(int(alvo))
		}
		return s
	case LinkCgroup:
		return "cgroup id=" + strconv.FormatUint(u64(info, n, 16), 10) +
			" attach_type=" + strconv.Itoa(int(u32(info, n, 24)))
	case LinkNetns:
		return "netns ino=" + strconv.Itoa(int(u32(info, n, 16)))
	case LinkXDP:
		return "xdp ifindex=" + strconv.Itoa(int(u32(info, n, 16)))
	case LinkPerfEvent:
		return alvoPerfEvent(fd, info, n)
	case LinkKprobeMulti:
		return "kprobe_multi em " + strconv.Itoa(int(u32(info, n, 24))) + " função(ões)"
	case LinkNetfilter:
		return "netfilter hook"
	case LinkTCX, LinkNetkit:
		return "tc ifindex=" + strconv.Itoa(int(u32(info, n, 16)))
	}
	return ""
}

// alvoPerfEvent cobre a família kprobe/uprobe/tracepoint, que é a de maior
// valor forense: é ela que nomeia a função do kernel interceptada.
//
// O layout é `{ __u32 type; __u32 pad; união }` a partir do 16, então a união
// começa no 24. O nome só existe em kernel 6.x — antes disso o campo não é
// preenchido e a resposta honesta é o tipo sem o nome.
func alvoPerfEvent(fd int, info []byte, n uint32) string {
	const (
		peUprobe     = 1
		peURetprobe  = 2
		peKprobe     = 3
		peKRetprobe  = 4
		peTracepoint = 5
		peEventoPuro = 6
		offUniao     = 24
		offNomeLen   = 32
	)
	tipo := u32(info, n, 16)
	rotulo := map[uint32]string{
		peUprobe: "uprobe", peURetprobe: "uretprobe",
		peKprobe: "kprobe", peKRetprobe: "kretprobe",
		peTracepoint: "tracepoint", peEventoPuro: "perf_event",
	}[tipo]
	if rotulo == "" {
		rotulo = "perf_event"
	}
	if nome := nomePorPonteiro(fd, offUniao, offNomeLen, 128); nome != "" {
		return rotulo + " " + nome
	}
	return rotulo
}

// nomePorPonteiro faz a segunda chamada do protocolo de duas etapas: aponta um
// buffer nosso no campo indicado e relê a info.
func nomePorPonteiro(fd int, offPtr, offLen, tam int) string {
	info := make([]byte, 256)
	buf := make([]byte, tam)
	if offPtr+8 > len(info) || offLen+4 > len(info) {
		return ""
	}
	// O endereço vai para dentro do buffer de INFO, que é o que o kernel lê
	// antes de escrever. Aqui o ponteiro é convertido para inteiro de propósito
	// — e o KeepAlive abaixo é o que garante que o buffer sobrevive à chamada.
	le.PutUint64(info[offPtr:], uint64(uintptr(unsafe.Pointer(&buf[0]))))
	le.PutUint32(info[offLen:], uint32(tam))

	attr := attrInfo{fd: uint32(fd), tamanho: uint32(len(info)), info: ptr(info)}

	_, _, errno := syscall.Syscall(sysBPF, cmdObjGetInfoByFD,
		uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	runtime.KeepAlive(buf)
	runtime.KeepAlive(info)
	if errno != 0 {
		return ""
	}
	s := cstr(buf, uint32(len(buf)), 0, tam)
	if !imprimivel(s) {
		return ""
	}
	return s
}

// ProgsPorTailCall devolve os programas alcançáveis por TAIL CALL.
//
// Existe por um falso positivo previsível: um programa referenciado por um mapa
// do tipo prog_array continua carregado sem descritor, sem pin e sem link — é o
// MAPA que o segura. É assim que cilium e afins encadeiam dezenas de programas,
// e sem esta leitura todos eles seriam acusados de órfãos.
//
// O bool diz se alguma leitura foi cortada pelo orçamento.
func ProgsPorTailCall() (map[uint32]bool, bool, error) {
	ids, cortou, err := todosOsIDs(cmdMapGetNextID)
	if err != nil {
		return nil, cortou, err
	}
	out := map[uint32]bool{}
	lookups := 0
	for _, id := range ids {
		fd, err := fdPorID(cmdMapGetFDByID, id)
		if err != nil {
			continue
		}
		info, n, err := infoDoFD(fd, 128)
		if err != nil {
			syscall.Close(fd)
			continue
		}
		tipo := u32(info, n, 0)
		valor := u32(info, n, 12)
		entradas := u32(info, n, 16)
		// prog_array (3) e prog-de-mapa dos tipos de dispatch guardam ID de
		// programa como VALOR. Os demais não interessam aqui.
		if tipo != MapProgArray || valor != 4 {
			syscall.Close(fd)
			continue
		}
		if entradas > maxTailKey {
			entradas = maxTailKey
			cortou = true
		}
		for k := uint32(0); k < entradas; k++ {
			if lookups >= maxLookups {
				cortou = true
				break
			}
			lookups++
			if v, ok := lookupU32(fd, k); ok && v != 0 {
				out[v] = true
			}
		}
		syscall.Close(fd)
	}
	return out, cortou, nil
}

// lookupU32 lê uma entrada de mapa cuja chave e cujo valor têm quatro bytes.
// Para um prog_array o valor devolvido é o ID do programa naquele índice.
func lookupU32(fd int, chave uint32) (uint32, bool) {
	k := make([]byte, 4)
	v := make([]byte, 8) // folga: o kernel exige value_size, e ele é 4 aqui
	le.PutUint32(k, chave)

	attr := attrLookup{fd: uint32(fd), chave: ptr(k), valor: ptr(v)}

	_, _, errno := syscall.Syscall(sysBPF, cmdMapLookupElem,
		uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	runtime.KeepAlive(k)
	runtime.KeepAlive(v)
	if errno != 0 {
		return 0, false
	}
	return le.Uint32(v), true
}

// ObjetoDoPin resolve o que está preso naquele caminho do bpffs.
//
// A classe não vem da bpf(2): ela vem do link do descritor em /proc/self/fd,
// que é "anon_inode:bpf-prog", "bpf-map" ou "bpf-link". É a mesma leitura que
// identifica um descritor de processo alheio, e por isso é a mesma resposta.
func ObjetoDoPin(caminho string) (Objeto, error) {
	p, err := syscall.BytePtrFromString(caminho)
	if err != nil {
		return Objeto{}, err
	}
	attr := attrObjGet{caminho: ponteiro64{p: unsafe.Pointer(p)}}

	r, _, errno := syscall.Syscall(sysBPF, cmdObjGet,
		uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	runtime.KeepAlive(p)
	if errno != 0 {
		return Objeto{}, errno
	}
	fd := int(r)
	defer syscall.Close(fd)

	classe := "?"
	if alvo, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd)); err == nil {
		classe = ClasseDeAnonInode(alvo)
	}
	info, n, err := infoDoFD(fd, 128)
	if err != nil {
		return Objeto{Classe: classe}, err
	}
	// Todos os três info começam com {type, id}: o id está no mesmo lugar.
	return Objeto{Classe: classe, ID: u32(info, n, 4)}, nil
}

// ClasseDeAnonInode traduz o alvo de um descritor para a classe do objeto bpf.
// Devolve "" quando o descritor não é bpf — que é o caso da esmagadora maioria.
func ClasseDeAnonInode(alvo string) string {
	s, ok := strings.CutPrefix(alvo, "anon_inode:bpf-")
	if !ok {
		return ""
	}
	switch s {
	case "prog", "map", "link":
		return s
	}
	return ""
}

// todosOsIDs itera a lista encadeada de ids do kernel.
func todosOsIDs(cmd uintptr) ([]uint32, bool, error) {
	var out []uint32
	var atual uint32
	for len(out) < maxObjetos {
		prox, err := proximoID(cmd, atual)
		if err != nil {
			if errno, ok := err.(syscall.Errno); ok && errno == syscall.ENOENT {
				return out, false, nil // fim da lista
			}
			if len(out) > 0 {
				// Falhar no meio é diferente de falhar no começo: o que já foi
				// lido continua valendo, e quem chama recebe o corte.
				return out, true, nil
			}
			return nil, false, err
		}
		out = append(out, prox)
		atual = prox
	}
	return out, true, nil
}

func proximoID(cmd uintptr, start uint32) (uint32, error) {
	attr := attrProximoID{startID: start}
	_, _, errno := syscall.Syscall(sysBPF, cmd,
		uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	if errno != 0 {
		return 0, errno
	}
	return attr.nextID, nil
}

func fdPorID(cmd uintptr, id uint32) (int, error) {
	attr := attrFDPorID{id: id}
	r, _, errno := syscall.Syscall(sysBPF, cmd,
		uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	if errno != 0 {
		return -1, errno
	}
	return int(r), nil
}

// infoDoFD devolve o buffer preenchido e QUANTO dele o kernel escreveu.
//
// O segundo valor é o que torna a leitura à prova de kernel antigo: o kernel
// devolve o tamanho da SUA struct, e ler além disso seria inventar campo. É a
// mesma regra do resto da base — campo ausente vira desconhecido, nunca zero.
func infoDoFD(fd int, tam int) ([]byte, uint32, error) {
	info := make([]byte, tam)
	attr := attrInfo{fd: uint32(fd), tamanho: uint32(tam), info: ptr(info)}

	_, _, errno := syscall.Syscall(sysBPF, cmdObjGetInfoByFD,
		uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	runtime.KeepAlive(info)
	if errno != 0 {
		return nil, 0, errno
	}
	n := attr.tamanho
	if n > uint32(tam) {
		n = uint32(tam)
	}
	return info, n, nil
}

// Leitores defensivos: fora do que o kernel preencheu, a resposta é zero e não
// lixo do buffer.
func u32(b []byte, n uint32, off int) uint32 {
	if off < 0 || uint32(off+4) > n || off+4 > len(b) {
		return 0
	}
	return le.Uint32(b[off:])
}

func u64(b []byte, n uint32, off int) uint64 {
	if off < 0 || uint32(off+8) > n || off+8 > len(b) {
		return 0
	}
	return le.Uint64(b[off:])
}

func cstr(b []byte, n uint32, off, tam int) string {
	if off < 0 || uint32(off+tam) > n || off+tam > len(b) {
		return ""
	}
	s := b[off : off+tam]
	if i := indexByte(s, 0); i >= 0 {
		s = s[:i]
	}
	return string(s)
}

func hexOu(b []byte, n uint32, off, tam int) string {
	if off < 0 || uint32(off+tam) > n || off+tam > len(b) {
		return ""
	}
	const hexa = "0123456789abcdef"
	out := make([]byte, 0, tam*2)
	for _, c := range b[off : off+tam] {
		out = append(out, hexa[c>>4], hexa[c&0xf])
	}
	return string(out)
}

func indexByte(b []byte, c byte) int {
	for i := range b {
		if b[i] == c {
			return i
		}
	}
	return -1
}

func imprimivel(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// BytecodeDePrograma devolve as instruções VERIFICADAS do programa — o que o
// kernel de fato vai executar, depois de o verificador reescrever o que
// precisou.
//
// # Por que isto existe
//
// É a única cópia. Um programa eBPF não tem arquivo em disco, não tem inode,
// não aparece em /proc/modules e some no próximo boot: se ninguém guardar o
// bytecode agora, não há amostra para analisar depois. Todo o resto do que esta
// ferramenta manda preservar é `cp`; isto não é.
//
// O protocolo é o de duas etapas do bpf_prog_info: a primeira chamada diz o
// TAMANHO, a segunda entrega os bytes num buffer nosso. Kernel que restringe a
// leitura do bytecode — `kptr_restrict`, ou sem CAP_SYS_ADMIN — devolve zero
// instruções, e a resposta honesta é dizer que não veio, nunca inventar um
// arquivo vazio.
func BytecodeDePrograma(id uint32) ([]byte, error) {
	fd, err := fdPorID(cmdProgGetFDByID, id)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(fd)

	info, n, err := infoDoFD(fd, 256)
	if err != nil {
		return nil, err
	}
	// xlated_prog_len fica no deslocamento 20 do bpf_prog_info, e o ponteiro
	// para onde escrever, no 32.
	tam := u32(info, n, 20)
	if tam == 0 {
		return nil, errSemBytecode
	}

	buf := make([]byte, tam)
	le.PutUint32(info[20:], tam)
	le.PutUint64(info[32:], uint64(uintptr(unsafe.Pointer(&buf[0]))))

	attr := attrInfo{fd: uint32(fd), tamanho: uint32(len(info)), info: ptr(info)}
	_, _, errno := syscall.Syscall(sysBPF, cmdObjGetInfoByFD,
		uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	runtime.KeepAlive(buf)
	runtime.KeepAlive(info)
	if errno != 0 {
		return nil, errno
	}
	// Kernel que recusa entregar o bytecode devolve o buffer intocado. Zerado
	// inteiro é "não veio", e não "programa vazio" — programa vazio não passa
	// no verificador.
	if todoZero(buf) {
		return nil, errSemBytecode
	}
	return buf, nil
}

const errSemBytecode = erroSimples("o kernel não entregou o bytecode: sem " +
	"CAP_SYS_ADMIN, ou leitura restrita por kptr_restrict")

type erroSimples string

func (e erroSimples) Error() string { return string(e) }

func todoZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}
