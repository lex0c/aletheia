package kbpf

import (
	"runtime"
	"strconv"
	"syscall"
	"unsafe"
)

// BPF_PROG_QUERY: os programas ANEXADOS a um cgroup (runbook §35).
//
// É o quinto e último detentor que faltava. tc e XDP já saem pelo rtnetlink;
// cgroup exige perguntar ao próprio kernel, por um FD do diretório do cgroup.
//
// # attached, não effective — e a diferença decide a atribuição
//
// Sem BPF_F_QUERY_EFFECTIVE (flags=0) a consulta devolve os programas anexados
// NAQUELE cgroup. Com a flag, devolveria os EFETIVOS — os herdados dos pais
// somados —, e o mesmo programa apareceria em cada descendente, escondendo o
// ponto real de anexação dentro de uma nuvem de duplicatas. A pergunta que a
// atribuição faz é "ONDE ele foi preso?", e essa é a attached. A herança se
// reconstrói percorrendo a árvore inteira: o ponto original está em algum
// ancestral que também é visitado.
const cmdProgQuery = 20

// ENOTSUPP é errno interno do kernel (524), não exportado pelo pacote syscall.
// Alguns pontos de anexação o devolvem no lugar de EINVAL quando não existem.
const enotsupp = syscall.Errno(524)

// attrProgQuery é a bpf_attr do BPF_PROG_QUERY, no layout estável desde o 4.15.
// O padding final NÃO é decorativo: a bpf_attr é uma união, e passar um tamanho
// que corta um campo no meio faz o kernel ler outro. O tamanho é conferido por
// teste, como as demais uniões deste pacote.
type attrProgQuery struct {
	targetFD    uint32     // FD do diretório do cgroup v2
	attachType  uint32     // qual ponto de anexação
	queryFlags  uint32     // 0 = attached; BPF_F_QUERY_EFFECTIVE = efetivos
	attachFlags uint32     // saída
	progIDs     ponteiro64 // buffer de saída: os IDs dos programas
	progCnt     uint32     // entrada: capacidade; saída: quantos há
	_           uint32     // padding: alinha o fim ao que o kernel espera
}

// TiposDeCgroup são os attach types válidos com um FD de cgroup. Consultar só
// estes evita o EINVAL de perguntar por tc/XDP num cgroup, que não é erro de
// verdade — é pergunta que não faz sentido.
var TiposDeCgroup = []uint32{
	AtCgroupInetIngress, AtCgroupInetEgress, AtCgroupInetSockCreate,
	AtCgroupSockOps, AtCgroupDevice,
	AtCgroupInet4Bind, AtCgroupInet6Bind, AtCgroupInet4Connect, AtCgroupInet6Connect,
	AtCgroupInet4PostBind, AtCgroupInet6PostBind,
	AtCgroupUDP4Sendmsg, AtCgroupUDP6Sendmsg, AtCgroupUDP4Recvmsg, AtCgroupUDP6Recvmsg,
	AtCgroupSysctl, AtCgroupGetsockopt, AtCgroupSetsockopt,
	AtCgroupInet4GetPeername, AtCgroupInet6GetPeername,
	AtCgroupInet4GetSockname, AtCgroupInet6GetSockname,
	AtCgroupInetSockRelease,
}

// enum bpf_attach_type — DIFERENTE do tipo de programa. É o ponto onde o
// programa roda, e é o que se informa ao BPF_PROG_QUERY.
const (
	AtCgroupInetIngress      = 0
	AtCgroupInetEgress       = 1
	AtCgroupInetSockCreate   = 2
	AtCgroupSockOps          = 3
	AtCgroupDevice           = 6
	AtCgroupInet4Bind        = 8
	AtCgroupInet6Bind        = 9
	AtCgroupInet4Connect     = 10
	AtCgroupInet6Connect     = 11
	AtCgroupInet4PostBind    = 12
	AtCgroupInet6PostBind    = 13
	AtCgroupUDP4Sendmsg      = 14
	AtCgroupUDP6Sendmsg      = 15
	AtCgroupSysctl           = 18
	AtCgroupUDP4Recvmsg      = 19
	AtCgroupUDP6Recvmsg      = 20
	AtCgroupGetsockopt       = 21
	AtCgroupSetsockopt       = 22
	AtCgroupInet4GetPeername = 29
	AtCgroupInet6GetPeername = 30
	AtCgroupInet4GetSockname = 31
	AtCgroupInet6GetSockname = 32
	AtCgroupInetSockRelease  = 34
)

var nomesDeAnexo = map[uint32]string{
	AtCgroupInetIngress: "inet_ingress", AtCgroupInetEgress: "inet_egress",
	AtCgroupInetSockCreate: "inet_sock_create", AtCgroupSockOps: "sock_ops",
	AtCgroupDevice: "device", AtCgroupInet4Bind: "inet4_bind", AtCgroupInet6Bind: "inet6_bind",
	AtCgroupInet4Connect: "inet4_connect", AtCgroupInet6Connect: "inet6_connect",
	AtCgroupInet4PostBind: "inet4_post_bind", AtCgroupInet6PostBind: "inet6_post_bind",
	AtCgroupUDP4Sendmsg: "udp4_sendmsg", AtCgroupUDP6Sendmsg: "udp6_sendmsg",
	AtCgroupUDP4Recvmsg: "udp4_recvmsg", AtCgroupUDP6Recvmsg: "udp6_recvmsg",
	AtCgroupSysctl: "sysctl", AtCgroupGetsockopt: "getsockopt", AtCgroupSetsockopt: "setsockopt",
	AtCgroupInet4GetPeername: "inet4_getpeername", AtCgroupInet6GetPeername: "inet6_getpeername",
	AtCgroupInet4GetSockname: "inet4_getsockname", AtCgroupInet6GetSockname: "inet6_getsockname",
	AtCgroupInetSockRelease: "inet_sock_release",
}

// NomeDeAnexo nomeia o ponto de anexação. Desconhecido sai com o número — um
// kernel mais novo tem pontos que este binário não conhece.
func NomeDeAnexo(at uint32) string {
	if n, ok := nomesDeAnexo[at]; ok {
		return n
	}
	return "attach_type_" + strconv.Itoa(int(at))
}

// maxProgsPorTipo limita o que se lê de UM ponto de anexação. Anexo de cgroup
// costuma ter um programa por tipo; dezenas já é anormal, e o teto é a folga.
const maxProgsPorTipo = 64

// AnexosDeCgroup consulta os programas ANEXADOS a um cgroup, por tipo. Erro num
// tipo NÃO aborta os outros: um attach type que o kernel não conhece devolve
// EINVAL, e isso é capacidade ausente daquele tipo, não falha do cgroup.
func AnexosDeCgroup(cgroupFD int, tipos []uint32) (map[uint32][]uint32, map[uint32]error) {
	porTipo := map[uint32][]uint32{}
	erros := map[uint32]error{}
	for _, at := range tipos {
		ids, err := queryUmTipo(cgroupFD, at)
		if err != nil {
			if errno, ok := err.(syscall.Errno); ok && (errno == syscall.EINVAL || errno == enotsupp) {
				continue // este ponto não existe neste kernel: não é lacuna
			}
			erros[at] = err
			continue
		}
		if len(ids) > 0 {
			porTipo[at] = ids
		}
	}
	return porTipo, erros
}

func queryUmTipo(fd int, attachType uint32) ([]uint32, error) {
	buf := make([]byte, maxProgsPorTipo*4)
	attr := attrProgQuery{
		targetFD: uint32(fd), attachType: attachType, queryFlags: 0,
		progIDs: ptr(buf), progCnt: maxProgsPorTipo,
	}
	_, _, errno := syscall.Syscall(sysBPF, cmdProgQuery,
		uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	runtime.KeepAlive(buf)
	if errno != 0 {
		return nil, errno
	}
	n := attr.progCnt
	if n > maxProgsPorTipo {
		n = maxProgsPorTipo
	}
	out := make([]uint32, n)
	for i := range out {
		out[i] = le.Uint32(buf[i*4:])
	}
	return out, nil
}
