package kbpf

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// As constantes de attach type são o CONTRATO com o kernel: um valor errado faz
// o BPF_PROG_QUERY perguntar por outro ponto, e a resposta — vazia — é
// indistinguível de "não há programa anexado aqui". Um teste que montasse o
// esperado a partir da mesma constante seria tautológico; este parseia o texto
// do UAPI guardado em testdata e compara com a tabela.
func TestAttachTypesBatemComOUAPI(t *testing.T) {
	b, err := os.ReadFile("testdata/bpf_attach_type.h")
	if err != nil {
		t.Fatal(err)
	}
	doUAPI := map[string]uint32{}
	val := 0
	re := regexp.MustCompile(`^\s*(BPF_[A-Z0-9_]+)\s*(?:=\s*([0-9]+))?\s*,?\s*$`)
	for _, ln := range strings.Split(string(b), "\n") {
		if i := strings.Index(ln, "/*"); i >= 0 {
			ln = ln[:i]
		}
		m := re.FindStringSubmatch(ln)
		if m == nil {
			continue
		}
		if m[2] != "" {
			n, _ := strconv.Atoi(m[2])
			val = n
		}
		doUAPI[m[1]] = uint32(val)
		val++
	}
	if len(doUAPI) < 40 {
		t.Fatalf("fixture do UAPI parece truncada: %d entradas", len(doUAPI))
	}

	nosso := map[string]uint32{
		"BPF_CGROUP_INET_INGRESS": AtCgroupInetIngress, "BPF_CGROUP_INET_EGRESS": AtCgroupInetEgress,
		"BPF_CGROUP_INET_SOCK_CREATE": AtCgroupInetSockCreate, "BPF_CGROUP_SOCK_OPS": AtCgroupSockOps,
		"BPF_CGROUP_DEVICE":     AtCgroupDevice,
		"BPF_CGROUP_INET4_BIND": AtCgroupInet4Bind, "BPF_CGROUP_INET6_BIND": AtCgroupInet6Bind,
		"BPF_CGROUP_INET4_CONNECT": AtCgroupInet4Connect, "BPF_CGROUP_INET6_CONNECT": AtCgroupInet6Connect,
		"BPF_CGROUP_INET4_POST_BIND": AtCgroupInet4PostBind, "BPF_CGROUP_INET6_POST_BIND": AtCgroupInet6PostBind,
		"BPF_CGROUP_UDP4_SENDMSG": AtCgroupUDP4Sendmsg, "BPF_CGROUP_UDP6_SENDMSG": AtCgroupUDP6Sendmsg,
		"BPF_CGROUP_UDP4_RECVMSG": AtCgroupUDP4Recvmsg, "BPF_CGROUP_UDP6_RECVMSG": AtCgroupUDP6Recvmsg,
		"BPF_CGROUP_SYSCTL":     AtCgroupSysctl,
		"BPF_CGROUP_GETSOCKOPT": AtCgroupGetsockopt, "BPF_CGROUP_SETSOCKOPT": AtCgroupSetsockopt,
		"BPF_CGROUP_INET4_GETPEERNAME": AtCgroupInet4GetPeername, "BPF_CGROUP_INET6_GETPEERNAME": AtCgroupInet6GetPeername,
		"BPF_CGROUP_INET4_GETSOCKNAME": AtCgroupInet4GetSockname, "BPF_CGROUP_INET6_GETSOCKNAME": AtCgroupInet6GetSockname,
		"BPF_CGROUP_INET_SOCK_RELEASE": AtCgroupInetSockRelease,
		"BPF_CGROUP_UNIX_CONNECT":      AtCgroupUnixConnect, "BPF_CGROUP_UNIX_SENDMSG": AtCgroupUnixSendmsg,
		"BPF_CGROUP_UNIX_RECVMSG":     AtCgroupUnixRecvmsg,
		"BPF_CGROUP_UNIX_GETPEERNAME": AtCgroupUnixGetPeername,
		"BPF_CGROUP_UNIX_GETSOCKNAME": AtCgroupUnixGetSockname,
	}
	for nome, meu := range nosso {
		uapi, ok := doUAPI[nome]
		if !ok {
			t.Errorf("%s não existe no UAPI guardado", nome)
			continue
		}
		if meu != uapi {
			t.Errorf("%s = %d, o UAPI diz %d", nome, meu, uapi)
		}
	}

	// E o inverso: todo BPF_CGROUP_* do UAPI tem de estar em TiposDeCgroup,
	// senão existe ponto de anexação que a ferramenta nunca pergunta — e o
	// programa aparece sem lugar, que é meia resposta.
	naTabela := map[uint32]bool{}
	for _, at := range TiposDeCgroup {
		naTabela[at] = true
	}
	for nome, v := range doUAPI {
		if !strings.HasPrefix(nome, "BPF_CGROUP_") || strings.Contains(nome, "_ITER_") {
			continue
		}
		if !naTabela[v] {
			t.Errorf("%s (=%d) existe no UAPI e NÃO é consultado por TiposDeCgroup", nome, v)
		}
	}
}
