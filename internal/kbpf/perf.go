package kbpf

import (
	"runtime"
	"syscall"
	"unsafe"
)

// Descritor de perf_event com programa eBPF anexado (BPF_TASK_FD_QUERY).
//
// # O ponto cego que isto fecha
//
// A forma ANTIGA de anexar um programa a um kprobe é abrir um perf_event e
// pendurar o programa nele por ioctl. Nesse caminho não existe link, e o
// descritor que segura o programa é um `anon_inode:[perf_event]` — cujo
// fdinfo NÃO cita o programa. Do lado de fora, o programa parece órfão.
//
// Sem esta leitura, todo host rodando bpftrace ou um agente de segurança com
// libbpf antiga produziria achado de "programa sem dono", e o achado estaria
// errado. Com ela, o dono aparece com nome e função interceptada.
//
// Existe desde o 4.16. Em kernel mais antigo devolve erro, e a resposta é a
// mesma de sempre: não afirmar nada.
const cmdTaskFDQuery = 20

// attrTaskFDQuery é a união correspondente da bpf_attr. O kernel ESCREVE de
// volta em progID e fdTipo — por isso os campos são lidos depois da chamada.
type attrTaskFDQuery struct {
	pid      uint32
	fd       uint32
	flags    uint32
	bufLen   uint32
	buf      ponteiro64
	progID   uint32
	fdTipo   uint32
	offset   uint64
	endereco uint64
}

// Tipos devolvidos em fd_type (enum bpf_task_fd_type).
var nomesDeSonda = map[uint32]string{
	0: "raw_tracepoint", 1: "tracepoint", 2: "kprobe",
	3: "kretprobe", 4: "uprobe", 5: "uretprobe",
}

// SondaDoDescritor pergunta ao kernel qual programa está pendurado no
// descritor <fd> do processo <pid>. Devolve id 0 quando não há nenhum — que é
// o caso da maioria dos perf_events, que são de perfilamento comum.
func SondaDoDescritor(pid, fd int) (progID uint32, tipo string, nome string) {
	buf := make([]byte, 128)
	attr := attrTaskFDQuery{
		pid: uint32(pid), fd: uint32(fd),
		bufLen: uint32(len(buf)), buf: ptr(buf),
	}

	_, _, errno := syscall.Syscall(sysBPF, cmdTaskFDQuery,
		uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	runtime.KeepAlive(buf)
	// ENOSPC é sucesso com NOME truncado, não falha.
	//
	// bpf_task_fd_query_copy escreve prog_id, fd_type e os offsets de volta ANTES
	// de propagar o -ENOSPC de bpf_copy_to_user, que acontece sempre que o nome
	// passa de 127 bytes — um uprobe num caminho longo
	// (/opt/<app>/jre/lib/.../libjvm.so) chega lá sem esforço. Descartar tudo
	// nesse caso fazia o perf_event que SEGURA o programa deixar de ser
	// atribuído, e o programa voltava a aparecer órfão: exatamente o falso
	// positivo que este arquivo existe para eliminar.
	if errno != 0 && errno != syscall.ENOSPC {
		return 0, "", ""
	}
	t := nomesDeSonda[attr.fdTipo]
	if t == "" {
		t = "perf_event"
	}
	n := cstr(buf, uint32(len(buf)), 0, len(buf))
	if !imprimivel(n) {
		n = ""
	}
	if errno == syscall.ENOSPC && n != "" {
		n += "…" // o nome não coube inteiro; dizê-lo é melhor que fingir
	}
	return attr.progID, t, n
}
