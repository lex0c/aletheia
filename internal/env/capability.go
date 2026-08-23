package env

import (
	"os"
	"sort"
	"strconv"
	"syscall"
	"unsafe"
)

// As capabilities do Linux, por número.
//
// Os bits são ABI e não mudam. A tabela existe porque a máscara sozinha é
// ilegível: `cap_permitted=0x0000000000200000` não diz a ninguém que aquele
// binário pode montar filesystem. É a mesma regra do resto desta ferramenta —
// o número vem com o que ele significa.
//
// A lista para em CAP_CHECKPOINT_RESTORE (40), que é o último definido até o
// 6.x. Um bit acima disso vira "CAP_<n>", e dizer o número é melhor que sumir
// com ele: um kernel mais novo que este binário existe.
var nomesDeCapability = [...]string{
	"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_FOWNER",
	"CAP_FSETID", "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_SETPCAP",
	"CAP_LINUX_IMMUTABLE", "CAP_NET_BIND_SERVICE", "CAP_NET_BROADCAST",
	"CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_IPC_LOCK", "CAP_IPC_OWNER",
	"CAP_SYS_MODULE", "CAP_SYS_RAWIO", "CAP_SYS_CHROOT", "CAP_SYS_PTRACE",
	"CAP_SYS_PACCT", "CAP_SYS_ADMIN", "CAP_SYS_BOOT", "CAP_SYS_NICE",
	"CAP_SYS_RESOURCE", "CAP_SYS_TIME", "CAP_SYS_TTY_CONFIG", "CAP_MKNOD",
	"CAP_LEASE", "CAP_AUDIT_WRITE", "CAP_AUDIT_CONTROL", "CAP_SETFCAP",
	"CAP_MAC_OVERRIDE", "CAP_MAC_ADMIN", "CAP_SYSLOG", "CAP_WAKE_ALARM",
	"CAP_BLOCK_SUSPEND", "CAP_AUDIT_READ", "CAP_PERFMON", "CAP_BPF",
	"CAP_CHECKPOINT_RESTORE",
}

// NomeDeCapability traduz um bit. Um bit que este binário não conhece vira
// "CAP_<n>" — some-lo faria uma capability nova de um kernel novo desaparecer
// da evidência.
func NomeDeCapability(bit int) string {
	if bit >= 0 && bit < len(nomesDeCapability) {
		return nomesDeCapability[bit]
	}
	return "CAP_" + strconv.Itoa(bit)
}

// NomesDeCapability traduz uma máscara inteira, em ordem de bit.
func NomesDeCapability(mask uint64) []string {
	var out []string
	for b := 0; b < 64; b++ {
		if mask&(1<<uint(b)) != 0 {
			out = append(out, NomeDeCapability(b))
		}
	}
	return out
}

// CapabilidadeDeArquivo é o `security.capability` decodificado.
type CapabilidadeDeArquivo struct {
	// Permitidas é a máscara que o binário GANHA ao executar.
	Permitidas []string `json:"permitted,omitempty"`
	// Herdaveis só vale junto com o conjunto do processo que executa.
	Herdaveis []string `json:"inheritable,omitempty"`
	// Efetivo é o bit que separa `cap_setuid+p` de `cap_setuid+ep`: com ele a
	// capability já sobe ATIVA na execução, e o binário não precisa nem pedir.
	// É a diferença entre um programa que PODE elevar e um que JÁ elevou.
	Efetivo bool `json:"effective"`
	// RootID é o uid dono no namespace, presente só na versão 3 do formato.
	RootID uint32 `json:"root_id,omitempty"`
	Versao int    `json:"version"`
}

// O layout do xattr `security.capability`, little-endian:
//
//	0..3    magic_etc: versão nos bits altos, flags nos baixos
//	4..7    permitted, 32 bits baixos
//	8..11   inheritable, 32 bits baixos
//	12..15  permitted, 32 bits altos   (a partir da versão 2)
//	16..19  inheritable, 32 bits altos
//	20..23  rootid                     (versão 3, namespace de usuário)
const (
	capFlagEfetivo = 0x000001
	capMaskVersao  = 0xFF000000
)

// DecodificarCapability lê o buffer do xattr `security.capability`.
//
// Um decodificador só, para os dois caminhos de aquisição: o coletor de SUID
// pergunta por CAMINHO durante a varredura, e a inspeção direcionada pergunta
// por DESCRITOR. Duas cópias do mesmo desdobramento de bits divergiriam — e a
// que divergisse seria a que ninguém está olhando.
func DecodificarCapability(buf []byte) (CapabilidadeDeArquivo, bool) {
	if len(buf) < 12 {
		return CapabilidadeDeArquivo{}, false
	}
	magic := le32(buf[0:])
	perm := uint64(le32(buf[4:]))
	herd := uint64(le32(buf[8:]))
	if len(buf) >= 20 {
		perm |= uint64(le32(buf[12:])) << 32
		herd |= uint64(le32(buf[16:])) << 32
	}
	c := CapabilidadeDeArquivo{
		Permitidas: NomesDeCapability(perm),
		Herdaveis:  NomesDeCapability(herd),
		Efetivo:    magic&capFlagEfetivo != 0,
		Versao:     int((magic & capMaskVersao) >> 24),
	}
	if len(buf) >= 24 {
		c.RootID = le32(buf[20:])
	}
	return c, true
}

// MascaraDeCapability devolve a máscara crua de permitidas e o bit efetivo. É a
// forma que o coletor de SUID usa, e ela sai do MESMO decodificador.
func MascaraDeCapability(buf []byte) (uint64, bool, bool) {
	c, ok := DecodificarCapability(buf)
	if !ok {
		return 0, false, false
	}
	var m uint64
	for _, n := range c.Permitidas {
		m |= bitDeNome(n)
	}
	return m, c.Efetivo, true
}

func bitDeNome(n string) uint64 {
	for i, x := range nomesDeCapability {
		if x == n {
			return 1 << uint(i)
		}
	}
	if len(n) > 4 {
		if b, err := strconv.Atoi(n[4:]); err == nil && b >= 0 && b < 64 {
			return 1 << uint(b)
		}
	}
	return 0
}

func le32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

// CapabilityDoFD lê o `security.capability` de um descritor já aberto e
// identificado.
func CapabilityDoFD(fh *os.File) (CapabilidadeDeArquivo, bool) {
	buf := make([]byte, 32)
	nb, err := syscall.BytePtrFromString("security.capability")
	if err != nil {
		return CapabilidadeDeArquivo{}, false
	}
	n, _, errno := syscall.Syscall6(syscall.SYS_FGETXATTR, fh.Fd(),
		uintptr(unsafe.Pointer(nb)), uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)), 0, 0)
	if errno != 0 {
		return CapabilidadeDeArquivo{}, false
	}
	return DecodificarCapability(buf[:n])
}

// TodasAsCapabilities é a tabela inteira, para quem precisa validar entrada.
func TodasAsCapabilities() []string {
	out := append([]string(nil), nomesDeCapability[:]...)
	sort.Strings(out)
	return out
}
