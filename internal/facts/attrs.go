package facts

import (
	"os"
	"sort"
	"syscall"
	"unsafe"

	"github.com/lex0c/aletheia/internal/env"
)

// Atributos de inode (runbook §7.11, §19).
//
// O `chattr +i` marca um arquivo como IMUTÁVEL, e a partir daí nem root o
// altera ou remove sem tirar o atributo antes. Um invasor que faz isso compra
// duas coisas: o implante resiste à limpeza, e a limpeza FALHA EM SILÊNCIO para
// quem não sabe procurar o atributo.
//
// A segunda importa mais aqui do que a primeira, e o motivo é próprio desta
// ferramenta: o roteiro que ela imprime manda remover persistência e tirar o
// bit setuid. Contra um arquivo imutável esses comandos devolvem "operação não
// permitida" — como root — e quem não conhece o atributo conclui que o host
// está quebrado, não que está defendido.
//
// O `+a` (append-only) é o primo menos usado e serve para o mesmo fim em log:
// o arquivo só cresce, e apagar rastro deixa de funcionar. Num log isso é
// endurecimento legítimo; num binário não é.

// AtributoInode é o que os flags do filesystem dizem sobre um arquivo.
type AtributoInode struct {
	Path     string `json:"path"`
	Imutavel bool   `json:"immutable,omitempty"`
	SoAnexa  bool   `json:"append_only,omitempty"`
	SemDump  bool   `json:"no_dump,omitempty"`
	Flags    uint32 `json:"flags"`
}

const (
	flImutavel = 0x00000010 // FS_IMMUTABLE_FL
	flSoAnexa  = 0x00000020 // FS_APPEND_FL
	flSemDump  = 0x00000040 // FS_NODUMP_FL
)

// ioctlGetFlags é o número do FS_IOC_GETFLAGS, e ele DEPENDE DA ARQUITETURA.
//
// A macro do kernel é `_IOR('f', 1, long)`, e `long` tem 8 bytes em 64 bits e 4
// em 32. Fixar 0x80086601 faria a leitura falhar em todo host i686 — em
// silêncio, devolvendo "sem atributo" para arquivos imutáveis. É o mesmo eixo
// que já quebrou a compilação de 32 bits uma vez neste projeto.
var ioctlGetFlags = uintptr(0x80000000 |
	(unsafe.Sizeof(int(0)) << 16) | ('f' << 8) | 1)

// coletarAtributos lê os flags dos arquivos sobre os quais a ferramenta FALA.
//
// O escopo é o conjunto de candidatos — o que executa, o que está agendado, o
// que carrega privilégio. Varrer o filesystem inteiro custaria um open por
// arquivo do host para responder sobre arquivos que ninguém citou.
func coletarAtributos(f *Facts, e *env.Env) {
	alvos := map[string]bool{}
	for i := range f.Ownership {
		alvos[f.Ownership[i].Path] = true
	}
	for i := range f.Suid {
		alvos[f.Suid[i].Path] = true
	}
	if len(alvos) == 0 {
		return
	}

	caminhos := make([]string, 0, len(alvos))
	for p := range alvos {
		caminhos = append(caminhos, p)
	}
	sort.Strings(caminhos)

	for _, p := range caminhos {
		flags, ok := flagsDoArquivo(e, p)
		if !ok || flags == 0 {
			continue
		}
		a := AtributoInode{
			Path:     p,
			Flags:    flags,
			Imutavel: flags&flImutavel != 0,
			SoAnexa:  flags&flSoAnexa != 0,
			SemDump:  flags&flSemDump != 0,
		}
		if !a.Imutavel && !a.SoAnexa && !a.SemDump {
			continue
		}
		f.Atributos = append(f.Atributos, a)
	}
}

// flagsDoArquivo lê os flags do inode via ioctl.
//
// Só arquivo REGULAR: abrir FIFO ou device pode bloquear, e nem todo
// filesystem implementa a chamada — nesses o erro é esperado e vira silêncio,
// não lacuna, porque "este filesystem não tem o conceito" não é o mesmo que
// "não consegui perguntar".
func flagsDoArquivo(e *env.Env, p string) (uint32, bool) {
	fi, err := e.Lstat(p)
	if err != nil || !fi.Mode().IsRegular() {
		return 0, false
	}
	fh, err := os.OpenFile(e.Path(p), os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return 0, false
	}
	defer fh.Close()

	var flags uint32
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fh.Fd(),
		ioctlGetFlags, uintptr(unsafe.Pointer(&flags)))
	if errno != 0 {
		return 0, false
	}
	return flags, true
}
