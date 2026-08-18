package facts

import (
	"encoding/hex"
	"os"
	"syscall"
	"unsafe"
)

// Identidade de arquivo pelo FILE HANDLE, e por que o inode não serve.
//
// O fdinfo de um inotify diz o inode e o dispositivo do que é observado, e a
// tentação é casar por (dispositivo, inode). Não funciona:
//
//	só inode          colide entre filesystems. Medido neste host: o
//	                  `gvfsd-trash` saiu "vigiando /etc/ssh" porque um inode do
//	                  home dele bateu com o de /etc/ssh. Numa ferramenta de
//	                  incidente, atribuição falsa é pior que não resolver nada
//	inode + sdev      o `sdev` do fdinfo é o dispositivo do SUPERBLOCO, e o
//	                  `st_dev` do stat, no btrfs, é o anônimo do SUBVOLUME. Os
//	                  dois números não batem, e no btrfs — padrão de Fedora e
//	                  openSUSE — nada resolveria
//
// O `f_handle` resolve os dois: é a identidade que o PRÓPRIO filesystem usa,
// e `name_to_handle_at` devolve exatamente os bytes que o fdinfo imprime.
// Verificado: /home/lex/.config sai 0601…17000000 tipo 4d nos dois lados.

// tamMaxHandle é o teto do MAX_HANDLE_SZ do kernel.
const tamMaxHandle = 128

type handleDeArquivo struct {
	bytes uint32
	tipo  int32
	dados [tamMaxHandle]byte
}

// handleDe devolve o file handle de um caminho, na mesma grafia do fdinfo:
// "<tipo em hex>:<bytes em hex>".
//
// Falhar é normal e não é lacuna: filesystem sem suporte a handle devolve
// EOPNOTSUPP, e o caminho simplesmente não entra no índice. O efeito é um watch
// que fica sem nome — declarado como tal, nunca atribuído a um palpite.
func handleDe(caminho string) (string, bool) {
	p, err := syscall.BytePtrFromString(caminho)
	if err != nil {
		return "", false
	}
	var h handleDeArquivo
	h.bytes = tamMaxHandle
	var mntID int32
	// AT_FDCWD é -100; o caminho é absoluto, então o diretório de referência
	// não é usado.
	_, _, errno := syscall.Syscall6(sysNameToHandleAt,
		uintptr(atFDCWD), uintptr(unsafe.Pointer(p)),
		uintptr(unsafe.Pointer(&h)), uintptr(unsafe.Pointer(&mntID)), 0, 0)
	if errno != 0 {
		return "", false
	}
	if h.bytes == 0 || int(h.bytes) > tamMaxHandle {
		return "", false
	}
	return chaveDeHandle(uint32(h.tipo), hex.EncodeToString(h.dados[:h.bytes])), true
}

const atFDCWD = ^uintptr(99) // -100 sem depender de conversão com sinal

// chaveDeHandle junta tipo e bytes numa chave só. O TIPO faz parte da
// identidade: dois filesystems podem produzir os mesmos bytes com formatos
// diferentes.
func chaveDeHandle(tipo uint32, bytes string) string {
	return hexDeUint(tipo) + ":" + bytes
}

func hexDeUint(n uint32) string {
	const d = "0123456789abcdef"
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = d[n&0xf]
		n >>= 4
	}
	return string(b[i:])
}

// chaveDeDevIno é a chave alternativa, (dispositivo, inode), na mesma grafia
// que o fdinfo usa. Ela é SEGURA — o dispositivo faz parte da identidade —,
// mas não resolve no btrfs, onde o `sdev` do fdinfo e o `st_dev` do stat são
// números diferentes para o mesmo filesystem.
func chaveDeDevIno(fi os.FileInfo) (string, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return "", false
	}
	return chaveDeDevInoBruta(uint64(st.Dev), st.Ino), true
}

func chaveDeDevInoBruta(dev, ino uint64) string {
	return "devino:" + hexDeUint(uint32(dev)) + ":" + hexDeUint64(ino)
}

func hexDeUint64(n uint64) string {
	const d = "0123456789abcdef"
	if n == 0 {
		return "0"
	}
	var b [16]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = d[n&0xf]
		n >>= 4
	}
	return string(b[i:])
}
