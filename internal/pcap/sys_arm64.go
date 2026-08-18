//go:build linux && arm64

package pcap

import (
	"syscall"
	"unsafe"
)

// getsockoptBytes lê uma opção de socket que é ESTRUTURA, e não int. O número da
// syscall aqui é o da tabela genérica (209), contra 55 no x86_64.
func getsockoptBytes(fd, nivel, opt int, b []byte) error {
	tam := uint32(len(b))
	_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT,
		uintptr(fd), uintptr(nivel), uintptr(opt),
		uintptr(unsafe.Pointer(&b[0])), uintptr(unsafe.Pointer(&tam)), 0)
	if errno != 0 {
		return errno
	}
	return nil
}
