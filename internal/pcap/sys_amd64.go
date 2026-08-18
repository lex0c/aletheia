//go:build linux && amd64

package pcap

import (
	"syscall"
	"unsafe"
)

// getsockoptBytes lê uma opção de socket que é ESTRUTURA, e não int — a stdlib
// só expõe as de tamanho conhecido, e PACKET_STATISTICS tem oito bytes.
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
