//go:build linux && !386

package main

import (
	"syscall"
	"unsafe"
)

// anexarBPFNoSocket faz o SO_ATTACH_BPF com o fd do programa já carregado.
func anexarBPFNoSocket(sk, prog int) error {
	const soAttachBPF = 50
	_, _, errno := syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(sk),
		syscall.SOL_SOCKET, soAttachBPF, uintptr(unsafe.Pointer(&prog)), 4, 0)
	if errno != 0 {
		return errno
	}
	return nil
}
