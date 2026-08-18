//go:build linux && 386

package pcap

import (
	"syscall"
	"unsafe"
)

// Em i386 NÃO EXISTE syscall.SYS_GETSOCKOPT: até o kernel 4.3 o i386 não tinha
// syscall própria para operação de socket — tudo passava pelo multiplexador
// `socketcall`, e é por isso que a stdlib do Go não define a constante nesta
// arquitetura.
//
// Usar o socketcall aqui não é retrocompatibilidade decorativa: os kernels
// legados da suíte (3.18 e 4.14 em i686) são exatamente o caso, e um número
// direto falharia com ENOSYS num guest e funcionaria no outro.
const (
	sysSocketcall = 102
	chamadaGet    = 15 // SYS_GETSOCKOPT dentro do socketcall
)

// getsockoptBytes lê uma opção de socket que é ESTRUTURA, e não int.
//
// O socketcall recebe os argumentos como um VETOR de unsigned long — aqui, de
// quatro bytes cada.
func getsockoptBytes(fd, nivel, opt int, b []byte) error {
	tam := uint32(len(b))
	args := [5]uint32{
		uint32(fd), uint32(nivel), uint32(opt),
		uint32(uintptr(unsafe.Pointer(&b[0]))),
		uint32(uintptr(unsafe.Pointer(&tam))),
	}
	_, _, errno := syscall.Syscall(sysSocketcall,
		chamadaGet, uintptr(unsafe.Pointer(&args[0])), 0)
	if errno != 0 {
		return errno
	}
	return nil
}
