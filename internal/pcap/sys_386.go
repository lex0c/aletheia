//go:build linux && 386

package pcap

import (
	"runtime"
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
	// Os ponteiros para `b` e `tam` viraram uint32 DENTRO de args, e a regra do
	// unsafe só protege `uintptr(unsafe.Pointer(x))` escrito na própria
	// chamada. Guardados num vetor, eles são números: nada impede o coletor de
	// achar que `b` e `tam` morreram antes do kernel escrever neles. O GC de
	// hoje não move objetos e o defeito não aparece — o que é a pior forma de
	// um defeito existir, porque ele espera a versão de Go que mudar isso.
	runtime.KeepAlive(b)
	runtime.KeepAlive(&tam)
	if errno != 0 {
		return errno
	}
	return nil
}
