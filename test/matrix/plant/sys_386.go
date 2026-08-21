//go:build linux && 386

package main

import (
	"runtime"
	"syscall"
	"unsafe"
)

// Em i386 NÃO EXISTE syscall.SYS_SETSOCKOPT: até o kernel 4.3 o i386 não tinha
// syscall própria para operação de socket — tudo passa pelo multiplexador
// `socketcall`, e é por isso que a stdlib do Go não define a constante nesta
// arquitetura. É o mesmo motivo, e a mesma solução, de internal/pcap/sys_386.go.
const (
	sysSocketcall = 102
	chamadaSet    = 14 // SYS_SETSOCKOPT dentro do socketcall
)

// anexarBPFNoSocket faz o SO_ATTACH_BPF com o fd do programa já carregado.
func anexarBPFNoSocket(sk, prog int) error {
	const soAttachBPF = 50
	args := [5]uint32{
		uint32(sk), uint32(syscall.SOL_SOCKET), uint32(soAttachBPF),
		uint32(uintptr(unsafe.Pointer(&prog))), 4,
	}
	_, _, errno := syscall.Syscall(sysSocketcall,
		chamadaSet, uintptr(unsafe.Pointer(&args[0])), 0)
	// Ver o KeepAlive de internal/pcap/sys_386.go: dentro de `args` o ponteiro
	// virou número, e nada avisa o coletor de que `prog` ainda está em uso.
	runtime.KeepAlive(&prog)
	if errno != 0 {
		return errno
	}
	return nil
}
