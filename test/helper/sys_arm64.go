//go:build linux && arm64

package main

import "syscall"

// memfd_create não está no pacote syscall da stdlib. O número é estável por
// arquitetura e é ABI do kernel — não muda.
const (
	sysMemfdCreate   = 279
	sysBPF           = 280
	sysPerfEventOpen = 241

	// SysV SHM: números do arm64 (tabela genérica). shmget(194), shmat(196).
	sysShmget = 194
	sysShmat  = 196
)

func criaShm(perms int) error {
	const ipcCreat = 0o1000
	id, _, errno := syscall.Syscall(sysShmget, 0, 4096, uintptr(ipcCreat|perms))
	if errno != 0 {
		return errno
	}
	syscall.Syscall(sysShmat, id, 0, 0)
	hold()
	return nil
}
