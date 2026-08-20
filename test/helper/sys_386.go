//go:build linux && 386

package main

import "syscall"

// memfd_create não está no pacote syscall da stdlib. O número é estável por
// arquitetura e é ABI do kernel — não muda.
const (
	sysMemfdCreate   = 356
	sysBPF           = 357
	sysPerfEventOpen = 336
)

// Em x86-32 o SysV IPC passa pelo multiplexador ipc(2), não por shmget/shmat
// diretos — outra ABI. O cenário de SysV SHM roda em amd64; aqui fica o stub
// honesto para o helper de 32 bits compilar.
func criaShm(perms, size int) error {
	return syscall.ENOSYS
}
