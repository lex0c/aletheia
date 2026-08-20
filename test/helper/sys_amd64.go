//go:build linux && amd64

package main

import "syscall"

// memfd_create não está no pacote syscall da stdlib. O número é estável por
// arquitetura e é ABI do kernel — não muda.
const (
	sysMemfdCreate   = 319
	sysBPF           = 321
	sysPerfEventOpen = 298

	// SysV SHM: números diretos do amd64. shmget(29), shmat(30).
	sysShmget = 29
	sysShmat  = 30
)

// criaShm cria um segmento SysV SHM com a permissão e o tamanho dados e anexa.
// key IPC_PRIVATE (0) faz o kernel criar um novo; IPC_CREAT autoriza. Anexar
// mantém nattch>0. Quem chama SEGURA o processo (hold), o que mantém o cpid
// resolvível para o criador.
func criaShm(perms, size int) error {
	const ipcCreat = 0o1000
	id, _, errno := syscall.Syscall(sysShmget, 0, uintptr(size), uintptr(ipcCreat|perms))
	if errno != 0 {
		return errno
	}
	syscall.Syscall(sysShmat, id, 0, 0) // se falhar, o segmento já existe
	return nil
}
