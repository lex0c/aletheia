//go:build linux && amd64

package main

// memfd_create não está no pacote syscall da stdlib. O número é estável por
// arquitetura e é ABI do kernel — não muda.
const (
	sysMemfdCreate   = 319
	sysBPF           = 321
	sysPerfEventOpen = 298
)
