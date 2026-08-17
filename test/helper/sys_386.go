//go:build linux && 386

package main

// memfd_create não está no pacote syscall da stdlib. O número é estável por
// arquitetura e é ABI do kernel — não muda.
const sysMemfdCreate = 356
