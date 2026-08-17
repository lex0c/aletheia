//go:build linux && arm64

package kbpf

import "unsafe"

// arm64 usa a tabela asm-generic, onde a bpf(2) é 280.
const sysBPF = 280

// Ver sys_amd64.go: em 64 bits o ponteiro já tem o tamanho da ABI.
type ponteiro64 struct {
	p unsafe.Pointer
}
