//go:build linux && amd64

package kbpf

import "unsafe"

// O número da bpf(2) não está no pacote syscall da stdlib, que está congelado
// desde antes dela existir. É ABI do kernel por arquitetura: não muda.
const sysBPF = 321

// Em 64 bits o ponteiro já tem o tamanho que a bpf_attr exige. O campo é
// unsafe.Pointer e não uintptr de propósito: guardar endereço como inteiro o
// esconde do coletor de lixo, e o buffer poderia ser recolhido entre a montagem
// da struct e a syscall — um erro que não falha em teste, falha sob pressão de
// memória.
type ponteiro64 struct {
	p unsafe.Pointer
}
