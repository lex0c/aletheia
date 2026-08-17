//go:build linux && 386

package kbpf

import "unsafe"

// Servidor i686 legado ainda existe, e é onde o número diverge: aqui a bpf(2)
// é 357, contra 321 no x86_64. Fixar um só faria a enumeração falhar em
// silêncio na arquitetura errada — devolvendo "nenhum programa" em vez de erro.
const sysBPF = 357

// Aqui o ponteiro tem QUATRO bytes e a bpf_attr exige OITO. O preenchimento vem
// depois do endereço porque em little-endian a metade baixa é a que carrega o
// valor: os quatro bytes altos ficam zerados, que é o que o kernel espera de um
// endereço de 32 bits promovido a 64.
//
// Este é o campo que decide se a leitura de mapa funciona ou lê outra coisa em
// i686, e o teste de layout trava os dois tamanhos.
type ponteiro64 struct {
	p unsafe.Pointer
	_ uint32
}
