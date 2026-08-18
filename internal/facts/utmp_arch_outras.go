//go:build linux && !amd64 && !386

package facts

// Fora do x86 não há o legado de compatibilidade de 32 bits: `ut_session` é long
// e o `ut_tv` é um `struct timeval` de verdade, o que leva o registro a 400
// bytes. É o caso do arm64 — e da musl em qualquer arquitetura, o que inclui
// todo host Alpine.
const tamanhoNativoDeUtmp = tamUtmp64
