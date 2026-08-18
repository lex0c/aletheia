//go:build linux && (amd64 || 386)

package facts

// O `struct utmp` do x86 tem 384 bytes: `ut_session` é int32 e o `ut_tv` é um
// par de int32, mantidos assim para compatibilidade binária com o utmp de 32
// bits. Vale para x86_64 e para i686.
const tamanhoNativoDeUtmp = tamUtmp32
