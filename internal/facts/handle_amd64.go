//go:build linux && amd64

package facts

// O número de `name_to_handle_at` no x86_64. Ele muda por arquitetura, e a
// stdlib do Go não o define — este projeto não tem dependência externa, então
// a constante mora aqui, uma por arquitetura, como já acontece no socketcall
// do i686.
const sysNameToHandleAt = 303
