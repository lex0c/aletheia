module github.com/lex0c/aletheia

go 1.25

// O patch do toolchain é FIXO para que dois builds da mesma tag produzam o
// mesmo binário. Sem ele o setup-go instala o último 1.25.x disponível NA HORA,
// e o release de hoje e o de daqui a três meses saem diferentes — o que torna
// impossível reconstruir e conferir o hash que a nota do release manda comparar.
toolchain go1.26.5
