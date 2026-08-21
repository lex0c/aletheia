package facts

import "testing"

// O que esconde texto é o MOVIMENTO DE CURSOR e o apagamento de tela, não a
// cor. A primeira versão disparava com qualquer ESC, e isso acusa a coisa mais
// comum que existe num .bashrc: um prompt colorido.
func TestEscapeDeTerminalSeparaApagamentoDeCor(t *testing.T) {
	esconde := []string{
		"# \x1b[2J\x1b[H",   // o `$(clear)` do truque
		"# \x1b[3J",         // limpa o scrollback
		"echo x\x1b[1A",     // sobe uma linha e sobrescreve
		"printf 'ok'\x1b[K", // apaga o resto da linha
		"a\rb",              // CR no meio: sobrescreve o que foi impresso
	}
	for _, ln := range esconde {
		if !temEscapeDeTerminal(ln) {
			t.Errorf("%q esconde conteúdo e precisa disparar", ln)
		}
	}

	naoEsconde := []string{
		"PS1='\\[\x1b[01;32m\\]\\u@\\h\\[\x1b[00m\\]\\$ '", // prompt colorido
		"export LS_COLORS='di=\x1b[01;34m'",
		"printf '\x1b]0;titulo\x07'", // OSC: título de janela
		"echo normal",
		"linha com CRLF do windows\r",
		"# comentário comum",
	}
	for _, ln := range naoEsconde {
		if temEscapeDeTerminal(ln) {
			t.Errorf("%q é configuração normal e não pode disparar", ln)
		}
	}
}
