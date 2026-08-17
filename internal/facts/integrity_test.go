package facts

import "testing"

// O mtree do pacman escapa caracteres em octal. Sem desescapar, todo caminho
// com espaço no nome falharia a comparação EM SILÊNCIO — que é a forma de erro
// que esta ferramenta existe para não cometer.
func TestDesescapaMtree(t *testing.T) {
	casos := map[string]string{
		`usr/bin/x`:            "usr/bin/x",
		`usr/share/a\040b/c`:   "usr/share/a b/c",
		`usr/lib/n\303\251.so`: "usr/lib/né.so",
		`sem/escape/nenhum`:    "sem/escape/nenhum",
	}
	for entrada, quer := range casos {
		if got := desescapaMtree(entrada); got != quer {
			t.Errorf("desescapaMtree(%q) = %q, quer %q", entrada, got, quer)
		}
	}
}
