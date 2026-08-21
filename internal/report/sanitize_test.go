package report

import "testing"

// O escape precisa ter LARGURA FIXA, senao ele volta a ser falsificavel — que e
// exatamente o que sanitize.go existe para impedir.
//
// Um `\n` (0x0a) seguido da letra `b` saia como `\xab`, que se le como um byte
// so; e quem escolhe a letra seguinte e quem escreveu o nome do arquivo. O
// mesmo valia para todo caractere de controle cujo codigo cabe num digito hex.
func TestEscapeTemLarguraFixa(t *testing.T) {
	casos := []struct{ entrada, quer string }{
		{"\nb", `\x0ab`},
		{"\rf", `\x0df`},
		{"\x1b[2J", `\x1b[2J`},
		// zero-width joiner: e assim que `index\u200d.php` fica visualmente
		// identico a `index.php` na tela de quem investiga.
		{"a\u200db", `a\u200db`},
		// RTL override: reordena o que o humano le sem mudar um byte.
		{"\u202eexe", `\u202eexe`},
		// Acima de U+FFFF a largura muda, e a categoria Cf inclui as TAG
		// characters (U+E0020-U+E007F) — o conjunto padrao de contrabando de
		// texto invisivel. Com quatro digitos fixos, `\ue0020` se lia como
		// `\ue002` seguido do literal `0`.
		{"a\U000E0020b", `a\U000e0020b`},
		{"\U0001BCA0", `\U0001bca0`},
		{"normal", "normal"},
	}
	for _, c := range casos {
		if got := Safe(c.entrada); got != c.quer {
			t.Errorf("Safe(%q) = %q, quer %q", c.entrada, got, c.quer)
		}
	}
}
