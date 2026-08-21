package report

import (
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Sanitização e redação da camada de SAÍDA.
//
// Dois problemas distintos, ambos com o mesmo veículo: o texto que vem do alvo.
//
//  1. INJEÇÃO DE TERMINAL. /proc/<pid>/cmdline aceita qualquer byte menos NUL,
//     inclusive ESC e newline, e o argv vai para a evidência do achado. Um
//     implante que define o próprio argv como
//     "nginx: worker\x1b[2J\x1b[H⛔ 0 ⚠ 0\n\n✓ nenhum indicador\n\nRESULT: OK"
//     faz o relatório LIMPAR A TELA e pintar um veredito limpo forjado. O campo
//     de evidência do achado vira o veículo de entrega — o atacante escreve na
//     saída da ferramenta que o está caçando.
//
//  2. VAZAMENTO DE SEGREDO. SPEC 5.4 exige redação na camada de saída, não só
//     no dump: o relatório vai para ticket, e-mail e post-mortem. Um
//     `mysqldump -u root -pS3cr3t` num achado CRITICAL levaria a credencial
//     viva junto.
//
// O JSONL escapa control chars por construção do encoder, então a falsificação
// só existia no texto que o humano lê — que é justamente onde ele decide.

// Safe torna uma linha segura para impressão em terminal.
func Safe(s string) string {
	if s == "" {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == utf8.RuneError:
			b.WriteString("\\x?")
		case r == '\t':
			b.WriteString("    ")
		case r < 0x20 || r == 0x7f:
			// ESC, CR, LF, BS e afins viram texto visível: o operador PRECISA
			// ver que o alvo tentou isso.
			// DOIS dígitos sempre. Sem o zero à esquerda o escape é
			// AMBÍGUO, e a ambiguidade volta a permitir exatamente o que este
			// arquivo existe para impedir: um `\n` (0x0a) seguido da letra `b`
			// saía como `\xab`, que se lê como um byte só. O atacante escolhe
			// a letra seguinte.
			b.WriteString("\\x" + zeros(strconv.FormatInt(int64(r), 16), 2))
		case unicode.Is(unicode.Cf, r):
			// Formatação invisível: RTL override e amigos reordenam o que o
			// humano lê sem mudar o byte.
			//
			// A LARGURA MUDA acima de U+FFFF, e não é detalhe: a categoria Cf
			// inclui as TAG characters (U+E0020–U+E007F), que são o conjunto
			// padrão de contrabando de texto invisível. Com quatro dígitos
			// fixos, `U+E0020` saía como `\ue0020` — que se lê como `\ue002`
			// seguido do literal `0`, e a ambiguidade que este arquivo existe
			// para fechar voltava exatamente nos caracteres que mais importam.
			//
			// A convenção é a do Go e a do Python: `\uXXXX` até U+FFFF,
			// `\UXXXXXXXX` acima. As duas têm largura fixa, e o prefixo
			// maiúsculo diz qual é.
			if r > 0xffff {
				b.WriteString("\\U" + zeros(strconv.FormatInt(int64(r), 16), 8))
			} else {
				b.WriteString("\\u" + zeros(strconv.FormatInt(int64(r), 16), 4))
			}
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// zeros completa com zeros à esquerda até a largura fixa do escape.
func zeros(s string, largura int) string {
	for len(s) < largura {
		s = "0" + s
	}
	return s
}

// SafeAll aplica Safe a uma lista.
func SafeAll(ss []string) []string {
	if len(ss) == 0 {
		return ss
	}
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = Safe(s)
	}
	return out
}
