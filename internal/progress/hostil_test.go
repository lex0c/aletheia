package progress

import (
	"strings"
	"testing"
)

// O detalhe do progresso é um nome de diretório do HOST INVESTIGADO, e nome de
// arquivo em Linux aceita qualquer byte menos `/` e NUL.
//
// Ele era escrito verbatim no stderr durante a varredura. Um
// `/var/www/<ESC>[?1049h…` troca o terminal do respondedor para o buffer
// alternativo, redefine a região de rolagem ou injeta texto com cara de saída da
// ferramenta — e o relatório que nasce depois do Stop() sai invisível ou
// adulterado. Um `\n` no nome quebra a aritmética de duas linhas do `\033[A` e
// faz o Stop apagar a linha errada.
//
// report.Safe cobre todo o resto da saída; esta superfície era a única que
// passava, e não dá para importá-lo daqui sem ciclo.
func TestDetalheNeutralizaControleVindoDoAlvo(t *testing.T) {
	casos := []struct {
		nome    string
		entrada string
	}{
		{"escape de terminal", "/var/www/\x1b[?1049h"},
		{"quebra de linha", "/var/www/a\nb"},
		{"retorno de carro", "/var/www/a\rb"},
		{"DEL", "/var/www/a\x7fb"},
		{"caractere de formatação", "/var/www/a‎b"},
	}
	for _, c := range casos {
		got := seguro(c.entrada)
		for _, r := range got {
			if r < 0x20 || r == 0x7f {
				t.Errorf("%s: sobrou byte de controle %q na saída %q",
					c.nome, r, got)
			}
		}
		if strings.ContainsAny(got, "\x1b\r\n") {
			t.Errorf("%s: a saída %q ainda carrega escape ou quebra", c.nome, got)
		}
	}
}

// Caminho normal não pode ser mexido: o operador precisa reconhecer o que está
// sendo lido, e trocar bytes à toa tornaria o batimento inútil.
func TestDetalheNaoMexeEmCaminhoNormal(t *testing.T) {
	for _, p := range []string{
		"/var/www/html",
		"/home/joana/projeto-2024",
		"/srv/aplicação/configuração", // acentuado é normal e precisa passar
		"",
	} {
		if got := seguro(p); got != p {
			t.Errorf("seguro(%q)=%q: caminho normal foi alterado", p, got)
		}
	}
}
