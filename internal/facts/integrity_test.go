package facts

import (
	"os"
	"testing"

	"github.com/lex0c/aletheia/internal/env"
)

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

// A imagem oficial do Ubuntu 14.04 DESVIA o /sbin/initctl com dpkg-divert e põe
// um stub no lugar. Diversão é mecanismo COM REGISTRO — o arquivo no caminho
// original passa a ser de outro pacote, e o hash do original nunca mais
// confere.
//
// O teste anterior desta regressão era decorativo: verificava que uma lista
// vazia de divergências não produz achado, o que é verdade trivialmente e não
// exercita diversão nenhuma.
func TestDiversaoSaiDaComparacao(t *testing.T) {
	dir := t.TempDir()
	// Formato real: blocos de três linhas — original, destino, pacote.
	conteudo := "/sbin/initctl\n/sbin/initctl.distrib\nupstart\n" +
		"/usr/bin/pod2latex\n/usr/bin/pod2latex.bundled\nlibpod-latex-perl\n"
	if err := os.MkdirAll(dir+"/var/lib/dpkg", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir+"/var/lib/dpkg/diversions", []byte(conteudo), 0o644); err != nil {
		t.Fatal(err)
	}

	e := env.Probe(env.Options{Root: dir})
	esperados := map[string]hashRef{
		"/sbin/initctl":         {hash: "aaa", algo: "md5"},
		"/usr/bin/pod2latex":    {hash: "bbb", algo: "md5"},
		"/usr/bin/nao-desviado": {hash: "ccc", algo: "md5"},
	}
	desviados := removerDesviados(e, esperados)

	for _, p := range []string{"/sbin/initctl", "/usr/bin/pod2latex"} {
		if _, ainda := esperados[p]; ainda {
			t.Errorf("%s foi desviado e continua na comparação", p)
		}
		if !desviados[p] {
			t.Errorf("%s precisa ser marcado como desviado, senão vira LACUNA de "+
				"cobertura e degrada toda imagem do Ubuntu", p)
		}
	}
	if _, ok := esperados["/usr/bin/nao-desviado"]; !ok {
		t.Error("o que não foi desviado precisa continuar sendo comparado")
	}
}
