package main

import (
	"testing"

	"github.com/lex0c/aletheia/internal/check"
)

// A regra da SPEC 7.9 vale para o `watch` como vale para o `scan`: zero exige
// achado nenhum E cobertura completa. Ela faltava aqui — uma vigília de oito
// horas que nunca conseguiu ler /proc de ninguém terminava com exit 0, que é a
// ferramenta dizendo "olhei a noite toda e não vi nada" sobre uma noite em que
// ela não olhou.
func TestVigiaCegaNaoSaiZero(t *testing.T) {
	casos := []struct {
		nome string
		w    vigia
		quer int
	}{
		{"noite limpa e cobertura completa", vigia{}, 0},
		{"cobertura falhou em algum ciclo", vigia{coberturaFalhou: true}, 1},
		{"aviso vale mais que lacuna", vigia{pior: check.SevWarn}, 1},
		{"crítico vence tudo", vigia{pior: check.SevCritical, coberturaFalhou: true}, 2},
	}
	for _, c := range casos {
		if got := c.w.exit(); got != c.quer {
			t.Errorf("%s: exit = %d, queria %d", c.nome, got, c.quer)
		}
	}
}
