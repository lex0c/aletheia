package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

// O rodapé separa LACUNA de ESCOPO, e o README documenta esse formato.
//
// Sem a separação a linha se contradizia: o escopo sai do denominador da
// cobertura (um kernel sem inet_diag nunca vai responder ao sock_diag) e
// continuava sendo contado na lista de não verificados, produzindo
// "105/105 completos · 2 não verificados".
func TestCoberturaSeparaEscopoDeLacuna(t *testing.T) {
	r := &check.Report{
		Coverage: check.Coverage{
			Total: 2, Complete: 2,
			NotChecked: []check.NotChecked{
				{
					ID: "cross.socket_view", Ref: "35.5",
					Reason: "este kernel não OFERECE a enumeração de socket por netlink",
					Escopo: true,
				},
				{
					ID: "priv.shadow", Ref: "7.9",
					Reason: "/etc/shadow ilegível: rode como root",
				},
			},
		},
	}
	var b bytes.Buffer
	writeCoverage(&b, temaPara(false), r, Options{})
	saida := b.String()

	if !strings.Contains(saida, "2/2 completos") {
		t.Errorf("o denominador não reflete o escopo removido: %q", saida)
	}
	if !strings.Contains(saida, "1 não verificados") {
		t.Errorf("a LACUNA precisa continuar contada: %q", saida)
	}
	if !strings.Contains(saida, "1 fora de escopo") {
		t.Errorf("o ESCOPO precisa sair em contagem própria, nunca somado aos "+
			"não verificados: %q", saida)
	}
}

// E no detalhe (-v) as duas listas saem com rótulos diferentes: misturá-las
// manda o operador atrás de um conserto que não existe.
func TestDetalheDeCoberturaRotulaEscopoSeparadamente(t *testing.T) {
	c := check.Coverage{
		Total: 1, Complete: 1,
		NotChecked: []check.NotChecked{
			{ID: "kernel.bpf_unowned", Reason: "modo image: não há kernel vivo", Escopo: true},
			{ID: "priv.shadow", Reason: "/etc/shadow ilegível"},
		},
	}
	var b bytes.Buffer
	writeCoberturaDetalhe(&b, temaPara(false), c, 1)
	saida := b.String()

	for _, quer := range []string{"não verificados", "fora de escopo",
		"kernel.bpf_unowned", "priv.shadow"} {
		if !strings.Contains(saida, quer) {
			t.Errorf("faltou %q na saída:\n%s", quer, saida)
		}
	}
	// O escopo precisa dizer que NÃO é lacuna — é essa frase que impede o
	// operador de procurar privilégio para consertar o inconsertável.
	if !strings.Contains(saida, "NÃO conta como lacuna") {
		t.Errorf("a seção de escopo não explica que não degrada cobertura:\n%s", saida)
	}
}

// A trava de ponta a ponta: escopo NÃO pode produzir INCOMPLETE.
//
// Era o efeito prático do defeito — um kernel compilado sem inet_diag fazia
// TODA varredura naquele host sair com exit 1, inclusive a de um host limpo.
func TestEscopoNaoDerrubaOVeredito(t *testing.T) {
	r := &check.Report{
		Coverage: check.Coverage{
			Total: 1, Complete: 1,
			NotChecked: []check.NotChecked{
				{ID: "cross.socket_view", Reason: "kernel sem inet_diag", Escopo: true},
			},
		},
	}
	if r.Coverage.Incomplete() {
		t.Error("cobertura marcada como incompleta só por causa de um check " +
			"fora de escopo: é a lacuna constante que nunca fecha, e ela " +
			"transforma exit 1 em ruído fixo")
	}

	var b bytes.Buffer
	Human(&b, r, &facts.Facts{}, &env.Env{Source: env.SourceLive}, Options{})
	if strings.Contains(b.String(), "RESULT: INCOMPLETE") {
		t.Errorf("o veredito saiu INCOMPLETE por escopo:\n%s", b.String())
	}
}

// A ARITMÉTICA continua fechando com escopo no meio.
//
// O escopo sai dos DOIS lados da conta: não entra no denominador e não entra na
// contagem de não verificados. Se saísse de um lado só, a linha de cobertura
// passaria a não fechar — e ela é lida como prestação de contas.
func TestAritmeticaDaCoberturaFechaComEscopo(t *testing.T) {
	c := check.Coverage{
		// 6 checks selecionados, 1 fora de escopo -> denominador 5.
		Total: 5, Complete: 2,
		Partial: []check.Partial{{ID: "a"}, {ID: "b"}},
		NotChecked: []check.NotChecked{
			{ID: "c", Reason: "sem root"},
			{ID: "d", Reason: "kernel sem inet_diag", Escopo: true},
		},
	}
	lacunas, escopo := c.NaoVerificados()
	if soma := c.Complete + len(c.Partial) + len(lacunas); soma != c.Total {
		t.Errorf("completos(%d) + parciais(%d) + lacunas(%d) = %d, e o total é %d: "+
			"a conta da linha de cobertura não fecha",
			c.Complete, len(c.Partial), len(lacunas), soma, c.Total)
	}
	if len(escopo) != 1 {
		t.Errorf("escopo=%d, queria 1", len(escopo))
	}
}
