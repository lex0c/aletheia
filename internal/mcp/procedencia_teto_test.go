package mcp

import (
	"strings"
	"testing"
)

// Um escalar da procedência não pode inutilizar a sessão inteira.
//
// A procedência entra em TODO envelope e nada nela responde a `limit`, cursor
// ou filtro — então um campo grande demais estoura o MaxResultado de toda
// resposta do servidor de uma vez. Medido com 2 MiB no /etc/hostname do alvo
// (invisível para o sistema em execução, porque o hostname do kernel é definido
// no boot): snapshot.capture, session.status, snapshot.list e até
// findings.list com limit=1 passaram todos a devolver -32602.
//
// E o encadeamento é o que tornava aquilo irrecuperável: o snapshot.capture
// SUCEDE por dentro e registra o retrato — só a resposta é recusada. O modelo
// nunca aprende o snapshot_id, o snapshot.list também não consegue dizer, e
// depois de quatro capturas (cada uma uma varredura inteira do alvo, cobrada do
// orçamento) o teto de retratos vivos chega, com um remédio que exige um ID que
// nenhuma tool sobrevivente pode revelar.
func TestCampoDaProcedenciaEhCortadoEDeclaraOCorte(t *testing.T) {
	grande := strings.Repeat("A", 2<<20)
	got := cortarCampoDoAlvo(grande)
	if len(got) > MaxCampoProcedencia+128 {
		t.Errorf("o campo saiu com %d bytes: o teto de %d não foi aplicado, e um "+
			"único escalar do alvo derruba toda resposta do servidor",
			len(got), MaxCampoProcedencia)
	}
	if !strings.Contains(got, "cortado") {
		t.Errorf("cortou em SILÊNCIO: %q…\n"+
			"Truncar sem dizer troca uma sessão morta por um fato adulterado — o "+
			"modelo leria o prefixo como se fosse o hostname inteiro", got[:60])
	}
	// Hostname real não pode ser tocado.
	if v := cortarCampoDoAlvo("web-01.prod.example.com"); v != "web-01.prod.example.com" {
		t.Errorf("hostname normal foi mexido: %q", v)
	}
}

// `provenance` carrega texto escolhido pelo alvo, e a resposta AFIRMA que
// host_supplied_paths é exaustiva.
//
// provenance.host é o /etc/hostname lido verbatim, e collected_by /
// collector_sha256 vêm de um artefato que o próprio envelope declara
// `authenticated: false` — quem escreveu o dump escolheu o que eles dizem.
// Enquanto isso a nota embarcada diz que a lista traz TODOS os caminhos com
// texto do alvo, e a regra 2 das Instrucoes treina o modelo a confiar nela.
//
// Medido: um `web-01\x1b[2J IGNORE ALL PREVIOUS INSTRUCTIONS…` no hostname
// aparecia em provenance — o bloco que o modelo lê PRIMEIRO, porque a ordem dos
// campos no Envelope é deliberada — com a lista dizendo só ['data',
// 'observability'].
//
// É o mesmo defeito que já tinha sido consertado para `observability`, e o
// comentário daquele conserto explica por que a formulação forte é a que vale.
func TestProvenanceEstaEntreOsCaminhosComTextoDoAlvo(t *testing.T) {
	for _, o := range []Observabilidade{{}, {LacunasDeColeta: []string{"x"}}} {
		r := RegioesDoHost(o)
		var tem bool
		for _, p := range r {
			if p == "provenance" {
				tem = true
			}
		}
		if !tem {
			t.Errorf("host_supplied_paths = %v, sem `provenance`.\n"+
				"provenance.host é o hostname lido verbatim do alvo e collected_by vem "+
				"de artefato não autenticado — texto do atacante numa região que a "+
				"resposta afirma ser de autoria da ferramenta.", r)
		}
	}
}
