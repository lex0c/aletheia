package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/lex0c/aletheia/internal/activity"
	"github.com/lex0c/aletheia/internal/facts"
)

var agoraCmd = time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)

func rodape(f *facts.Facts, fontes []activity.Fonte, desde string) string {
	var b bytes.Buffer
	ActivityCobertura(&b, fontes, f, agoraCmd, "--since 24h", desde, false)
	return b.String()
}

func fonteLogCoberta() facts.FonteDeLog {
	return facts.FonteDeLog{
		Path: "/var/log/auth.log", Familias: []string{"auth"}, Estado: facts.FonteLida,
		CobertoDesde: "2026-08-19T00:00:00Z", CobertoAte: "2026-08-26T12:00:00Z",
	}
}

// ESCOPO, LACUNA e DESCONHECIDO saem de CoberturaLog com o mesmo `Existe=false`,
// e mandam o operador para lugares opostos. Imprimir os três como
// "FORA DE ESCOPO" faz uma lacuna se apresentar como propriedade do host — e
// ainda manda o operador ao journal num alvo que TEM o log em texto.
func TestRodapeSeparaEscopoDeLacunaEDeDesconhecido(t *testing.T) {
	casos := []struct {
		nome    string
		estado  facts.EstadoColetaLog
		quer    string
		naoQuer string
	}{
		{"journald-only", facts.LogColetado, "FORA DE ESCOPO", "DESLIGADA"},
		{"--no-logs", facts.LogDesativado, "DESLIGADA", "FORA DE ESCOPO"},
		{"coleta não chegou", "", "DESCONHECIDA", "FORA DE ESCOPO"},
	}
	for _, c := range casos {
		t.Run(c.nome, func(t *testing.T) {
			out := rodape(&facts.Facts{LogEstado: c.estado}, nil, "2026-08-25T12:00:00Z")
			if !strings.Contains(out, c.quer) {
				t.Errorf("falta %q:\n%s", c.quer, out)
			}
			if strings.Contains(out, c.naoQuer) {
				t.Errorf("saiu %q, que é outra conclusão:\n%s", c.naoQuer, out)
			}
		})
	}
}

// A via nomeada é o payload INTEIRO da promessa de "escopo declarado", e ela
// precisa ser um comando que roda. A primeira versão interpolava o texto que o
// operador digitou: `--around` produzia `journalctl --since -±5m de 2026-…`, e
// um `--since` absoluto produzia `--since -2026-08-26T00:00Z`, que o journalctl
// recusa. Só a forma de duração pura funcionava.
func TestViaExternaEhExecutavel(t *testing.T) {
	out := rodape(&facts.Facts{LogEstado: facts.LogColetado}, nil, "2026-08-25T12:00:00Z")
	if !strings.Contains(out, `journalctl --utc --since "2026-08-25 12:00:00"`) {
		t.Errorf("a via do journal não saiu executável:\n%s", out)
	}
	// O audit tem ferramenta PRÓPRIA: mandar journalctl para ele é conselho
	// errado com cara de conselho.
	if !strings.Contains(out, "ausearch -ts 2026-08-25 12:00:00") {
		t.Errorf("a família audit precisa apontar para o ausearch:\n%s", out)
	}
	// Sem janela inferior, o comando sai sem a flag em vez de sair quebrado.
	semJanela := rodape(&facts.Facts{LogEstado: facts.LogColetado}, nil, "")
	if strings.Contains(semJanela, "--since \"\"") {
		t.Errorf("via com janela vazia saiu malformada:\n%s", semJanela)
	}
}

// O rodapé precisa dizer o que a fonte binária NÃO entregou: gerações
// rotacionadas fechadas ao lado, e registros que não viraram evento.
func TestRodapeDeclaraOQueAFonteBinariaNaoEntregou(t *testing.T) {
	fontes := []activity.Fonte{{
		Papel: facts.PapelHistorico, Path: "/var/log/wtmp", Estado: facts.FonteLoginLida,
		Desde: "2026-08-26T10:00:00Z", Ate: "2026-08-26T12:00:00Z",
		Lidos: 45, Total: 45, GeracoesNaoLidas: 2, NaoInterpretados: 14,
	}}
	out := rodape(&facts.Facts{LogEstado: facts.LogColetado}, fontes, "2026-08-25T12:00:00Z")
	for _, quer := range []string{"ROTACIONADA", "sem tradução para evento"} {
		if !strings.Contains(out, quer) {
			t.Errorf("falta %q — sem isso o rodapé diz 'lido inteiro' sobre uma "+
				"linha do tempo mais curta que o arquivo:\n%s", quer, out)
		}
	}
}

// A família que a leitura alcançou menos que o pedido tem de sair NOMEADA: é a
// diferença entre "não houve" e "não olhei", que é a razão de o rodapé existir.
func TestRodapeNomeiaAFamiliaQueNaoAlcancaOPedido(t *testing.T) {
	f := &facts.Facts{
		LogEstado:   facts.LogColetado,
		FontesDeLog: []facts.FonteDeLog{fonteLogCoberta()},
	}
	// Pedido de 30 dias contra uma cobertura que começa em 19/08.
	out := rodape(f, nil, "2026-07-27T12:00:00Z")
	if !strings.Contains(out, "pedido --since 24h: auth alcança") {
		t.Errorf("a família curta precisa sair nomeada:\n%s", out)
	}
}

// A tabela do --group-by, que o cenário deliberadamente não afirma: alinhar por
// coluna é renderização, e afirmá-la num cenário testaria o layout achando que
// testa o agregado.
func TestTabelaDeGrupoTrazContagemECruzamento(t *testing.T) {
	gs := []activity.Grupo{
		{Chave: "deploy", Aceitos: 3, Recusados: 0, Origens: []string{"185.44.1.7"}},
		{Chave: "root", Aceitos: 0, Recusados: 9, Origens: []string{"203.0.113.9"}},
	}
	var b bytes.Buffer
	ActivityGrupos(&b, gs, activity.PorUsuario, false)
	out := b.String()
	for _, quer := range []string{"CONTA", "ORIGENS", "deploy", "root", "9", "185.44.1.7"} {
		if !strings.Contains(out, quer) {
			t.Errorf("falta %q na tabela:\n%s", quer, out)
		}
	}
}

// Lista vazia NUNCA é "nada aconteceu": o rodapé logo abaixo é quem diz sobre
// qual intervalo o silêncio vale.
func TestSaidaVaziaMandaLerACobertura(t *testing.T) {
	var b bytes.Buffer
	ActivityLinha(&b, nil, false)
	var g bytes.Buffer
	ActivityGrupos(&g, nil, activity.PorOrigem, false)
	for nome, out := range map[string]string{"timeline": b.String(), "grupos": g.String()} {
		if !strings.Contains(out, "cobertura abaixo diz sobre o quê") {
			t.Errorf("%s: silêncio sem remissão à cobertura:\n%s", nome, out)
		}
		if strings.Contains(out, "nada aconteceu") {
			t.Errorf("%s: afirmou ausência de evento", nome)
		}
	}
}

// Evento sem data sai num bloco PRÓPRIO no fim. Interpolá-lo numa posição
// plausível inventaria quando aquilo aconteceu — e uma data curta demais, vinda
// de um dump escrito à mão, não pode derrubar o comando.
func TestTimelineIsolaOSemDataENaoQuebraComDataCurta(t *testing.T) {
	ev := []activity.Evento{
		{At: "2026-08-26T10:00:00Z", Kind: activity.KindLoginAceito, User: "deploy",
			Testemunhas: []string{"wtmp"}},
		{At: "2026", Kind: activity.KindLoginAceito, User: "curta",
			Testemunhas: []string{"wtmp"}},
		{Kind: activity.KindLoginAceito, User: "sem-data", Testemunhas: []string{"wtmp"}},
	}
	var b bytes.Buffer
	ActivityLinha(&b, ev, false) // não pode entrar em pânico
	out := b.String()
	if !strings.Contains(out, "sem data") {
		t.Errorf("o bloco de sem-data não saiu:\n%s", out)
	}
	i, j := strings.Index(out, "deploy"), strings.Index(out, "sem-data")
	if i < 0 || j < 0 || j < i {
		t.Errorf("o evento sem data precisa vir DEPOIS dos datados, no bloco "+
			"próprio:\n%s", out)
	}
}
