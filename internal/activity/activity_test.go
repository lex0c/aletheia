package activity

import (
	"testing"
	"time"

	"github.com/lex0c/aletheia/internal/facts"
)

var agora = time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)

func em(h int) string {
	return agora.Add(-time.Duration(h) * time.Hour).Format(carimbo)
}

// hostCom monta um retrato com as três fontes declaradas LIDAS. Os testes que
// querem outra coisa sobrescrevem a fonte depois.
func hostCom(logins []facts.Login, fontes ...facts.FonteDeLogin) *facts.Facts {
	if len(fontes) == 0 {
		fontes = []facts.FonteDeLogin{
			{Path: "/var/log/wtmp", Papel: facts.PapelHistorico, Estado: facts.FonteLoginLida, Lidos: len(logins), Registros: len(logins)},
			{Path: "/var/log/btmp", Papel: facts.PapelRecusadas, Estado: facts.FonteLoginLida},
			{Path: "/run/utmp", Papel: facts.PapelSessoes, Estado: facts.FonteLoginLida},
		}
	}
	return &facts.Facts{Logins: logins, FontesDeLogin: fontes}
}

func entrada(user, origem string, hAtras int) facts.Login {
	return facts.Login{Tipo: facts.TipoLoginUsuario, User: user, Origem: origem, QuandoU: em(hAtras)}
}

// "Não observada anteriormente" só pode ser respondida se houver ANTES.
//
// Quando a retenção começa DENTRO da janela não existe passado com que
// comparar, e responder 0 seria inventar uma negativa — a forma exata do falso
// "limpo" que esta base persegue. O bit ao lado da contagem é o que separa
// "conferi e não há" de "não pude conferir".
func TestOrigemNaoObservadaAntesExigeHistoricoAnteriorAJanela(t *testing.T) {
	t.Run("retenção alcança antes da janela", func(t *testing.T) {
		f := hostCom([]facts.Login{
			entrada("deploy", "10.0.0.9", 200), // muito antes da janela
			entrada("deploy", "10.0.0.9", 3),   // origem conhecida
			entrada("deploy", "185.44.1.7", 2), // origem sem passado
		})
		r := Resumir(f, agora, 24*time.Hour)
		if !r.OrigensNaoObservadasAntesCalc {
			t.Fatal("a retenção alcança 200h atrás: a pergunta PODE ser feita")
		}
		if r.OrigensNaoObservadasAntes != 1 {
			t.Errorf("= %d, queria 1 (só 185.44.1.7 não tem passado)",
				r.OrigensNaoObservadasAntes)
		}
	})

	t.Run("retenção começa dentro da janela", func(t *testing.T) {
		f := hostCom([]facts.Login{
			entrada("deploy", "10.0.0.9", 3),
			entrada("deploy", "185.44.1.7", 2),
		})
		// A fonte foi truncada pelo teto: o que veio antes não foi examinado.
		f.FontesDeLogin[0].Truncada = true
		r := Resumir(f, agora, 24*time.Hour)
		if r.OrigensNaoObservadasAntesCalc {
			t.Error("a retenção começa 3h atrás e a janela pede 24h: não há " +
				"ANTES com que comparar, e a contagem não pode ser afirmada")
		}
		if r.OrigensNaoObservadasAntes != 0 {
			t.Errorf("= %d: sem poder responder, o número tem de ficar zerado e "+
				"o bit desligado — quem imprime lê o bit", r.OrigensNaoObservadasAntes)
		}
	})
}

// btmp ilegível não pode virar "nenhuma recusa".
//
// É o caso COMUM, não o exótico: o btmp é 0600 de root em toda distribuição, e
// toda varredura sem privilégio o encontra fechado. Zero ali diria "ninguém
// tentou entrar" sobre um arquivo que ninguém abriu.
func TestBtmpIlegivelNaoViraZeroRecusas(t *testing.T) {
	f := hostCom([]facts.Login{entrada("deploy", "10.0.0.9", 2)})
	f.FontesDeLogin[1] = facts.FonteDeLogin{
		Path: "/var/log/btmp", Papel: facts.PapelRecusadas,
		Estado: facts.FonteLoginIlegivel, Motivo: "permission denied",
	}
	r := Resumir(f, agora, 24*time.Hour)

	s, ok := r.Fonte(facts.PapelRecusadas)
	if !ok {
		t.Fatal("a fonte de recusadas sumiu do resumo")
	}
	if s.Lida() {
		t.Error("btmp ilegível não pode sair como lido")
	}
	if !s.Existe() {
		t.Error("ILEGÍVEL não é AUSENTE: o arquivo existe, e a diferença separa " +
			"'este host não tem btmp' de 'esta execução não é root'")
	}
	if r.Recusados != 0 {
		t.Errorf("Recusados = %d: sem leitura não há contagem", r.Recusados)
	}
}

// O marcador de boot carrega a VERSÃO DO KERNEL no campo de origem. Contá-lo
// como entrada põe texto de kernel na lista de endereços de onde alguém entrou
// — e é essa lista que o operador percorre procurando o que não reconhece.
func TestBootNaoEhEntradaNemOrigem(t *testing.T) {
	f := hostCom([]facts.Login{
		{Tipo: facts.TipoBoot, User: "reboot", Origem: "6.12.104-1-MANJARO", QuandoU: em(5)},
		entrada("deploy", "10.0.0.9", 2),
	})
	r := Resumir(f, agora, 24*time.Hour)
	if r.Aceitos != 1 {
		t.Errorf("Aceitos = %d, queria 1", r.Aceitos)
	}
	if r.Origens != 1 {
		t.Errorf("Origens = %d, queria 1: a versão do kernel não é origem", r.Origens)
	}
}

// A janela recorta, e o que ficou fora não desaparece da COBERTURA — é ele que
// sustenta a resposta sobre "não observada antes".
func TestJanelaRecortaContagemMasNaoCobertura(t *testing.T) {
	f := hostCom([]facts.Login{
		entrada("velho", "10.0.0.1", 100),
		entrada("deploy", "10.0.0.9", 2),
	})
	r := Resumir(f, agora, 24*time.Hour)
	if r.Aceitos != 1 {
		t.Errorf("Aceitos = %d, queria 1: a entrada de 100h atrás está fora", r.Aceitos)
	}
	h, _ := r.Fonte(facts.PapelHistorico)
	if h.Desde != em(100) {
		t.Errorf("Desde = %q, queria %q: a cobertura é do que foi LIDO, e não do "+
			"que a janela deixou passar", h.Desde, em(100))
	}
	if !h.CobreJanela {
		t.Error("a fonte alcança 100h atrás e a janela pede 24h: ela cobre")
	}
}

// Coleta que não rodou não pode produzir zeros. É o retrato volátil do `watch`,
// que não chama collectLogins.
func TestSemColetaDeLoginNaoHaResumo(t *testing.T) {
	r := Resumir(&facts.Facts{}, agora, 24*time.Hour)
	if r.Coletado() {
		t.Error("sem FontesDeLogin a coleta não rodou, e quem imprime tem de " +
			"CALAR o bloco em vez de mostrar zeros")
	}
	if r := Resumir(nil, agora, 24*time.Hour); r.Coletado() {
		t.Error("Facts nil")
	}
}

// A unidade da janela é a que se usa numa investigação.
func TestDuracaoUsaHorasAteDoisDias(t *testing.T) {
	casos := []struct {
		d    time.Duration
		quer string
	}{
		{24 * time.Hour, "24h"},
		{32 * time.Hour, "32h"},
		{3*time.Hour + 12*time.Minute, "3h12m"},
		{7 * 24 * time.Hour, "7d"},
		{45 * time.Minute, "45m"},
	}
	for _, c := range casos {
		if got := dur(c.d); got != c.quer {
			t.Errorf("dur(%v) = %q, queria %q", c.d, got, c.quer)
		}
	}
}

// A COBERTURA EXIGE ÂNCORA OBSERVADA. Nenhum outro fato a substitui.
//
// Duas versões anteriores deste teste afirmaram o contrário e passaram:
//
//	"li o arquivo inteiro"        não prova alcance: a retenção do logrotate é
//	                              finita, e a geração que tinha o passado
//	                              expira. Ausência de rotacionado hoje é
//	                              ausência de rotacionado hoje
//	Base: "wtmp"                  não é o que collectLogs escreve (ele grava o
//	                              caminho COMPLETO), então a contagem de
//	                              gerações saía zero em produção e o teste
//	                              provava que o código lia o que ele mesmo
//	                              tinha escrito
func TestCoberturaExigeAncoraObservadaAnteriorAJanela(t *testing.T) {
	// Arquivo lido inteiro, sem rotacionado ao lado, cujo registro mais antigo
	// é de 2h atrás. Ele NÃO cobre 24h.
	f := hostCom([]facts.Login{entrada("deploy", "10.0.0.9", 2)})
	h, _ := Resumir(f, agora, 24*time.Hour).Fonte(facts.PapelHistorico)
	if h.CobreJanela {
		t.Error("arquivo completo com 2h de dados não cobre 24h: a retenção do " +
			"logrotate é finita, e a geração que tinha o passado pode ter " +
			"expirado — ausência de rotacionado não é prova de idade")
	}

	// Com uma âncora anterior à janela, aí sim.
	g := hostCom([]facts.Login{
		entrada("antigo", "10.0.0.1", 30),
		entrada("deploy", "10.0.0.9", 2),
	})
	h, _ = Resumir(g, agora, 24*time.Hour).Fonte(facts.PapelHistorico)
	if !h.CobreJanela {
		t.Error("há registro observado de 30h atrás: se algo tivesse acontecido " +
			"nas últimas 24h, estaria neste arquivo")
	}
}

// Arquivo VAZIO não cobre janela nenhuma, e a razão é adversarial: `: > wtmp`
// produz exatamente a forma de um wtmp legitimamente novo. Existe um check
// inteiro sobre esse estado (antiforense.wtmp_cleared) — a cobertura não pode
// tratá-lo como prova de que nada aconteceu.
func TestArquivoVazioNaoCobreJanela(t *testing.T) {
	f := hostCom(nil)
	h, _ := Resumir(f, agora, 24*time.Hour).Fonte(facts.PapelHistorico)
	if h.CobreJanela {
		t.Error("wtmp vazio saiu como cobertura de 24h")
	}
}

// A GERAÇÃO ROTACIONADA ao lado, na representação que collectLogs produz de
// verdade: `Base` é o caminho COMPLETO do arquivo vivo da série.
func TestGeracaoRotacionadaAoLadoEhContada(t *testing.T) {
	f := hostCom([]facts.Login{
		entrada("antigo", "10.0.0.1", 30),
		entrada("deploy", "10.0.0.9", 2),
	})
	f.Logs = []facts.ArquivoDeLog{
		{Path: "/var/log/wtmp", Base: "/var/log/wtmp", Geracao: 0},
		{Path: "/var/log/wtmp.1", Base: "/var/log/wtmp", Geracao: 1},
		// Datada: a rotação por sufixo de data do logrotate (dateext).
		{Path: "/var/log/wtmp-20260801", Base: "/var/log/wtmp", Geracao: 1, Datada: true},
		// Outra série: não conta.
		{Path: "/var/log/btmp.1", Base: "/var/log/btmp", Geracao: 1},
	}
	h, _ := Resumir(f, agora, 24*time.Hour).Fonte(facts.PapelHistorico)
	if h.GeracoesNaoLidas != 2 {
		t.Errorf("GeracoesNaoLidas = %d, queria 2 — a coleta de login abre só a "+
			"geração viva, e o rodapé precisa dizer o que ficou fechado ao lado",
			h.GeracoesNaoLidas)
	}
}

// A CONTAGEM de recusa é sobre o btmp inteiro; o TOPO é que é sobre origem de
// rede. login(1) e gerenciador de display escrevem no btmp com ut_host VAZIO, e
// filtrar a contagem fazia 40 falhas de console saírem como "nenhuma" — uma
// linha abaixo da cobertura dizendo "40 registros, lido inteiro".
func TestRecusaLocalContaNaTotalizacao(t *testing.T) {
	var logins []facts.Login
	for i := 0; i < 40; i++ {
		logins = append(logins, facts.Login{
			Tipo: facts.TipoLoginUsuario, User: "lex", Linha: "tty1",
			Falhou: true, QuandoU: em(2)})
	}
	logins = append(logins, facts.Login{
		Tipo: facts.TipoLoginUsuario, User: "root", Origem: "185.44.1.7",
		Falhou: true, QuandoU: em(1)})

	r := Resumir(hostCom(logins), agora, 24*time.Hour)
	if r.Recusados != 41 {
		t.Errorf("Recusados = %d, queria 41: a pergunta é quantas tentativas "+
			"foram recusadas, e o console também é uma tentativa", r.Recusados)
	}
	if len(r.TopOrigensRecusa) != 1 || r.TopOrigensRecusa[0].Chave != "185.44.1.7" {
		t.Errorf("o TOPO é por origem de rede — tty física não é endereço: %v",
			r.TopOrigensRecusa)
	}
}

// Origem vista num registro SEM DATA não pode ser chamada de "não observada
// anteriormente": ela FOI observada, e o que falta é saber se foi antes ou
// dentro da janela. Preferir não classificar a fazer uma afirmação temporal que
// o registro impede.
func TestOrigemVistaSemDataNaoEhNaoObservadaAntes(t *testing.T) {
	f := hostCom([]facts.Login{
		entrada("deploy", "10.0.0.1", 30),
		{Tipo: facts.TipoLoginUsuario, User: "deploy", Origem: "185.44.1.7"},
		entrada("deploy", "185.44.1.7", 2),
	})
	r := Resumir(f, agora, 24*time.Hour)
	if !r.OrigensNaoObservadasAntesCalc {
		t.Fatal("há âncora de 30h atrás: a pergunta pode ser feita")
	}
	if r.OrigensNaoObservadasAntes != 0 {
		t.Errorf("= %d, queria 0: 185.44.1.7 aparece num registro sem data, e "+
			"esse registro impede a afirmação em vez de sustentá-la",
			r.OrigensNaoObservadasAntes)
	}
}
