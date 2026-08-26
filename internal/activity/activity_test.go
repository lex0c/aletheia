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

// O teto de 2000 registros NÃO é o único jeito de o passado ficar de fora — o
// logrotate roda no wtmp e no btmp por padrão em toda distribuição, e a coleta
// de login só abre a geração VIVA.
//
// Sem contar o que existe ao lado, no dia 2 do mês um wtmp de duas horas com
// wtmp.1 fechado ao lado saía como `≥24h`: o falso "limpo" produzido pelo campo
// que existe para impedi-lo.
func TestGeracaoRotacionadaAoLadoDerrubaACobertura(t *testing.T) {
	logins := []facts.Login{entrada("deploy", "10.0.0.9", 2)}
	f := hostCom(logins)
	// Leitura completa da geração viva: o teto não mordeu.
	f.FontesDeLogin[0].Truncada = false

	t.Run("sem rotacionado ao lado", func(t *testing.T) {
		r := Resumir(f, agora, 24*time.Hour)
		h, _ := r.Fonte(facts.PapelHistorico)
		if !h.CobreJanela {
			t.Error("o arquivo foi lido inteiro e não há geração ao lado: se " +
				"algo tivesse acontecido nas 24h, estaria ali")
		}
	})

	t.Run("com rotacionado ao lado", func(t *testing.T) {
		g := hostCom(logins)
		g.Logs = []facts.ArquivoDeLog{
			{Path: "/var/log/wtmp", Base: "wtmp", Geracao: 0},
			{Path: "/var/log/wtmp.1", Base: "wtmp", Geracao: 1},
		}
		r := Resumir(g, agora, 24*time.Hour)
		h, _ := r.Fonte(facts.PapelHistorico)
		if h.GeracoesNaoLidas != 1 {
			t.Fatalf("GeracoesNaoLidas = %d, queria 1", h.GeracoesNaoLidas)
		}
		if h.CobreJanela {
			t.Error("o wtmp.1 existe e não foi aberto: a leitura alcança 2h, " +
				"e afirmar cobertura de 24h aqui é o falso 'limpo' que esta " +
				"feature existe para não cometer")
		}
	})
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
