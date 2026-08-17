package main

import (
	"testing"
	"time"

	"github.com/lex0c/aletheia/internal/facts"
)

// constante separa AUTOMAÇÃO de pessoa, e é a decisão central do amostrador:
// intervalo regular é máquina, irregular é gente.
func TestConstanteSeparaAutomacaoDePessoa(t *testing.T) {
	casos := []struct {
		nome  string
		d     []float64
		quer  bool
		media float64
	}{
		{"exato", []float64{600, 600, 600}, true, 600},
		{"com jitter de amostragem", []float64{595, 610, 600}, true, 601.67},
		{"humano: irregular", []float64{30, 600, 90}, false, 0},
		{"um fora basta para derrubar", []float64{600, 600, 900}, false, 0},
		{"vazio não é padrão", nil, false, 0},
	}
	for _, c := range casos {
		t.Run(c.nome, func(t *testing.T) {
			m, ok := constante(c.d)
			if ok != c.quer {
				t.Fatalf("constante(%v) = %v, queria %v", c.d, ok, c.quer)
			}
			if ok && (m < c.media-1 || m > c.media+1) {
				t.Errorf("média %v, queria ~%v", m, c.media)
			}
		})
	}
}

// O cruzamento das duas cadências: o amostrador mede o ritmo DE FORA sem saber
// de onde vem, e a coleta completa sabe quais gatilhos existem. Juntar os dois
// é o que transforma "há automação" em "é este cron aqui".
func TestGatilhoComPeriodoNomeiaQuemDispara(t *testing.T) {
	f := &facts.Facts{
		Cron: []facts.CronEntry{
			{File: "/etc/cron.d/x", Line: 1, Schedule: "*/10 * * * *", IntervalSec: 600},
			{File: "/etc/crontab", Line: 9, Schedule: "17 * * * *", IntervalSec: 3600},
		},
		Units: []facts.Unit{
			{Name: "beacon.timer", OnUnitActiveSec: "45s"},
			{Name: "sem-periodo.timer"},
		},
	}
	if got := gatilhoComPeriodo(f, 600); got == "" || !contemTudo(got, "cron", "*/10") {
		t.Errorf("não nomeou o cron de 10 minutos: %q", got)
	}
	if got := gatilhoComPeriodo(f, 45); got == "" || !contemTudo(got, "beacon.timer", "45s") {
		t.Errorf("não nomeou o timer de 45s: %q", got)
	}
	// Jitter dentro da tolerância ainda casa: a amostragem não é pontual.
	if got := gatilhoComPeriodo(f, 640); got == "" {
		t.Error("640s tinha que casar com o cron de 600s dentro da tolerância")
	}
	// E não pode inventar: 300s não é nenhum dos gatilhos.
	if got := gatilhoComPeriodo(f, 300); got != "" {
		t.Errorf("nenhum gatilho tem 300s, e devolveu %q", got)
	}
	if got := gatilhoComPeriodo(nil, 600); got != "" {
		t.Errorf("sem varredura completa não há gatilho a nomear: %q", got)
	}
}

func contemTudo(s string, partes ...string) bool {
	for _, p := range partes {
		if !contem(s, p) {
			return false
		}
	}
	return true
}

func contem(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// Conexão de ENTRADA não é destino: o "peer" dela é a porta efêmera de quem
// nos procurou, número diferente a cada requisição. Contá-las faz um servidor
// com tráfego imprimir uma linha por requisição, com o beacon enterrado no
// meio — apareceu no primeiro cenário, com o listener do próprio rig.
func TestAmostradorSoOlhaOQueSai(t *testing.T) {
	entrada := func(porta int) facts.Socket {
		return facts.Socket{Proto: "tcp", State: "ESTAB", Dir: facts.DirIn,
			PeerIP: "10.0.0.9", PeerPort: porta, LocalPort: 443}
	}
	saida := facts.Socket{Proto: "tcp", State: "ESTAB", Dir: facts.DirOut,
		PeerIP: "51.91.190.241", PeerPort: 443, LocalPort: 51234}

	a := novoAmostrador()
	t0 := tempoDeTeste(0)
	// primeira amostra é a referência
	a.amostra(&facts.Facts{Sockets: []facts.Socket{entrada(40001)}}, nil, t0)

	linhas := a.amostra(&facts.Facts{
		Sockets: []facts.Socket{entrada(40002), entrada(40003), saida},
	}, nil, tempoDeTeste(5))

	if len(linhas) != 1 {
		t.Fatalf("esperava só a conexão de SAÍDA, deu %d linha(s): %v", len(linhas), linhas)
	}
	if !contem(linhas[0], "51.91.190.241:443") {
		t.Errorf("a linha não é a da saída: %q", linhas[0])
	}
}

// O ritmo é medido sobre REAPARIÇÕES, não sobre amostras. Um destino que fica
// de pé o tempo todo — um serviço legítimo — tem UMA aparição, por mais que
// seja amostrado cem vezes.
func TestAmostradorNaoConfundePermanenteComPeriodico(t *testing.T) {
	a := novoAmostrador()
	fixo := facts.Facts{Sockets: []facts.Socket{{
		Proto: "tcp", State: "ESTAB", Dir: facts.DirOut,
		PeerIP: "10.0.0.5", PeerPort: 5432, LocalPort: 40000,
	}}}
	for i := 0; i < 10; i++ {
		for _, l := range a.amostra(&fixo, nil, tempoDeTeste(i*5)) {
			t.Errorf("conexão que nunca caiu não pode gerar evento: %q", l)
		}
	}
	if len(a.jaFalouDoPeriodo) != 0 {
		t.Error("um destino permanente não tem período: ele nunca voltou porque nunca saiu")
	}
}

// E o pulso: sai e volta em ritmo constante, três vezes, e aí sim.
func TestAmostradorMedeORitmoDeQuemVaiEVolta(t *testing.T) {
	a := novoAmostrador()
	com := facts.Facts{Sockets: []facts.Socket{{
		Proto: "tcp", State: "ESTAB", Dir: facts.DirOut,
		PeerIP: "51.91.190.241", PeerPort: 443, LocalPort: 40000,
	}}}
	sem := facts.Facts{}

	var mediu bool
	// pulso de 10s: presente num instante, ausente no seguinte
	for i := 0; i < 9; i++ {
		f := &sem
		if i%2 == 0 {
			f = &com
		}
		for _, l := range a.amostra(f, nil, tempoDeTeste(i*5)) {
			if contem(l, "intervalo constante é AUTOMAÇÃO") && contem(l, "~10s") {
				mediu = true
			}
		}
	}
	if !mediu {
		t.Error("três voltas de 10s são um período, e ele não foi afirmado")
	}
	// E afirmado UMA vez: repetir a cada volta afogaria o resto.
	if n := len(a.jaFalouDoPeriodo); n != 1 {
		t.Errorf("o período tem que ser dito uma vez só, e foi %d", n)
	}
}

// tempoDeTeste dá instantes determinísticos: o amostrador mede intervalos, e um
// teste que use o relógio de verdade mediria o escalonador.
func tempoDeTeste(seg int) time.Time {
	return time.Date(2026, 8, 17, 3, 0, 0, 0, time.UTC).Add(time.Duration(seg) * time.Second)
}
