package activity

import (
	"testing"
)

func ev(kind Kind, user, origem string, at string) Evento {
	return Evento{Kind: kind, User: user, Origem: origem, At: at,
		Testemunhas: []string{"wtmp"}}
}

// O eixo de ORIGEM responde "de onde alguém entrou". `:0` é display do X, `~` é
// marcador de boot e vazio é tty física: nenhum dos três é endereço, e uma
// linha para eles seria uma resposta a outra pergunta.
func TestTabelaPorOrigemSoTemOrigemDeRede(t *testing.T) {
	gs := Agrupar([]Evento{
		ev(KindLoginAceito, "lex", ":0", at(2, 0)),
		ev(KindLoginAceito, "lex", "", at(2, 0)),
		ev(KindLoginAceito, "deploy", "10.0.0.9", at(1, 0)),
	}, PorOrigem)
	if len(gs) != 1 || gs[0].Chave != "10.0.0.9" {
		t.Fatalf("a tabela de origem saiu como %+v", gs)
	}
}

// A ordem é por VOLUME, com desempate pela chave: duas execuções sobre o mesmo
// retrato precisam sair iguais.
func TestTabelaOrdenaPorVolumeComDesempateEstavel(t *testing.T) {
	var evs []Evento
	for i := 0; i < 3; i++ {
		evs = append(evs, ev(KindLoginRecusado, "root", "203.0.113.9", at(2, i)))
	}
	evs = append(evs,
		ev(KindLoginAceito, "deploy", "10.0.0.9", at(1, 0)),
		ev(KindLoginAceito, "ana", "10.0.0.8", at(1, 0)))

	gs := Agrupar(evs, PorUsuario)
	if len(gs) != 3 || gs[0].Chave != "root" || gs[0].Recusados != 3 {
		t.Fatalf("ordem/contagem erradas: %+v", gs)
	}
	// Empate em 1: `ana` antes de `deploy`.
	if gs[1].Chave != "ana" || gs[2].Chave != "deploy" {
		t.Errorf("o desempate não é estável: %+v", gs)
	}
}

// Evento sem data não estreita nem alarga o intervalo do grupo, e no sumário
// ele é contado À PARTE: somá-lo ao total faria o intervalo parecer cobrir
// tudo que foi contado.
func TestSemDataNaoAncoraIntervaloEEhContadoAParte(t *testing.T) {
	evs := []Evento{
		ev(KindLoginAceito, "deploy", "10.0.0.9", at(2, 0)),
		ev(KindLoginAceito, "deploy", "10.0.0.9", ""),
	}
	gs := Agrupar(evs, PorUsuario)
	if gs[0].Primeiro != at(2, 0) || gs[0].Ultimo != at(2, 0) {
		t.Errorf("o evento sem data mexeu no intervalo: %+v", gs[0])
	}
	s := Sumarizar(evs)
	if s.Total != 2 || s.SemData != 1 {
		t.Errorf("Total=%d SemData=%d, queria 2 e 1", s.Total, s.SemData)
	}
	if s.Primeiro != at(2, 0) {
		t.Errorf("Primeiro = %q: o sem-data não pode ancorar o intervalo", s.Primeiro)
	}
}

// Só a divergência AFIRMADA conta. `nao_confirmado` é a ausência que não
// sustenta afirmação, e somá-la inflaria "o número que merece investigação"
// com exatamente o que ele existe para não incluir.
func TestSumarioContaSoDivergenciaAfirmada(t *testing.T) {
	a := ev(KindLoginAceito, "x", "10.0.0.1", at(2, 0))
	a.Divergente = DivergenteAusente
	b := ev(KindLoginAceito, "y", "10.0.0.2", at(2, 0))
	b.Divergente = DivergenteNaoConfirmado
	if got := Sumarizar([]Evento{a, b}).Divergentes; got != 1 {
		t.Errorf("Divergentes = %d, queria 1", got)
	}
}
