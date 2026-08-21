package facts

import "testing"

// Um PID oculto que também é PAI de um processo visível é achado pelas DUAS
// vias: o cruzarPPID o vê pelo filho, e a sondagem o vê pela faixa. Ele precisa
// sair UMA vez.
//
// Não é hipótese. Enquanto a sondagem parava em 65536, a colisão dependia de o
// pai ter PID baixo e quase nunca acontecia; cobrindo pid_max inteiro ela passou
// a ser a regra. Sem o filtro, o relatório sairia com duas linhas para o mesmo
// processo — uma CRITICAL (via ppid, que não tem corrida) e uma não —, que é o
// tipo de ruído que faz o operador duvidar do resto.
func TestSondagemNaoRepeteOQueOPPIDJaAchou(t *testing.T) {
	// PIDs altos e inventados: o que está sob teste é a DECISÃO sobre um
	// conjunto de candidatos, não a resposta do kernel. Números acima de
	// qualquer pid_max real garantem que nenhum tgidDe/readTrim case com
	// processo de verdade e mude o resultado por acidente.
	const jaVisto, novo = 9_000_001, 9_000_002

	cand := map[int]string{jaVisto: "kill(2)", novo: "kill(2)"}
	out := ocultosDeCandidatos(cand, map[int]bool{jaVisto: true})

	if len(out) != 1 {
		t.Fatalf("saíram %d achados, queria 1: %+v", len(out), out)
	}
	if out[0].PID != novo {
		t.Errorf("saiu o pid %d: o que já tinha sido achado por outra via não "+
			"pode voltar pela sondagem", out[0].PID)
	}
}

// E o contrário precisa continuar valendo: sem colisão, todo candidato vira
// achado, em ordem de PID.
//
// A ordem não é estética. A varredura é paralela e monta um mapa, e mapa em Go
// itera fora de ordem — sem ordenar, duas execuções do mesmo host produziriam
// relatórios diferentes, e comparar dois relatórios é metade do uso da
// ferramenta.
func TestOcultosSaemOrdenadosEPorTestemunha(t *testing.T) {
	cand := map[int]string{9_000_003: "kill(2)", 9_000_001: "stat em /proc", 9_000_002: "kill(2)"}
	out := ocultosDeCandidatos(cand, nil)

	if len(out) != 3 {
		t.Fatalf("saíram %d achados, queria 3", len(out))
	}
	for i, quer := range []int{9_000_001, 9_000_002, 9_000_003} {
		if out[i].PID != quer {
			t.Fatalf("posição %d é o pid %d, queria %d: a saída tem que ser estável",
				i, out[i].PID, quer)
		}
	}
	// A testemunha que respondeu entra no texto: "responde a kill(2)" e
	// "responde a stat em /proc" mandam o analista para lugares diferentes.
	if out[0].Como != "sondagem: responde a stat em /proc e não aparece na listagem" {
		t.Errorf("o achado não nomeia a testemunha: %q", out[0].Como)
	}
	if out[1].Como != "sondagem: responde a kill(2) e não aparece na listagem" {
		t.Errorf("o achado não nomeia a testemunha: %q", out[1].Como)
	}
}
