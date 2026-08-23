//go:build race

package mcp

import "testing"

// pularSobCorrida tira as capturas VIVAS do host de baixo do -race.
//
// Elas rodam facts.Collect sobre o filesystem REAL do runner — collectCodigo
// varre arquivo por arquivo com regex —, e sob o detector de corrida isso é
// dezenas de vezes mais lento: na CI estourou o teto de 10 min do pacote, com um
// teste preso em analisarConteudo. A concorrência do próprio Collect (as
// goroutines de analisarFila) É exercitada sob -race pelo pacote facts, que roda
// em segundos com entrada controlada; repeti-la aqui, sobre o host inteiro, não
// acrescenta cobertura de corrida — só tempo. E o comportamento vivo é coberto
// pela suíte de cenários, em contêiner.
func pularSobCorrida(t *testing.T) {
	t.Helper()
	t.Skip("captura viva do host é pesada demais sob -race (estoura o teto do " +
		"pacote); a corrida de facts.Collect é coberta pelo pacote facts, e o " +
		"comportamento vivo pela suíte de cenários")
}
