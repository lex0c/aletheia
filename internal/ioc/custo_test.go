package ioc

import (
	"strconv"
	"testing"
	"time"
)

func listaGrande(n int) *Lista {
	l := &Lista{Arquivo: "bench"}
	for i := 0; i < n; i++ {
		h := "d41d8cd98f00b204e9800998ecf8427" + strconv.Itoa(i%10)
		l.Itens = append(l.Itens,
			Indicador{Tipo: Hash, Valor: h + strconv.Itoa(i), Bruto: h, Algo: "md5"},
			Indicador{Tipo: IP, Valor: "10." + strconv.Itoa(i%250) + "." +
				strconv.Itoa((i/250)%250) + "." + strconv.Itoa(i%7), Bruto: "ip"},
		)
	}
	return l
}

// O custo de casar hash e IP NÃO pode crescer com o tamanho da lista.
//
// O Casar varria l.Itens inteiro a cada chamada, com o filtro de tipo dentro do
// laço. Medido antes do índice: 14,2 ns por indicador por chamada — e o volume
// de chamadas é que fazia o estrago, porque varrerProcessos emite
// `5 + len(EnvKeys)` por processo e varrerRede duas por socket. Um servidor com
// 30 mil processos e 100 mil sockets faz ~950 mil chamadas, e com 10 mil
// indicadores (um export de MISP comum, muito abaixo do teto de 16 MiB) isso
// dava 135 SEGUNDOS. O `wtf` tem orçamento de 2s, e o motor só confere o
// Deadline entre checks: uma vez dentro do ioc.match nada interrompia.
//
// A trava é de ESCALA, não de relógio: mede a mesma carga contra uma lista 10×
// maior e exige que o custo não acompanhe. Um limite em milissegundos
// dependeria da máquina e piscaria em CI carregada — que é como uma trava perde
// a confiança de quem a lê.
func TestCasarNaoCresceComOTamanhoDaLista(t *testing.T) {
	if testing.Short() {
		t.Skip("teste de custo: pulado em -short")
	}
	const consultas = 20000
	medir := func(l *Lista) time.Duration {
		l.montarIndice() // fora da medição: ele é pago uma vez por execução
		inicio := time.Now()
		for i := 0; i < consultas; i++ {
			l.Casar(Hash, "d41d8cd98f00b204e9800998ecf84270")
			l.Casar(IP, "203.0.113.7")
		}
		return time.Since(inicio)
	}
	pequena := medir(listaGrande(1000))
	grande := medir(listaGrande(10000))

	// 10× mais indicadores não pode custar mais que 3× — folga generosa para
	// ruído de máquina, e ainda assim intransponível para uma varredura linear,
	// que custaria ~10×.
	if grande > 3*pequena {
		t.Errorf("com 10× mais indicadores o custo foi %v contra %v (%.1f×).\n"+
			"Isso é o perfil da VARREDURA LINEAR que o índice de montarIndice() "+
			"existe para evitar — procure por um laço sobre l.Itens dentro do Casar.",
			grande, pequena, float64(grande)/float64(pequena))
	}
}

func BenchmarkCasarHash(b *testing.B) {
	l := listaGrande(10000)
	l.montarIndice()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l.Casar(Hash, "d41d8cd98f00b204e9800998ecf84270")
	}
}
