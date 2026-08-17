package env

// A volta: de nome gravado para valor.
//
// Um `collect` grava o ambiente da COLETA — o que aquela execução conseguiu ver,
// e por que não viu o resto. O `analyze` precisa reconstruir isso EXATAMENTE, e
// nunca sondar a máquina onde a análise está rodando: a cobertura pertence a
// quem coletou.
//
// Os nomes viajam como texto de propósito. Um bitmask numérico gravado hoje
// mudaria de significado quando alguém inserisse uma capacidade no meio do
// iota — e o dump de um incidente é lido meses depois, por um binário mais novo.

// CapDeNome devolve a capacidade com aquele nome.
//
// Nome desconhecido não é erro: é um dump de uma versão que sondava algo que
// este binário não conhece. Ignorá-lo é seguro — nenhum check daqui pede uma
// capacidade que não existe aqui. Fingir que a conhecemos é que seria mentira.
func CapDeNome(n string) (Cap, bool) {
	for _, e := range capNames {
		if e.n == n {
			return e.c, true
		}
	}
	return 0, false
}

// CapsDeNomes remonta o conjunto, devolvendo à parte os nomes que este binário
// não reconhece — para que quem chama possa DIZER isso em vez de engolir.
func CapsDeNomes(ns []string) (Cap, []string) {
	var c Cap
	var estranhos []string
	for _, n := range ns {
		if v, ok := CapDeNome(n); ok {
			c |= v
			continue
		}
		estranhos = append(estranhos, n)
	}
	return c, estranhos
}

// TodasAsCaps é o conjunto que este binário sabe sondar. Serve para descobrir o
// que um dump ANTIGO não declarou — capacidade que ninguém sondou não pode
// aparecer como "indisponível" seco, porque isso se confunde com "sondei e não
// tinha".
func TodasAsCaps() []string {
	out := make([]string, 0, len(capNames))
	for _, e := range capNames {
		out = append(out, e.n)
	}
	return out
}

// SourceDeNome devolve a origem gravada. Qualquer coisa que não seja "image" é
// tratada como host vivo, que é o padrão da ferramenta.
func SourceDeNome(s string) Source {
	if s == "image" {
		return SourceImage
	}
	return SourceLive
}

// ClockDeCodigo devolve o estado do relógio gravado. Código fora da faixa vira
// desconhecido — que é a resposta honesta para "não sei o que esse número era".
func ClockDeCodigo(n int) ClockState {
	switch ClockState(n) {
	case ClockSynced:
		return ClockSynced
	case ClockUnsynced:
		return ClockUnsynced
	}
	return ClockUnknown
}
