package checks

import (
	"sort"
	"strconv"
	"strings"
)

// O pool de workers, e por que ele quase quebrou dois checks de rede.
//
// # O caso
//
// Uma saída de `ss -tunap` de um servidor de aplicação em produção: 524
// processos, 1053 sockets, e a topologia mais banal que existe —
//
//	php-fpm  →  35.231.119.5:443    uma API externa
//	php-fpm  →  10.142.0.55:27017   o MongoDB da casa
//
// 497 dos 524 processos tinham as duas pontas abertas ao mesmo tempo, e "saída
// externa e saída interna no mesmo processo" é, letra por letra, a assinatura de
// pivô da §12.2. O check produzia 497 avisos. Nenhum deles era ataque.
//
// # Por que isso é pior que um falso positivo comum
//
// Um falso positivo isolado custa uma investigação. Este custa o RELATÓRIO: 497
// linhas iguais não são um relatório, são uma parede — e a lição que o operador
// tira dela é ignorar a saída inteira, junto com o achado que importaria.
//
// E o número não é fixo: ele CRESCE com o tamanho do pool. Um servidor maior
// produz um relatório pior, que é exatamente o contrário do que se quer.
//
// # A regra
//
// Achados que diferem só pelo PID viram UM, com a contagem e os pids dentro. A
// identidade de um achado de rede não é o processo: é o EXECUTÁVEL falando com
// os MESMOS destinos. Trinta workers do mesmo pool são um fato sobre o serviço,
// não trinta fatos.
//
// O implante continua aparecendo: ele é um processo com um par de destinos que
// mais ninguém tem, e um grupo de um se comporta exatamente como antes — mesmo
// sujeito `pid=N`, mesma evidência. Nada foi perdido; o que sumiu foi a
// repetição.
type poolDeProcessos struct {
	ordem []string
	pids  map[string][]int
}

func novoPool() *poolDeProcessos {
	return &poolDeProcessos{pids: map[string][]int{}}
}

// junta registra um processo sob a FORMA dele: o executável mais o conjunto de
// destinos, que é o que identifica o achado.
func (g *poolDeProcessos) junta(exe string, destinos []string, pid int) string {
	chave := exe + "\x00" + strings.Join(ordenadoUnico(destinos), ",")
	if _, visto := g.pids[chave]; !visto {
		g.ordem = append(g.ordem, chave)
	}
	g.pids[chave] = append(g.pids[chave], pid)
	return chave
}

// Grupos devolve as formas na ordem em que apareceram.
func (g *poolDeProcessos) Grupos() []string { return g.ordem }

// PIDs devolve os processos daquela forma, em ordem numérica — a ordem de
// aparição é a do readdir de /proc, que muda entre execuções e faria o mesmo
// host produzir relatórios diferentes.
func (g *poolDeProcessos) PIDs(chave string) []int {
	ps := g.pids[chave]
	sort.Ints(ps)
	return ps
}

// maxPIDsNoAchado é quantos pids cabem na evidência. O teto existe porque a
// alternativa é uma linha de 500 números, que ninguém lê e que quebra o
// alinhamento do relatório inteiro. A CONTAGEM nunca é truncada.
const maxPIDsNoAchado = 8

// notaDoPool é a frase que o grupo acrescenta ao achado.
//
// Ela diz o que a repetição SIGNIFICA sem afirmar legitimidade: a ferramenta não
// sabe se o pool é legítimo, e dizer que é seria trocar um erro por outro. O que
// ela pode afirmar é a forma — e a forma de um pool de aplicação é diferente da
// de um implante, que costuma ser um processo só.
func notaDoPool(n int, exe string) string {
	return strconv.Itoa(n) + " processos do MESMO executável (" + exe + ") com o " +
		"MESMO conjunto de destinos: é a forma de um pool de aplicação — php-fpm, " +
		"uwsgi, worker de fila —, e não a de um implante, que costuma ser um " +
		"processo só. A pergunta continua sendo sobre o EXECUTÁVEL, e ela vale " +
		"uma vez, não " + strconv.Itoa(n)
}

// listaDePIDs formata os processos do grupo, com teto e sem esconder o total.
func listaDePIDs(pids []int) string {
	var ss []string
	for i, p := range pids {
		if i >= maxPIDsNoAchado {
			ss = append(ss, "… (+"+strconv.Itoa(len(pids)-maxPIDsNoAchado)+")")
			break
		}
		ss = append(ss, strconv.Itoa(p))
	}
	return "pids: " + strings.Join(ss, " ")
}

func ordenadoUnico(ss []string) []string {
	visto := map[string]bool{}
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		if !visto[s] {
			visto[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
