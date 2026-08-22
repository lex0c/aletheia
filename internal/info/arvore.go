package info

import (
	"sort"
	"strconv"

	"github.com/lex0c/aletheia/internal/facts"
)

// A árvore de processos: a linhagem na forma em que ela se lê.
//
// # Por que a lista plana não basta
//
// O censo responde "quem roda o quê"; o dossiê responde "o que é este pid". A
// pergunta que sobra é a da §16 do runbook, e é a primeira que um respondedor
// faz diante de um processo estranho: DE ONDE ele veio. Um shell cujo pai é um
// servidor web conta uma história inteira — e numa lista plana ordenada por PID
// os dois ficam a trezentas linhas de distância.
//
// O pai é o vetor de entrada. É por ele que se descobre que o minerador não foi
// instalado: ele foi executado por um php-fpm que atendeu um POST.

// NoDaArvore é um processo na árvore.
type NoDaArvore struct {
	PID  int    `json:"pid"`
	PPID int    `json:"ppid"`
	UID  int    `json:"uid"`
	Nome string `json:"name,omitempty"`
	// Linha é o argv REDIGIDO e encurtado — a mesma forma que o resto do
	// pacote usa, para que um segredo em linha de comando não vaze por aqui
	// depois de ter sido mascarado em todo lugar.
	Linha string `json:"cmdline,omitempty"`
	// Container é vazio para processo do HOST, e a diferença muda qual
	// pergunta faz sentido sobre o binário dele.
	Container string `json:"container,omitempty"`
	Estado    string `json:"state,omitempty"`

	Filhos []NoDaArvore `json:"children,omitempty"`
	// FilhosOmitidos conta o que não coube na profundidade ou no teto. Corte
	// silencioso se lê como "não havia mais nada", e o número é a diferença.
	FilhosOmitidos int `json:"children_omitted,omitempty"`
}

// ArvoreDeProcessos é a resposta.
type ArvoreDeProcessos struct {
	Alvo int `json:"target,omitempty"`
	// Achou é falso quando o PID não está neste retrato. Não é erro: é
	// resposta, e Sinais diz o que ela significa.
	Achou bool `json:"found"`

	// Ancestrais vai do PAI até a raiz, nessa ordem. Sem Filhos preenchidos:
	// aqui a pergunta é a cadeia, não a vizinhança.
	Ancestrais []NoDaArvore `json:"ancestors,omitempty"`
	No         *NoDaArvore  `json:"node,omitempty"`

	// Raizes é a resposta quando nenhum alvo foi pedido.
	Raizes []NoDaArvore `json:"roots,omitempty"`

	Truncado bool     `json:"truncated"`
	Sinais   []string `json:"signals,omitempty"`
}

const (
	profPadrao = 4
	profMaxima = 16
	// tetoDeNos existe porque um host com trinta mil processos produziria uma
	// árvore que ninguém lê e que estoura qualquer orçamento de resposta. O que
	// não couber é CONTADO, nunca calado.
	tetoDeNos = 2000
)

// Arvore monta a linhagem de um PID, ou as raízes quando pid <= 0.
func Arvore(f *facts.Facts, pid, prof int) *ArvoreDeProcessos {
	switch {
	case prof <= 0:
		prof = profPadrao
	case prof > profMaxima:
		prof = profMaxima
	}
	a := &ArvoreDeProcessos{Alvo: pid}
	filhosDe := indiceDeFilhos(f)
	orcamento := tetoDeNos

	if pid <= 0 {
		// Sem alvo: as RAÍZES do que este retrato enxerga. Raiz é quem não tem
		// pai visível — o init, e também o processo cujo pai morreu ou está
		// fora do namespace que a coleta alcançou.
		for i := range f.Processes {
			p := &f.Processes[i]
			if p.PPID != 0 && f.ProcessByPID(p.PPID) != nil {
				continue
			}
			a.Raizes = append(a.Raizes, montarNo(f, p, filhosDe, prof, &orcamento))
		}
		sort.Slice(a.Raizes, func(i, j int) bool { return a.Raizes[i].PID < a.Raizes[j].PID })
		a.Achou = len(a.Raizes) > 0
		a.Truncado = orcamento <= 0
		if a.Truncado {
			a.Sinais = append(a.Sinais, "a árvore passou do teto de "+
				strconv.Itoa(tetoDeNos)+" nós e foi cortada: children_omitted conta o resto")
		}
		return a
	}

	p := f.ProcessByPID(pid)
	if p == nil {
		a.Sinais = append(a.Sinais, "nenhum processo com este pid nos fatos desta "+
			"coleta — ele pode ter terminado, ou nunca ter existido")
		return a
	}
	a.Achou = true

	// Ancestrais, do pai até onde a cadeia alcançar. O teto de 32 é contra
	// CICLO: /proc é lido processo a processo, e um retrato inconsistente
	// (ou hostil) pode conter A→B→A. Sem teto isto seria um laço infinito
	// dentro de um servidor.
	visto := map[int]bool{pid: true}
	for ppid, n := p.PPID, 0; ppid > 0 && n < 32; n++ {
		pp := f.ProcessByPID(ppid)
		if pp == nil {
			a.Sinais = append(a.Sinais, "o pai pid="+strconv.Itoa(ppid)+
				" não está neste retrato: ele morreu e este processo foi adotado, "+
				"e a linhagem original se perdeu")
			break
		}
		if visto[ppid] {
			a.Sinais = append(a.Sinais, "ciclo na cadeia de pais em pid="+
				strconv.Itoa(ppid)+": o retrato é inconsistente aqui")
			break
		}
		visto[ppid] = true
		a.Ancestrais = append(a.Ancestrais, noRaso(f, pp))
		ppid = pp.PPID
	}

	no := montarNo(f, p, filhosDe, prof, &orcamento)
	a.No = &no
	a.Truncado = orcamento <= 0
	if a.Truncado {
		a.Sinais = append(a.Sinais, "a árvore passou do teto de "+
			strconv.Itoa(tetoDeNos)+" nós e foi cortada: children_omitted conta o resto")
	}
	return a
}

func indiceDeFilhos(f *facts.Facts) map[int][]int {
	m := map[int][]int{}
	for i := range f.Processes {
		p := &f.Processes[i]
		m[p.PPID] = append(m[p.PPID], p.PID)
	}
	for _, v := range m {
		sort.Ints(v)
	}
	return m
}

func montarNo(f *facts.Facts, p *facts.Process, filhosDe map[int][]int,
	prof int, orcamento *int) NoDaArvore {

	n := noRaso(f, p)
	filhos := filhosDe[p.PID]
	if prof <= 0 || len(filhos) == 0 {
		n.FilhosOmitidos = len(filhos)
		return n
	}
	for _, pid := range filhos {
		if *orcamento <= 0 {
			n.FilhosOmitidos = len(filhos) - len(n.Filhos)
			return n
		}
		fp := f.ProcessByPID(pid)
		if fp == nil {
			continue
		}
		// Autorreferência: um processo cujo PPID é ele mesmo faria a recursão
		// não terminar. Não acontece num /proc são, e o retrato pode não ser.
		if fp.PID == p.PID {
			continue
		}
		*orcamento--
		n.Filhos = append(n.Filhos, montarNo(f, fp, filhosDe, prof-1, orcamento))
	}
	return n
}

func noRaso(f *facts.Facts, p *facts.Process) NoDaArvore {
	return NoDaArvore{
		PID: p.PID, PPID: p.PPID, UID: p.UID,
		Nome:      nz(p.Exe, p.Comm),
		Linha:     linhaCurta(p),
		Container: p.Container,
		Estado:    p.State,
	}
}
