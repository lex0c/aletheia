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

	// Ciclo marca o nó em que a descida PAROU porque o pid já estava no
	// caminho. Sem ele, um ciclo A→B→A fabrica uma linhagem alternada que não
	// existe, até o teto de profundidade — gerações inventadas, indistinguíveis
	// de gerações reais.
	Ciclo bool `json:"cycle,omitempty"`

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
		var raizes []*facts.Process
		for i := range f.Processes {
			p := &f.Processes[i]
			if p.PPID != 0 && f.ProcessByPID(p.PPID) != nil {
				continue
			}
			raizes = append(raizes, p)
		}

		// E DEPOIS o que nenhuma raiz alcança.
		//
		// Este bloco é o conserto de uma primitiva de OCULTAÇÃO. O teste acima
		// exclui quem tem pai visível; num ciclo (10 é pai de 11, 11 é pai de
		// 10) os dois têm pai visível e nenhum é raiz — então nenhum aparece,
		// `truncated` fica false e nenhum sinal é emitido. Medido: com {1},
		// {10,ppid 11}, {11,ppid 10} e {42,ppid 42}, a árvore devolvia SÓ o pid
		// 1. Apontar o próprio PPid para um filho era um jeito grátis de sumir
		// da única ferramenta feita para expor linhagem.
		//
		// Um componente órfão entra pela MENOR pid dele, e só uma vez.
		alcancados := map[int]bool{}
		for _, r := range raizes {
			marcarAlcancados(r.PID, filhosDe, alcancados)
		}
		orfaos := 0
		var extras []*facts.Process
		for i := range f.Processes {
			p := &f.Processes[i]
			if alcancados[p.PID] {
				continue
			}
			extras = append(extras, p)
			orfaos += marcarAlcancados(p.PID, filhosDe, alcancados)
		}
		if len(extras) > 0 {
			a.Sinais = append(a.Sinais, strconv.Itoa(orfaos)+" processo(s) que NENHUMA "+
				"raiz alcança: a cadeia de pais deles tem ciclo, ou aponta para um pai "+
				"que é descendente do próprio processo. Não é estado normal de /proc — "+
				"e numa árvore ingênua eles seriam INVISÍVEIS")
		}

		for _, p := range append(raizes, extras...) {
			a.Raizes = append(a.Raizes, montarNo(f, p, filhosDe, prof, &orcamento, map[int]bool{}))
		}
		sort.Slice(a.Raizes, func(i, j int) bool { return a.Raizes[i].PID < a.Raizes[j].PID })
		a.Achou = len(a.Raizes) > 0
		a.marcarTruncagem(orcamento)
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

	no := montarNo(f, p, filhosDe, prof, &orcamento, map[int]bool{})
	a.No = &no
	a.marcarTruncagem(orcamento)
	return a
}

// marcarTruncagem declara TODO corte, e não só o do orçamento de nós.
//
// Truncado saía do orçamento apenas — e o corte comum é o outro, porque
// profPadrao é 4: numa árvore de systemd com sete níveis a resposta vinha com
// `truncated:false` e dezenas de nós carregando children_omitted>0. Um modelo
// que conferisse a bandeira antes de concluir "o pid 1 não tem descendente que
// case com X" era informado de que a visão estava completa depois de a maior
// parte da árvore ter sido descartada. O doc de FilhosOmitidos já dizia que
// corte silencioso se lê como "não havia mais nada".
func (a *ArvoreDeProcessos) marcarTruncagem(orcamento int) {
	if orcamento <= 0 {
		a.Truncado = true
		a.Sinais = append(a.Sinais, "a árvore passou do teto de "+
			strconv.Itoa(tetoDeNos)+" nós e foi cortada: children_omitted conta o resto")
	}
	omitidos := 0
	var contar func(n *NoDaArvore)
	contar = func(n *NoDaArvore) {
		omitidos += n.FilhosOmitidos
		for i := range n.Filhos {
			contar(&n.Filhos[i])
		}
	}
	if a.No != nil {
		contar(a.No)
	}
	for i := range a.Raizes {
		contar(&a.Raizes[i])
	}
	if omitidos > 0 && !a.Truncado {
		a.Truncado = true
		a.Sinais = append(a.Sinais, strconv.Itoa(omitidos)+" descendente(s) não "+
			"couberam na profundidade pedida: aumente `depth` ou peça a subárvore "+
			"pelo pid — children_omitted diz onde o corte caiu")
	}
}

// marcarAlcancados percorre os descendentes e devolve quantos marcou. O mapa é
// a guarda de ciclo: um componente cíclico é percorrido uma vez só.
func marcarAlcancados(pid int, filhosDe map[int][]int, vistos map[int]bool) int {
	if vistos[pid] {
		return 0
	}
	vistos[pid] = true
	n := 1
	for _, c := range filhosDe[pid] {
		n += marcarAlcancados(c, filhosDe, vistos)
	}
	return n
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
	prof int, orcamento *int, naPilha map[int]bool) NoDaArvore {

	n := noRaso(f, p)

	// A guarda é do CAMINHO, e não da autorreferência.
	//
	// A versão anterior só recusava `fp.PID == p.PID`, que pega A→A e deixa
	// passar A→B→A — e a caminhada da §16 é exatamente a que um ciclo estraga.
	// Medido: com 10 e 11 apontando um para o outro, `depth:6` devolvia seis
	// níveis alternando os mesmos dois processos, uma cadeia de gerações que
	// não existe e que se lê como linhagem real. A caminhada de ANCESTRAIS,
	// sessenta linhas acima, já se defendia disso; a de descendentes não.
	if naPilha[p.PID] {
		n.Ciclo = true
		n.FilhosOmitidos = len(filhosDe[p.PID])
		return n
	}
	naPilha[p.PID] = true
	defer delete(naPilha, p.PID)

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
		*orcamento--
		n.Filhos = append(n.Filhos, montarNo(f, fp, filhosDe, prof-1, orcamento, naPilha))
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
