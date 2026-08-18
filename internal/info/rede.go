package info

import (
	"sort"
	"strconv"

	"github.com/lex0c/aletheia/internal/facts"
)

// O censo de REDE — a mesma pergunta do censo de processos, feita sobre o
// outro eixo: com quem esta máquina fala, e quem fala com ela.
//
// O que separa isto de `ss -tunap` são as três coisas que separam o censo de
// processos de um `ps`:
//
//	compara com o TETO      contar conexão é fácil. O que responde "por que o
//	                        connect está falhando" é a contagem contra o
//	                        conntrack e contra a faixa de porta efêmera
//	agrupa pelo EXECUTÁVEL  um processo com quatrocentas conexões é UM fato, e
//	                        não quatrocentos. O `ss` imprime as quatrocentas
//	NOMEIA o padrão         um destino por host, sempre na mesma porta, é
//	                        varredura ou movimento lateral — e dizer isso poupa
//	                        a hora que se gasta olhando a lista até perceber

// CensoDeRede é o retrato de com quem esta máquina fala.
type CensoDeRede struct {
	Total     int
	PorEstado []Contagem

	// Escutas é o que a máquina EXPÕE, que é a pergunta que vem primeiro.
	Escutas []Escuta
	// Saida agrupa quem fala para fora pelo executável real.
	Saida []Falante
	// Entrada é quem conectou aqui, agrupado por origem.
	Entrada []Contagem

	Tetos   []TetoDeRede
	Padroes []Padrao

	// SemDono conta os sockets cujo processo não pôde ser identificado. Sem
	// root, o fd de processo alheio é ilegível — e o socket existe do mesmo
	// jeito. Contar é o que impede a lista de parecer completa.
	SemDono int
}

// Escuta é uma porta aberta, com o que decide se ela é superfície de ataque: o
// endereço em que está ligada.
type Escuta struct {
	Proto      string
	Porta      int
	Bind       string
	Executavel string
	PID        int
	// Exposta diz que o bind NÃO é loopback: a porta está aberta para fora.
	Exposta bool
	// DonoDesconhecido separa "ninguém segura" de "não pude ver quem segura".
	DonoDesconhecido bool
	// Sockets é quantos descritores seguram esta MESMA escuta. Com
	// SO_REUSEPORT um serviço divide a porta entre vários processos ou threads,
	// e o `ss` imprime uma linha por descritor — é o ruído que faz um nginx com
	// doze workers parecer doze portas abertas. Aqui é uma escuta, com o número
	// ao lado.
	Sockets int
}

// Falante é um executável e o que ele abriu para fora.
type Falante struct {
	Executavel string
	Conexoes   int
	// Destinos é quantos endereços DISTINTOS — é a diferença entre um pool
	// (muitas conexões, um destino) e um leque (uma conexão, muitos destinos).
	Destinos int
	Publicos int
	Portas   []Contagem
}

// TetoDeRede é um limite com a ocupação medida contra ele.
type TetoDeRede struct {
	Nome  string
	Uso   int
	Teto  int
	Nota  string
	Lido  bool
	Perto bool
}

// portasDeWeb são as portas em que o leque também é a forma NORMAL. Elas NÃO
// são excluídas do reconhecimento — são ordenadas por último e recebem a
// ressalva junto.
//
// A primeira versão deste arquivo as descartava, e isso estava errado por
// construção: a porta é exatamente o campo que o atacante escolhe. C2 moderno
// usa 443 de propósito, e um filtro por porta é um filtro pelo que o adversário
// controla — a ferramenta estaria cega justamente onde ele decidiu se esconder.
//
// O que separa navegador de C2 em 443 não é a porta: é QUEM. Essa é a pergunta
// de propriedade do binário, e o censo não a responde — ele diz onde ela é
// respondida.
var portasDeWeb = map[int]bool{80: true, 443: true, 8080: true, 8443: true}

// minLeque é quantos destinos distintos, na MESMA porta, antes de chamar de
// leque. Abaixo disso é uso normal — dois ou três destinos é qualquer cliente.
const minLeque = 8

// minPool é quantas conexões para o MESMO destino antes de chamar de pool.
const minPool = 8

// CensoDaRede monta o retrato. É puro sobre os fatos: os mesmos números saem de
// um host vivo e de um retrato coletado semanas atrás.
func CensoDaRede(f *facts.Facts) *CensoDeRede {
	c := &CensoDeRede{Total: len(f.Sockets)}

	estados := map[string]int{}
	origens := map[string]int{}
	porExe := map[string]*Falante{}
	escutas := map[string]*Escuta{}
	destinosDe := map[string]map[string]bool{}
	portasDe := map[string]map[int]int{}

	for i := range f.Sockets {
		s := &f.Sockets[i]
		estados[s.State]++
		if s.PID == 0 {
			c.SemDono++
		}

		switch s.Dir {
		case facts.DirListen:
			exe := exeDoPID(f, s.PID)
			k := s.Proto + "|" + strconv.Itoa(s.LocalPort) + "|" + s.LocalIP + "|" + exe
			if e := escutas[k]; e != nil {
				e.Sockets++
				break
			}
			e := &Escuta{
				Proto:            s.Proto,
				Porta:            s.LocalPort,
				Bind:             s.LocalIP,
				Executavel:       exe,
				PID:              s.PID,
				Exposta:          !ehLoopback(s.LocalIP),
				DonoDesconhecido: s.PID == 0,
				Sockets:          1,
			}
			escutas[k] = e
		case facts.DirOut:
			if s.Peer() == "" {
				continue
			}
			exe := exeDoPID(f, s.PID)
			if exe == "" {
				exe = "(dono não identificado)"
			}
			fl := porExe[exe]
			if fl == nil {
				fl = &Falante{Executavel: exe}
				porExe[exe] = fl
				destinosDe[exe] = map[string]bool{}
				portasDe[exe] = map[int]int{}
			}
			fl.Conexoes++
			if s.PeerScope == facts.ScopePublic {
				fl.Publicos++
			}
			destinosDe[exe][s.PeerIP] = true
			portasDe[exe][s.PeerPort]++
		case facts.DirIn:
			if s.PeerIP != "" {
				origens[s.PeerIP]++
			}
		}
	}

	for _, e := range escutas {
		c.Escutas = append(c.Escutas, *e)
	}
	for exe, fl := range porExe {
		fl.Destinos = len(destinosDe[exe])
		fl.Portas = ordenarContagens(portasNomeadas(portasDe[exe]))
		c.Saida = append(c.Saida, *fl)
	}
	sort.Slice(c.Saida, func(i, j int) bool {
		if c.Saida[i].Conexoes != c.Saida[j].Conexoes {
			return c.Saida[i].Conexoes > c.Saida[j].Conexoes
		}
		return c.Saida[i].Executavel < c.Saida[j].Executavel
	})

	// Escuta EXPOSTA primeiro: é a que responde à pergunta que se faz primeiro.
	sort.Slice(c.Escutas, func(i, j int) bool {
		a, b := c.Escutas[i], c.Escutas[j]
		if a.Exposta != b.Exposta {
			return a.Exposta
		}
		if a.Porta != b.Porta {
			return a.Porta < b.Porta
		}
		if a.Proto != b.Proto {
			return a.Proto < b.Proto
		}
		if a.Bind != b.Bind {
			return a.Bind < b.Bind
		}
		return a.Executavel < b.Executavel
	})

	c.PorEstado = ordenarContagens(mapaParaContagens(estados))
	c.Entrada = ordenarContagens(mapaParaContagens(origens))
	c.Tetos = tetosDaRede(f, estados)
	c.Padroes = padroesDeRede(f, porExe, destinosDe, portasDe)
	return c
}

// tetosDaRede monta os limites com a ocupação medida. Teto NÃO LIDO fica de
// fora: uma linha "0 de 0" seria pior que a ausência dela, porque parece medida.
func tetosDaRede(f *facts.Facts, estados map[string]int) []TetoDeRede {
	l := f.LimitesRede
	var out []TetoDeRede

	if l.ConntrackLido && l.ConntrackMax > 0 {
		t := TetoDeRede{
			Nome: "conntrack", Uso: l.ConntrackCount, Teto: l.ConntrackMax, Lido: true,
			Nota: "cheio, o kernel DERRUBA pacote e escreve \"table full\" no dmesg: " +
				"a perda é intermitente e não aparece em log de aplicação",
		}
		t.Perto = t.Uso*10 >= t.Teto*9
		out = append(out, t)
	}

	if faixa := l.FaixaEfemera(); faixa > 0 {
		// TIME-WAIT é o que come a faixa: cada conexão fechada segura a porta
		// de origem por volta de 60s antes de devolvê-la.
		tw := estados["TIME-WAIT"]
		t := TetoDeRede{
			Nome: "portas efêmeras", Uso: tw, Teto: faixa, Lido: true,
			Nota: "TIME-WAIT segura a porta de origem por ~60s depois do fecho; " +
				"esgotar a faixa faz connect() falhar com EADDRNOTAVAIL",
		}
		t.Perto = t.Uso*10 >= t.Teto*9
		out = append(out, t)
	}
	return out
}

// padroesDeRede nomeia as formas. É a parte que nenhum `ss` dá.
func padroesDeRede(
	f *facts.Facts,
	porExe map[string]*Falante,
	destinosDe map[string]map[string]bool,
	portasDe map[string]map[int]int,
) []Padrao {
	var out []Padrao
	exes := make([]string, 0, len(porExe))
	for e := range porExe {
		exes = append(exes, e)
	}
	sort.Strings(exes)

	for _, exe := range exes {
		// LEQUE: muitos destinos DISTINTOS na mesma porta.
		for porta, n := range portasDe[exe] {
			if n < minLeque {
				continue
			}
			distintos := destinosDistintosNaPorta(f, exe, porta)
			if distintos < minLeque {
				continue // muitas conexões para POUCOS destinos é pool, tratado abaixo
			}
			out = append(out, Padrao{
				Tipo: "leque de saída",
				Alvo: exe + " → " + strconv.Itoa(distintos) + " endereços na porta " +
					strconv.Itoa(porta),
				N:     distintos,
				Comum: portasDeWeb[porta],
				Detalhe: "um destino por host e sempre a MESMA porta é a forma de " +
					"varredura ou de movimento lateral — " + nomeDaPorta(porta),
			})
		}

		// POOL: muitas conexões para o MESMO destino.
		if fl := porExe[exe]; fl.Conexoes >= minPool && fl.Destinos == 1 {
			out = append(out, Padrao{
				Tipo:    "pool",
				Alvo:    exe + " → " + strconv.Itoa(fl.Conexoes) + " conexões a um destino só",
				N:       fl.Conexoes,
				Detalhe: "muitas conexões para UM destino é pool de conexão, e é a forma normal de cliente de banco, de fila e de cache",
			})
		}
	}
	// Web por ÚLTIMO. É a forma normal de navegador e de atualizador, e num
	// desktop ela aparece toda vez; pô-la no topo enterraria o leque em porta
	// de serviço, que é o que muda o que o operador faz em seguida. Ordenar
	// não é o mesmo que esconder — a linha continua lá, com a ressalva.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Comum != out[j].Comum {
			return !out[i].Comum
		}
		return out[i].N > out[j].N
	})
	return out
}

// destinosDistintosNaPorta conta endereços diferentes que aquele executável
// alcançou NAQUELA porta. É o número que separa leque de pool.
func destinosDistintosNaPorta(f *facts.Facts, exe string, porta int) int {
	vistos := map[string]bool{}
	for i := range f.Sockets {
		s := &f.Sockets[i]
		if s.Dir != facts.DirOut || s.PeerPort != porta || s.PeerIP == "" {
			continue
		}
		e := exeDoPID(f, s.PID)
		if e == "" {
			e = "(dono não identificado)"
		}
		if e == exe {
			vistos[s.PeerIP] = true
		}
	}
	return len(vistos)
}

// nomeDaPorta dá sentido ao número. Não é catálogo de serviços: são as portas
// cuja presença num leque MUDA o que o operador faz em seguida.
func nomeDaPorta(p int) string {
	switch p {
	case 22:
		return "22 é SSH — leque aqui é movimento lateral por credencial ou chave"
	case 23:
		return "23 é telnet, e em rede de produção ele quase não existe mais"
	case 445, 139:
		return "445/139 é SMB — leque aqui é varredura de compartilhamento"
	case 3389:
		return "3389 é RDP"
	case 3306, 5432, 1433, 27017, 6379:
		return "porta de BANCO — leque aqui é procura por instância exposta"
	case 25, 465, 587:
		return "porta de SMTP — leque aqui costuma ser envio de spam"
	case 80, 443, 8080, 8443:
		// A ressalva tem os DOIS lados. Dizer só que é comum ensinaria a pular
		// a linha, e é nela que o C2 moderno mora de propósito.
		return "porta de WEB, onde esta forma é a NORMA (navegador, atualizador, " +
			"cliente de API) — e é também a porta que C2 escolhe justamente por " +
			"isso. A porta NÃO separa os dois: quem separa é 'que pacote entregou " +
			"este binário', e é `aletheia scan` que faz essa pergunta"
	}
	return "porta " + strconv.Itoa(p)
}

func mapaParaContagens(m map[string]int) []Contagem {
	out := make([]Contagem, 0, len(m))
	for k, n := range m {
		out = append(out, Contagem{Rotulo: k, N: n})
	}
	return out
}

func portasNomeadas(m map[int]int) []Contagem {
	out := make([]Contagem, 0, len(m))
	for p, n := range m {
		out = append(out, Contagem{Rotulo: strconv.Itoa(p), N: n})
	}
	return out
}

// ordenarContagens ordena por contagem e, no empate, por rótulo — a ordem
// precisa ser ESTÁVEL, porque estes números saem em JSONL e se comparam por
// diff entre execuções.
func ordenarContagens(cs []Contagem) []Contagem {
	sort.Slice(cs, func(i, j int) bool {
		if cs[i].N != cs[j].N {
			return cs[i].N > cs[j].N
		}
		return cs[i].Rotulo < cs[j].Rotulo
	})
	return cs
}

func exeDoPID(f *facts.Facts, pid int) string {
	if pid == 0 {
		return ""
	}
	if p := f.ProcessByPID(pid); p != nil {
		if p.Exe != "" {
			return p.Exe
		}
		return p.Comm
	}
	return ""
}
