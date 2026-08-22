package info

import (
	"sort"
	"strconv"
	"strings"

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
	Total     int        `json:"total"`
	PorEstado []Contagem `json:"by_state,omitempty"`

	// Escutas é o que a máquina EXPÕE, que é a pergunta que vem primeiro.
	Escutas []Escuta `json:"listeners,omitempty"`
	// Saida agrupa quem fala para fora pelo executável real.
	Saida []Falante `json:"outbound,omitempty"`
	// Entrada é quem conectou aqui, agrupado por origem.
	Entrada []Contagem `json:"inbound,omitempty"`

	Tetos   []TetoDeRede `json:"limits,omitempty"`
	Padroes []Padrao     `json:"patterns,omitempty"`

	// SemDono conta os sockets cujo processo não pôde ser identificado. Sem
	// root, o fd de processo alheio é ilegível — e o socket existe do mesmo
	// jeito. Contar é o que impede a lista de parecer completa.
	SemDono int `json:"without_owner,omitempty"`
}

// Escuta é uma porta aberta, com o que decide se ela é superfície de ataque: o
// endereço em que está ligada.
type Escuta struct {
	Proto      string `json:"proto"`
	Porta      int    `json:"port"`
	Bind       string `json:"bind"`
	Executavel string `json:"exe,omitempty"`
	PID        int    `json:"pid,omitempty"`
	// Exposta diz que o bind NÃO é loopback: a porta está aberta para fora.
	Exposta bool `json:"exposed"`
	// DonoDesconhecido separa "ninguém segura" de "não pude ver quem segura".
	DonoDesconhecido bool `json:"owner_unknown,omitempty"`
	// Sockets é quantos descritores seguram esta MESMA escuta. Com
	// SO_REUSEPORT um serviço divide a porta entre vários processos ou threads,
	// e o `ss` imprime uma linha por descritor — é o ruído que faz um nginx com
	// doze workers parecer doze portas abertas. Aqui é uma escuta, com o número
	// ao lado.
	Sockets int `json:"sockets,omitempty"`
}

// Falante é um executável e o que ele abriu para fora.
type Falante struct {
	Executavel string `json:"exe,omitempty"`
	Conexoes   int    `json:"connections"`
	// Destinos é quantos ENDEREÇOS distintos, e Endpoints quantos pares
	// endereço:porta distintos. Os dois números juntos é que separam as três
	// formas, e usar só o primeiro rotulava varredura de porta como pool:
	//
	//	pool       muitas conexões, UM endpoint      (10.0.0.9:5432)
	//	leque      muitos destinos, uma porta        (N hosts na 22)
	//	varredura  UM destino, muitas portas         (10.0.0.9 em 16 portas)
	Destinos  int        `json:"destinations"`
	Endpoints int        `json:"endpoints"`
	Publicos  int        `json:"public"`
	Portas    []Contagem `json:"ports,omitempty"`
}

// TetoDeRede é um limite com a ocupação medida contra ele.
type TetoDeRede struct {
	Nome  string `json:"name"`
	Uso   int    `json:"used"`
	Teto  int    `json:"limit"`
	Nota  string `json:"note,omitempty"`
	Lido  bool   `json:"read"`
	Perto bool   `json:"near_limit,omitempty"`
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

// minPool é quantas conexões para o MESMO endpoint antes de chamar de pool.
const minPool = 8

// minVarredura é quantas portas DISTINTAS no mesmo destino antes de chamar de
// varredura. Cliente legítimo fala com duas ou três portas de um host —
// aplicação mais métricas, banco mais réplica. Oito é a faixa em que a
// explicação inocente acaba.
const minVarredura = 8

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
	endpointsDe := map[string]map[string]bool{}
	portasPorIP := map[string]map[string]map[int]bool{}

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
				endpointsDe[exe] = map[string]bool{}
				portasPorIP[exe] = map[string]map[int]bool{}
			}
			fl.Conexoes++
			if s.PeerScope == facts.ScopePublic {
				fl.Publicos++
			}
			destinosDe[exe][s.PeerIP] = true
			portasDe[exe][s.PeerPort]++
			endpointsDe[exe][s.Peer()] = true
			if portasPorIP[exe][s.PeerIP] == nil {
				portasPorIP[exe][s.PeerIP] = map[int]bool{}
			}
			portasPorIP[exe][s.PeerIP][s.PeerPort] = true
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
		fl.Endpoints = len(endpointsDe[exe])
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
	c.Padroes = padroesDeRede(f, porExe, portasDe, portasPorIP)
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
	portasDe map[string]map[int]int,
	portasPorIP map[string]map[string]map[int]bool,
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

		// VARREDURA DE PORTAS: um destino, muitas PORTAS distintas.
		//
		// É a forma transposta do leque, e é a que um scanner produz. Ela
		// entrava aqui como "pool" — o rótulo BENIGNO —, porque a condição do
		// pool olhava só o número de endereços distintos e dezesseis portas do
		// mesmo host somam um endereço. A ferramenta dava nome de cliente de
		// banco para a forma exata de uma varredura.
		for _, ip := range ordenarChaves(portasPorIP[exe]) {
			portas := portasPorIP[exe][ip]
			if len(portas) < minVarredura {
				continue
			}
			out = append(out, Padrao{
				Tipo: "varredura de portas",
				Alvo: exe + " → " + strconv.Itoa(len(portas)) + " portas distintas em " + ip,
				N:    len(portas),
				Detalhe: "muitas PORTAS num mesmo destino é a forma de varredura: " +
					"cliente legítimo fala com duas ou três portas de um host, não com " +
					"dezenas. " + amostraDePortas(portas),
			})
		}

		// POOL: muitas conexões para o MESMO endpoint — endereço E porta.
		if fl := porExe[exe]; fl.Conexoes >= minPool && fl.Endpoints == 1 {
			out = append(out, Padrao{
				Tipo:  "pool",
				Alvo:  exe + " → " + strconv.Itoa(fl.Conexoes) + " conexões a um endereço:porta só",
				N:     fl.Conexoes,
				Comum: true,
				Detalhe: "muitas conexões para UM endpoint é pool de conexão, e é a " +
					"forma normal de cliente de banco, de fila e de cache",
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

// ordenarChaves dá ordem fixa a um mapa por endereço: sem isto, duas execuções
// do mesmo retrato listam os padrões embaralhados.
func ordenarChaves(m map[string]map[int]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// amostraDePortas nomeia algumas das portas alcançadas. São elas que dizem o
// que a varredura procurava — a lista de um scanner de inventário e a de quem
// caça banco exposto não se parecem.
func amostraDePortas(portas map[int]bool) string {
	ns := make([]int, 0, len(portas))
	for p := range portas {
		ns = append(ns, p)
	}
	sort.Ints(ns)
	const teto = 10
	corte := ns
	sufixo := ""
	if len(ns) > teto {
		corte = ns[:teto]
		sufixo = " …"
	}
	partes := make([]string, 0, len(corte))
	for _, p := range corte {
		partes = append(partes, strconv.Itoa(p))
	}
	return "portas: " + strings.Join(partes, " ") + sufixo
}
