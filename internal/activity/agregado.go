package activity

import (
	"sort"

	"github.com/lex0c/aletheia/internal/facts"
)

// Agregação sobre a linha do tempo JÁ FILTRADA.
//
// Ela roda sobre os eventos que o filtro deixou passar, e não sobre os fatos:
// assim `--since 7d --user deploy --group-by ip` conta exatamente o que a
// timeline correspondente mostraria. Um agregado calculado por outro caminho
// daria dois números para a mesma pergunta, que é o defeito que AgregadoDeLog
// documenta ter recusado.

// Eixos aceitos por Agrupar.
const (
	PorOrigem  = "ip"
	PorUsuario = "user"
	PorKind    = "kind"
)

// Grupo é uma linha da tabela do --group-by.
type Grupo struct {
	Chave string `json:"key"`

	Aceitos   int `json:"accepted"`
	Recusados int `json:"refused"`
	Outros    int `json:"other"`

	// Os conjuntos que cruzam o eixo: agrupado por origem, o que interessa é
	// QUAIS contas ela tocou; agrupado por conta, de quais origens.
	Usuarios []string `json:"users,omitempty"`
	Origens  []string `json:"origins,omitempty"`
	Metodos  []string `json:"methods,omitempty"`

	Primeiro string `json:"first,omitempty"`
	Ultimo   string `json:"last,omitempty"`
}

// N é o total de eventos do grupo.
func (g Grupo) N() int { return g.Aceitos + g.Recusados + g.Outros }

// Agrupar monta a tabela. A ordem é por volume, e o desempate é pela chave —
// duas execuções sobre o mesmo retrato precisam sair iguais.
func Agrupar(ev []Evento, por string) []Grupo {
	idx := map[string]*Grupo{}
	usuarios := map[string]map[string]bool{}
	origens := map[string]map[string]bool{}
	metodos := map[string]map[string]bool{}
	var ordem []string

	for i := range ev {
		e := &ev[i]
		ch, ok := chaveDoEixo(e, por)
		if !ok {
			continue
		}
		g := idx[ch]
		if g == nil {
			g = &Grupo{Chave: ch}
			idx[ch] = g
			usuarios[ch] = map[string]bool{}
			origens[ch] = map[string]bool{}
			metodos[ch] = map[string]bool{}
			ordem = append(ordem, ch)
		}
		switch e.Kind {
		case KindLoginAceito:
			g.Aceitos++
		case KindLoginRecusado:
			g.Recusados++
		default:
			g.Outros++
		}
		if e.User != "" {
			usuarios[ch][e.User] = true
		}
		if facts.OrigemDeRede(e.Origem) {
			origens[ch][e.Origem] = true
		}
		if e.Metodo != "" {
			metodos[ch][e.Metodo] = true
		}
		// Evento sem data não estreita nem alarga o intervalo do grupo: ele não
		// pode empurrar o primeiro nem o último.
		if e.At == "" {
			continue
		}
		if g.Primeiro == "" || e.At < g.Primeiro {
			g.Primeiro = e.At
		}
		if e.At > g.Ultimo {
			g.Ultimo = e.At
		}
	}

	out := make([]Grupo, 0, len(ordem))
	for _, ch := range ordem {
		g := *idx[ch]
		g.Usuarios = chaves(usuarios[ch])
		g.Origens = chaves(origens[ch])
		g.Metodos = chaves(metodos[ch])
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].N() != out[j].N() {
			return out[i].N() > out[j].N()
		}
		return out[i].Chave < out[j].Chave
	})
	return out
}

func chaveDoEixo(e *Evento, por string) (string, bool) {
	switch por {
	case PorOrigem:
		// Só origem DE REDE: `:0` é display do X, `~` é marcador de boot e vazio
		// é tty física. Nenhum dos três responde "de onde alguém entrou", que é
		// a pergunta que esta tabela existe para responder.
		if !facts.OrigemDeRede(e.Origem) {
			return "", false
		}
		return e.Origem, true
	case PorUsuario:
		if e.User == "" {
			return "", false
		}
		return e.User, true
	case PorKind:
		return string(e.Kind), true
	}
	return "", false
}

// Sumario é o --summary: os agregados de uma janela, sem a lista de eventos.
type Sumario struct {
	Total int `json:"total"`
	// SemData é contado à parte porque ele não pertence a nenhum intervalo, e
	// somá-lo ao resto faria o Primeiro/Ultimo abaixo parecer cobrir tudo.
	SemData int `json:"undated"`

	Primeiro string `json:"first,omitempty"`
	Ultimo   string `json:"last,omitempty"`

	PorKind     []Contagem `json:"by_kind,omitempty"`
	TopOrigens  []Contagem `json:"top_origins,omitempty"`
	TopUsuarios []Contagem `json:"top_users,omitempty"`

	// Divergentes conta os eventos que uma testemunha registrou e a outra,
	// tendo como registrar, não registrou. É o número que merece investigação.
	Divergentes int `json:"divergent"`
}

const maxNoSumario = 10

// Sumarizar resume a linha do tempo filtrada.
func Sumarizar(ev []Evento) Sumario {
	s := Sumario{Total: len(ev)}
	kinds := map[string]int{}
	origens := map[string]int{}
	usuarios := map[string]int{}

	for i := range ev {
		e := &ev[i]
		kinds[string(e.Kind)]++
		if facts.OrigemDeRede(e.Origem) {
			origens[e.Origem]++
		}
		if e.User != "" {
			usuarios[e.User]++
		}
		if e.Divergente == DivergenteAusente {
			s.Divergentes++
		}
		if e.At == "" {
			s.SemData++
			continue
		}
		if s.Primeiro == "" || e.At < s.Primeiro {
			s.Primeiro = e.At
		}
		if e.At > s.Ultimo {
			s.Ultimo = e.At
		}
	}

	s.PorKind = topN(kinds, maxNoSumario)
	s.TopOrigens = topN(origens, maxNoSumario)
	s.TopUsuarios = topN(usuarios, maxNoSumario)
	return s
}

func chaves(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
