// Package info responde perguntas pontuais sobre um alvo — um processo, um
// endereço, uma porta, um arquivo — melhor do que a saída crua dos comandos do
// sistema.
//
// # Por que existe
//
// O resto desta ferramenta responde "este host está comprometido?". Há uma
// classe inteira de pergunta que aparece ANTES dessa, no meio do incidente, e
// que hoje se responde encadeando dez pipelines de `ps`, `awk`, `sort` e `uniq`:
//
//	su: failed to execute /bin/bash: Resource temporarily unavailable
//
// Para chegar de lá até "o uid node tem 5007 tarefas contra um teto de 4096, e
// 400 delas são cópias do mesmo cron que se sobrepõe", o operador roda quinze
// comandos e cruza a saída na cabeça. Nenhum deles sozinho diz isso — e a
// ferramenta já tem TODOS os números na mão.
//
// # O que separa isto de `ps`
//
// Três coisas, e todas aparecem naquele caso:
//
//	compara com o TETO      contar tarefas é fácil; saber contra o que comparar
//	                        exige ler /proc/<pid>/limits de cada processo
//	agrupa pelo EXECUTÁVEL  o nome no `ps` é escolha do processo. Agrupar por
//	                        exe real separa 400 cópias de um implante de 400
//	                        cópias de um script legítimo
//	NOMEIA o padrão         N cópias do mesmo comando, começadas em intervalos
//	                        regulares, é a forma de um cron que se sobrepõe —
//	                        e dizer isso poupa a hora que se gasta descobrindo
package info

import (
	"sort"
	"strconv"
	"time"

	"github.com/lex0c/aletheia/internal/facts"
)

// CensoDeProcessos é o retrato de quem está rodando o quê, por usuário.
type CensoDeProcessos struct {
	Processos int              `json:"processes"`
	Tarefas   int              `json:"tasks"`
	Usuarios  []UsuarioNoCenso `json:"users,omitempty"`
	// Padroes são as repetições reconhecidas — cron sobreposto, pool, laço de
	// respawn. É a parte que um `ps` não dá.
	Padroes []Padrao `json:"patterns,omitempty"`
}

// UsuarioNoCenso é o que um uid está consumindo, e contra que teto.
type UsuarioNoCenso struct {
	UID       int    `json:"uid"`
	Nome      string `json:"name,omitempty"`
	Processos int    `json:"processes"`
	Tarefas   int    `json:"tasks"`

	// Teto é o menor RLIMIT_NPROC visto entre os processos deste uid. Menor, e
	// não maior: é ele que decide onde o próximo fork falha.
	Teto int `json:"nproc_max,omitempty"`
	// TetoLido diz se algum processo deste uid teve o limite lido. Sem isso, a
	// ausência de teto significa "não olhei", e não "não há teto".
	TetoLido bool `json:"nproc_max_read"`

	PorExecutavel []Contagem `json:"by_exe,omitempty"`
	PorComando    []Contagem `json:"by_cmd,omitempty"`
	PorPai        []Contagem `json:"by_parent,omitempty"`
	PorEstado     []Contagem `json:"by_state,omitempty"`
	Zumbis        int        `json:"zombies,omitempty"`
}

// Contagem é um agrupamento com o rótulo já pronto para impressão.
type Contagem struct {
	Rotulo string `json:"label"`
	N      int    `json:"n"`
}

// Padrao é uma repetição que tem NOME.
type Padrao struct {
	Tipo    string `json:"kind"` // "cron sobreposto" | "pool" | "respawn" | "leque de saída"
	Alvo    string `json:"target"`
	N       int    `json:"n"`
	Detalhe string `json:"detail,omitempty"`
	// Comum marca o padrão cuja forma também é a do uso legítimo frequente.
	// Ele NÃO é suprimido — vai para o fim da lista, com a ressalva junto:
	// suprimir seria filtrar pelo campo que o atacante escolhe.
	Comum bool `json:"common,omitempty"`
}

// Perto diz se o usuário está a menos de 10% do teto — a faixa em que o próximo
// `su`, o próximo deploy e o próximo shell já falham.
func (u UsuarioNoCenso) Perto() bool {
	return u.TetoLido && u.Teto > 0 && u.Tarefas*10 >= u.Teto*9
}

// Estourou diz que o uid já passou do teto. É a explicação direta de EAGAIN em
// fork e em execve.
func (u UsuarioNoCenso) Estourou() bool {
	return u.TetoLido && u.Teto > 0 && u.Tarefas >= u.Teto
}

// Censo monta o retrato. Ele é puro sobre os fatos: os mesmos números saem de um
// host vivo e de um retrato coletado semanas atrás.
func Censo(f *facts.Facts) *CensoDeProcessos {
	c := &CensoDeProcessos{}
	porUID := map[int]*UsuarioNoCenso{}

	for i := range f.Processes {
		p := &f.Processes[i]
		if p.Vanished {
			continue
		}
		u, ok := porUID[p.UID]
		if !ok {
			u = &UsuarioNoCenso{UID: p.UID, Nome: nomeDoUID(f, p.UID)}
			porUID[p.UID] = u
		}
		u.Processos++
		c.Processos++

		// Tarefas, não processos: o RLIMIT_NPROC conta as duas coisas juntas, e
		// é por isso que um host com poucos processos e muitas threads estoura
		// sem ninguém entender.
		t := p.Threads
		if t <= 0 {
			t = 1
		}
		u.Tarefas += t
		c.Tarefas += t

		if p.NProcMax != 0 {
			if !u.TetoLido || (p.NProcMax > 0 && (u.Teto <= 0 || p.NProcMax < u.Teto)) {
				u.Teto = p.NProcMax
			}
			u.TetoLido = true
		}
		if p.State == "Z" {
			u.Zumbis++
		}
	}

	for _, u := range porUID {
		preencherAgrupamentos(f, u)
		c.Usuarios = append(c.Usuarios, *u)
	}
	// Quem está mais perto do teto primeiro; empatando, quem tem mais tarefas.
	// É a ordem da urgência, não a alfabética.
	sort.Slice(c.Usuarios, func(i, j int) bool {
		a, b := c.Usuarios[i], c.Usuarios[j]
		if a.Estourou() != b.Estourou() {
			return a.Estourou()
		}
		if a.Perto() != b.Perto() {
			return a.Perto()
		}
		return a.Tarefas > b.Tarefas
	})
	c.Padroes = reconhecerPadroes(f)
	return c
}

func preencherAgrupamentos(f *facts.Facts, u *UsuarioNoCenso) {
	exe := map[string]int{}
	cmd := map[string]int{}
	pai := map[int]int{}
	estado := map[string]int{}

	for i := range f.Processes {
		p := &f.Processes[i]
		if p.UID != u.UID || p.Vanished {
			continue
		}
		// O EXECUTÁVEL, não o nome: `comm` e `argv[0]` são escolha do processo,
		// e um implante que se chama `[kworker/0:1]` some no agrupamento por
		// nome — que é exatamente onde ninguém olha.
		exe[nz(p.Exe, "(exe ilegível: "+p.Comm+")")]++
		cmd[linhaCurta(p)]++
		pai[p.PPID]++
		estado[nz(p.State, "?")]++
	}
	u.PorExecutavel = topN(exe, 8)
	u.PorComando = topN(cmd, 8)
	u.PorEstado = topN(estado, 6)

	porPai := map[string]int{}
	for ppid, n := range pai {
		porPai[descreverPai(f, ppid)] = n
	}
	u.PorPai = topN(porPai, 6)
}

// reconhecerPadroes é a parte que nenhum `ps` faz: dar NOME à repetição.
//
// O caso que a motivou: 400 processos `sh` e 406 `node` sob o mesmo usuário, com
// 103 `sendmail` e 103 `postdrop` do lado. Nenhum comando isolado diz o que é
// isso; a forma diz — cópias do MESMO comando, começadas em intervalos
// REGULARES, e nenhuma delas termina.
func reconhecerPadroes(f *facts.Facts) []Padrao {
	type grupo struct {
		inicios []time.Time
		exemplo *facts.Process
		n       int
	}
	por := map[string]*grupo{}

	for i := range f.Processes {
		p := &f.Processes[i]
		if p.Vanished || len(p.Argv) == 0 {
			continue
		}
		k := strconv.Itoa(p.UID) + "\x00" + linhaCurta(p)
		g, ok := por[k]
		if !ok {
			g = &grupo{exemplo: p}
			por[k] = g
		}
		g.n++
		if t, err := time.Parse(time.RFC3339, p.StartUTC); err == nil {
			g.inicios = append(g.inicios, t)
		}
	}

	var out []Padrao
	for _, g := range por {
		// Menos de vinte cópias não é padrão: é um pool, um build, um teste. O
		// corte é alto de propósito — nomear padrão onde não há é pior que
		// calar, porque a frase tem cara de conclusão.
		if g.n < 20 {
			continue
		}
		p := Padrao{Alvo: linhaCurta(g.exemplo), N: g.n, Tipo: "repetição"}
		if med, regular := cadencia(g.inicios); regular {
			p.Tipo = "cron sobreposto"
			p.Detalhe = "as cópias começaram em intervalos REGULARES de ~" +
				med.Round(time.Second).String() + ", e nenhuma terminou: é a forma de " +
				"um agendamento cujo job demora mais que o próprio intervalo. Cada " +
				"disparo acrescenta uma cópia, e o total só cresce"
		} else {
			p.Detalhe = strconv.Itoa(g.n) + " processos com a MESMA linha de comando " +
				"e o mesmo usuário. Sem datas regulares entre eles, pode ser pool de " +
				"aplicação, laço de respawn ou fork descontrolado"
		}
		if len(g.inicios) > 0 {
			p.Detalhe += " · a mais antiga começou em " + maisAntiga(g.inicios).Format(time.RFC3339)
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].N > out[j].N })
	return out
}

// cadencia decide se os inícios são regulares, e devolve o intervalo típico.
//
// A regularidade é o que separa "cron sobreposto" de "pool que subiu junto": um
// pool nasce todo no mesmo segundo; um cron deixa um rastro de um por intervalo.
func cadencia(ts []time.Time) (time.Duration, bool) {
	if len(ts) < 5 {
		return 0, false
	}
	sort.Slice(ts, func(i, j int) bool { return ts[i].Before(ts[j]) })
	var difs []time.Duration
	for i := 1; i < len(ts); i++ {
		d := ts[i].Sub(ts[i-1])
		if d <= 0 {
			continue
		}
		difs = append(difs, d)
	}
	if len(difs) < 4 {
		return 0, false
	}
	sort.Slice(difs, func(i, j int) bool { return difs[i] < difs[j] })
	mediana := difs[len(difs)/2]
	if mediana < time.Second || mediana > 24*time.Hour {
		return 0, false
	}
	// Regular = a maioria dos intervalos cabe numa faixa estreita em torno da
	// mediana. Tolerância larga porque o relógio do cron não é o do processo:
	// carga alta atrasa o disparo em segundos.
	dentro := 0
	for _, d := range difs {
		if d >= mediana*7/10 && d <= mediana*13/10 {
			dentro++
		}
	}
	return mediana, dentro*10 >= len(difs)*7
}

func maisAntiga(ts []time.Time) time.Time {
	t := ts[0]
	for _, x := range ts {
		if x.Before(t) {
			t = x
		}
	}
	return t
}
