// Package progress mostra que a coleta longa não travou.
//
// A parte cara de um scan é a COLETA — a varredura de filesystem passa por
// dezenas de milhares de diretórios —, e num disco lento ou atrás de um mount
// de rede ela parece um programa pendurado. Este pacote pinta um batimento no
// stderr enquanto isso corre.
//
// Três regras que o tornam seguro:
//
//   - só stderr. O stdout carrega o relatório e o JSONL, e um caractere de
//     controle no meio de um JSONL o corromperia. Nada aqui toca no stdout.
//   - só terminal. Se o stderr é pipe ou arquivo — automação, `2>log`, triagem
//     de frota por ssh —, tudo vira no-op: nenhum caractere de escape sai. É o
//     que mantém `wtf --oneline` limpo para quem ordena por exit code.
//   - some antes do relatório. Stop apaga a linha, então o relatório nasce numa
//     tela limpa.
//
// ASCII de propósito: a VM que mais precisa disto boota num console serial, e
// braille não desenha lá. `\r` e `\033[K` são vt100, que o serial entende.
package progress

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Reporter pinta o estágio atual e o tempo decorrido, uma vez por tique.
type Reporter struct {
	w       io.Writer
	tty     bool
	start   time.Time
	largura int // colunas do terminal, para truncar e não quebrar a linha

	mu       sync.Mutex
	stage    string
	detalhe  string // o que está sendo lido agora (um caminho)
	frame    int
	desenhou bool // já desenhou as duas linhas ao menos uma vez

	done    chan struct{}
	wg      sync.WaitGroup
	stopped bool
}

// New cria o reporter. Ele só faz algo se w for um terminal e disabled for
// falso; caso contrário todos os métodos são no-op e nenhum byte sai.
//
// A detecção de terminal é da biblioteca padrão: um char device é console ou
// pty, um pipe/arquivo não é. Sem dependência externa, que é invariante deste
// projeto.
func New(w io.Writer, start time.Time, disabled bool) *Reporter {
	r := &Reporter{w: w, start: start, stage: "coletando", largura: larguraTerminal(), done: make(chan struct{})}
	if !disabled {
		if fh, ok := w.(*os.File); ok {
			if fi, err := fh.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 {
				r.tty = true
			}
		}
	}
	if r.tty {
		r.wg.Add(1)
		go r.loop()
	}
	return r
}

// Stage troca o rótulo do estágio, limpa o detalhe (é de outra fase) e redesenha
// na hora — a mudança de fase não espera o próximo tique.
func (r *Reporter) Stage(name string) {
	if !r.tty {
		return
	}
	r.mu.Lock()
	r.stage = name
	r.detalhe = ""
	r.mu.Unlock()
	r.draw()
}

// Detalhe guarda o caminho sendo lido AGORA. É barato de propósito (só grava): o
// laço quente da varredura chama isto por diretório, e é o TIQUE que desenha —
// então nem todo caminho aparece, só o que estiver corrente a cada 120ms.
func (r *Reporter) Detalhe(s string) {
	if !r.tty {
		return
	}
	r.mu.Lock()
	r.detalhe = s
	r.mu.Unlock()
}

// Stop encerra o batimento e apaga AS DUAS linhas. Idempotente: o explícito
// antes do relatório e o defer de segurança não se atrapalham.
func (r *Reporter) Stop() {
	if !r.tty {
		return
	}
	r.mu.Lock()
	if r.stopped {
		r.mu.Unlock()
		return
	}
	r.stopped = true
	desenhou := r.desenhou
	r.mu.Unlock()
	close(r.done)
	r.wg.Wait()
	if desenhou {
		// estamos na 2ª linha: limpa-a, sobe, limpa a 1ª.
		fmt.Fprint(r.w, "\r\033[K\033[A\r\033[K")
	} else {
		fmt.Fprint(r.w, "\r\033[K")
	}
}

func (r *Reporter) loop() {
	defer r.wg.Done()
	t := time.NewTicker(120 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-r.done:
			return
		case <-t.C:
			r.mu.Lock()
			r.frame++
			r.mu.Unlock()
			r.draw()
		}
	}
}

var giro = [...]byte{'|', '/', '-', '\\'}

func (r *Reporter) draw() {
	r.mu.Lock()
	stage, det, frame := r.stage, r.detalhe, r.frame
	desenhou := r.desenhou
	r.desenhou = true
	r.mu.Unlock()

	// Segundos inteiros: o batimento já prova vida, e milissegundos piscando só
	// cansam a vista.
	larg := r.largura
	if larg <= 0 {
		larg = 80
	}
	seg := int(time.Since(r.start).Seconds())
	l1 := fmt.Sprintf("%c %s… %ds", giro[frame%len(giro)], stage, seg)
	l2 := "  " + encurtarCauda(det, larg-3) // a cauda (o arquivo) é o que interessa

	// Duas linhas, com o cursor voltando à primeira. Truncadas para caber na
	// largura: linha que passa da coluna quebra, e aí o `\033[A` sobe para o
	// lugar errado e deixa rastro. `\033[K` apaga o que sobrou de um caminho
	// mais longo no tique anterior.
	var b strings.Builder
	if desenhou {
		b.WriteString("\033[A") // sobe da 2ª linha para a 1ª
	}
	b.WriteString("\r")
	b.WriteString(encurtarCauda(l1, larg-1))
	b.WriteString("\033[K\n\r")
	b.WriteString(l2)
	b.WriteString("\033[K")
	fmt.Fprint(r.w, b.String())
}

// larguraTerminal devolve as colunas do terminal via COLUMNS, ou 80. Sem ioctl
// (que teria número de syscall por arquitetura): 80 é o piso seguro, e truncar
// para ele nunca quebra num terminal de 80 ou mais.
func larguraTerminal() int {
	if c := os.Getenv("COLUMNS"); c != "" {
		if n, err := strconv.Atoi(c); err == nil && n >= 40 {
			return n
		}
	}
	return 80
}

// encurtarCauda mostra o FIM de uma string longa — o nome do arquivo diz mais
// que a raiz do caminho. Corta em fronteira de rune para não partir UTF-8.
func encurtarCauda(s string, max int) string {
	if max < 4 {
		max = 4
	}
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return "…" + string(r[len(r)-(max-1):])
}
