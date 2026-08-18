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
	"sync"
	"time"
)

// Reporter pinta o estágio atual e o tempo decorrido, uma vez por tique.
type Reporter struct {
	w     io.Writer
	tty   bool
	start time.Time

	mu    sync.Mutex
	stage string
	frame int

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
	r := &Reporter{w: w, start: start, stage: "coletando", done: make(chan struct{})}
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

// Stage troca o rótulo do estágio e redesenha na hora — a mudança de fase não
// espera o próximo tique.
func (r *Reporter) Stage(name string) {
	if !r.tty {
		return
	}
	r.mu.Lock()
	r.stage = name
	r.mu.Unlock()
	r.draw()
}

// Stop encerra o batimento e apaga a linha. Idempotente: chamar duas vezes — o
// explícito antes do relatório e o defer de segurança — não faz mal.
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
	r.mu.Unlock()
	close(r.done)
	r.wg.Wait()
	fmt.Fprint(r.w, "\r\033[K") // volta ao início da linha e apaga até o fim
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
	stage, frame := r.stage, r.frame
	r.mu.Unlock()
	// Segundos inteiros: o batimento já prova vida, e milissegundos piscando
	// só cansam a vista.
	seg := int(time.Since(r.start).Seconds())
	fmt.Fprintf(r.w, "\r%c %s… %ds\033[K", giro[frame%len(giro)], stage, seg)
}
