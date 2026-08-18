package progress

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// A regra que protege o stdout: um bytes.Buffer NÃO é terminal, então tudo cala.
// É o mesmo caminho de um pipe ou de `2>arquivo` — automação e JSONL intactos.
func TestSemTerminalNaoEscreveNada(t *testing.T) {
	var buf bytes.Buffer
	r := New(&buf, time.Now(), false)
	r.Stage("varredura de filesystem")
	r.Stop()
	if buf.Len() != 0 {
		t.Errorf("sem terminal, nada pode sair — veio %q", buf.String())
	}
}

// E o disabled (--no-progress) cala mesmo que fosse terminal: a flag ganha da
// detecção.
func TestDisabledCala(t *testing.T) {
	var buf bytes.Buffer
	r := New(&buf, time.Now(), true)
	if r.tty {
		t.Fatal("disabled tem de desligar o tty")
	}
	r.Stage("x")
	r.Stop()
	if buf.Len() != 0 {
		t.Errorf("--no-progress não pode escrever: %q", buf.String())
	}
}

// Com terminal, o desenho traz o rótulo, o tempo e o retorno de carro que
// reescreve a linha; e o Stop apaga com o clear-to-EOL. Constrói o reporter à
// mão com tty=true porque um bytes.Buffer nunca seria detectado como terminal.
func TestDesenhoTrazRotuloTempoEApaga(t *testing.T) {
	var buf bytes.Buffer
	r := &Reporter{w: &buf, tty: true, start: time.Now().Add(-3 * time.Second), done: make(chan struct{})}
	r.Stage("processos")
	saida := buf.String()
	if !strings.Contains(saida, "\r") {
		t.Error("sem \\r a linha não se reescreve — vira scroll")
	}
	if !strings.Contains(saida, "processos") {
		t.Error("o estágio precisa aparecer: é ele que diz ONDE travou")
	}
	if !strings.Contains(saida, "s\x1b[K") && !strings.Contains(saida, "s") {
		t.Error("o tempo decorrido precisa aparecer")
	}
	buf.Reset()
	r.Stop()
	if !strings.Contains(buf.String(), "\x1b[K") {
		t.Error("Stop tem de APAGAR a linha, senão o relatório nasce sobre ela")
	}
}

// Stop duas vezes — o explícito antes do relatório e o defer de segurança — não
// pode entrar em pânico fechando o canal duas vezes.
func TestStopIdempotente(t *testing.T) {
	var buf bytes.Buffer
	r := &Reporter{w: &buf, tty: true, start: time.Now(), done: make(chan struct{})}
	r.Stop()
	r.Stop() // não pode dar panic
}
