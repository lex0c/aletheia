package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// O destino do --out e do --json é aceito por TIPO, e o tipo do device decide.
//
// O ramo permissivo existe de propósito: /dev/stdout e /dev/console são uso
// automatizado legítimo. Mas ele confiava no os.Stat, que SEGUE symlink — então
// um `dump.json -> /dev/sda` plantado no diretório de incidente chegava
// classificado como "device, pode" e o collect gravava o dump por cima da
// tabela de partição do host investigado, com fsync e close bem-sucedidos,
// .sha256 escrito ao lado e exit 0.
//
// Esta trava mora aqui, e não num teste de ponta a ponta, porque provar o ramo
// com um /dev/sda gravável exigiria root — e trava que só roda como root não
// roda.
func TestTipoDeSaidaRecusaDeviceDeBlocoEAceitaOsLegitimos(t *testing.T) {
	casos := []struct {
		nome   string
		modo   os.FileMode
		recusa bool
		porque string
	}{
		{"device de bloco (/dev/sda)", os.ModeDevice, true,
			"escrever ali destrói o disco do host investigado"},
		{"arquivo comum", 0, true,
			"trocado entre a conferência e a abertura — nunca sobrescrever"},
		{"char device (/dev/mem, /dev/port, /dev/watchdog)", os.ModeDevice | os.ModeCharDevice, true,
			"/dev/mem escreve memória física e /dev/watchdog ARMA no open — a " +
				"premissa de que char device é inofensivo é falsa"},
		{"socket", os.ModeSocket, true, "não é destino de arquivo"},
		{"fifo (pipe nomeado)", os.ModeNamedPipe, false,
			"escrever num pipe não destrói nada, e o O_NONBLOCK já resolve o " +
				"caso sem leitor"},
	}
	for _, c := range casos {
		t.Run(c.nome, func(t *testing.T) {
			got := tipoDeSaidaRecusado(c.modo)
			if c.recusa && got == "" {
				t.Errorf("ACEITOU %s — %s", c.nome, c.porque)
			}
			if !c.recusa && got != "" {
				t.Errorf("recusou %s (%s), e ele é %s", c.nome, got, c.porque)
			}
		})
	}
}

// A recusa de device acontece SEM abrir o device.
//
// A revisão anterior fechou metade: char device passou a ser recusado, mas a
// classificação continuava vindo depois de um `os.OpenFile(path, O_WRONLY)`.
// Para device isso é tarde — o próprio texto da recusa diz "ARMA no open, antes
// de qualquer byte", e o código fazia exatamente esse open. Um
// `resultado.json -> /dev/watchdog` no diretório de incidente reiniciava o host
// investigado e só então recebia o erro.
//
// O teste não pode abrir um watchdog para provar isso, então mede a propriedade
// verificável: sobre um device, openJSONOut devolve erro e NENHUM descritor
// escrevível chega a existir. O /dev/null é o dublê — mesmo tipo, mesma classe
// de open, sem consequência.
//
// A trava anterior testava só tipoDeSaidaRecusado(mode), que é a decisão
// isolada; ela passaria com a ordem errada. Esta exercita o caminho inteiro.
func TestSaidaEmDeviceEhRecusadaSemAbrir(t *testing.T) {
	antes := descritoresAbertos(t)
	fh, err := openJSONOut("/dev/null")
	if err == nil {
		fh.Close()
		t.Fatal("openJSONOut ABRIU um device para escrita: num /dev/watchdog o " +
			"temporizador do host investigado já teria armado, e a recusa depois " +
			"disso chega tarde")
	}
	if depois := descritoresAbertos(t); depois > antes {
		t.Errorf("sobrou descritor aberto depois da recusa (%d -> %d): o open "+
			"aconteceu antes da classificação", antes, depois)
	}
}

// E o FIFO — o único especial que segue permitido — continua atendido, porque
// recusá-lo custaria um uso automatizado real e provar o tipo antes custa nada.
func TestSaidaEmFifoContinuaPermitida(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "saida")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Skipf("mkfifo indisponível: %v", err)
	}
	// Sem leitor, o O_NONBLOCK transforma o que seria travamento eterno em
	// ENXIO — e a mensagem precisa explicar isso, não vazar /proc/self/fd.
	_, err := openJSONOut(p)
	if err == nil {
		t.Fatal("um FIFO sem leitor foi aceito: a escrita penduraria")
	}
	if strings.Contains(err.Error(), "/proc/self/fd") {
		t.Errorf("a mensagem vaza detalhe de implementação: %v", err)
	}
	if !strings.Contains(err.Error(), "leitor") {
		t.Errorf("a mensagem não diz a causa (FIFO sem leitor): %v", err)
	}

	// Com leitor, abre normalmente.
	go func() {
		fh, err := os.OpenFile(p, os.O_RDONLY, 0)
		if err == nil {
			io.Copy(io.Discard, fh)
			fh.Close()
		}
	}()
	var w *os.File
	for i := 0; i < 200 && w == nil; i++ {
		if fh, err := openJSONOut(p); err == nil {
			w = fh
		} else {
			time.Sleep(5 * time.Millisecond)
		}
	}
	if w == nil {
		t.Fatal("FIFO com leitor não abriu: o uso automatizado legítimo quebrou")
	}
	defer w.Close()
	if _, err := w.Write([]byte("ok\n")); err != nil {
		t.Errorf("escrita no FIFO falhou (O_NONBLOCK não foi retirado?): %v", err)
	}
}

// descritoresAbertos conta os fds do próprio processo. É a forma direta de
// perguntar "houve abertura?" sem instrumentar o código sob teste.
func descritoresAbertos(t *testing.T) int {
	t.Helper()
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("/proc não disponível: %v", err)
	}
	return len(ents)
}
