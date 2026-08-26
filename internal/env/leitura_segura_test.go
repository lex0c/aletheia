package env

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/lex0c/aletheia/internal/safeio"
)

// NENHUMA LEITURA ABRE O QUE AINDA NÃO PROVOU SER ARQUIVO COMUM.
//
// TestInspecaoNaoAbreObjetoNaoProvado já afirma isto para AbrirParaInspecao. Ele
// não afirmava nada sobre ReadFile, Open e OpenFD — que são 86 dos chamadores
// desta ferramenta contra os 2 daquele —, e ali a propriedade era FALSA:
//
//	fh, err := os.OpenFile(p, O_RDONLY|O_NONBLOCK|O_NOATIME, 0)  // o open já rodou
//	fi, _ := fh.Stat()
//	if !fi.Mode().IsRegular() { return ErrNaoEhArquivo }         // tarde
//
// O O_NONBLOCK resolvia o fifo e não resolvia o device: para um device node, o
// open() do driver acontece na primeira linha. Com
//
//	ln -sf /dev/watchdog /etc/ld.so.preload
//
// a varredura seguia o link e ARMAVA o watchdog — sobre um caminho que
// collectLoader lê em toda execução. A recusa que saía depois era impecável e o
// host já tinha sido alterado.
//
// A asserção óbvia não distingue nada: ErrNaoEhArquivo sai igual nas duas
// implementações. O que separa é se a abertura real aconteceu, e isso só aparece
// instrumentando o abridor — é para isso que safeio.ObservarAberturaReal existe.
func TestLeituraNuncaAbreObjetoNaoProvado(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, "parece-config")
	if err := os.Symlink("/dev/zero", link); err != nil {
		t.Skipf("sem symlink neste ambiente: %v", err)
	}
	fifo := filepath.Join(dir, "fifo-config")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo indisponível: %v", err)
	}

	var reais []string
	safeio.ObservarAberturaReal = func(p string) { reais = append(reais, p) }
	t.Cleanup(func() { safeio.ObservarAberturaReal = nil })

	e := &Env{}
	casos := []struct {
		nome, alvo string
		fn         func(string) error
	}{
		{"ReadFile/symlink-para-device", link, func(p string) error {
			_, err := e.ReadFile(p)
			return err
		}},
		{"OpenFD/device", "/dev/zero", func(p string) error {
			fh, err := e.OpenFD(p)
			if fh != nil {
				fh.Close()
			}
			return err
		}},
		{"Open/symlink-para-device", link, func(p string) error {
			fh, err := e.Open(p)
			if fh != nil {
				fh.Close()
			}
			return err
		}},
		{"ReadFile/fifo", fifo, func(p string) error {
			_, err := e.ReadFile(p)
			return err
		}},
	}
	for _, c := range casos {
		t.Run(c.nome, func(t *testing.T) {
			reais = nil
			// O timeout não é zelo: um fifo aberto sem O_NONBLOCK pendura a
			// goroutine para sempre, e sem isto o teste ficaria parado em vez
			// de falhar.
			done := make(chan error, 1)
			go func() { done <- c.fn(c.alvo) }()
			select {
			case err := <-done:
				if !errors.Is(err, ErrNaoEhArquivo) {
					t.Fatalf("err=%v, queria ErrNaoEhArquivo", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("BLOQUEOU: o open pendurou a varredura")
			}
			if len(reais) > 0 {
				t.Errorf("%d abertura(s) REAL sobre um objeto que não é arquivo "+
					"comum: %v\nO open() do driver roda antes de qualquer recusa — "+
					"num host comprometido um caminho de aparência banal pode ser "+
					"um /dev/qualquer-coisa que faz algo ao ser aberto.",
					len(reais), reais)
			}
		})
	}
}

// E O CAMINHO FELIZ CONTINUA SEGUINDO SYMLINK.
//
// Sem isto, um código que recusasse tudo passaria no teste acima. E a cadeia
// importa: /etc/os-release -> /usr/lib/os-release é rootfs normal, não evasão —
// uma primitive que recusasse link quebraria a coleta em toda distribuição.
func TestLeituraSegueCadeiaDeSymlink(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	if err := os.WriteFile(real, []byte("conteudo\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real", filepath.Join(dir, "l1")); err != nil {
		t.Skipf("sem symlink: %v", err)
	}
	if err := os.Symlink(filepath.Join(dir, "l1"), filepath.Join(dir, "l2")); err != nil {
		t.Fatal(err)
	}

	e := &Env{}
	// Dois saltos, um relativo e um absoluto: são as duas regras de resolução, e
	// trocá-las faria a leitura cair num arquivo que ninguém pediu.
	b, err := e.ReadFile(filepath.Join(dir, "l2"))
	if err != nil || string(b) != "conteudo\n" {
		t.Fatalf("cadeia de symlink: %q %v", b, err)
	}

	fh, err := e.OpenFD(filepath.Join(dir, "l1"))
	if err != nil {
		t.Fatalf("OpenFD pelo link: %v", err)
	}
	defer fh.Close()
	fi, err := fh.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("o descritor tinha de ser o do arquivo comum: %v %v", fi, err)
	}
}
