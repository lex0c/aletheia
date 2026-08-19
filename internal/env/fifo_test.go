package env

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// O cenário é `mkfifo /var/log/wtmp` num host que a ferramenta vai varrer.
// ReadFile gastava um Lstat para recusar fifo e Open não recusava nada, então
// lerUtmp travava em open(2) e hashDoArquivo travava DENTRO de um worker — com
// o wg.Wait() do chamador esperando para sempre. Sem timeout e sem lacuna
// declarada: a varredura simplesmente não terminava.
func TestFifoNaoBloqueiaNemEmReadFileNemEmOpen(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "wtmp")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Skipf("mkfifo indisponível neste ambiente: %v", err)
	}
	e := &Env{}
	casos := []struct {
		nome string
		fn   func() error
	}{
		{"ReadFile", func() error { _, err := e.ReadFile(fifo); return err }},
		{"Open", func() error {
			fh, err := e.Open(fifo)
			if err == nil {
				fh.Close()
			}
			return err
		}},
		{"OpenFD", func() error {
			fh, err := e.OpenFD(fifo)
			if err == nil {
				fh.Close()
			}
			return err
		}},
	}
	for _, c := range casos {
		t.Run(c.nome, func(t *testing.T) {
			done := make(chan error, 1)
			go func() { done <- c.fn() }()
			select {
			case err := <-done:
				if !errors.Is(err, ErrNaoEhArquivo) {
					t.Fatalf("esperava ErrNaoEhArquivo, veio %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("BLOQUEOU: o open do fifo pendurou a varredura")
			}
		})
	}

	// E o arquivo comum continua sendo lido normalmente.
	reg := filepath.Join(dir, "normal")
	if err := os.WriteFile(reg, []byte("ok\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, err := e.ReadFile(reg); err != nil || string(b) != "ok\n" {
		t.Fatalf("arquivo comum quebrou: %q %v", b, err)
	}
}

// root == nil significa "host vivo" em todos os acessores, e Close() punha
// exatamente isso: qualquer leitura depois do Close passava a ler o filesystem
// do ANALISTA enquanto Path() continuava imprimindo o caminho sob a imagem.
func TestEnvDeImagemSemRaizRecusaLeitura(t *testing.T) {
	e := &Env{Root: "/mnt/img", Source: SourceImage}
	if _, err := e.ReadFile("/etc/hostname"); !errors.Is(err, ErrSemRaiz) {
		t.Errorf("ReadFile devolveu %v, quer ErrSemRaiz", err)
	}
	if _, err := e.Stat("/etc/hostname"); !errors.Is(err, ErrSemRaiz) {
		t.Errorf("Stat devolveu %v, quer ErrSemRaiz", err)
	}
	if _, err := e.Lstat("/etc/hostname"); !errors.Is(err, ErrSemRaiz) {
		t.Errorf("Lstat devolveu %v, quer ErrSemRaiz", err)
	}
	if _, err := e.ReadDir("/etc"); !errors.Is(err, ErrSemRaiz) {
		t.Errorf("ReadDir devolveu %v, quer ErrSemRaiz", err)
	}
	if _, err := e.Readlink("/etc/os-release"); !errors.Is(err, ErrSemRaiz) {
		t.Errorf("Readlink devolveu %v, quer ErrSemRaiz", err)
	}
	// E o host vivo (Source zero / SourceLive) continua lendo.
	vivo := &Env{}
	if _, err := vivo.Stat("/"); err != nil {
		t.Errorf("host vivo quebrou: %v", err)
	}
}
