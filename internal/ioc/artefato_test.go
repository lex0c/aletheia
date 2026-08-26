package ioc

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// `mkfifo indicators.yml` PENDURAVA O SCAN INTEIRO.
//
// A lista é carregada antes da varredura, e o os.Open de um fifo não retorna
// até aparecer um escritor. Não havia timeout, cancelamento nem lacuna: o
// comando simplesmente não saía do lugar. O teto de MaxLista não ajuda — um
// teto de leitura não protege contra um open que não volta.
func TestListaEmFifoNaoTravaOScan(t *testing.T) {
	p := filepath.Join(t.TempDir(), "indicators.yml")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Skipf("mkfifo indisponível: %v", err)
	}
	done := make(chan error, 1)
	go func() { _, err := Carregar(p); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("um fifo não é lista de indicadores: tinha de ser recusado")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("BLOQUEOU: Carregar num fifo pendurou o scan")
	}
}

// E a lista de verdade continua carregando, inclusive por symlink — que é como
// um diretório de caso costuma apontar para a lista compartilhada.
func TestListaPorSymlinkCarrega(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.yml")
	if err := os.WriteFile(real, []byte("paths: [/tmp/mau]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "indicators.yml")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("sem symlink: %v", err)
	}
	l, err := Carregar(link)
	if err != nil {
		t.Fatalf("lista por symlink: %v", err)
	}
	if l == nil || len(l.Do(Caminho)) == 0 {
		t.Error("a lista carregou sem o indicador de caminho")
	}
}
