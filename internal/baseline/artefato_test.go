package baseline

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// UMA BASELINE EM FIFO PENDURAVA O SCAN ANTES DA VARREDURA COMEÇAR.
//
// MaxBaseline defende contra tamanho, e um `truncate -s 8G` era o cenário que
// ele foi escrito para fechar. Ele não defende contra um open que não retorna —
// e o arquivo mora no diretório de incidente DO HOST INVESTIGADO, onde quem tem
// escrita escolhe o que ele é. `mkfifo baseline.json` bastava.
func TestBaselineEmFifoNaoTravaOScan(t *testing.T) {
	p := filepath.Join(t.TempDir(), "baseline.json")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Skipf("mkfifo indisponível: %v", err)
	}
	done := make(chan error, 1)
	go func() { _, err := Carregar(p); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("um fifo não é baseline: tinha de ser recusado")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("BLOQUEOU: Carregar num fifo pendurou o scan")
	}
}

// E UM SYMLINK PARA DEVICE TAMBÉM NÃO ABRE O DEVICE.
//
// `ln -sf /dev/zero baseline.json` num diretório de incidente: o os.Open seguia
// o link e abria o device. Com /dev/zero o efeito é uma leitura sem fim contida
// pelo teto; com um device cujo open() tem efeito colateral, o efeito é no HOST.
func TestBaselineParaDeviceEhRecusada(t *testing.T) {
	p := filepath.Join(t.TempDir(), "baseline.json")
	if err := os.Symlink("/dev/zero", p); err != nil {
		t.Skipf("sem symlink: %v", err)
	}
	done := make(chan error, 1)
	go func() { _, err := Carregar(p); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("um device não é baseline: tinha de ser recusado")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("BLOQUEOU ou leu sem fim")
	}
}
