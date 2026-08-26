package safeio

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// ARTEFATO DO OPERADOR TAMBÉM É ENTRADA HOSTIL.
//
// Havia três implementações desta fronteira nesta árvore, e as três eram
// diferentes:
//
//	dump      O_NONBLOCK + fstat depois — fechava o fifo, não fechava o device
//	baseline  os.Open seco
//	ioc       os.Open seco
//
// As duas últimas travavam para SEMPRE num fifo, e as duas são carregadas ANTES
// da varredura: o `scan` inteiro não saía do lugar. O caminho é escolhido pelo
// operador; o CONTEÚDO vem do host investigado, do pendrive, do share.
func TestArtefatoNaoTravaENaoAbreDevice(t *testing.T) {
	dir := t.TempDir()

	fifo := filepath.Join(dir, "indicators.yml")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo indisponível: %v", err)
	}
	link := filepath.Join(dir, "baseline.json")
	if err := os.Symlink("/dev/zero", link); err != nil {
		t.Skipf("sem symlink: %v", err)
	}
	dirAlvo := filepath.Join(dir, "sub")
	if err := os.Mkdir(dirAlvo, 0o755); err != nil {
		t.Fatal(err)
	}

	var reais []string
	ObservarAberturaReal = func(p string) { reais = append(reais, p) }
	t.Cleanup(func() { ObservarAberturaReal = nil })

	for _, alvo := range []string{fifo, link, dirAlvo} {
		t.Run(filepath.Base(alvo), func(t *testing.T) {
			reais = nil
			done := make(chan error, 1)
			go func() {
				fh, err := AbrirArtefato(alvo)
				if fh != nil {
					fh.Close()
				}
				done <- err
			}()
			select {
			case err := <-done:
				if !errors.Is(err, ErrNaoRegular) {
					t.Fatalf("err=%v, queria ErrNaoRegular", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("BLOQUEOU: o open do artefato pendurou a ferramenta")
			}
			if len(reais) > 0 {
				t.Errorf("abertura REAL sobre objeto não provado: %v", reais)
			}
		})
	}
}

// E O CAMINHO RELATIVO CONTINUA FUNCIONANDO.
//
// A trava de raiz do modo image normaliza tudo contra "/", e aplicá-la aqui
// quebraria um `--ioc ../casos/x.yml`: o caminho é do OPERADOR, e o diretório
// de trabalho dele é parte da resposta.
func TestArtefatoAceitaCaminhoRelativo(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "lista.yml"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(sub)

	fh, err := AbrirArtefato("../lista.yml")
	if err != nil {
		t.Fatalf("caminho relativo com \"..\": %v", err)
	}
	defer fh.Close()
	b := make([]byte, 8)
	n, _ := fh.Read(b)
	if string(b[:n]) != "x\n" {
		t.Errorf("leu %q", b[:n])
	}
}
