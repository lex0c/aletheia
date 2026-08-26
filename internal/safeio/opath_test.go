package safeio

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// O_PATH FAZ O QUE ESTE CÓDIGO ACHA QUE FAZ.
//
// A constante não é exportada pelo syscall do Go e está escrita à mão aqui —
// 010000000, o valor do asm-generic. Um número de kernel escrito à mão merece
// prova, e a propriedade que importa não é o número: é que o descritor
// resultante NÃO seja legível, porque é isso que garante que o open() do driver
// não foi chamado.
func TestOPathAbreSemPermitirLeitura(t *testing.T) {
	// O alvo é um ARQUIVO COMUM, e não um diretório: ler um diretório falha de
	// qualquer jeito, e um teste sobre "/" passaria mesmo com oPath = 0. A
	// primeira versão deste teste fazia exatamente isso, e a mutação que zerava
	// a constante passou limpa.
	alvo := filepath.Join(t.TempDir(), "comum.txt")
	if err := os.WriteFile(alvo, []byte("conteudo"), 0o644); err != nil {
		t.Fatal(err)
	}
	fd, err := syscall.Open(alvo, syscall.O_RDONLY|oPath|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("O_PATH não abriu um arquivo comum: a constante 0x%x não é "+
			"O_PATH neste kernel/arquitetura (%v)", oPath, err)
	}
	defer syscall.Close(fd)

	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		t.Fatalf("fstat num descritor O_PATH tem de funcionar: %v", err)
	}
	b := make([]byte, 1)
	if n, err := syscall.Read(fd, b); err == nil {
		t.Fatalf("o descritor de um arquivo comum é LEGÍVEL (%d byte): isto não "+
			"é O_PATH, e o open do driver de um device node estaria sendo "+
			"chamado antes da recusa", n)
	}
}
