package safeio

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// A REABERTURA SEM /proc RECUSA UM ARQUIVO TROCADO.
//
// /proc/self/fd/N reabre o MESMO inode por construção, e é o caminho preferido.
// Mas /proc pode não estar montado — um shell de resgate, um initramfs —, e ali
// file.read falhava inteiro com um erro que fala de /proc/self/fd/3 para quem
// pediu /etc/shadow.
//
// O segundo caminho reabre pelo NOME a partir do descritor do diretório pai,
// que continua pinado. Isso reabre uma janela minúscula: entre a identificação e
// a reabertura, alguém com escrita no diretório pode trocar o arquivo. A janela
// não é fechada com uma promessa — ela é CONFERIDA: o inode reaberto tem de ser
// o mesmo, e divergir vira recusa em vez de conteúdo de outro objeto.
func TestReaberturaSemProcRecusaArquivoTrocado(t *testing.T) {
	dir := t.TempDir()
	alvo := filepath.Join(dir, "alvo")
	if err := os.WriteFile(alvo, []byte("o certo"), 0o644); err != nil {
		t.Fatal(err)
	}
	pai, err := syscall.Open(dir, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(pai)

	var st syscall.Stat_t
	if err := syscall.Stat(alvo, &st); err != nil {
		t.Fatal(err)
	}

	// 1. Inode confere: abre.
	fh, err := reabrirPeloPai(pai, "alvo", st, os.O_RDONLY, false)
	if err != nil {
		t.Fatalf("com o inode certo tinha de abrir: %v", err)
	}
	b := make([]byte, 16)
	n, _ := fh.Read(b)
	fh.Close()
	if string(b[:n]) != "o certo" {
		t.Errorf("leu %q", b[:n])
	}

	// 2. O arquivo é TROCADO por outro com o mesmo nome — o que um atacante com
	//    escrita no diretório faz.
	if err := os.Remove(alvo); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(alvo, []byte("o do atacante"), 0o644); err != nil {
		t.Fatal(err)
	}
	var novoSt syscall.Stat_t
	if err := syscall.Stat(alvo, &novoSt); err != nil {
		t.Fatal(err)
	}
	if novoSt.Ino == st.Ino {
		t.Skip("o filesystem reciclou o inode: o teste não distingue nada aqui")
	}

	if fh, err := reabrirPeloPai(pai, "alvo", st, os.O_RDONLY, false); err == nil {
		b := make([]byte, 32)
		n, _ := fh.Read(b)
		fh.Close()
		t.Fatalf("o arquivo foi trocado e a reabertura devolveu %q: a resposta "+
			"descreveria a identidade de um objeto e o conteúdo de outro", b[:n])
	} else if !strings.Contains(err.Error(), "TROCADO") {
		t.Errorf("a recusa precisa dizer o que houve: %v", err)
	}

	// 3. E o DEVICE também entra na comparação. A identidade do Linux é o par
	//    (st_dev, st_ino): número de inode só é único DENTRO de um filesystem, e
	//    num host onde o atacante monta filesystem outro dispositivo pode trazer
	//    um inode de mesmo número naquele nome.
	esperado := novoSt
	esperado.Dev++
	if fh, err := reabrirPeloPai(pai, "alvo", esperado, os.O_RDONLY, false); err == nil {
		fh.Close()
		t.Error("o dev divergiu e a reabertura aceitou: comparar só o inode " +
			"aceita a troca de filesystem sob o mesmo nome")
	}
}
