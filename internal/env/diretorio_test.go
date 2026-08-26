package env

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// O TETO DE ENTRADAS AGE ANTES DA ALOCAÇÃO, E É DECLARADO.
//
// os.ReadDir materializa o diretório inteiro antes de devolver a primeira
// entrada, e a lista é escolhida por quem escreve nele. O teto que agia depois
// disso protegia o tamanho da SAÍDA, não o custo de chegar nela.
func TestReadDirTemTetoQueDeclara(t *testing.T) {
	orig := maxEntradasParaTeste
	maxEntradasParaTeste = 100
	t.Cleanup(func() { maxEntradasParaTeste = orig })

	dir := t.TempDir()
	for i := 0; i < 250; i++ {
		if err := os.WriteFile(filepath.Join(dir, "f"+strconv.Itoa(i)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	e := &Env{}

	ents, err := e.ReadDir(dir)
	if !errors.Is(err, ErrDiretorioCortado) {
		t.Fatalf("err=%v, queria ErrDiretorioCortado", err)
	}
	if len(ents) != 100 {
		t.Errorf("voltaram %d entradas, queria o teto de 100", len(ents))
	}
	// AS ENTRADAS VOLTAM JUNTO COM O ERRO. Descartá-las faria um atacante
	// apagar a varredura de um diretório inteiro criando cem mil arquivos
	// vazios ao lado do que ele quer esconder.
	if len(ents) == 0 {
		t.Error("a listagem cortada devolveu nada: o corte virou recusa")
	}
	// E EhLacuna classifica: os trinta chamadores que já perguntam isso passam
	// a declarar a lacuna certa sem uma linha de mudança.
	if !EhLacuna(err) {
		t.Error("um diretório cortado não está sendo classificado como lacuna")
	}

	// ReadDirNamesErr devolve os dois pelo mesmo motivo.
	nomes, err := e.ReadDirNamesErr(dir)
	if !errors.Is(err, ErrDiretorioCortado) || len(nomes) != 100 {
		t.Errorf("ReadDirNamesErr: %d nomes, err=%v", len(nomes), err)
	}
	// ReadDirNames engole o erro por contrato, e aí examinar cem é melhor que
	// examinar zero.
	if n := e.ReadDirNames(dir); len(n) != 100 {
		t.Errorf("ReadDirNames devolveu %d nomes num diretório cortado", len(n))
	}
}

// A ORDEM CONTINUA ESTÁVEL.
//
// ReadDirBatch entrega na ordem do readdir, que não é ordenada. ReadDir ordena
// o que guardou porque o drift compara saída contra saída: sem isso, duas
// coletas do mesmo host produzem listas em ordens diferentes.
func TestReadDirOrdenaComoAntes(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"zeta", "alfa", "meio", "beta"} {
		if err := os.WriteFile(filepath.Join(dir, n), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ents, err := (&Env{}).ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	quer := []string{"alfa", "beta", "meio", "zeta"}
	for i, ent := range ents {
		if ent.Name() != quer[i] {
			t.Fatalf("ordem %v, queria %v", nomesDe(ents), quer)
		}
	}
}

func nomesDe(ents []os.DirEntry) []string {
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}

// UM /var/log TROCADO POR FIFO NÃO PENDURA A LISTAGEM.
//
// É o mesmo caminho que abrirVerificado fecha para arquivo, entrando pela porta
// da listagem: sem O_DIRECTORY, o os.Open de um fifo bloqueia até aparecer um
// escritor, e não há timeout nem cancelamento nesse caminho.
func TestListagemDeFifoNaoTrava(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "log")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo indisponível: %v", err)
	}
	e := &Env{}
	for _, c := range []struct {
		nome string
		fn   func() error
	}{
		{"ReadDir", func() error { _, err := e.ReadDir(fifo); return err }},
		{"ReadDirBatch", func() error {
			return e.ReadDirBatch(fifo, func(os.DirEntry) error { return nil })
		}},
	} {
		t.Run(c.nome, func(t *testing.T) {
			done := make(chan error, 1)
			go func() { done <- c.fn() }()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("listou um fifo")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("BLOQUEOU: a listagem pendurou a varredura")
			}
		})
	}
}

// UM DIRETÓRIO INFLADO NÃO PODE APAGAR A VARREDURA DELE.
//
// O padrão desta base é `if err != nil { declara a lacuna; return }`, e para um
// diretório cortado esse `return` joga fora as entradas que FORAM lidas. Contra
// um atacante isso inverte o incentivo: encher o diretório passa a ser mais
// barato que esconder o arquivo, porque apaga a varredura inteira em vez de só
// torná-la cara.
//
// ListagemCortada é o que separa "não consegui listar" de "listei até o teto".
func TestListagemCortadaSeparaDoIlegivel(t *testing.T) {
	orig := maxEntradasParaTeste
	maxEntradasParaTeste = 50
	t.Cleanup(func() { maxEntradasParaTeste = orig })

	dir := t.TempDir()
	for i := 0; i < 120; i++ {
		if err := os.WriteFile(filepath.Join(dir, "f"+strconv.Itoa(i)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	e := &Env{}

	_, err := e.ReadDir(dir)
	if !ListagemCortada(err) {
		t.Errorf("um diretório cortado não foi reconhecido: %v", err)
	}
	if !EhLacuna(err) {
		t.Error("cortado tem de continuar sendo lacuna: as duas coisas são " +
			"verdade ao mesmo tempo")
	}

	// E o diretório que realmente não abre NÃO é "cortado": o chamador que
	// seguisse com as entradas ali estaria seguindo com um slice vazio.
	_, err = e.ReadDir(filepath.Join(dir, "nao-existe"))
	if ListagemCortada(err) {
		t.Errorf("um diretório ausente foi classificado como cortado: %v", err)
	}
	if EhLacuna(err) {
		t.Errorf("ausência não é lacuna: %v", err)
	}

	semPermissao := filepath.Join(dir, "fechado")
	if err := os.Mkdir(semPermissao, 0o000); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 {
		_, err = e.ReadDir(semPermissao)
		if ListagemCortada(err) {
			t.Errorf("um diretório sem permissão foi classificado como cortado: %v", err)
		}
		if !EhLacuna(err) {
			t.Errorf("sem permissão é lacuna: %v", err)
		}
	}
}
