package env

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// Ler um arquivo MOVE o atime dele, e num filesystem com `relatime` — o padrão
// de toda distribuição — isso apaga a data em que o arquivo foi lido pela
// última vez.
//
// Medido antes da correção: um `authorized_keys` com atime de 1º de junho saía
// da varredura com o atime de HOJE. A ferramenta usa data como evidência (§9);
// destruir uma das três enquanto lê as outras é o investigador apagando a
// resposta de "quem leu isto, e quando".
func TestLeituraPreservaOAtime(t *testing.T) {
	raiz := dirQueRastreiaAtime(t)
	p := filepath.Join(raiz, "authorized_keys")
	if err := os.WriteFile(p, []byte("ssh-rsa AAAA x@y\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Bem no passado, como um arquivo que ninguém toca há semanas.
	antigo := time.Date(2026, 6, 1, 3, 0, 0, 0, time.UTC)
	if err := os.Chtimes(p, antigo, antigo); err != nil {
		t.Fatal(err)
	}
	// dirQueRastreiaAtime já provou que o relógio anda aqui.
	antes, err := atimeDe(p)
	if err != nil {
		t.Fatal(err)
	}

	e := Probe(Options{Root: raiz})
	t.Cleanup(e.Close)
	if _, err := e.ReadFile("/authorized_keys"); err != nil {
		t.Fatalf("o arquivo precisa continuar sendo LIDO: %v", err)
	}

	depois, err := atimeDe(p)
	if err != nil {
		t.Fatal(err)
	}
	if !depois.Equal(antes) {
		t.Errorf("o atime andou de %v para %v: a leitura apagou a data em que "+
			"alguém leu este arquivo pela última vez", antes, depois)
	}
}

// dirQueRastreiaAtime devolve um diretório onde o atime de fato anda.
//
// O teste de atime pulava quando TMPDIR estava em noatime — que é o caso desta
// máquina — e pular é honesto, mas uma garantia cujo teste nunca roda no
// ambiente de quem desenvolve é quase uma garantia que ninguém confere. Foi
// assim que a regressão do percurso por descritor passou: o coletor tinha
// teste, o teste pulava, e o caminho novo nasceu sem O_NOATIME.
//
// Então há um segundo chão: o diretório do pacote, que está num filesystem de
// verdade. Só se NENHUM dos dois rastrear é que o teste pula.
func dirQueRastreiaAtime(t *testing.T) string {
	t.Helper()
	rastreia := func(dir string) bool {
		p := filepath.Join(dir, "sonda-atime")
		if os.WriteFile(p, []byte("x"), 0o644) != nil {
			return false
		}
		antigo := time.Date(2026, 6, 1, 3, 0, 0, 0, time.UTC)
		if os.Chtimes(p, antigo, antigo) != nil {
			return false
		}
		if lerCru(p) != nil {
			return false
		}
		depois, err := atimeDe(p)
		return err == nil && !depois.Equal(antigo)
	}
	if d := t.TempDir(); rastreia(d) {
		return d
	}
	d, err := os.MkdirTemp(".", "atime")
	if err != nil {
		t.Skipf("sem onde medir atime: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	// ABSOLUTO: AbrirParaInspecao normaliza com path.Clean("/"+p), então um
	// caminho relativo viraria outro caminho, ancorado na raiz.
	if abs, err := filepath.Abs(d); err == nil {
		d = abs
	}
	if !rastreia(d) {
		t.Skip("nenhum filesystem alcançável rastreia atime: aqui o teste não " +
			"distinguiria a correção da ausência dela")
	}
	return d
}

func atimeDe(p string) (time.Time, error) {
	fi, err := os.Lstat(p)
	if err != nil {
		return time.Time{}, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return time.Time{}, errors.New("sem Stat_t neste sistema")
	}
	// int64() explícito: em i386 os campos de Timespec são int32, e passá-los
	// direto para time.Unix (que quer int64) não compila. Cross-compilar os
	// TESTES para as três arquiteturas passou a ser portão de CI, e foi assim
	// que isto apareceu.
	return time.Unix(int64(st.Atim.Sec), int64(st.Atim.Nsec)).UTC(), nil
}

// lerCru lê pelo caminho normal do Go, SEM O_NOATIME. Serve para provar que o
// filesystem sob o teste realmente atualiza atime.
func lerCru(p string) error {
	fh, err := os.Open(p)
	if err != nil {
		return err
	}
	defer fh.Close()
	buf := make([]byte, 64)
	if _, err := fh.Read(buf); err != nil && err.Error() != "EOF" {
		return err
	}
	return nil
}
