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
	raiz := t.TempDir()
	p := filepath.Join(raiz, "authorized_keys")
	if err := os.WriteFile(p, []byte("ssh-rsa AAAA x@y\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Bem no passado, como um arquivo que ninguém toca há semanas.
	antigo := time.Date(2026, 6, 1, 3, 0, 0, 0, time.UTC)
	if err := os.Chtimes(p, antigo, antigo); err != nil {
		t.Fatal(err)
	}
	// PROVA que este filesystem mexe no atime, antes de afirmar que a leitura
	// não mexeu. Sem isto o teste passa por vacuidade: em `noatime` — que é
	// como o /tmp desta máquina está montado, e é onde t.TempDir() cai —
	// leitura nenhuma move atime, e a asserção fica verdadeira mesmo com o
	// O_NOATIME removido. Foi assim que a primeira versão deste teste passou
	// no mutante.
	if err := lerCru(p); err != nil {
		t.Fatal(err)
	}
	if depoisDoCru, err := atimeDe(p); err != nil {
		t.Skipf("atime não é legível aqui: %v", err)
	} else if depoisDoCru.Equal(antigo) {
		t.Skip("o filesystem deste TempDir está em noatime: nada move atime " +
			"aqui, e o teste não teria como distinguir a correção da ausência dela")
	}
	// De volta ao passado, agora com a garantia de que o relógio anda.
	if err := os.Chtimes(p, antigo, antigo); err != nil {
		t.Fatal(err)
	}
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

func atimeDe(p string) (time.Time, error) {
	fi, err := os.Lstat(p)
	if err != nil {
		return time.Time{}, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return time.Time{}, errors.New("sem Stat_t neste sistema")
	}
	return time.Unix(st.Atim.Sec, st.Atim.Nsec).UTC(), nil
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
