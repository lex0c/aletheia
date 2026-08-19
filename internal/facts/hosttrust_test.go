package facts

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/lex0c/aletheia/internal/env"
)

func TestCollectConfiancaDeHost(t *testing.T) {
	raiz := t.TempDir()
	esc := func(rel, conteudo string, modo os.FileMode) {
		full := filepath.Join(raiz, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(conteudo), modo); err != nil {
			t.Fatal(err)
		}
	}
	// passwd para o laço de homes achar /home/ana
	esc("etc/passwd", "root:x:0:0::/root:/bin/sh\nana:x:1000:1000::/home/ana:/bin/sh\n", 0o644)
	esc("etc/hosts.equiv", "# confiança\n+\n", 0o644) // curinga, sistema
	esc("root/.rhosts", "buildserver\n", 0o644)       // nomeado, usuário
	esc("home/ana/.shosts", "outro\n", 0o644)
	// Chmod explícito: WriteFile aplica o umask e comeria o bit de grupo/outros.
	if err := os.Chmod(filepath.Join(raiz, "home/ana/.shosts"), 0o646); err != nil {
		t.Fatal(err)
	}

	e := env.Probe(env.Options{Root: raiz, Version: "test"})
	defer e.Close()
	f := &Facts{}
	collectConfiancaDeHost(f, e)

	if len(f.ConfiancaDeHost) != 3 {
		t.Fatalf("esperava 3 arquivos de confiança, veio %d: %+v", len(f.ConfiancaDeHost), f.ConfiancaDeHost)
	}
	porPath := map[string]ConfiancaDeHost{}
	for _, c := range f.ConfiancaDeHost {
		porPath[c.Path] = c
	}
	if c := porPath["/etc/hosts.equiv"]; !c.Curinga || c.Escopo != "sistema" {
		t.Errorf("hosts.equiv com + tinha de ser curinga/sistema: %+v", c)
	}
	if c := porPath["/root/.rhosts"]; c.Curinga || c.Escopo != "usuario" || c.Conta != "root" {
		t.Errorf("/root/.rhosts: %+v", c)
	}
	if c := porPath["/home/ana/.shosts"]; !c.Gravavel {
		t.Errorf("/home/ana/.shosts devia ser detectado gravável: modo=%s", c.Modo)
	}
}
