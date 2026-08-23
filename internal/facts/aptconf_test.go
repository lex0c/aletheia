package facts

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/lex0c/aletheia/internal/env"
)

// O lexer do apt tem de bater com a ordem do parser real: bloco antes de linha,
// e aspas protegendo os dois. O caso que importa é adversário — um hook escondido
// atrás de um bloco /* … */ que fecha no meio de uma linha começada por #, que o
// parser genérico de gatilho descartaria inteira.
func TestAnalisarAptHooks(t *testing.T) {
	casos := []struct {
		nome string
		conf string
		quer []string // comandos esperados; nil = nenhum hook
	}{
		{"só opção (50unattended-upgrades)", `
APT::Periodic::Unattended-Upgrade "1";
Unattended-Upgrade::Origins-Pattern {
  "origin=Debian,codename=${distro_codename}";
};`, nil},

		{"hook simples com chave", `DPkg::Pre-Install-Pkgs {"/usr/local/bin/x";};`,
			[]string{"/usr/local/bin/x"}},

		{"hook sem chave", `APT::Update::Pre-Invoke "/usr/bin/y";`,
			[]string{"/usr/bin/y"}},

		{"exemplo comentado com //", `// DPkg::Pre-Invoke {"/z";};`, nil},

		{"exemplo comentado em bloco", `/* DPkg::Pre-Invoke {"/z";}; */`, nil},

		{"exemplo comentado com #", `# DPkg::Post-Invoke {"/z";};`, nil},

		// O ATAQUE: o bloco abre na linha 1, a linha 2 começa com # (que o parser
		// genérico jogaria fora), o */ fecha o bloco no meio dela, e o hook fica
		// ATIVO. O apt executa /implant; o Aletheia tem de ver.
		{"hook escondido atrás de bloco fechando após #",
			"/*\n# */ DPkg::Pre-Invoke {\"/usr/local/bin/implant\";};",
			[]string{"/usr/local/bin/implant"}},

		{"palavra-chave DENTRO de string não é hook",
			`APT::Get::Assume-Yes "true"; Foo "mentions pre-invoke here";`, nil},

		{"# dentro de string é dado, não comentário",
			`DPkg::Pre-Invoke {"/bin/sh -c '# not a comment'";};`,
			[]string{"/bin/sh -c '# not a comment'"}},
	}
	for _, c := range casos {
		hooks := analisarAptHooks([]byte(c.conf))
		var got []string
		for _, h := range hooks {
			got = append(got, h.Text)
		}
		if len(got) != len(c.quer) {
			t.Errorf("%s: hooks=%v, queria %v", c.nome, got, c.quer)
			continue
		}
		for i := range got {
			if got[i] != c.quer[i] {
				t.Errorf("%s: hook[%d]=%q, queria %q", c.nome, i, got[i], c.quer[i])
			}
		}
	}
}

// A prova do CAMINHO INTEIRO: escreve o apt.conf.d adversário no disco e roda o
// coletor de verdade, para o hook escondido chegar em AptHooks apesar de o
// parser genérico descartar a linha começada por #.
//
// É a lacuna que a revisão apontou: os testes de check montavam Trigger na mão e
// não passavam por lerTrigger, então nunca exercitavam a perda de informação.
func TestColetorExtraiHookEscondido(t *testing.T) {
	raiz := t.TempDir()
	dir := filepath.Join(raiz, "etc/apt/apt.conf.d")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// O bloco abre na linha 1; a linha 2 começa com # e o */ fecha o bloco no
	// meio dela. O apt executa o hook; o parser genérico jogaria a linha 2 fora.
	conf := "/*\n# */ DPkg::Pre-Invoke {\"/usr/local/bin/implant\";};\n"
	if err := os.WriteFile(filepath.Join(dir, "99hook"), []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	// E um vizinho só de opção, que NÃO pode virar hook.
	confOpts := "APT::Periodic::Unattended-Upgrade \"1\";\n"
	if err := os.WriteFile(filepath.Join(dir, "50opts"), []byte(confOpts), 0o644); err != nil {
		t.Fatal(err)
	}

	e := env.Probe(env.Options{Root: raiz, Version: "test"})
	f := &Facts{}
	collectTriggers(f, e)

	var hook, opts *Trigger
	for i := range f.Triggers {
		switch filepath.Base(f.Triggers[i].File) {
		case "99hook":
			hook = &f.Triggers[i]
		case "50opts":
			opts = &f.Triggers[i]
		}
	}
	if hook == nil {
		t.Fatal("o apt.conf.d 99hook não foi coletado como gatilho")
	}
	if len(hook.AptHooks) != 1 || hook.AptHooks[0].Text != "/usr/local/bin/implant" {
		t.Errorf("o hook escondido não chegou em AptHooks pelo coletor: %v\n"+
			"É o falso negativo determinístico que a correção existe para fechar.",
			hook.AptHooks)
	}
	if opts != nil && len(opts.AptHooks) != 0 {
		t.Errorf("o apt.conf.d só de opção ganhou AptHooks: %v", opts.AptHooks)
	}
}
