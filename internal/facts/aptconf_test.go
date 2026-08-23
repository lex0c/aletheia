package facts

import (
	"os"
	"path/filepath"
	"strings"
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

		// P2 da revisão: substring não é diretiva. Pre-Invoke-Disabled contém
		// "pre-invoke" e o apt NÃO executa a opção.
		{"nome que só CONTÉM o hook não é hook",
			`Foo::Pre-Invoke-Disabled {"/usr/local/bin/x";};`, nil},

		// P2 da revisão: escopo aninhado. DPkg{ Pre-Invoke{}; Post-Invoke{}; }
		// é sintaxe válida, e um hook não pode consumir o comando do outro.
		{"escopo aninhado com dois hooks",
			"DPkg {\n Pre-Invoke { \"a\"; };\n Post-Invoke { \"b\"; };\n};",
			[]string{"a", "b"}},

		{"lista de comandos no mesmo hook",
			`DPkg::Pre-Install-Pkgs {"a"; "b";};`, []string{"a", "b"}},

		// Caminho COMPLETO, não sufixo. Foo::Pre-Invoke termina em pre-invoke e o
		// apt não o executa — só os subtrees DPkg:: e APT::Update:: são chamados.
		{"escopo errado não é hook (Foo::Pre-Invoke)",
			`Foo::Pre-Invoke {"/x";};`, nil},

		{"APT::Update::Post-Invoke-Stats é hook real",
			`APT::Update::Post-Invoke-Stats {"/stats";};`, []string{"/stats"}},

		// Aninhamento profundo: APT { Update { Pre-Invoke {…} } } = apt::update::pre-invoke.
		{"escopo aninhado profundo casa o caminho",
			`APT { Update { Pre-Invoke { "/deep"; }; }; };`, []string{"/deep"}},

		// Item NOMEADO na lista: RunScripts executa o valor de cada filho, então
		// DPkg::Pre-Invoke::backdoor é hook. Forma escalar e forma de bloco.
		{"item nomeado escalar é hook",
			`DPkg::Pre-Invoke::backdoor "/usr/local/bin/.x";`,
			[]string{"/usr/local/bin/.x"}},
		{"item nomeado em bloco é hook",
			`DPkg::Post-Invoke::b { "/y"; };`, []string{"/y"}},
		// Mas o escopo errado com filho continua NÃO sendo hook.
		{"escopo errado com filho não é hook",
			`Foo::Pre-Invoke::backdoor "/x";`, nil},
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

// #include é diretiva do apt, não comentário: um hook escondido num arquivo
// incluído deixa de ser falso negativo. E #clear é declarado como limite.
func TestColetorResolveIncludeApt(t *testing.T) {
	raiz := t.TempDir()
	dir := filepath.Join(raiz, "etc/apt/apt.conf.d")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(raiz, "opt"), 0o755); err != nil {
		t.Fatal(err)
	}
	// 99x inclui um arquivo fora de qualquer diretório de gatilho.
	if err := os.WriteFile(filepath.Join(dir, "99x"),
		[]byte("#include \"/opt/.apt-hidden\";\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(raiz, "opt/.apt-hidden"),
		[]byte("DPkg::Pre-Invoke {\"/usr/local/bin/.implant\";};\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	e := env.Probe(env.Options{Root: raiz, Version: "test"})
	f := &Facts{}
	collectTriggers(f, e)

	var achou bool
	for i := range f.Triggers {
		if filepath.Base(f.Triggers[i].File) == "99x" {
			for _, h := range f.Triggers[i].AptHooks {
				if h.Text == "/usr/local/bin/.implant" {
					achou = true
				}
			}
		}
	}
	if !achou {
		t.Errorf("o hook do arquivo INCLUÍDO não chegou em AptHooks: #include foi " +
			"tratado como comentário, e o hook ficou invisível")
	}
}

// #clear é declarado como limite honesto, não fingido resolvido.
func TestClearApenasDeclaraLimite(t *testing.T) {
	raiz := t.TempDir()
	dir := filepath.Join(raiz, "etc/apt/apt.conf.d")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	conf := "DPkg::Pre-Invoke {\"/x\";};\n#clear DPkg::Pre-Invoke;\n"
	if err := os.WriteFile(filepath.Join(dir, "50c"), []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	e := env.Probe(env.Options{Root: raiz, Version: "test"})
	f := &Facts{}
	collectTriggers(f, e)

	// A chave TEM de ser "apt", não "startup": sob "startup" a lacuna contamina
	// a fonte de drift inteira (profile.d, rc.local, PAM…) — o poison do P1.
	var naApt, naStartup bool
	for _, g := range f.Partial["apt"] {
		if strings.Contains(g, "#clear") {
			naApt = true
		}
	}
	for _, g := range f.Partial["startup"] {
		if strings.Contains(g, "#clear") {
			naStartup = true
		}
	}
	if !naApt {
		t.Error("o apt.conf usa #clear e o limite não foi declarado sob a chave " +
			"'apt': ou não foi declarado, ou foi para 'startup' e vai poluir a " +
			"fonte de drift inteira")
	}
	if naStartup {
		t.Error("o #clear foi declarado sob 'startup': contamina o drift de " +
			"profile.d/rc.local/PAM, que não têm nada com a config do apt")
	}
}

// O apt não carrega qualquer arquivo de apt.conf.d — só nome válido, sem
// extensão ou .conf. Um 99implant.bak com hook NÃO executa, e não pode virar
// gatilho ativo (falso positivo determinístico, potencialmente CRITICAL).
func TestColetorFiltraFragmentosQueOAptIgnora(t *testing.T) {
	raiz := t.TempDir()
	dir := filepath.Join(raiz, "etc/apt/apt.conf.d")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	hook := "DPkg::Pre-Invoke {\"/x\";};\n"
	arquivos := map[string]bool{ // nome -> apt carrega?
		"99good":        true,
		"99good.conf":   true,
		"50unatt-upgr":  true,
		"99implant.bak": false,
		"99x.disabled":  false,
		"99x~":          false,
		"99x.dpkg-old":  false,
		"99@x":          false,
	}
	for n := range arquivos {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(hook), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	e := env.Probe(env.Options{Root: raiz, Version: "test"})
	f := &Facts{}
	collectTriggers(f, e)

	virouGatilho := map[string]bool{}
	for i := range f.Triggers {
		virouGatilho[filepath.Base(f.Triggers[i].File)] = true
	}
	for n, deveCarregar := range arquivos {
		if virouGatilho[n] != deveCarregar {
			t.Errorf("%s: virou gatilho=%v, apt carrega=%v", n, virouGatilho[n], deveCarregar)
		}
	}
}
