package info

import (
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/facts"
)

// O caso que originou o comando: invasor acrescenta backdoor e faz `--amend`
// para o commit revisado virar outro. O reflog guarda o sha ANTERIOR, e é por
// ele que o conteúdo anterior volta — enquanto o `gc` não roda.
func TestAmendViraReescritaComOComandoDeRecuperacao(t *testing.T) {
	r := &facts.RepoGit{
		Dir: "/srv/app",
		Reflog: []facts.EntradaReflog{
			{De: "aaa", Para: "bbb", Acao: "commit", Quem: "dev <d@x>"},
			{De: "bbb", Para: "ccc", Acao: "commit (amend)", Quem: "invasor <i@evil>",
				QuandoU: "2026-08-18T13:38:52Z"},
		},
	}
	c := CensoDoGit(r)
	if len(c.Reescritas) != 1 {
		t.Fatalf("reescritas = %+v — commit normal NÃO é reescrita", c.Reescritas)
	}
	re := c.Reescritas[0]
	if !strings.Contains(re.Recupera, "bbb") {
		t.Errorf("o comando precisa citar o sha ANTERIOR, que é o que devolve o "+
			"conteúdo apagado: %q", re.Recupera)
	}
	// E o inventário de atores, que a revisão de código não dá.
	if len(c.Identidades) != 2 {
		t.Errorf("identidades = %+v", c.Identidades)
	}
}

// hooksPath tira os hooks de .git/hooks: quem inspecionar o lugar de sempre
// não encontra nada. É a forma que derrota a inspeção manual.
func TestHooksPathViraPadraoNomeado(t *testing.T) {
	r := &facts.RepoGit{
		Dir: "/srv/app",
		Config: []facts.OpcaoDeGit{
			{Chave: "core.hookspath", Valor: "../fora", Motivo: "redireciona"},
		},
		Hooks: []facts.HookDeGit{{Nome: "post-checkout", Executavel: true}},
	}
	c := CensoDoGit(r)
	if c.HooksRedirecionados != "../fora" {
		t.Fatalf("o redirecionamento não foi lido: %q", c.HooksRedirecionados)
	}
	var achou bool
	for _, p := range c.Padroes {
		if p.Tipo == "hooks redirecionados" {
			achou = true
			if p.Comum {
				t.Error("redirecionar hook para fora do repositório NÃO é forma comum")
			}
		}
	}
	if !achou {
		t.Errorf("padrões = %+v", c.Padroes)
	}
}

// Hook SEM bit de execução não roda — o git entrega quatorze de exemplo assim.
// Contá-los faria todo repositório do mundo aparecer com hooks ativos.
func TestHookSemBitDeExecucaoNaoContaComoAtivo(t *testing.T) {
	r := &facts.RepoGit{Dir: "/srv/app", Hooks: []facts.HookDeGit{
		{Nome: "pre-commit", Executavel: false},
		{Nome: "post-checkout", Executavel: true},
	}}
	c := CensoDoGit(r)
	if c.HooksAtivos != 1 {
		t.Errorf("hooks ativos = %d, queria 1", c.HooksAtivos)
	}
}

// As formas que TAMBÉM são uso legítimo frequente vêm marcadas e por último —
// git-lfs usa filtro, e todo mundo usa exclude local. Marcar não é suprimir.
func TestFormasComunsVemMarcadasEPorUltimo(t *testing.T) {
	r := &facts.RepoGit{
		Dir:       "/srv/app",
		Atributos: []string{"*.psd filter=lfs"},
		Exclude:   []string{"/build"},
		Intrusos:  []string{".cache.bin"},
	}
	c := CensoDoGit(r)
	if len(c.Padroes) != 3 {
		t.Fatalf("padrões = %+v", c.Padroes)
	}
	// O intruso no .git não é forma comum, e vem antes das duas que são.
	if c.Padroes[0].Comum {
		t.Errorf("o arquivo estranho dentro do .git vem primeiro: %+v", c.Padroes)
	}
	for _, p := range c.Padroes[1:] {
		if !p.Comum {
			t.Errorf("%q precisa vir marcado como forma comum", p.Tipo)
		}
	}
}

// Repositório sem nada não inventa padrão. Nomear forma onde não há é pior que
// calar, porque a frase sai com cara de conclusão.
func TestRepoLimpoNaoInventaPadrao(t *testing.T) {
	c := CensoDoGit(&facts.RepoGit{Dir: "/srv/app", HEAD: "ref: refs/heads/main"})
	if len(c.Padroes) != 0 {
		t.Errorf("padrões = %+v", c.Padroes)
	}
	if len(c.Reescritas) != 0 {
		t.Errorf("reescritas = %+v", c.Reescritas)
	}
}
