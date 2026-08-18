package info

import (
	"sort"
	"strconv"
	"strings"

	"github.com/lex0c/aletheia/internal/facts"
)

// O censo de um REPOSITÓRIO — a terceira pergunta do `info`, no eixo do código.
//
// A varredura já procura `.git/hooks` em árvore (§7.12). O que ela não faz é
// olhar UM repositório por dentro, e é lá que a adulteração se esconde:
//
//	config que EXECUTA    hooksPath, fsmonitor, filter, alias com "!" — todos
//	                      rodam comando, por repositório, fora de /etc, e
//	                      sobrevivem a `git pull`
//	histórico REESCRITO   `--amend` e `reset --hard` reescrevem o que já foi
//	                      revisado. O reflog guarda o sha ANTERIOR, e é por ele
//	                      que o conteúdo apagado volta
//	escondido do status   .git/info/exclude nunca é commitado: um arquivo
//	                      listado ali some do `git status` e da revisão

// CensoDeGit é o retrato de um repositório.
type CensoDeGit struct {
	Dir     string
	HEAD    string
	Remotes []facts.RemoteGit

	// Executa é a superfície de execução do repositório, ordenada.
	Executa []facts.OpcaoDeGit
	Hooks   []facts.HookDeGit
	// HooksRedirecionados diz que os hooks NÃO estão em .git/hooks.
	HooksRedirecionados string

	// Reescritas são os movimentos de reflog que reescreveram histórico.
	Reescritas []Reescrita
	Movimentos int

	Escondidos []string

	// Identidades é QUEM moveu ref neste repositório, com a contagem. Sai do
	// reflog, que registra nome e e-mail de cada movimento — e uma identidade
	// que aparece duas vezes em quinhentos movimentos é uma visita.
	Identidades []Contagem

	Refs          int
	ObjetosSoltos int
	Packs         int

	Atributos []string
	Intrusos  []string

	// HooksAtivos são os que têm bit de execução: só eles rodam.
	HooksAtivos int

	IndexUTC string
	HeadUTC  string

	Padroes []Padrao
	Lacunas []string
}

// Reescrita é um movimento de reflog que apagou ou trocou histórico.
type Reescrita struct {
	Acao    string
	De      string
	Para    string
	Quem    string
	QuandoU string
	Msg     string
	// Recupera é o comando que traz de volta o que foi reescrito.
	Recupera string
}

// acoesQueReescrevem são as ações de reflog que TROCAM o que já existia, em vez
// de acrescentar. É a diferença entre "houve trabalho" e "o que havia mudou".
var acoesQueReescrevem = map[string]string{
	"commit (amend)": "o commit anterior foi SUBSTITUÍDO: a mensagem e o " +
		"conteúdo antigos não estão mais na branch",
	"reset":          "a branch foi movida para trás: os commits entre os dois shas saíram dela",
	"rebase":         "a série foi reescrita: todos os shas mudaram",
	"rebase (start)": "início de rebase — a série a seguir foi reescrita",
	"rebase -i":      "rebase interativo: commits podem ter sido editados, fundidos ou removidos",
	"filter-branch":  "reescrita em massa do histórico",
	"checkout -B":    "a branch foi recriada apontando para outro lugar",
	"branch -f":      "a branch foi movida à força",
	"update-ref":     "a ref foi movida diretamente, sem passar por commit",
}

// minRepeticaoDeReescrita é quantas reescritas seguidas antes de chamar de
// padrão. Uma é trabalho normal — todo mundo faz `--amend` para corrigir a
// mensagem. Várias na mesma sessão, sim.
const minRepeticaoDeReescrita = 3

// CensoDoGit monta o retrato. Puro sobre o que foi lido: os mesmos números
// saem de um host vivo e de uma imagem montada.
func CensoDoGit(r *facts.RepoGit) *CensoDeGit {
	c := &CensoDeGit{
		Dir: r.Dir, HEAD: r.HEAD, Remotes: r.Remotes, Hooks: r.Hooks,
		Escondidos: r.Exclude, IndexUTC: r.IndexUTC, HeadUTC: r.HeadUTC,
		Movimentos: len(r.Reflog), Lacunas: r.Lacunas,
		Refs: r.Refs, ObjetosSoltos: r.ObjetosSoltos, Packs: r.Packs,
		Atributos: r.Atributos, Intrusos: r.Intrusos,
	}
	for _, h := range r.Hooks {
		if h.Executavel {
			c.HooksAtivos++
		}
	}

	// QUEM mexeu, pelo reflog. É o inventário de atores do repositório, e é a
	// pergunta que a revisão de código não responde: ela vê o autor do commit,
	// que é campo LIVRE — o reflog registra quem rodou o comando na máquina.
	quem := map[string]int{}
	for i := range r.Reflog {
		if n := r.Reflog[i].Quem; n != "" {
			quem[n]++
		}
	}
	c.Identidades = ordenarContagens(mapaParaContagens(quem))

	c.Executa = append(c.Executa, r.Config...)
	sort.SliceStable(c.Executa, func(i, j int) bool { return c.Executa[i].Chave < c.Executa[j].Chave })
	for _, o := range r.Config {
		if o.Chave == "core.hookspath" {
			c.HooksRedirecionados = o.Valor
		}
	}

	for i := range r.Reflog {
		e := &r.Reflog[i]
		motivo, reescreve := acoesQueReescrevem[e.Acao]
		if !reescreve {
			continue
		}
		c.Reescritas = append(c.Reescritas, Reescrita{
			Acao: e.Acao, De: e.De, Para: e.Para, Quem: e.Quem,
			QuandoU: e.QuandoU, Msg: motivo,
			// O sha ANTERIOR é o ponteiro para o que sumiu, e ele continua no
			// banco de objetos até o próximo `gc`. É a única coisa aqui que
			// tem prazo.
			Recupera: "git cat-file -p " + e.De,
		})
	}
	sort.SliceStable(c.Reescritas, func(i, j int) bool {
		return c.Reescritas[i].QuandoU > c.Reescritas[j].QuandoU
	})

	c.Padroes = padroesDeGit(c)
	return c
}

func padroesDeGit(c *CensoDeGit) []Padrao {
	var out []Padrao

	// Hooks fora do repositório: quem inspecionar .git/hooks não vê nada.
	if c.HooksRedirecionados != "" {
		out = append(out, Padrao{
			Tipo: "hooks redirecionados",
			Alvo: "core.hooksPath = " + c.HooksRedirecionados,
			N:    len(c.Hooks),
			Detalhe: "os hooks que ESTE repositório roda não estão em .git/hooks: " +
				"quem inspecionar o lugar de sempre não encontra nada, e o que " +
				"executa mora fora do alcance da revisão de código",
		})
	}

	// Reescrita repetida: uma é trabalho normal, várias é padrão.
	if n := len(c.Reescritas); n >= minRepeticaoDeReescrita {
		out = append(out, Padrao{
			Tipo: "histórico reescrito",
			Alvo: strconv.Itoa(n) + " movimento(s) que trocaram histórico",
			N:    n,
			Detalhe: "reescrever é operação normal de desenvolvimento — e é também " +
				"a forma de fazer um commit revisado virar outro. O sha ANTERIOR " +
				"de cada linha ainda está no banco de objetos, até o próximo `gc`",
		})
	}

	// Hook ATIVO é a superfície de execução do repositório: ele roda em ação
	// corriqueira de desenvolvedor, sem ninguém pedir.
	if c.HooksAtivos > 0 {
		out = append(out, Padrao{
			Tipo: "hook executável",
			Alvo: strconv.Itoa(c.HooksAtivos) + " hook(s) com bit de execução",
			N:    c.HooksAtivos,
			Detalhe: "hook roda em `commit`, `checkout`, `merge` e `push` sem " +
				"ninguém pedir, e não é commitado: não aparece em revisão de " +
				"código nem em diff. Num servidor que atualiza por `git pull`, " +
				"é persistência que sobrevive ao redeploy (§7.12)",
		})
	}

	// Arquivo estranho DENTRO do .git: o diretório é pulado por quase toda
	// ferramenta e não aparece no `git status`.
	if n := len(c.Intrusos); n > 0 {
		out = append(out, Padrao{
			Tipo: "arquivo estranho dentro do .git",
			Alvo: strconv.Itoa(n) + " nome(s) que o git não cria",
			N:    n,
			Detalhe: "o .git é pulado por quase toda varredura e não aparece no " +
				"`git status`: é esconderijo com carona — " + amostraDeLinhas(c.Intrusos),
		})
	}

	// Filtro sobre arquivo: o comando roda a cada checkout dos que casarem.
	if n := len(c.Atributos); n > 0 {
		out = append(out, Padrao{
			Tipo: "filtro sobre arquivo",
			Alvo: strconv.Itoa(n) + " regra(s) de filtro em .gitattributes",
			N:    n,
			Detalhe: "a regra diz SOBRE QUE ARQUIVOS o `filter.*.smudge` da config " +
				"roda, e `*` significa todos: um comando por arquivo, a cada " +
				"checkout e a cada clone — " + amostraDeLinhas(c.Atributos),
			// git-lfs usa exatamente esta forma, e é comum.
			Comum: true,
		})
	}

	// Ignorar LOCAL é o esconderijo que a revisão de código não alcança.
	if n := len(c.Escondidos); n > 0 {
		out = append(out, Padrao{
			Tipo: "escondido do git status",
			Alvo: strconv.Itoa(n) + " padrão(ões) em .git/info/exclude",
			N:    n,
			Detalhe: "este arquivo NÃO é commitado e não aparece em revisão nenhuma: " +
				"um arquivo que casa com ele some do `git status` para sempre — " +
				"padrões: " + amostraDeLinhas(c.Escondidos),
			// Ignorar local é recurso legítimo e usado: build local, .env de
			// desenvolvimento, artefato de editor.
			Comum: true,
		})
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Comum != out[j].Comum {
			return !out[i].Comum
		}
		return out[i].N > out[j].N
	})
	return out
}

func amostraDeLinhas(ls []string) string {
	const teto = 6
	corte := ls
	sufixo := ""
	if len(ls) > teto {
		corte = ls[:teto]
		sufixo = " …"
	}
	return strings.Join(corte, " · ") + sufixo
}
