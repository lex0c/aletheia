package facts

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lex0c/aletheia/internal/env"
)

// Leitura de um repositório git, SEM executar git.
//
// O binário do host pode ser o implante — é a premissa da ferramenta inteira —,
// e `git log` num repositório adulterado responde o que o atacante quiser se
// ele trocou o git ou pôs um alias. Tudo aqui sai de ARQUIVO, e por isso
// funciona igual sobre imagem montada.
//
// # Por que um repositório merece leitura própria
//
// A varredura já procura `.git/hooks` em árvore (§7.12), e isso cobre a rota
// mais conhecida. Fica de fora o que só aparece olhando UM repositório por
// dentro, e que é onde a adulteração se esconde:
//
//	.git/config          é configuração EXECUTÁVEL. hooksPath, fsmonitor,
//	                     filter, alias com "!" e credential.helper todos rodam
//	                     comando — por repositório, fora de /etc, e sobrevivem
//	                     a `git pull`
//	.git/logs/HEAD       o reflog: toda reescrita de histórico fica registrada
//	                     aqui, com o sha ANTERIOR. É o que devolve o commit que
//	                     um `--amend` apagou
//	.git/info/exclude    ignora local, que nunca é commitado. Um arquivo listado
//	                     ali some do `git status` e some da revisão de código

// RepoGit é o que se lê de um repositório sem executar nada.
type RepoGit struct {
	Dir    string `json:"dir"`
	GitDir string `json:"git_dir"`
	HEAD   string `json:"head,omitempty"`

	Remotes []RemoteGit     `json:"remotes,omitempty"`
	Config  []OpcaoDeGit    `json:"config_exec,omitempty"`
	Hooks   []HookDeGit     `json:"hooks,omitempty"`
	Reflog  []EntradaReflog `json:"reflog,omitempty"`
	Exclude []string        `json:"local_exclude,omitempty"`

	// Refs, ObjetosSoltos e Packs dimensionam o repositório. Servem à mesma
	// função do "331 processos" no censo de processos: sem tamanho, nenhuma
	// contagem abaixo significa alguma coisa.
	Refs          int `json:"refs,omitempty"`
	ObjetosSoltos int `json:"loose_objects,omitempty"`
	Packs         int `json:"packs,omitempty"`

	// Atributos são as linhas de .gitattributes que apontam para um FILTRO.
	// Elas são a outra metade do `filter.*.smudge`: o filtro só roda nos
	// arquivos que uma dessas linhas casar.
	Atributos []string `json:"filter_attrs,omitempty"`

	// Intrusos são arquivos dentro de .git que não pertencem ao git. O
	// diretório é pulado por quase toda ferramenta e não aparece no `git
	// status`: é esconderijo com carona.
	Intrusos []string `json:"foreign_in_gitdir,omitempty"`

	// IndexUTC e HeadUTC datam a última escrita: é o que se compara com a
	// janela do incidente.
	IndexUTC string `json:"index_utc,omitempty"`
	HeadUTC  string `json:"head_utc,omitempty"`

	// Lacunas é o que NÃO pôde ser lido. Um repositório meio lido não pode
	// sair com cara de repositório limpo.
	Lacunas []string `json:"gaps,omitempty"`
}

type RemoteGit struct {
	Nome string `json:"name"`
	URL  string `json:"url"`
}

// OpcaoDeGit é uma opção de config que EXECUTA COMANDO. Não é toda a config:
// é a superfície de execução, que é o que interessa a uma triagem.
type OpcaoDeGit struct {
	Chave  string `json:"key"`
	Valor  string `json:"value"`
	Motivo string `json:"why"`
}

type HookDeGit struct {
	Nome       string `json:"name"`
	Caminho    string `json:"path"`
	Tamanho    int64  `json:"size"`
	ModUTC     string `json:"mod_utc,omitempty"`
	Executavel bool   `json:"executable"`
}

// EntradaReflog é um movimento de ref. O sha ANTERIOR é o que devolve o que
// foi reescrito.
type EntradaReflog struct {
	De      string `json:"from"`
	Para    string `json:"to"`
	Quem    string `json:"who,omitempty"`
	QuandoU string `json:"when_utc,omitempty"`
	Acao    string `json:"action"`
	Msg     string `json:"message,omitempty"`
}

// maxReflog limita a leitura aos movimentos mais RECENTES. O reflog de um
// repositório antigo tem dezenas de milhares de linhas, e a triagem olha o
// recente.
const maxReflog = 500

// LerRepoGit lê o repositório em `dir`, ou diz por que não conseguiu.
func LerRepoGit(f *Facts, e *env.Env, dir string) *RepoGit {
	r := &RepoGit{Dir: dir}

	// `.git` pode ser DIRETÓRIO ou ARQUIVO: worktree e submódulo põem ali um
	// "gitdir: <caminho>" apontando para outro lugar. Tratar só o diretório
	// deixaria worktree e submódulo — que é onde um repositório extra passa
	// despercebido — completamente fora.
	ponto := strings.TrimRight(dir, "/") + "/.git"
	switch {
	case e.IsDir(ponto):
		r.GitDir = ponto
	case e.Exists(ponto):
		b, err := e.ReadFile(ponto)
		if err != nil {
			r.Lacunas = append(r.Lacunas, ponto+" não pôde ser lido: "+env.MotivoDoErro(err))
			return r
		}
		alvo := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(b)), "gitdir:"))
		if alvo == "" {
			r.Lacunas = append(r.Lacunas, ponto+" é arquivo e não declara gitdir")
			return r
		}
		if !strings.HasPrefix(alvo, "/") {
			alvo = strings.TrimRight(dir, "/") + "/" + alvo
		}
		r.GitDir = alvo
	case e.IsDir(strings.TrimRight(dir, "/") + "/objects"):
		r.GitDir = strings.TrimRight(dir, "/") // repositório bare
	default:
		return nil // não é repositório
	}

	lerHEAD(r, e)
	lerConfigGit(r, e)
	lerHooksGit(r, e)
	lerReflog(r, e)
	lerExclude(r, e)
	contarRepo(r, e)
	lerAtributos(r, e)
	lerIntrusos(r, e)
	r.IndexUTC = modUTC(e, r.GitDir+"/index")
	r.HeadUTC = modUTC(e, r.GitDir+"/HEAD")
	return r
}

func lerHEAD(r *RepoGit, e *env.Env) {
	b, err := e.ReadFile(r.GitDir + "/HEAD")
	if err != nil {
		r.Lacunas = append(r.Lacunas, "HEAD não pôde ser lido: "+env.MotivoDoErro(err))
		return
	}
	r.HEAD = strings.TrimSpace(string(b))
}

// execDeGit são as chaves de config que RODAM COMANDO, com o motivo de cada
// uma. É a lista que transforma "config do repositório" em "superfície de
// execução".
//
// Nenhuma delas é exótica: todas são recurso documentado do git. O que as
// torna interessantes numa triagem é que ficam DENTRO do repositório, fora de
// /etc, e sobrevivem a `git pull` — quem escreve no repo escreve nelas.
var execDeGit = map[string]string{
	"core.hookspath": "REDIRECIONA os hooks para outro diretório: quem inspecionar " +
		".git/hooks não vê nada, e o que roda está em outro lugar",
	"core.fsmonitor": "o git EXECUTA este comando a cada operação que consulta o " +
		"estado da árvore — inclusive `git status`",
	"core.sshcommand":   "substitui o ssh que o git usa para buscar e enviar",
	"core.pager":        "roda a cada saída paginada",
	"core.editor":       "roda a cada commit sem -m",
	"credential.helper": "roda a cada autenticação; com `!` na frente é shell",
	"uploadpack.packobjectshook": "roda no SERVIDOR a cada clone ou fetch: num " +
		"repositório servido por rede, é execução remota por desenho",
	"http.proxy":  "redireciona a busca por um intermediário",
	"https.proxy": "redireciona a busca por um intermediário",
}

// prefixosDeExec são famílias de chave em que o SUFIXO varia: filter.<nome>.clean,
// alias.<qualquer>, diff.<nome>.textconv.
var prefixosDeExec = []struct{ pre, suf, motivo string }{
	{"filter.", ".clean", "roda ao ADICIONAR arquivo que casa o .gitattributes"},
	{"filter.", ".smudge", "roda ao EXTRAIR arquivo que casa o .gitattributes — " +
		"é execução em todo checkout e clone"},
	{"filter.", ".process", "roda como filtro persistente durante checkout e commit"},
	{"diff.", ".textconv", "roda ao gerar diff do tipo de arquivo"},
	{"diff.", ".command", "substitui o diff inteiro"},
	{"merge.", ".driver", "roda ao resolver merge do tipo de arquivo"},
	{"alias.", "", "alias de git; começando com `!` é comando de SHELL"},
	{"url.", ".insteadof", "REESCREVE a URL de origem: um fetch pode ir para " +
		"outro lugar sem que o remote pareça mudado"},
	{"include.", "", "inclui outro arquivo de config, que pode trazer qualquer " +
		"uma das chaves acima de um caminho fora do repositório"},
	{"includeif.", "", "inclui outro arquivo de config condicionalmente"},
}

func lerConfigGit(r *RepoGit, e *env.Env) {
	b, err := e.ReadFile(r.GitDir + "/config")
	if err != nil {
		if env.EhLacuna(err) {
			r.Lacunas = append(r.Lacunas, "config não pôde ser lido: "+env.MotivoDoErro(err))
		}
		return
	}
	for _, o := range ParseConfigGit(string(b)) {
		if strings.HasPrefix(o.Chave, "remote.") && strings.HasSuffix(o.Chave, ".url") {
			nome := strings.TrimSuffix(strings.TrimPrefix(o.Chave, "remote."), ".url")
			r.Remotes = append(r.Remotes, RemoteGit{Nome: nome, URL: o.Valor})
			continue
		}
		if motivo, ok := execDeGit[o.Chave]; ok {
			r.Config = append(r.Config, OpcaoDeGit{Chave: o.Chave, Valor: o.Valor, Motivo: motivo})
			continue
		}
		for _, p := range prefixosDeExec {
			if strings.HasPrefix(o.Chave, p.pre) && strings.HasSuffix(o.Chave, p.suf) {
				r.Config = append(r.Config, OpcaoDeGit{Chave: o.Chave, Valor: o.Valor, Motivo: p.motivo})
				break
			}
		}
	}
}

// ParseConfigGit separa o formato do git-config em chave canônica e valor.
//
// É exportado porque é função PURA sobre texto, e o formato é onde ele morde:
// seção com subseção entre aspas (`[filter "lfs"]`), continuação com barra
// invertida, e comentário com `#` ou `;`. A chave sai em minúsculas porque o
// git compara seção e variável sem caixa — mas a SUBSEÇÃO é sensível a caixa, e
// achatar tudo faria `[filter "Lfs"]` e `[filter "lfs"]` colidirem.
func ParseConfigGit(texto string) []OpcaoDeGit {
	var out []OpcaoDeGit
	secao, sub := "", ""
	for _, bruta := range strings.Split(texto, "\n") {
		ln := strings.TrimSpace(bruta)
		if ln == "" || strings.HasPrefix(ln, "#") || strings.HasPrefix(ln, ";") {
			continue
		}
		if strings.HasPrefix(ln, "[") {
			// O cabeçalho termina no ']', e o git aceita a variável na MESMA
			// linha: `[alias] ev = !echo pwned` funciona, conferido contra o
			// binário. Cortar com TrimSuffix no fim da LINHA fazia o corpo
			// virar "core] fsmonitor = /tmp/.x" — o core.fsmonitor, que o git
			// EXECUTA a cada `git status`, desaparecia, e toda chave seguinte
			// até o próximo '[' saía com uma chave inutilizável que não casava
			// com execDeGit. Uma linha escrita pelo atacante desligava a
			// leitura da superfície de execução do repositório inteiro dali
			// para baixo.
			fim := strings.IndexByte(ln, ']')
			if fim < 0 {
				continue // cabeçalho truncado: não abre seção nenhuma
			}
			corpo := ln[1:fim]
			if i := strings.IndexByte(corpo, '"'); i >= 0 {
				secao = strings.ToLower(strings.TrimSpace(corpo[:i]))
				sub = strings.Trim(corpo[i:], `" `)
			} else {
				secao, sub = strings.ToLower(strings.TrimSpace(corpo)), ""
			}
			// E o que sobrou da linha é um par chave=valor desta seção.
			ln = strings.TrimSpace(ln[fim+1:])
			if ln == "" {
				continue
			}
		}
		k, v, ok := strings.Cut(ln, "=")
		if !ok {
			continue
		}
		chave := strings.ToLower(strings.TrimSpace(k))
		if secao == "" {
			continue
		}
		cheia := secao + "." + chave
		if sub != "" {
			cheia = secao + "." + sub + "." + chave
		}
		out = append(out, OpcaoDeGit{Chave: cheia, Valor: strings.TrimSpace(v)})
	}
	return out
}

// hooksDeExemplo são os que o git instala sozinho. Eles vêm SEM bit de
// execução, e por isso não rodam — contá-los faria todo repositório do mundo
// aparecer com quatorze hooks.
func lerHooksGit(r *RepoGit, e *env.Env) {
	dir := r.GitDir + "/hooks"
	// hooksPath redireciona: quem olha .git/hooks não vê o que roda.
	for _, o := range r.Config {
		if o.Chave == "core.hookspath" {
			d := o.Valor
			if !strings.HasPrefix(d, "/") {
				d = strings.TrimRight(r.Dir, "/") + "/" + d
			}
			dir = d
		}
	}
	nomes := e.ReadDirNames(dir)
	for _, n := range nomes {
		if strings.HasSuffix(n, ".sample") {
			continue
		}
		p := dir + "/" + n
		fi, err := e.Lstat(p)
		if err != nil || fi.IsDir() {
			continue
		}
		h := HookDeGit{
			Nome: n, Caminho: p, Tamanho: fi.Size(),
			Executavel: fi.Mode().Perm()&0o111 != 0,
			ModUTC:     modUTC(e, p),
		}
		r.Hooks = append(r.Hooks, h)
	}
}

func lerReflog(r *RepoGit, e *env.Env) {
	b, err := e.ReadFile(r.GitDir + "/logs/HEAD")
	if err != nil {
		// Reflog AUSENTE é resposta em repositório recém-clonado, e é achado
		// quando havia histórico: apagá-lo é a forma de esconder a reescrita.
		if env.EhLacuna(err) {
			r.Lacunas = append(r.Lacunas, "o reflog não pôde ser lido: "+
				env.MotivoDoErro(err)+" — a reescrita de histórico não pôde ser avaliada")
		}
		return
	}
	linhas := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if n := len(linhas); n > maxReflog {
		r.Lacunas = append(r.Lacunas, "o reflog tem "+strconv.Itoa(n)+
			" movimentos e foram lidos os "+strconv.Itoa(maxReflog)+
			" mais recentes: o que veio antes NÃO foi examinado")
		linhas = linhas[n-maxReflog:]
	}
	for _, ln := range linhas {
		if ent, ok := ParseLinhaDeReflog(ln); ok {
			r.Reflog = append(r.Reflog, ent)
		}
	}
}

// ParseLinhaDeReflog separa uma linha do reflog. O formato:
//
//	<sha antigo> <sha novo> <nome> <email> <epoch> <fuso>\t<ação>: <mensagem>
//
// O sha ANTIGO é o que importa: ele é o ponteiro para o que um `--amend` ou um
// `reset --hard` deixaram para trás, e é por ele que o conteúdo anterior se
// recupera com `git cat-file`.
func ParseLinhaDeReflog(ln string) (EntradaReflog, bool) {
	cabeca, resto, ok := strings.Cut(ln, "\t")
	if !ok {
		return EntradaReflog{}, false
	}
	campos := strings.Fields(cabeca)
	if len(campos) < 4 {
		return EntradaReflog{}, false
	}
	ent := EntradaReflog{De: campos[0], Para: campos[1]}
	// O e-mail vem entre <>: o que estiver antes é o nome, que pode ter espaço.
	for i := 2; i < len(campos); i++ {
		if strings.HasPrefix(campos[i], "<") {
			ent.Quem = strings.Join(campos[2:i+1], " ")
			if i+1 < len(campos) {
				ent.QuandoU = epochParaUTC(campos[i+1])
			}
			break
		}
	}
	acao, msg, temMsg := strings.Cut(resto, ": ")
	ent.Acao = strings.TrimSpace(acao)
	if temMsg {
		ent.Msg = strings.TrimSpace(msg)
	}
	return ent, true
}

func lerExclude(r *RepoGit, e *env.Env) {
	b, err := e.ReadFile(r.GitDir + "/info/exclude")
	if err != nil {
		return
	}
	for _, ln := range strings.Split(string(b), "\n") {
		t := strings.TrimSpace(ln)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		r.Exclude = append(r.Exclude, t)
	}
}

// epochParaUTC converte o segundo do reflog. Valor ilegível vira vazio, e não
// "agora": data inventada num relatório de incidente é pior que data ausente.
func epochParaUTC(s string) string {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
		return ""
	}
	return time.Unix(n, 0).UTC().Format("2006-01-02T15:04:05Z")
}

// contarRepo dimensiona o repositório: refs, objetos soltos e packs.
func contarRepo(r *RepoGit, e *env.Env) {
	var contarRefs func(dir string, prof int)
	contarRefs = func(dir string, prof int) {
		if prof > 4 {
			return
		}
		for _, n := range e.ReadDirNames(dir) {
			p := dir + "/" + n
			if e.IsDir(p) {
				contarRefs(p, prof+1)
				continue
			}
			r.Refs++
		}
	}
	contarRefs(r.GitDir+"/refs", 0)
	// packed-refs guarda as refs empacotadas, uma por linha.
	if b, err := e.ReadFile(r.GitDir + "/packed-refs"); err == nil {
		for _, ln := range strings.Split(string(b), "\n") {
			t := strings.TrimSpace(ln)
			if t != "" && !strings.HasPrefix(t, "#") && !strings.HasPrefix(t, "^") {
				r.Refs++
			}
		}
	}

	for _, n := range e.ReadDirNames(r.GitDir + "/objects") {
		// Os diretórios de objeto solto são os dois primeiros dígitos do sha.
		if len(n) != 2 {
			continue
		}
		r.ObjetosSoltos += len(e.ReadDirNames(r.GitDir + "/objects/" + n))
	}
	for _, n := range e.ReadDirNames(r.GitDir + "/objects/pack") {
		if strings.HasSuffix(n, ".pack") {
			r.Packs++
		}
	}
}

// lerAtributos pega as linhas de .gitattributes que ativam FILTRO.
//
// O filtro em si está na config; esta é a outra metade, e sem ela não se sabe
// SOBRE QUE ARQUIVOS ele roda. `* filter=x` é o caso extremo: todo arquivo do
// repositório passa por um comando a cada checkout.
func lerAtributos(r *RepoGit, e *env.Env) {
	for _, p := range []string{
		strings.TrimRight(r.Dir, "/") + "/.gitattributes",
		r.GitDir + "/info/attributes",
	} {
		b, err := e.ReadFile(p)
		if err != nil {
			continue
		}
		for _, ln := range strings.Split(string(b), "\n") {
			t := strings.TrimSpace(ln)
			if t == "" || strings.HasPrefix(t, "#") {
				continue
			}
			if strings.Contains(t, "filter=") || strings.Contains(t, "diff=") {
				r.Atributos = append(r.Atributos, t)
			}
		}
	}
}

// arquivosDoGit são os nomes que o próprio git cria na raiz do .git. O que
// estiver fora desta lista foi posto ali por outra pessoa.
var arquivosDoGit = map[string]bool{
	"HEAD": true, "ORIG_HEAD": true, "FETCH_HEAD": true, "MERGE_HEAD": true,
	"CHERRY_PICK_HEAD": true, "REVERT_HEAD": true, "BISECT_HEAD": true,
	"config": true, "description": true, "index": true, "packed-refs": true,
	"COMMIT_EDITMSG": true, "MERGE_MSG": true, "SQUASH_MSG": true,
	"TAG_EDITMSG": true, "shallow": true, "gitdir": true, "commondir": true,
	"HEAD.lock": true, "index.lock": true, "config.worktree": true,
	"sourcetreeconfig.json": true, "AUTO_MERGE": true, "REBASE_HEAD": true,
	// diretórios
	"objects": true, "refs": true, "hooks": true, "info": true, "logs": true,
	"branches": true, "modules": true, "worktrees": true, "rebase-merge": true,
	"rebase-apply": true, "lfs": true, "annex": true, "filter-repo": true,
}

func lerIntrusos(r *RepoGit, e *env.Env) {
	for _, n := range e.ReadDirNames(r.GitDir) {
		if arquivosDoGit[n] || strings.HasSuffix(n, ".lock") {
			continue
		}
		r.Intrusos = append(r.Intrusos, n)
	}
	sort.Strings(r.Intrusos)
}
