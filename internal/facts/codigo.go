package facts

import (
	"regexp"
	"strings"

	"github.com/lex0c/aletheia/internal/env"
)

// Padrões de backdoor em código (runbook §24, §16).
//
// A postura, e ela é a mesma do resto da ferramenta: isto é PENEIRA, não prova.
// Pega o webshell comum — e a maioria dos reais é copiada de padrão conhecido —,
// e erra o ofuscado a fundo, porque quem quer burlar regex burla (`ev`.`al`,
// cadeia de `chr()`, decodificação empilhada). Um match diz "leia este trecho",
// não "isto é backdoor". Reconhecer por padrão é atalho; o que dá peso é o
// cruzamento com "este arquivo MUDOU", que o check faz com o mtime.
//
// O sinal forte é a CO-OCORRÊNCIA: um sink de execução aplicado a entrada de
// request na mesma construção. `echo \`$_REQUEST[0]\`` não é "tem crase" nem
// "tem $_REQUEST" — é a crase (shell_exec do PHP) sobre o dado do atacante.
// Nenhum código legítimo faz isso, e é por isso que quase não dá falso positivo.

// MatchDeCodigo é um padrão suspeito achado numa linha.
type MatchDeCodigo struct {
	Linha  int    `json:"line"`
	Tier   int    `json:"tier"` // 2 = quase sem falso positivo; 1 = suspeito
	Regra  string `json:"rule"`
	Trecho string `json:"snippet"`
}

// regraDeCodigo é um padrão com seu rótulo e peso.
type regraDeCodigo struct {
	re     *regexp.Regexp
	tier   int
	rotulo string
}

// As entradas de request de cada linguagem, embutidas nos padrões de sink para
// exigir a co-ocorrência.
const (
	phpInput = `\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\b`
	jsInput  = `(?:req\.(?:query|body|params|headers|cookies)|process\.argv|process\.env)`
	pyInput  = `(?:request\.(?:args|form|values|data|json|cookies|files)|sys\.argv|\binput\s*\()`
)

// mustDup compila e entra em pânico no init se o padrão for inválido — erro de
// programador, não de runtime.
func mustDup(tier int, rotulo, pat string) regraDeCodigo {
	return regraDeCodigo{re: regexp.MustCompile(pat), tier: tier, rotulo: rotulo}
}

// Os sinks de execução do PHP, para os padrões de "sink sobre entrada".
const phpSinks = `eval|assert|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|call_user_func|call_user_func_array|array_map`

var regrasPHP = []regraDeCodigo{
	// TIER 2 — sink DIRETO sobre entrada de request. O caso do bootstrap.php.
	mustDup(2, "shell via crase sobre entrada de request", "`[^`]*"+phpInput),
	mustDup(2, "sink de execução sobre entrada de request", `\b(?:`+phpSinks+`)\s*\(\s*[^;]{0,120}`+phpInput),
	mustDup(2, "eval de conteúdo decodificado — assinatura de webshell",
		`\b(?:eval|assert)\s*\(\s*@?\s*(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|hex2bin|convert_uudecode)\b`),
	mustDup(2, "preg_replace com modificador /e — executa o replacement",
		`\bpreg_replace\s*\(\s*['"][^'"]{1,200}/[a-zA-DF-Z]*e[a-zA-DF-Z]*['"]`),
	// TIER 1 — suspeito, precisa de leitura (e o mtime decide o peso).
	mustDup(1, "create_function — equivale a eval, obsoleto e favorito de shell", `\bcreate_function\s*\(`),
	mustDup(1, "decodificação empilhada", `\b(?:base64_decode|gzinflate|gzuncompress)\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13)\b`),
	mustDup(1, "chamada de função por variável de variável", `\$\{?\$[a-zA-Z_]\w*\}?\s*\(`),
	mustDup(1, "eval presente", `\beval\s*\(`),
	mustDup(1, "blob base64 longo embutido no código", `['"][A-Za-z0-9+/]{200,}={0,2}['"]`),
}

var regrasJS = []regraDeCodigo{
	mustDup(2, "child_process sobre entrada de request",
		`\b(?:exec|execSync|spawn|spawnSync|execFile)\s*\(\s*[^;]{0,120}`+jsInput),
	mustDup(2, "eval sobre entrada de request", `\beval\s*\(\s*[^;]{0,120}`+jsInput),
	mustDup(2, "new Function sobre entrada de request", `new\s+Function\s*\(\s*[^;]{0,120}`+jsInput),
	mustDup(1, "eval presente", `\beval\s*\(`),
	mustDup(1, "new Function — eval por outro nome", `new\s+Function\s*\(`),
	mustDup(1, "child_process carregado", `require\s*\(\s*['"]child_process['"]`),
}

var regrasPy = []regraDeCodigo{
	mustDup(2, "eval/exec sobre entrada de request", `\b(?:eval|exec)\s*\(\s*[^;\n]{0,120}`+pyInput),
	mustDup(2, "os.system sobre entrada de request", `\bos\.system\s*\(\s*[^;\n]{0,120}`+pyInput),
	mustDup(2, "subprocess com shell=True sobre entrada de request",
		`\bsubprocess\.\w+\s*\([^;\n]{0,200}shell\s*=\s*True[^;\n]{0,200}`+pyInput),
	mustDup(2, "pickle.loads sobre entrada — desserialização executa código", `\bpickle\.loads\s*\(\s*[^;\n]{0,120}`+pyInput),
	mustDup(1, "exec/eval presente", `\b(?:eval|exec)\s*\(`),
	mustDup(1, "subprocess com shell=True", `\bsubprocess\.\w+\s*\([^;\n]{0,200}shell\s*=\s*True`),
	mustDup(1, "pickle.loads — desserialização é superfície de RCE", `\bpickle\.loads\s*\(`),
}

// regrasPorLinguagem mapeia a extensão para o conjunto de padrões.
func regrasPorLinguagem(lang string) []regraDeCodigo {
	switch lang {
	case "php":
		return regrasPHP
	case "js":
		return regrasJS
	case "python":
		return regrasPy
	}
	return nil
}

// linguagemPorExtensao devolve a linguagem de um caminho, ou "" se não é código
// que sabemos analisar. É o filtro que mantém a varredura barata: não abre .jpg.
func linguagemPorExtensao(path string) string {
	i := strings.LastIndexByte(path, '.')
	if i < 0 {
		return ""
	}
	switch strings.ToLower(path[i:]) {
	case ".php", ".php3", ".php4", ".php5", ".php7", ".phtml", ".phar", ".inc":
		return "php"
	case ".js", ".cjs", ".mjs", ".jsx", ".ts":
		return "js"
	case ".py", ".pyw":
		return "python"
	}
	return ""
}

// ehComentario responde se a linha é claramente um comentário — reduz o falso
// positivo de casar um padrão dentro de `// exemplo: eval($_GET)`. Não é lexer:
// código de verdade não esconde webshell em comentário, e o operador vê o
// trecho de qualquer forma.
func ehComentario(linha string) bool {
	t := strings.TrimSpace(linha)
	return strings.HasPrefix(t, "//") || strings.HasPrefix(t, "#") ||
		strings.HasPrefix(t, "*") || strings.HasPrefix(t, "/*")
}

// maxTrecho é o teto do trecho guardado: o suficiente para o operador
// reconhecer, sem despejar uma linha minificada de 40 KB no relatório.
const maxTrecho = 160

// analisarConteudo roda os padrões da linguagem sobre o conteúdo e devolve os
// matches. Puro: a mesma entrada dá a mesma saída, e é isto que o teste exercita
// com o exemplo real.
func analisarConteudo(conteudo, lang string) []MatchDeCodigo {
	regras := regrasPorLinguagem(lang)
	if regras == nil {
		return nil
	}
	var out []MatchDeCodigo
	linhas := strings.Split(conteudo, "\n")
	for i, linha := range linhas {
		if ehComentario(linha) {
			continue
		}
		melhor := -1 // um match por linha: o de maior tier
		var achado MatchDeCodigo
		for _, r := range regras {
			if r.re.MatchString(linha) {
				if r.tier > melhor {
					melhor = r.tier
					achado = MatchDeCodigo{Linha: i + 1, Tier: r.tier, Regra: r.rotulo, Trecho: trecho(linha)}
				}
			}
		}
		if melhor >= 0 {
			out = append(out, achado)
		}
	}
	return out
}

func trecho(linha string) string {
	t := strings.TrimSpace(linha)
	if len(t) > maxTrecho {
		return t[:maxTrecho] + "…"
	}
	return t
}

// A varredura de código: onde procurar, e os tetos.
//
// É mais barata que a de SUID porque filtra por EXTENSÃO no nome do dirent —
// não abre .jpg nem faz stat por arquivo. O custo é readdir por diretório mais
// a leitura dos arquivos de código, e os dois são limitados. Como toda
// varredura da ferramenta, o teto é DECLARADO: parar em silêncio diria "nenhum
// backdoor" quando o que houve foi parar antes.
const (
	maxCodigoDirs     = 20000
	maxCodigoArquivos = 20000
	maxCodigoDepth    = 12
	// Teto por arquivo: um webshell cabe em bytes; um bundle minificado de 40 MB
	// é ruído e custo. O que passar disso é dito.
	maxCodigoBytes = 2 << 20
)

// codigoRaizes são as árvores onde código SERVIDO mora — é ali que um webshell
// tem para que existir. Deliberadamente não é "/" inteiro: varrer a raiz
// arrasta /usr e /proc sem acrescentar sinal.
var codigoRaizes = []string{"/var/www", "/srv", "/usr/share/nginx", "/data", "/opt"}

// CodigoSuspeito é um arquivo de código com um ou mais padrões encontrados. O
// mtime vem junto porque é ele que o check usa para pesar: um padrão num
// arquivo que MUDOU na janela do incidente é outra conversa.
type CodigoSuspeito struct {
	Path    string          `json:"path"`
	Lang    string          `json:"lang"`
	ModUTC  string          `json:"mod_utc,omitempty"`
	Matches []MatchDeCodigo `json:"matches"`
}

type varreduraCodigo struct {
	dirs           int
	arquivos       int
	truncado       bool
	tempo          bool
	grandesPulados int
}

func collectCodigo(f *Facts, e *env.Env) {
	raizes := append([]string{}, codigoRaizes...)
	raizes = append(raizes, homeDirs(e)...)

	var st varreduraCodigo
	vistos := map[string]bool{}
	for _, r := range raizes {
		if r == "" || vistos[r] {
			continue
		}
		vistos[r] = true
		varrerCodigo(f, e, r, 0, &st, vistos)
	}

	if st.truncado {
		f.denyPersist("codigo", "a varredura de código parou em "+
			itoa(maxCodigoDirs)+" diretórios ou "+itoa(maxCodigoArquivos)+
			" arquivos: o excedente NÃO foi analisado")
	}
	if st.tempo {
		f.denyPersist("codigo", "a varredura de código parou pelo orçamento de "+
			"tempo: o que faltou NÃO foi analisado — rode `scan` sem teto")
	}
	if st.grandesPulados > 0 {
		f.denyPersist("codigo", itoa(st.grandesPulados)+" arquivo(s) de código "+
			"acima de 2 MB NÃO foram analisados (minificado ou payload grande): "+
			"um webshell cabe em bytes, mas um payload ofuscado pode não caber")
	}
}

func varrerCodigo(f *Facts, e *env.Env, dir string, prof int, st *varreduraCodigo, vistos map[string]bool) {
	if prof > maxCodigoDepth || st.truncado || st.tempo {
		return
	}
	if e.WalkExpired() {
		st.tempo = true
		return
	}
	if st.dirs >= maxCodigoDirs || st.arquivos >= maxCodigoArquivos {
		st.truncado = true
		return
	}
	st.dirs++

	for _, n := range e.ReadDirNames(dir) {
		p := dir + "/" + n
		if e.IsDir(p) {
			// As mesmas árvores que só geram profundidade e ruído. vendor e
			// node_modules TAMBÉM podem esconder shell — mas varrê-los inteiros
			// é o custo que acabamos de medir, então ficam de fora e isso é dito.
			if pularNoCodigo[n] {
				// Exclusão de CUSTO, silenciosa como a de node_modules na
				// varredura de SUID: vendor está em quase todo host, e declarar
				// lacuna aqui degradaria a cobertura para sempre. O limite —
				// shell escondido em dependência não é pego — está no FP do check.
				continue
			}
			if vistos[p] {
				continue // uma árvore já alcançada por outra raiz
			}
			vistos[p] = true
			varrerCodigo(f, e, p, prof+1, st, vistos)
			continue
		}
		lang := linguagemPorExtensao(n)
		if lang == "" {
			continue
		}
		if st.arquivos >= maxCodigoArquivos {
			st.truncado = true
			return
		}
		st.arquivos++

		// Tamanho antes de ler: não puxar um bundle de 40 MB para a memória.
		if fi, err := e.Lstat(p); err == nil && fi.Size() > maxCodigoBytes {
			st.grandesPulados++
			continue
		}
		b, err := e.ReadFile(p)
		if err != nil {
			continue
		}
		ms := analisarConteudo(string(b), lang)
		if len(ms) == 0 {
			continue
		}
		cs := CodigoSuspeito{Path: p, Lang: lang, Matches: ms}
		if fi, err := e.Lstat(p); err == nil && !fi.ModTime().IsZero() {
			cs.ModUTC = fi.ModTime().UTC().Format("2006-01-02T15:04:05Z")
		}
		f.CodigoSuspeito = append(f.CodigoSuspeito, cs)
	}
}

// pularNoCodigo são as árvores de dependência que não se percorre: varrê-las
// inteiras é o custo de I/O que já mordeu a varredura de SUID.
var pularNoCodigo = map[string]bool{
	"node_modules": true, "vendor": true, ".git": true, ".cache": true,
	".svn": true, "bower_components": true, ".npm": true,
}
