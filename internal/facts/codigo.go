package facts

import (
	"regexp"
	"sort"
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

// Entrada controlada, em DOIS domínios de confiança distintos. Misturá-los era
// impreciso: exec(process.env.X) é código ruim, mas NÃO significa "atacante
// remoto controla o comando". Só a REMOTA — request HTTP, incluindo os
// frameworks — sustenta CRÍTICO; a LOCAL (argv, env, stdin) sai como aviso.
const (
	phpRemota = `(?:\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\b|php://input|\$\w*[Rr]equest->(?:input|get|query|post|all|json|cookie)\b|\$\w*[Rr]equest->(?:request|query|json)->get\b)`
	phpLocal  = `(?:\bgetenv\s*\(|\$argv\b|\$_ENV\b)`

	// Express, Koa (ctx), Hapi (request.payload/query/params).
	jsRemota = `(?:req\.(?:query|body|params|headers|cookies)|request\.(?:query|payload|params)|ctx\.(?:query|params|headers|request))`
	jsLocal  = `(?:process\.argv|process\.env)`

	// Django (request.GET/POST/...) e Flask (request.args/form/...).
	pyRemota = `(?:request\.(?:GET|POST|COOKIES|FILES|META|args|form|values|data|json|cookies|files|body))`
	pyLocal  = `(?:sys\.argv|\binput\s*\(|\bos\.environ)`
)

const (
	// Sinks que executam o próprio ARGUMENTO: input dentro da chamada é o
	// perigo. call_user_func/array_map saíram daqui de propósito — eles
	// executam o CALLBACK (1º arg), não o argumento, e ficam num padrão à
	// parte: `call_user_func('trim', $_POST)` não é RCE (função fixa), só
	// `call_user_func($_GET['f'], ...)` é.
	phpSinks     = `eval|assert|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec`
	phpCallbacks = `call_user_func|call_user_func_array|array_map|array_filter|usort|array_walk`
	phpInclui    = `include|include_once|require|require_once`
	jsSinks      = `exec|execSync|spawn|spawnSync|execFile`
)

// mustDup compila e entra em pânico no init se o padrão for inválido.
func mustDup(tier int, rotulo, pat string) regraDeCodigo {
	return regraDeCodigo{re: regexp.MustCompile(pat), tier: tier, rotulo: rotulo}
}

// defsCodigo reúne os padrões de uma linguagem. O casamento de sink+entrada usa
// BALANCEAMENTO de parênteses (não `[^;]`), o que corrige duas coisas: em JS sem
// ponto-e-vírgula, `exec("x")` deixa de casar com um req do statement seguinte; e
// em Python multilinha, `subprocess.run(\n request.args,\n shell=True)` passa a
// casar. O taint é ORDENADO por offset e respeita reatribuição.
type defsCodigo struct {
	// sinkAbre casa `nome(` de um sink cujo ARGUMENTO executa; o argumento
	// balanceado é testado por entrada. cbAbre é o callback cujo PRIMEIRO arg é
	// a função executada.
	sinkAbre *regexp.Regexp
	cbAbre   *regexp.Regexp
	inputRem *regexp.Regexp
	inputLoc *regexp.Regexp
	// atribui casa `var = rhs` (grupo 1 = var, grupo 2 = rhs), e varTok acha as
	// variáveis usadas dentro dos argumentos de um sink.
	atribui *regexp.Regexp
	varTok  *regexp.Regexp
	// dynAbre casa uma CHAMADA por variável, `$var(` ou `var(`, capturando o
	// nome no grupo 1 — para pegar `$fn = $_GET['f']; $fn(...)`. `new $var()` é
	// instanciação (vulnerabilidade de object injection, não backdoor) e é
	// excluída no motor.
	dynAbre *regexp.Regexp
	// especiais são construções fechadas casadas direto (crase, /e, include…);
	// suspeito é tier 1.
	especiais []regraDeCodigo
	suspeito  []regraDeCodigo
}

var reShellTrue = regexp.MustCompile(`shell\s*=\s*True`)

var defsPHP = defsCodigo{
	sinkAbre: regexp.MustCompile(`\b(?:` + phpSinks + `|unserialize|` + phpInclui + `)\s*\(`),
	cbAbre:   regexp.MustCompile(`\b(?:` + phpCallbacks + `)\s*\(`),
	inputRem: regexp.MustCompile(phpRemota),
	inputLoc: regexp.MustCompile(phpLocal),
	atribui:  regexp.MustCompile(`(\$\w+)\s*=\s*([^;]{0,400})`),
	varTok:   regexp.MustCompile(`\$\w+`),
	dynAbre:  regexp.MustCompile(`(\$\w+)\s*\(`),
	especiais: []regraDeCodigo{
		mustDup(2, "shell via crase sobre entrada de request", "`[^`\\x00-\\x1f]{0,120}"+phpRemota),
		mustDup(2, "função nomeada pelo request (chamada dinâmica)", `\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\b(?:\s*\[[^\]]{0,40}\])?\s*\(`),
		mustDup(2, "include/require sobre entrada de request — LFI/RFI", `\b(?:`+phpInclui+`)\b\s*\(?\s*[^;]{0,160}`+phpRemota),
		mustDup(2, "eval de conteúdo decodificado — assinatura de webshell", `\b(?:eval|assert)\s*\(\s*@?\s*(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|hex2bin|convert_uudecode)\b`),
		mustDup(2, "preg_replace /e sobre entrada de request — executa o replacement", `\bpreg_replace\s*\(\s*['"][^'"]{1,200}/[a-zA-DF-Z]*e[a-zA-DF-Z]*['"][^;]{0,200}`+phpRemota),
		mustDup(2, "preg_replace /e com sink no replacement — RCE", "\\bpreg_replace\\s*\\(\\s*['\"][^'\"]{1,200}/[a-zA-DF-Z]*e[a-zA-DF-Z]*['\"]\\s*,\\s*[^;]{0,80}(?:\\b(?:system|exec|shell_exec|passthru|eval|assert|popen|proc_open)\\b|`)"),
	},
	suspeito: []regraDeCodigo{
		mustDup(1, "create_function — equivale a eval, obsoleto e favorito de shell", `\bcreate_function\s*\(`),
		mustDup(1, "decodificação empilhada", `\b(?:base64_decode|gzinflate|gzuncompress)\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13)\b`),
		mustDup(1, "eval presente", `\beval\s*\(`),
		mustDup(1, "preg_replace com modificador /e (deprecado)", `\bpreg_replace\s*\(\s*['"][^'"]{1,200}/[a-zA-DF-Z]*e[a-zA-DF-Z]*['"]`),
		mustDup(1, "blob base64 longo embutido no código", `['"][A-Za-z0-9+/]{200,}={0,2}['"]`),
	},
}

var defsJS = defsCodigo{
	sinkAbre: regexp.MustCompile(`\b(?:eval|` + jsSinks + `)\s*\(|new\s+Function\s*\(|\bvm\.run\w+\s*\(`),
	inputRem: regexp.MustCompile(jsRemota),
	inputLoc: regexp.MustCompile(jsLocal),
	atribui:  regexp.MustCompile(`\b(\w+)\s*=\s*([^;\n]{0,400})`),
	varTok:   regexp.MustCompile(`\b\w+\b`),
	dynAbre:  regexp.MustCompile(`\b(\w+)\s*\(`),
	suspeito: []regraDeCodigo{
		mustDup(1, "eval presente", `\beval\s*\(`),
		mustDup(1, "new Function — eval por outro nome", `new\s+Function\s*\(`),
		mustDup(1, "child_process carregado", `require\s*\(\s*['"]child_process['"]`),
	},
}

var defsPy = defsCodigo{
	sinkAbre: regexp.MustCompile(`\b(?:eval|exec|os\.system|os\.popen|subprocess\.\w+|pickle\.loads)\s*\(`),
	inputRem: regexp.MustCompile(pyRemota),
	inputLoc: regexp.MustCompile(pyLocal),
	atribui:  regexp.MustCompile(`\b(\w+)\s*=\s*([^;\n]{0,400})`),
	varTok:   regexp.MustCompile(`\b\w+\b`),
	suspeito: []regraDeCodigo{
		mustDup(1, "exec/eval presente", `\b(?:eval|exec)\s*\(`),
		mustDup(1, "subprocess com shell=True", `\bsubprocess\.\w+\s*\([^;\n]{0,200}shell\s*=\s*True`),
		mustDup(1, "pickle.loads — desserialização é superfície de RCE", `\bpickle\.loads\s*\(`),
	},
}

// defsPorLinguagem mapeia a extensão para os padrões da linguagem.
func defsPorLinguagem(lang string) *defsCodigo {
	switch lang {
	case "php":
		return &defsPHP
	case "js":
		return &defsJS
	case "python":
		return &defsPy
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

// maxTrecho é o teto do trecho guardado: o suficiente para o operador
// reconhecer, sem despejar uma linha minificada de 40 KB no relatório.
const maxTrecho = 160

// analisarConteudo é o motor de peneira, em três camadas. Puro: a mesma entrada
// dá a mesma saída, e é isto que o teste exercita com os exemplos reais.
//
// A varredura roda no ARQUIVO inteiro, não linha a linha — é o que pega a forma
// multilinha `system(\n  $_GET['x']\n)`, porque `[^;]` casa a quebra de linha. E
// há um MICRO-TAINT de um salto: `$cmd = $_GET[...]` marca $cmd, e um sink que
// recebe $cmd depois vira achado. Não é um analisador de fluxo; é o suficiente
// para o implante minimamente organizado que separa a entrada do sink em duas
// linhas — a forma que o casamento por linha perdia inteira.
func analisarConteudo(conteudo, lang string) []MatchDeCodigo {
	def := defsPorLinguagem(lang)
	if def == nil {
		return nil
	}
	// Comentário vira espaço (mesmo tamanho em bytes, quebras preservadas): os
	// offsets continuam apontando para a linha certa no ORIGINAL, e um padrão
	// dentro de `// exemplo: eval($_GET)` deixa de casar.
	masc := mascararComentarios(conteudo, lang)

	// Um achado por linha, o de maior tier: sink+entrada crítico ganha do eval
	// solto na mesma linha.
	porLinha := map[int]MatchDeCodigo{}
	registrar := func(off, tier int, rotulo string) {
		if off < 0 || off > len(conteudo) {
			return
		}
		ln, texto := numeroDaLinha(conteudo, off)
		if ex, ok := porLinha[ln]; ok && ex.Tier >= tier {
			return
		}
		porLinha[ln] = MatchDeCodigo{Linha: ln, Tier: tier, Regra: rotulo, Trecho: trecho(texto)}
	}

	// Um evento é uma atribuição (marca/limpa taint de uma var) ou um sink (que
	// pode receber entrada DIRETA nos argumentos, ou uma variável tainted).
	type evento struct {
		off            int
		atrib          bool
		nome           string // atribuição: a var
		classe         int    // atribuição: 2 remota | 1 local | 0 limpa
		remDir, locDir bool   // sink: entrada direta no argumento balanceado
		vars           []string
		rotulo         string
	}
	var evs []evento

	for _, m := range def.atribui.FindAllStringSubmatchIndex(masc, -1) {
		rhs := masc[m[4]:m[5]]
		classe := 0
		if def.inputRem.MatchString(rhs) {
			classe = 2
		} else if def.inputLoc.MatchString(rhs) {
			classe = 1
		}
		evs = append(evs, evento{off: m[0], atrib: true, nome: masc[m[2]:m[3]], classe: classe})
	}
	adicionarSink := func(loc []int, primeiroArgSo bool, rotulo string) {
		nome := masc[loc[0]:loc[1]]
		args := argBalanceado(masc, loc[1]-1)
		// subprocess só é sink com shell=True; sem isso a lista é execução segura.
		if strings.Contains(nome, "subprocess") && !reShellTrue.MatchString(args) {
			return
		}
		if primeiroArgSo {
			args = primeiroArgTop(args)
		}
		e := evento{off: loc[0], vars: def.varTok.FindAllString(args, -1), rotulo: rotulo}
		if def.inputRem.MatchString(args) {
			e.remDir = true
		} else if def.inputLoc.MatchString(args) {
			e.locDir = true
		}
		evs = append(evs, e)
	}
	for _, loc := range def.sinkAbre.FindAllStringIndex(masc, -1) {
		adicionarSink(loc, false, "sink de execução sobre entrada de request")
	}
	if def.cbAbre != nil {
		for _, loc := range def.cbAbre.FindAllStringIndex(masc, -1) {
			adicionarSink(loc, true, "callback nomeado pelo request — executa função escolhida pelo atacante")
		}
	}
	// Chamada dinâmica `$fn(...)` onde $fn é tainted: o atacante escolhe a
	// função. EXCLUI `new $fn()` (instanciação = object injection, uma
	// vulnerabilidade, não backdoor — e o padrão de um exemplo inseguro de
	// biblioteca como o jpGraph) e método/estático (`.m()`, `->m()`, `::m()`).
	if def.dynAbre != nil {
		for _, m := range def.dynAbre.FindAllStringSubmatchIndex(masc, -1) {
			if !chamadaDinamicaValida(masc, m[0]) {
				continue
			}
			evs = append(evs, evento{off: m[0], vars: []string{masc[m[2]:m[3]]},
				rotulo: "função nomeada por variável de entrada de request (chamada dinâmica)"})
		}
	}

	// ORDENADO por offset: um sink antes da contaminação não é achado, e a
	// reatribuição a valor seguro limpa o taint. É o que separa fluxo real de
	// coincidência de nome entre funções.
	sort.Slice(evs, func(i, j int) bool { return evs[i].off < evs[j].off })
	taint := map[string]int{}
	for _, e := range evs {
		if e.atrib {
			taint[e.nome] = e.classe
			continue
		}
		switch {
		case e.remDir:
			registrar(e.off, 2, e.rotulo)
		case e.locDir:
			registrar(e.off, 1, e.rotulo+" — entrada LOCAL (argv/env)")
		default:
			maior := 0
			for _, v := range e.vars {
				if taint[v] > maior {
					maior = taint[v]
				}
			}
			if maior == 2 {
				registrar(e.off, 2, "sink sobre variável de entrada de request (fluxo)")
			} else if maior == 1 {
				registrar(e.off, 1, "sink sobre variável de entrada LOCAL (argv/env)")
			}
		}
	}

	// Construções fechadas (crase, /e, include, ofuscação) — ordem-independentes.
	for _, r := range def.especiais {
		for _, loc := range r.re.FindAllStringIndex(masc, -1) {
			registrar(loc[0], r.tier, r.rotulo)
		}
	}
	for _, r := range def.suspeito {
		for _, loc := range r.re.FindAllStringIndex(masc, -1) {
			registrar(loc[0], 1, r.rotulo)
		}
	}

	out := make([]MatchDeCodigo, 0, len(porLinha))
	for _, m := range porLinha {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Linha < out[j].Linha })
	return out
}

// numeroDaLinha devolve a linha (1-based) do offset e o texto dela, do conteúdo
// ORIGINAL — para o operador ler o código de verdade, não a versão mascarada.
func numeroDaLinha(s string, off int) (int, string) {
	if off > len(s) {
		off = len(s)
	}
	linha := 1 + strings.Count(s[:off], "\n")
	ini := strings.LastIndexByte(s[:off], '\n') + 1
	fim := strings.IndexByte(s[off:], '\n')
	if fim < 0 {
		fim = len(s)
	} else {
		fim += off
	}
	return linha, s[ini:fim]
}

// argBalanceado devolve o texto entre o '(' em `abre` e o ')' que o fecha,
// respeitando aninhamento e PULANDO strings — assim um ')' dentro de "a)b" não
// fecha cedo, e um sink em JS/Python não estende o argumento até o statement
// seguinte (que não tem ';' para barrar). Limita o alcance para não varrer o
// arquivo inteiro num parêntese que nunca fecha.
func argBalanceado(s string, abre int) string {
	if abre < 0 || abre >= len(s) || s[abre] != '(' {
		return ""
	}
	limite := abre + 4000
	if limite > len(s) {
		limite = len(s)
	}
	prof := 0
	var str byte // 0 = código; senão a aspa que abriu
	for i := abre; i < limite; i++ {
		c := s[i]
		if str != 0 {
			if c == '\\' {
				i++
			} else if c == str {
				str = 0
			}
			continue
		}
		switch c {
		case '\'', '"', '`':
			str = c
		case '(':
			prof++
		case ')':
			prof--
			if prof == 0 {
				return s[abre+1 : i]
			}
		}
	}
	return s[abre+1 : limite]
}

// primeiroArgTop devolve o primeiro argumento (até a primeira vírgula de topo),
// para os callbacks: só o 1º arg é a função executada.
func primeiroArgTop(args string) string {
	prof := 0
	var str byte
	for i := 0; i < len(args); i++ {
		c := args[i]
		if str != 0 {
			if c == '\\' {
				i++
			} else if c == str {
				str = 0
			}
			continue
		}
		switch c {
		case '\'', '"', '`':
			str = c
		case '(', '[', '{':
			prof++
		case ')', ']', '}':
			prof--
		case ',':
			if prof == 0 {
				return args[:i]
			}
		}
	}
	return args
}

// mascararComentarios troca comentário e INTERIOR de string por espaço,
// preservando tamanho em bytes e quebras de linha — os offsets continuam
// apontando para a linha certa no original.
//
// É uma máquina de estados, não um lexer completo, mas entende string: comentário
// só começa em NORMAL, então `//` dentro de "http://x" NÃO apaga o resto da linha
// — o bypass que a versão anterior tinha, e que apagava um webshell depois de uma
// string com `//`. E branquear o interior das aspas deixa o casamento balanceado
// de parênteses correto (parêntese dentro de string não conta) e evita casar um
// $_GET escrito DENTRO de uma string.
//
// A crase do PHP é EXCEÇÃO: ela é shell_exec, um sink, não uma string — o
// conteúdo dela precisa ficar visível para o padrão de webshell.
func mascararComentarios(s, lang string) string {
	b := []byte(s)
	n := len(b)
	branco := func(i int) {
		if i < n && b[i] != '\n' {
			b[i] = ' '
		}
	}
	const (
		norm = iota
		aspaS
		aspaD
		crase
		comLinha
		comBloco
	)
	st := norm
	for i := 0; i < n; i++ {
		c := b[i]
		switch st {
		case norm:
			switch {
			case c == '/' && i+1 < n && b[i+1] == '/':
				branco(i)
				branco(i + 1)
				i++
				st = comLinha
			case c == '#' && lang != "js":
				branco(i)
				st = comLinha
			case c == '/' && i+1 < n && b[i+1] == '*':
				branco(i)
				branco(i + 1)
				i++
				st = comBloco
			case c == '\'':
				st = aspaS
			case c == '"':
				st = aspaD
			case c == '`' && lang != "php":
				st = crase // template literal do JS é string; a crase do PHP não
			}
		case comLinha:
			if c == '\n' {
				st = norm
			} else {
				branco(i)
			}
		case comBloco:
			if c == '*' && i+1 < n && b[i+1] == '/' {
				branco(i)
				branco(i + 1)
				i++
				st = norm
			} else {
				branco(i)
			}
		case aspaS:
			// Dentro de string NÃO se branqueia (o blob base64 embutido e o
			// conteúdo precisam ficar visíveis); só se rastreia o estado para o
			// comentário não começar aqui. O escape pula o próximo char.
			if c == '\\' {
				i++
			} else if c == '\'' {
				st = norm
			}
		case aspaD:
			if c == '\\' {
				i++
			} else if c == '"' {
				st = norm
			}
		case crase:
			if c == '\\' {
				i++
			} else if c == '`' {
				st = norm
			}
		}
	}
	return string(b)
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
	maxCodigoDepth = 12
	// Teto por arquivo: um webshell cabe em bytes; um bundle minificado de 40 MB
	// é ruído e custo. O que passar disso é dito.
	maxCodigoBytes = 2 << 20
)

// maxCodigoDirs e maxCodigoArquivos são o teto POR RAIZ. São var, não const,
// só para o teste poder baixá-los e exercitar a exaustão sem plantar 20 mil
// arquivos.
var (
	maxCodigoDirs     = 20000
	maxCodigoArquivos = 20000
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
	dirs              int
	arquivos          int
	truncado          bool
	tempo             bool
	grandesPulados    int
	dirsIlegiveis     int
	arquivosIlegiveis int
}

func collectCodigo(f *Facts, e *env.Env) {
	raizes := append([]string{}, codigoRaizes...)
	raizes = append(raizes, homeDirs(e)...)

	// Orçamento POR RAIZ, não global. Com um contador único, uma raiz enorme —
	// um /var/www com árvore `generated/` de dezenas de milhares de arquivos —
	// esgotava o teto e as raízes SEGUINTES (/data, onde muitas vezes mora a
	// aplicação) nunca eram alcançadas. Num host real a ferramenta achou o
	// webshell em /var/www e perdeu o de /data/.../app/bootstrap.php por isso.
	// Cada raiz recebe o seu teto; o tempo (--fs-budget) continua o limite
	// global para disco lento, e a truncagem de qualquer raiz é declarada.
	var st varreduraCodigo
	vistos := map[string]bool{}
	for _, r := range raizes {
		if r == "" || vistos[r] {
			continue
		}
		vistos[r] = true
		porRaiz := varreduraCodigo{tempo: st.tempo}
		varrerCodigo(f, e, r, 0, &porRaiz, vistos)
		st.truncado = st.truncado || porRaiz.truncado
		st.tempo = st.tempo || porRaiz.tempo
		st.grandesPulados += porRaiz.grandesPulados
		st.dirsIlegiveis += porRaiz.dirsIlegiveis
		st.arquivosIlegiveis += porRaiz.arquivosIlegiveis
	}

	if st.truncado {
		f.denyPersist("codigo", "a varredura de código atingiu o teto de "+
			itoa(maxCodigoDirs)+" diretórios ou "+itoa(maxCodigoArquivos)+
			" arquivos em ALGUMA raiz (o teto é por raiz): parte de uma árvore "+
			"grande NÃO foi analisada — um webshell mais fundo nela passa")
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
	if st.dirsIlegiveis > 0 {
		f.denyPersist("codigo", itoa(st.dirsIlegiveis)+" diretório(s) sob os web "+
			"roots não puderam ser LISTADOS (permissão): o que havia neles NÃO "+
			"foi analisado — sem root, boa parte do disco de aplicação é ilegível")
	}
	if st.arquivosIlegiveis > 0 {
		f.denyPersist("codigo", itoa(st.arquivosIlegiveis)+" arquivo(s) de código "+
			"foram listados e não puderam ser LIDOS (permissão): um backdoor num "+
			"deles passa, e a ausência de achado ali é desconhecimento, não resposta")
	}
}

func varrerCodigo(f *Facts, e *env.Env, dir string, prof int, st *varreduraCodigo, vistos map[string]bool) {
	e.Detalhe(dir)
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

	// ReadDir e NÃO ReadDirNames: o segundo engole o erro e devolve lista
	// vazia, o que transformaria um diretório com permissão negada em "nenhum
	// arquivo" — a confusão entre "não achei" e "não consegui ver", dentro do
	// próprio scanner. Diretório ilegível vira lacuna DECLARADA. Não-existe
	// (raiz que este host não tem) NÃO é lacuna, e EhLacuna separa os dois.
	ents, err := e.ReadDir(dir)
	if err != nil {
		if env.EhLacuna(err) {
			st.dirsIlegiveis++
		}
		return
	}
	for _, ent := range ents {
		n := ent.Name()
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
			// Um .php que o readdir listou e o ReadFile não abriu SOME do
			// universo avaliado se calarmos. Ilegível é lacuna; não-existe
			// (corrida: arquivo removido entre listar e ler) não é.
			if env.EhLacuna(err) {
				st.arquivosIlegiveis++
			}
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

// isWordByte responde se o byte faz parte de um identificador.
func isWordByte(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// chamadaDinamicaValida diz se `nome(` em `pos` é mesmo uma chamada por
// variável — não `new nome()` (instanciação), nem `.m()`/`->m()`/`::m()`
// (método), nem `function nome()` (definição).
func chamadaDinamicaValida(s string, pos int) bool {
	i := pos - 1
	for i >= 0 && (s[i] == ' ' || s[i] == '\t') {
		i--
	}
	if i >= 0 {
		if c := s[i]; c == '.' || c == '>' || c == ':' {
			return false // método de objeto ou estático
		}
	}
	fim := i + 1
	for i >= 0 && isWordByte(s[i]) {
		i--
	}
	switch s[i+1 : fim] {
	case "new", "function":
		return false
	}
	return true
}
