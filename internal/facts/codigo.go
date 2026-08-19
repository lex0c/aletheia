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
	// perigo. call_user_func e os de array saíram daqui de propósito — eles
	// executam o CALLBACK, não o argumento, e ficam num padrão à parte:
	// `call_user_func('trim', $_POST)` não é RCE (função fixa), só
	// `call_user_func($_GET['f'], ...)` é.
	phpSinks  = `eval|assert|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec`
	phpInclui = `include|include_once|require|require_once`
	jsSinks   = `exec|execSync|spawn|spawnSync|execFile`

	// O callback é o argumento que EXECUTA — e ele NÃO é sempre o primeiro:
	// `array_map(cb, arr)` tem a função na frente, `array_filter(arr, cb)`
	// atrás. Ler os dois como "1º argumento" era ler o ARRAY como se fosse a
	// função chamada, e num Adminer de verdade isso rendia três críticos:
	// `array_filter($_POST["source"], 'strlen')` não executa o $_POST.
	phpCbArg1 = `call_user_func|call_user_func_array|array_map`
	phpCbArg2 = `array_filter|usort|uasort|uksort|array_walk|array_walk_recursive|array_reduce|preg_replace_callback`
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
	// balanceado é testado por entrada. cbArg1 e cbArg2 são os callbacks, e o
	// número diz QUAL argumento é a função executada.
	sinkAbre *regexp.Regexp
	cbArg1   *regexp.Regexp
	cbArg2   *regexp.Regexp
	inputRem *regexp.Regexp
	inputLoc *regexp.Regexp
	// atribui casa `var = rhs` (grupo 1 = var, grupo 2 = rhs), e varTok acha as
	// variáveis usadas dentro dos argumentos de um sink.
	atribui *regexp.Regexp
	varTok  *regexp.Regexp
	// sanNum casa um RHS que é COERÇÃO NUMÉRICA (`intval`, `number_format`,
	// `(int)`…): o resultado é um número, o que mata injeção de código/caminho
	// mesmo sobre $_GET. É a ÚNICA sanitização reconhecida — coerção numérica é
	// prova, função genérica não é (o review foi explícito: `$x=f($x)` mantém
	// taint, senão um `$x=base64_decode($x)` de webshell escaparia).
	sanNum *regexp.Regexp
	// dynAbre casa uma CHAMADA por variável, `$var(` ou `var(`, capturando o
	// nome no grupo 1 — para pegar `$fn = $_GET['f']; $fn(...)`. `new $var()` é
	// instanciação (vulnerabilidade de object injection, não backdoor) e é
	// excluída no motor.
	dynAbre *regexp.Regexp
	// switchAbre e listaAbre casam os dois GUARDS que prendem uma variável de
	// request a um conjunto FINITO de literais antes do sink — `switch($do){
	// case 'tmssql': $do(); }` e `in_array($fn, ['a','b'])`. Grupo 1 = a
	// variável restrita. É o que separa dispatcher legado de execução
	// arbitrária, e o motor precisava saber ver.
	switchAbre *regexp.Regexp
	listaAbre  *regexp.Regexp
	// escopoAbre casa o cabeçalho de uma função até o `{` do corpo, para o
	// taint não atravessar função. Só PHP o define: em JS e Python a função
	// interna ENXERGA a variável de fora, e apagar o taint ali seria perder
	// fluxo de verdade.
	escopoAbre *regexp.Regexp
	// guardaCaminho casa `validate_file($v)` — o validador de caminho do WP, que
	// bloqueia `../`. Grupo 1 = a var validada. Rebaixa um include DELA de LFI
	// arbitrário para confinado (tier 1). Só PHP.
	guardaCaminho *regexp.Regexp
	// especiais são construções fechadas casadas direto (crase, /e, include…);
	// suspeito é tier 1.
	especiais []regraDeCodigo
	suspeito  []regraDeCodigo
}

var reShellTrue = regexp.MustCompile(`shell\s*=\s*True`)

var defsPHP = defsCodigo{
	sinkAbre: regexp.MustCompile(`\b(?:` + phpSinks + `|unserialize|` + phpInclui + `)\s*\(`),
	cbArg1:   regexp.MustCompile(`\b(?:` + phpCbArg1 + `)\s*\(`),
	cbArg2:   regexp.MustCompile(`\b(?:` + phpCbArg2 + `)\s*\(`),
	inputRem: regexp.MustCompile(phpRemota),
	inputLoc: regexp.MustCompile(phpLocal),
	atribui:  regexp.MustCompile(`(\$\w+)\s*=\s*([^;]{0,400})`),
	varTok:   regexp.MustCompile(`\$\w+`),
	dynAbre:  regexp.MustCompile(`(\$\w+)\s*\(`),
	sanNum:   regexp.MustCompile(`^\s*@?\s*(?:\(\s*(?:int|integer|float|double|real|bool|boolean)\s*\)|(?:intval|floatval|doubleval|boolval|number_format|count|sizeof|strlen|mb_strlen|abs|intdiv|round|ceil|floor|hexdec|bindec|octdec|ip2long|crc32)\s*\()`),
	// `switch ($do) {` e `in_array($fn, ` — o resto da validação (rótulos
	// literais, ausência de `default`, lista fixa) é feita no motor.
	switchAbre:    regexp.MustCompile(`\bswitch\s*\(\s*(\$\w+)\s*\)\s*\{`),
	listaAbre:     regexp.MustCompile(`\bin_array\s*\(\s*(\$\w+)\s*,\s*`),
	guardaCaminho: regexp.MustCompile(`\b(?:validate_file|validate_plugin)\s*\(\s*(\$\w+)`),
	// `[^{;]` não atravessa o `{` do corpo nem o `;` de um método abstrato:
	// o `{` casado é sempre o que ABRE a função.
	escopoAbre: regexp.MustCompile(`\bfunction\b[^{;]{0,300}\{`),
	especiais: []regraDeCodigo{
		mustDup(2, "função nomeada pelo request (chamada dinâmica)", `\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\b(?:\s*\[[^\]]{0,40}\])?\s*\(`),
		// `[^;{}\n]`, e não `[^;]`: sem isso o span pulava o fim do statement
		// e casava a linha SEGUINTE. Medido: `<?php include('menu.php') ?>` com
		// `$_SERVER['PHP_SELF']` no <form> de baixo saía CRÍTICO — a forma mais
		// comum de PHP legado que existe. A forma com parênteses, multilinha
		// inclusive, continua coberta pelo motor de sink (argumento balanceado).
		mustDup(2, "include/require sobre entrada de request — LFI/RFI", `\b(?:`+phpInclui+`)\b\s*\(?\s*[^;{}\n]{0,160}`+phpRemota),
		mustDup(2, "eval de conteúdo decodificado — assinatura de webshell", `\b(?:eval|assert)\s*\(\s*@?\s*(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|hex2bin|convert_uudecode)\b`),
		mustDup(2, "preg_replace /e sobre entrada de request — executa o replacement", `\bpreg_replace\s*\(\s*['"][^'"]{1,200}/[a-zA-DF-Z]*e[a-zA-DF-Z]*['"][^;{}]{0,200}`+phpRemota),
		mustDup(2, "preg_replace /e com sink no replacement — RCE", "\\bpreg_replace\\s*\\(\\s*['\"][^'\"]{1,200}/[a-zA-DF-Z]*e[a-zA-DF-Z]*['\"]\\s*,\\s*[^;{}]{0,80}(?:\\b(?:system|exec|shell_exec|passthru|eval|assert|popen|proc_open)\\b|`)"),
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
	// SEM dynAbre em JS: `fn()` onde fn é string do request NÃO é RCE — string
	// não é chamável em JS (dá TypeError). O `$fn()` do PHP é que roda a função
	// nomeada. Manter dynAbre aqui só rendia FP (`const fn=req.query.fn; fn()`).
	switchAbre: regexp.MustCompile(`\bswitch\s*\(\s*(\w+)\s*\)\s*\{`),
	sanNum:     regexp.MustCompile(`^\s*(?:Number|parseInt|parseFloat)\s*\(`),
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
	sanNum:   regexp.MustCompile(`^\s*(?:int|float|len|abs|round|ord)\s*\(`),
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
// multilinha `system(\n  $_GET['x']\n)`, pelo ARGUMENTO BALANCEADO. E há um
// MICRO-TAINT de um salto: `$cmd = $_GET[...]` marca $cmd, e um sink que recebe
// $cmd depois vira achado. Não é um analisador de fluxo; é o suficiente para o
// implante minimamente organizado que separa a entrada do sink em duas linhas —
// a forma que o casamento por linha perdia inteira.
//
// A medição num host de produção com 8 críticos (3 webshells, 5 enganos) disse
// onde o micro-taint errava, e NENHUM dos cinco era "olhou mais de uma linha":
// era ele não conhecer a ESTRUTURA em volta da linha. Por isso o motor aprendeu
// três coisas, e o teste trava cada uma:
//
//	escopo   `$p=$_GET[x]` numa função e `include($p)` em OUTRA são duas
//	         variáveis homônimas, não um fluxo — a não ser que a de dentro
//	         importe a de fora (`global`, `use`)
//	guard    dentro de `switch($do){case 'a': $do();}` ou de um `in_array` de
//	         literais, o valor é um da lista, não o que o atacante mandar:
//	         vira aviso, não crítico
//	posição  a crase do PHP é shell_exec em posição de CÓDIGO; dentro de
//	         "..." ela é aspa de identificador do MySQL
//
// Cortar o multilinha teria escondido dois desses cinco e, junto, o webshell de
// duas linhas — `$c=$_POST['c']; system($c);` —, que é a forma mais copiada que
// existe. O erro não estava no alcance; estava na leitura.
func analisarConteudo(conteudo, lang string) []MatchDeCodigo {
	def := defsPorLinguagem(lang)
	if def == nil {
		return nil
	}
	// Comentário vira espaço (mesmo tamanho em bytes, quebras preservadas): os
	// offsets continuam apontando para a linha certa no ORIGINAL, e um padrão
	// dentro de `// exemplo: eval($_GET)` deixa de casar.
	// masc: strings VISÍVEIS — motor de taint, assinaturas e FONTES (php://input,
	// $_GET interpolado). mascDyn: todas as strings apagadas, só para a chamada
	// dinâmica `$var(`, que dentro de string nunca é chamada.
	masc, mascDyn, crases := mascararComentarios(conteudo, lang)

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

	// marca é o taint de uma variável: a classe e em que FUNÇÃO ela foi
	// contaminada — o escopo é resolvido na hora da atribuição, porque os
	// eventos vêm em ordem de offset e o cursor só anda para a frente.
	// pathSafe: a variável passou por um validador de CAMINHO do WP
	// (validate_file/validate_plugin), que bloqueia `../`. Torna um include
	// dela confinado (não LFI arbitrário) — mas NÃO sanitiza system/eval.
	type marca struct {
		classe, esc int
		pathSafe    bool
	}

	// Um evento é uma atribuição (marca/limpa taint de uma var) ou um sink (que
	// pode receber entrada DIRETA nos argumentos, ou uma variável tainted).
	type evento struct {
		off            int
		atrib          bool
		nome           string // atribuição: a var
		classe         int    // atribuição: 2 remota | 1 local | 0 limpa
		remDir, locDir bool   // sink: entrada direta na IDENTIDADE do callable
		vars           []string
		rotulo         string
		// Callback (`call_user_func($reg[$k])`): a IDENTIDADE do callable é a
		// base, sem subscrito. idxVars/idxRem guardam o que reachou o ÍNDICE: se
		// só o índice é request, é dispatch por registro (tier 1), não execução
		// arbitrária. Foi o FP do wp-admin/admin.php do WordPress core.
		callback bool
		idxVars  []string
		idxRem   bool
		// Atribuição: as variáveis do RHS, para propagar taint. `$b = $a` leva o
		// taint de $a a $b; `$x = base64_decode($x)` o MANTÉM. Sem isto, um
		// webshell `request -> var -> var -> sink` passava (FN pior que os FPs).
		rhsVars []string
		// guardaCam: `validate_file($v)` — marca $v como validado para CAMINHO a
		// partir deste offset. ehInclude: o sink é include/require (só nele o
		// validador de caminho rebaixa).
		guardaCam bool
		ehInclude bool
	}
	var evs []evento

	// listas guarda `$permitidos = ['a','b']` — a allowlist posta numa variável,
	// que é como o guard do in_array aparece na prática. Sai daqui de graça: as
	// atribuições já estão sendo varridas, e só quando há in_array no arquivo.
	listas := map[string]bool{}
	temLista := strings.Contains(masc, "in_array")
	for _, m := range def.atribui.FindAllStringSubmatchIndex(masc, -1) {
		rhs := masc[m[4]:m[5]]
		if temLista && listaLiteral(rhs, 0) {
			listas[masc[m[2]:m[3]]] = true
		}
		// `$x == $_GET[a]` e `$k => $_GET[v]` casam o mesmo `var = rhs`, e não
		// são atribuição: comparar e indexar não contaminam ninguém.
		if strings.HasPrefix(rhs, "=") || strings.HasPrefix(rhs, ">") {
			continue
		}
		// Coerção numérica limpa o taint mesmo sobre $_GET: `intval($_GET['id'])`
		// é um número, não roda código nem atravessa caminho. Única sanitização
		// reconhecida — e sem propagar var do RHS.
		if def.sanNum != nil && def.sanNum.MatchString(rhs) {
			evs = append(evs, evento{off: m[0], atrib: true, nome: masc[m[2]:m[3]], classe: 0})
			continue
		}
		classe := 0
		if def.inputRem.MatchString(rhs) {
			classe = 2
		} else if def.inputLoc.MatchString(rhs) {
			classe = 1
		}
		evs = append(evs, evento{off: m[0], atrib: true, nome: masc[m[2]:m[3]],
			classe: classe, rhsVars: def.varTok.FindAllString(rhs, -1)})
	}
	// argCb 0 = o sink executa os argumentos inteiros; 1 ou 2 = só aquele
	// argumento é a função executada (o callback).
	adicionarSink := func(loc []int, argCb int, rotulo string) {
		nome := masc[loc[0]:loc[1]]
		args := argBalanceado(masc, loc[1]-1)
		// subprocess só é sink com shell=True; sem isso a lista é execução segura.
		if strings.Contains(nome, "subprocess") && !reShellTrue.MatchString(args) {
			return
		}
		if argCb > 0 {
			args = argNoTopo(args, argCb)
		}
		e := evento{off: loc[0], rotulo: rotulo, ehInclude: ehSinkInclude(nome)}
		ident := args
		if argCb > 0 {
			// O que o callback EXECUTA é a base do callable, não o índice.
			// `$wp_importers[$importer][2]` chama a entrada REGISTRADA em
			// $wp_importers; $importer só a seleciona.
			e.callback = true
			e.idxVars = def.varTok.FindAllString(args, -1)
			e.idxRem = def.inputRem.MatchString(args)
			ident = semSubscritos(args)
			// Callable-array `array($obj, $metodo)`/`[$obj, $metodo]`: é chamada
			// de MÉTODO num objeto FIXO — o request escolhe o NOME do método,
			// não a função. A identidade é o 1º elemento (o objeto); o método é
			// índice, como `$obj->$m()`. Foi o FP do spellchecker do TinyMCE.
			if base, ok := primeiroElemCallable(args); ok {
				ident = base
			}
		}
		e.vars = def.varTok.FindAllString(ident, -1)
		if def.inputRem.MatchString(ident) {
			e.remDir = true
		} else if def.inputLoc.MatchString(ident) {
			e.locDir = true
		}
		evs = append(evs, e)
	}
	for _, loc := range def.sinkAbre.FindAllStringIndex(masc, -1) {
		adicionarSink(loc, 0, "sink de execução sobre entrada de request")
	}
	// Validador de CAMINHO do WordPress: `validate_file($v)`/`validate_plugin($v)`
	// bloqueia `../`. Um webshell nunca decora `include($_GET)` com isso, então
	// a presença sobre a var é sinal de código de framework guardado. Marca a
	// var como validada para caminho a partir daqui; um include DELA depois vira
	// tier 1 (confinado), enquanto system/eval sobre ela seguem críticos.
	if def.guardaCaminho != nil {
		for _, m := range def.guardaCaminho.FindAllStringSubmatchIndex(masc, -1) {
			evs = append(evs, evento{off: m[0], guardaCam: true, nome: masc[m[2]:m[3]]})
		}
	}
	const rotCb = "callback nomeado pelo request — executa função escolhida pelo atacante"
	if def.cbArg1 != nil {
		for _, loc := range def.cbArg1.FindAllStringIndex(masc, -1) {
			adicionarSink(loc, 1, rotCb)
		}
	}
	if def.cbArg2 != nil {
		for _, loc := range def.cbArg2.FindAllStringIndex(masc, -1) {
			adicionarSink(loc, 2, rotCb)
		}
	}
	// Chamada dinâmica `$fn(...)` onde $fn é tainted: o atacante escolhe a
	// função. EXCLUI `new $fn()` (instanciação = object injection, uma
	// vulnerabilidade, não backdoor — e o padrão de um exemplo inseguro de
	// biblioteca como o jpGraph) e método/estático (`.m()`, `->m()`, `::m()`).
	if def.dynAbre != nil {
		for _, m := range def.dynAbre.FindAllStringSubmatchIndex(mascDyn, -1) {
			if !chamadaDinamicaValida(masc, m[0]) {
				continue
			}
			evs = append(evs, evento{off: m[0], vars: []string{masc[m[2]:m[3]]},
				rotulo: "função nomeada por variável de entrada de request (chamada dinâmica)"})
		}
	}

	// A ESTRUTURA que o taint precisa conhecer antes de andar: em que função
	// cada offset está, e onde uma variável está presa a uma allowlist. Sem
	// isso o micro-taint só sabe "$_GET chegou nesta variável, e esta variável
	// chegou neste sink" — e é aí que ele erra, dos dois jeitos medidos em host
	// real: casando variáveis homônimas de funções diferentes, e ignorando o
	// guard que restringe o valor antes do sink.
	escopos := novoCursor(coletarEscopos(masc, def), def)
	guardas := coletarGuardas(masc, def, listas)

	// ORDENADO por offset: um sink antes da contaminação não é achado, e a
	// reatribuição a valor seguro limpa o taint. É o que separa fluxo real de
	// coincidência de nome entre funções.
	sort.Slice(evs, func(i, j int) bool { return evs[i].off < evs[j].off })
	taint := map[string]marca{}
	for _, e := range evs {
		if e.guardaCam {
			// só marca se a var já está contaminada; validar valor limpo é no-op.
			if mk, ok := taint[e.nome]; ok && mk.classe > 0 {
				mk.pathSafe = true
				taint[e.nome] = mk
			}
			continue
		}
		if e.atrib {
			esc := escopos.em(e.off)
			classe := e.classe
			// Propaga o taint das variáveis do RHS: `$b = $a` contamina $b, e
			// `$x = f($x)` mantém $x — não tratamos função como sanitizador
			// (o review foi explícito). Só do MESMO escopo, para não casar
			// homônimas de funções diferentes.
			for _, v := range e.rhsVars {
				if v == e.nome {
					if mk := taint[v]; mk.classe > classe {
						classe = mk.classe // `$x = f($x)`: o $x ANTERIOR
					}
					continue
				}
				if mk := taint[v]; mk.classe > classe &&
					(mk.esc == esc || escopos.importa(masc, esc, v)) {
					classe = mk.classe
				}
			}
			taint[e.nome] = marca{classe: classe, esc: esc}
			continue
		}
		switch {
		case e.remDir:
			registrar(e.off, 2, e.rotulo)
		case e.locDir:
			registrar(e.off, 1, e.rotulo+" — entrada LOCAL (argv/env)")
		default:
			maior, rotulo := 0, ""
			aqui := escopos.em(e.off)
			for _, v := range e.vars {
				mk := taint[v]
				if mk.classe == 0 {
					continue
				}
				// Escopo: a contaminação numa função e o sink em OUTRA são duas
				// variáveis homônimas, não um fluxo — nada a registrar.
				if mk.esc != aqui && !escopos.importa(masc, aqui, v) {
					continue
				}
				classe, rot := mk.classe, "sink sobre variável de entrada LOCAL (argv/env)"
				if classe == 2 {
					rot = "sink sobre variável de entrada de request (fluxo)"
					// Guard: dentro da allowlist a variável vale um dos rótulos
					// escritos ali, não o que o atacante mandar. Continua
					// merecendo leitura (tier 1) — a lista pode crescer, ou
					// conter algo que não devia —, mas não é execução arbitrária.
					switch {
					case dentroDeGuarda(guardas, v, e.off):
						classe, rot = 1, "entrada de request PRESA a allowlist literal "+
							"(switch/in_array) antes do sink — dispatch, não execução arbitrária"
					case e.ehInclude && mk.pathSafe:
						// include de caminho já validado (validate_file bloqueia
						// `../`): confinado ao diretório, não LFI arbitrário. Só
						// vale para include — system/eval sobre a var seguem tier 2.
						classe, rot = 1, "include de caminho VALIDADO por validate_file "+
							"(sem `../`) — LFI mitigado, não execução arbitrária"
					}
				}
				if classe > maior {
					maior, rotulo = classe, rot
				}
			}
			// Callback cuja IDENTIDADE está limpa mas o ÍNDICE é request: é
			// dispatch por registro indexado pelo request (roteador, tabela de
			// handlers registrados) — o atacante escolhe QUAL entrada roda, não
			// executa o que quiser. Merece leitura (tier 1), não crítico.
			if maior == 0 && e.callback {
				idx := e.idxRem
				for _, v := range e.idxVars {
					if idx {
						break
					}
					if mk := taint[v]; mk.classe >= 1 && (mk.esc == aqui || escopos.importa(masc, aqui, v)) {
						idx = true
					}
				}
				if idx {
					maior, rotulo = 1, "callback indexado por request num registro "+
						"(dispatch por chave, não execução arbitrária)"
				}
			}
			if maior > 0 {
				registrar(e.off, maior, rotulo)
			}
		}
	}

	// A crase do PHP é shell_exec, e é o padrão de maior sinal que existe — mas
	// SÓ em posição de código. Dentro de uma string ela é aspa de identificador
	// do MySQL, e é assim que ela aparece em ferramenta de banco:
	// `str_replace("`", "``", $campo)`. Medido no Adminer real: metade dos
	// críticos do arquivo era crase dentro de string. Por isso quem diz onde
	// elas estão é o mascarador, que conhece o estado, e não uma regex.
	for i := 0; i+1 < len(crases); i += 2 {
		if crases[i+1]-crases[i] > maxSpanCrase {
			continue // par improvável: comando de shell não tem esse tamanho
		}
		if def.inputRem.MatchString(masc[crases[i]+1 : crases[i+1]]) {
			registrar(crases[i], 2, "shell via crase sobre entrada de request")
		}
	}

	// Construções fechadas (/e, include, ofuscação) — ordem-independentes. Leem
	// a visão de ASSINATURA: o /e e o blob base64 moram DENTRO da string.
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
	if fim := fimBalanceado(s, abre, maxSpanArg); fim >= 0 {
		return s[abre+1 : fim]
	}
	limite := abre + maxSpanArg
	if limite > len(s) {
		limite = len(s)
	}
	return s[abre+1 : limite]
}

// Alcance dos scanners balanceados. Estourar o teto NÃO é erro: é quem chamou
// ficar SEM o span, e sem span o motor não suprime nada — o lado seguro do erro.
const (
	maxSpanArg   = 4000  // os argumentos de uma chamada
	maxSpanBloco = 64000 // o corpo de um switch ou de um if
	maxSpanCond  = 800   // da condição até o corpo que ela protege
	maxSpanCrase = 200   // o comando dentro de uma crase do PHP
)

// fimBalanceado devolve o offset do delimitador que FECHA o aberto em `abre` —
// vale `(`, `[` e `{` —, ou -1 se ele não fechar dentro de `alcance` bytes. Pula
// strings pelo mesmo motivo de argBalanceado: um `)` dentro de "a)b" não fecha
// nada.
func fimBalanceado(s string, abre, alcance int) int {
	if abre < 0 || abre >= len(s) {
		return -1
	}
	ab := s[abre]
	var fecha byte
	switch ab {
	case '(':
		fecha = ')'
	case '[':
		fecha = ']'
	case '{':
		fecha = '}'
	default:
		return -1
	}
	limite := abre + alcance
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
		case ab:
			prof++
		case fecha:
			prof--
			if prof == 0 {
				return i
			}
		}
	}
	return -1
}

// guarda é o trecho onde uma variável de request está PRESA a um conjunto finito
// de literais: o corpo de um `switch` de rótulos literais, ou o corpo do `if` de
// um `in_array` com lista fixa. Lá dentro, `$do()` não é "o atacante escolhe a
// função" — é dispatch por allowlist.
type guarda struct {
	nome     string
	ini, fim int
}

// coletarGuardas acha os guards de allowlist do arquivo.
//
// O caso que obrigou a isto é real (reportico/adodb, tests/tmssql.php):
//
//	$do = $_GET['do'];
//	switch($do) { case 'tpear': case 'tadodb': case 'tmssql': $do(); }
//
// O motor via `$_GET -> $do -> $do()` e gritava CRÍTICO. Mas `?do=system` não
// casa nenhum `case` e o sink não roda: o switch É a allowlist. É o limite
// seguinte do micro-taint — ele entendia source→atribuição→sink, e não entendia
// que um guard reduz o valor a um conjunto seguro antes do sink.
func coletarGuardas(masc string, def *defsCodigo, listas map[string]bool) []guarda {
	var gs []guarda
	if def.switchAbre != nil && strings.Contains(masc, "switch") {
		for _, m := range def.switchAbre.FindAllStringSubmatchIndex(masc, -1) {
			abre := m[1] - 1 // o `{` que o padrão já consumiu
			fim := fimBalanceado(masc, abre, maxSpanBloco)
			if fim < 0 || !rotulosLiterais(masc[abre+1:fim]) {
				continue
			}
			gs = append(gs, guarda{nome: masc[m[2]:m[3]], ini: abre, fim: fim})
		}
	}
	if def.listaAbre != nil && strings.Contains(masc, "in_array") {
		for _, m := range def.listaAbre.FindAllStringSubmatchIndex(masc, -1) {
			if negado(masc, m[0]) || !listaFixa(masc, m[1], listas) {
				continue
			}
			ini, fim := corpoDaCondicao(masc, m[0])
			if ini < 0 {
				continue
			}
			gs = append(gs, guarda{nome: masc[m[2]:m[3]], ini: ini, fim: fim})
		}
	}
	return gs
}

// dentroDeGuarda diz se o sink em `off` está sob um guard daquela variável.
func dentroDeGuarda(gs []guarda, v string, off int) bool {
	for _, g := range gs {
		// `>=` no começo: sem chaves, o corpo do if COMEÇA no sink —
		// `if (in_array($f,['a'])) $f();`.
		if g.nome == v && off >= g.ini && off < g.fim {
			return true
		}
	}
	return false
}

// rotulosLiterais diz se o corpo de um switch é uma allowlist FECHADA: todo
// `case` de topo tem rótulo literal (string ou número) e não há `default`.
//
// `default` derruba o guard — por ele passa qualquer valor, inclusive
// `?do=system`. Rótulo que não é literal (constante, variável, expressão)
// também derruba: o que ele vale não está escrito ali, e o motor não inventa.
func rotulosLiterais(corpo string) bool {
	casos, prof := 0, 0
	var str byte
	for i := 0; i < len(corpo); i++ {
		c := corpo[i]
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
			continue
		case '{', '(', '[':
			prof++
			continue
		case '}', ')', ']':
			prof--
			continue
		}
		// Só palavra de TOPO: `case`/`default` de um switch aninhado é assunto
		// dele, não deste.
		if prof != 0 || !isWordByte(c) || (i > 0 && isWordByte(corpo[i-1])) {
			continue
		}
		fim := i
		for fim < len(corpo) && isWordByte(corpo[fim]) {
			fim++
		}
		switch corpo[i:fim] {
		case "default":
			return false
		case "case":
			j := fim
			for j < len(corpo) && (corpo[j] == ' ' || corpo[j] == '\t' || corpo[j] == '\n' || corpo[j] == '\r') {
				j++
			}
			if j >= len(corpo) {
				return false
			}
			if k := corpo[j]; k != '\'' && k != '"' && k != '-' && (k < '0' || k > '9') {
				return false
			}
			casos++
		}
		i = fim - 1
	}
	return casos > 0
}

var (
	// `['a','b']` ou `array('a', 2)` no começo do trecho — quem pergunta já
	// está no 2º argumento do in_array. O CONTEÚDO é validado à parte, por
	// varredura: aninhar repetições numa regex só estoura o limite do RE2.
	reListaAbre = regexp.MustCompile(`^\s*(?:\[|array\s*\()`)
	reVarPHP    = regexp.MustCompile(`^\$\w+`)
)

// listaLiteral diz se o que começa em `pos` é uma lista FECHADA de literais.
// Lista montada em tempo de execução — `$permitidos[] = $x`, `explode(...)`,
// função — não restringe valor nenhum e não vira guard.
func listaLiteral(s string, pos int) bool {
	cabeca := pos + 16 // `array (` e o espaço em volta cabem de sobra
	if cabeca > len(s) {
		cabeca = len(s)
	}
	loc := reListaAbre.FindStringIndex(s[pos:cabeca])
	if loc == nil {
		return false
	}
	abre := pos + loc[1] - 1 // o `[` ou o `(` de array(
	fim := fimBalanceado(s, abre, maxSpanCond)
	if fim < 0 {
		return false
	}
	return soLiterais(s[abre+1 : fim])
}

// soLiterais diz se o interior de uma lista é só string, número e vírgula. É
// varredura, não regex, porque a string tem de ser pulada inteira: `'a,b'` é UM
// literal.
func soLiterais(interior string) bool {
	itens := 0
	for i := 0; i < len(interior); i++ {
		c := interior[i]
		switch {
		case c == '\'' || c == '"':
			fecha := c
			i++
			for ; i < len(interior) && interior[i] != fecha; i++ {
				if interior[i] == '\\' {
					i++
				}
			}
			if i >= len(interior) {
				return false // string aberta: o interior não é o que parece
			}
			itens++
		case c >= '0' && c <= '9':
			for i+1 < len(interior) && (interior[i+1] >= '0' && interior[i+1] <= '9' || interior[i+1] == '.') {
				i++
			}
			itens++
		case c == ',' || c == '-' || c == '+' || c == ' ' || c == '\t' || c == '\n' || c == '\r':
		default:
			return false // variável, constante, chamada: não é conjunto fechado
		}
	}
	return itens > 0
}

// listaFixa diz se o 2º argumento do in_array, que começa em `pos`, é o conjunto
// fechado — literal ali mesmo, ou a variável que recebeu um.
func listaFixa(s string, pos int, listas map[string]bool) bool {
	if pos >= len(s) {
		return false
	}
	if listaLiteral(s, pos) {
		return true
	}
	fim := pos + maxSpanCond
	if fim > len(s) {
		fim = len(s)
	}
	if v := reVarPHP.FindString(s[pos:fim]); v != "" {
		return listas[v]
	}
	return false
}

// negado diz se o guard está sob um `!`. `if (!in_array(...)) die();` protege o
// que vem DEPOIS, não o corpo do if, e ler isso ao contrário esconderia um sink
// de verdade. Sem certeza, não é guard.
func negado(s string, pos int) bool {
	i := pos - 1
	for i >= 0 && (s[i] == ' ' || s[i] == '\t') {
		i--
	}
	return i >= 0 && s[i] == '!'
}

// corpoDaCondicao devolve o span protegido por um guard que está dentro de uma
// condição: fecha os argumentos do guard, acha o `)` que fecha o `if (`, e pega
// o bloco `{ }` — ou, sem chaves, o statement único até o `;`. Devolve (-1, -1)
// quando o guard não está numa condição (`$ok = in_array(...)`), e aí não há
// corpo protegido para reconhecer.
func corpoDaCondicao(s string, pos int) (int, int) {
	teto := pos + maxSpanCond
	if teto > len(s) {
		teto = len(s)
	}
	ab := strings.IndexByte(s[pos:teto], '(')
	if ab < 0 {
		return -1, -1
	}
	i := fimBalanceado(s, pos+ab, maxSpanArg)
	if i < 0 {
		return -1, -1
	}
	limite := i + maxSpanCond
	if limite > len(s) {
		limite = len(s)
	}
	prof, resto := 0, i+1
	var str byte
	for i++; i < limite; i++ {
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
		case '|':
			// `in_array(...) || $_GET['x']`: o OR deixa o corpo alcançável SEM
			// a allowlist ser verdadeira. Não é guard — o atacante entra pelo
			// outro lado. Sem certeza de que a lista é condição NECESSÁRIA, não
			// rebaixa.
			if prof == 0 && i+1 < limite && s[i+1] == '|' {
				return -1, -1
			}
		case '(':
			prof++
		case ';', '{':
			return -1, -1 // acabou o statement sem condição nenhuma
		case ')':
			if prof > 0 {
				prof--
				continue
			}
			// `in_array(...) == false` inverte a condição igual ao `!`, e o
			// corpo passa a ser o caminho NÃO restrito. Sem certeza, não é guard.
			if strings.Contains(s[resto:i], "false") {
				return -1, -1
			}
			j := i + 1 // fechou o `if (`: o corpo é o que vem a seguir
			for j < limite && (s[j] == ' ' || s[j] == '\t' || s[j] == '\n' || s[j] == '\r') {
				j++
			}
			if j < limite && s[j] == '{' {
				if fim := fimBalanceado(s, j, maxSpanBloco); fim >= 0 {
					return j, fim
				}
				return -1, -1
			}
			if fim := strings.IndexByte(s[j:limite], ';'); fim >= 0 {
				return j, j + fim
			}
			return -1, -1
		}
	}
	return -1, -1
}

// escopoFn é o corpo de uma função: `ini` é o `{`, `fim` o `}` que o fecha, e
// `cab` o cabeçalho de `function` até o `{` — onde mora o `use ($x)` da closure.
type escopoFn struct {
	ini, fim, prof int
	cab            string
}

// coletarEscopos delimita os corpos de função numa passada só.
//
// Existe porque o micro-taint é GLOBAL ao arquivo, e casava variáveis de funções
// DIFERENTES: `$p = $_GET['page']` numa e `include($p)` em outra são duas
// variáveis com o mesmo nome, não um fluxo — e num arquivo legado de mil linhas
// isso rende crítico atrás de crítico. Função que não fecha (arquivo truncado,
// chave solta no meio de HTML) fica sem `fim`, e sem span o motor não suprime
// nada.
func coletarEscopos(masc string, def *defsCodigo) []escopoFn {
	if def.escopoAbre == nil || !strings.Contains(masc, "function") {
		return nil
	}
	abre := map[int]int{} // offset do `{` -> offset do `function`
	for _, m := range def.escopoAbre.FindAllStringIndex(masc, -1) {
		abre[m[1]-1] = m[0]
	}
	if len(abre) == 0 {
		return nil
	}
	var out []escopoFn
	var pilha []int
	prof := 0
	var str byte
	for i := 0; i < len(masc); i++ {
		c := masc[i]
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
		case '{':
			prof++
			if ini, ok := abre[i]; ok {
				out = append(out, escopoFn{ini: i, fim: -1, prof: prof, cab: masc[ini:i]})
				pilha = append(pilha, len(out)-1)
			}
		case '}':
			if n := len(pilha); n > 0 && out[pilha[n-1]].prof == prof {
				out[pilha[n-1]].fim = i
				pilha = pilha[:n-1]
			}
			prof--
		}
	}
	return out
}

// cursorEscopo responde "em que função está este offset" andando JUNTO com os
// eventos, que vêm em ordem. Cada escopo entra e sai da pilha uma vez só — a
// busca linear por escopo custava caro num arquivo minificado, onde um só
// `<?php` tem centenas de funções.
type cursorEscopo struct {
	escopos []escopoFn
	varTok  *regexp.Regexp
	prox    int
	pilha   []int
	// importados é o cache de `global $x;` e `use ($x)` por escopo — a conta é
	// feita uma vez por função, e só quando alguma variável exige.
	importados []map[string]bool
}

func novoCursor(escopos []escopoFn, def *defsCodigo) *cursorEscopo {
	return &cursorEscopo{escopos: escopos, varTok: def.varTok,
		importados: make([]map[string]bool, len(escopos))}
}

// em devolve o índice da função MAIS INTERNA que contém o offset, ou -1 para o
// topo do arquivo. Só anda para a frente: os eventos chegam ordenados.
func (c *cursorEscopo) em(off int) int {
	for c.prox < len(c.escopos) && c.escopos[c.prox].ini < off {
		if e := c.escopos[c.prox]; e.fim > off {
			c.pilha = append(c.pilha, c.prox)
		}
		c.prox++
	}
	for len(c.pilha) > 0 && c.escopos[c.pilha[len(c.pilha)-1]].fim < off {
		c.pilha = c.pilha[:len(c.pilha)-1]
	}
	if len(c.pilha) == 0 {
		return -1
	}
	return c.pilha[len(c.pilha)-1]
}

var (
	reUse    = regexp.MustCompile(`\buse\s*\([^)]{0,300}\)`)
	reGlobal = regexp.MustCompile(`\bglobal\b[^;]{0,300};`)
)

// importa diz se a função `i` traz a variável de FORA explicitamente — `global
// $x;` no corpo, `use ($x)` no cabeçalho da closure. Sem uma das duas, o `$x` de
// dentro é outra variável, e casar as duas é coincidência de nome.
func (c *cursorEscopo) importa(masc string, i int, v string) bool {
	if i < 0 || i >= len(c.escopos) {
		return false
	}
	if c.importados[i] == nil {
		e := c.escopos[i]
		vs := map[string]bool{}
		for _, t := range c.varTok.FindAllString(reUse.FindString(e.cab), -1) {
			vs[t] = true
		}
		for _, g := range reGlobal.FindAllString(masc[e.ini:e.fim], -1) {
			for _, t := range c.varTok.FindAllString(g, -1) {
				vs[t] = true
			}
		}
		c.importados[i] = vs
	}
	return c.importados[i][v]
}

// argNoTopo devolve o n-ésimo argumento (1-based) de uma lista já balanceada,
// cortando nas vírgulas de TOPO. É para os callbacks: o que o sink executa é UM
// argumento, e qual deles depende da função.
func argNoTopo(args string, n int) string {
	prof, ini, visto := 0, 0, 1
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
				if visto == n {
					return args[ini:i]
				}
				visto++
				ini = i + 1
			}
		}
	}
	if visto == n {
		return args[ini:]
	}
	return ""
}

// primeiroElemCallable, para um callback que é `array($obj, $metodo)` ou
// `[$obj, $metodo]`, devolve o 1º elemento (o objeto/classe) — a IDENTIDADE do
// callable. O 2º é o NOME do método: request ali é dispatch de método no objeto
// fixo, não execução arbitrária. Devolve ("", false) se não for um array-callable.
func primeiroElemCallable(s string) (string, bool) {
	t := strings.TrimSpace(s)
	var corpo string
	switch {
	case strings.HasPrefix(t, "array"):
		r := strings.TrimSpace(strings.TrimPrefix(t, "array"))
		if !strings.HasPrefix(r, "(") {
			return "", false
		}
		fim := fimBalanceado(r, 0, maxSpanArg)
		if fim < 0 {
			return "", false
		}
		corpo = r[1:fim]
	case strings.HasPrefix(t, "["):
		fim := fimBalanceado(t, 0, maxSpanArg)
		if fim < 0 {
			return "", false
		}
		corpo = t[1:fim]
	default:
		return "", false
	}
	// só o 1º elemento (argNoTopo devolve o 1º arg até a vírgula de topo);
	// precisa haver um 2º (o método) para ser callable de método, senão é array
	// normal — se o 1º elemento é o corpo inteiro, não havia vírgula.
	prim := argNoTopo(corpo, 1)
	if strings.TrimSpace(prim) == "" || len(strings.TrimSpace(prim)) == len(strings.TrimSpace(corpo)) {
		return "", false
	}
	return prim, true
}

// semSubscritos apaga o conteúdo dos colchetes `[...]` de uma expressão, deixando
// só a IDENTIDADE base. `$reg[$k]` -> `$reg`: para um callback, o que executa é
// o que está no registro, não a chave. Pula string para um `]` dentro de "a]b"
// não fechar cedo.
func semSubscritos(s string) string {
	b := []byte(s)
	prof := 0
	var str byte
	for i := 0; i < len(b); i++ {
		c := b[i]
		if str != 0 {
			if prof > 0 {
				b[i] = ' '
			}
			if c == '\\' {
				i++
			} else if c == str {
				str = 0
			}
			continue
		}
		switch c {
		case '\'', '"', '`':
			if prof > 0 {
				b[i] = ' '
			}
			str = c
		case '[':
			prof++
			b[i] = ' '
		case ']':
			if prof > 0 {
				prof--
			}
			b[i] = ' '
		default:
			if prof > 0 {
				b[i] = ' '
			}
		}
	}
	return string(b)
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
// conteúdo dela precisa ficar visível para o padrão de webshell. Por isso o
// mascarador devolve TAMBÉM os offsets das crases que viu em posição de código:
// só essas são shell_exec. A que aparece dentro de "..." é aspa de identificador
// do MySQL, e quem sabe distinguir as duas é esta máquina de estados.
//
// Devolve DUAS visões, do mesmo tamanho em bytes:
//
//	masc     comentário apagado, interior de STRING VISÍVEL. É a visão de quase
//	         tudo: assinaturas (blob base64, /e), FONTES (`php://input`,
//	         `$_GET` interpolado em "...") e sinks. Uma fonte literal em string
//	         PRECISA ficar visível — apagá-la cega o webshell que lê o corpo do
//	         POST com `file_get_contents('php://input')`.
//	mascDyn  interior de TODA string apagado — usada SÓ pela chamada dinâmica
//	         `$var(`. Um `$var(` dentro de uma string nunca é chamada; era o FP
//	         do `$s(` em `sprintf('%1$s (...')` do wp-admin. Só o dynAbre precisa
//	         dessa visão; o resto perderia fontes se a usasse.
func mascararComentarios(s, lang string) (masc, mascDyn string, crases []int) {
	b := []byte(s)
	bc := append([]byte(nil), b...) // a visão do taint: aspa simples apagada
	n := len(b)
	branco := func(i int) {
		if i < n && b[i] != '\n' {
			b[i] = ' '
			bc[i] = ' '
		}
	}
	brancoCod := func(i int) {
		if i < n && bc[i] != '\n' {
			bc[i] = ' ' // só na visão do taint
		}
	}
	const (
		norm = iota
		aspaS
		aspaD
		crase
		comLinha
		comBloco
		foraPHP
	)
	// Num .php, o arquivo é SAÍDA até o primeiro `<?`: o que está fora da tag
	// não é código, é HTML. Tratar HTML como código dessincronizava a máquina
	// no primeiro apóstrofo — `<p>it's here</p>` abria uma string que engolia o
	// código depois dela, e um `echo \`$_REQUEST[0]\`` logo abaixo sumia da
	// peneira. Fragmento SEM tag nenhuma (o teste, um .inc de código puro) é
	// tratado como código inteiro: senão a análise viraria silêncio.
	st := norm
	if lang == "php" && strings.Contains(s, "<?") {
		st = foraPHP
	}
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
			case c == '<' && lang == "php" && i+2 < n && b[i+1] == '<' && b[i+2] == '<':
				// heredoc/nowdoc: o fim é o RÓTULO no começo de uma linha, não
				// uma aspa. Sem isto, um apóstrofo lá dentro (`don't`) abria
				// uma string que engolia o código seguinte. O interior fica
				// VISÍVEL, como o das outras strings — `$_GET` interpolado
				// dentro dele é dado de verdade.
				if fim, ok := pulaHeredoc(b, i); ok {
					i = fim
				}
			case c == '\'':
				st = aspaS
			case c == '"':
				st = aspaD
			case c == '`':
				if lang == "php" {
					crases = append(crases, i)
					break
				}
				st = crase // template literal do JS é string; a crase do PHP não
			case c == '?' && lang == "php" && i+1 < n && b[i+1] == '>':
				branco(i)
				branco(i + 1)
				i++
				st = foraPHP // fechou a tag: daqui até o próximo `<?` é saída
			}
		case foraPHP:
			if c == '<' && i+1 < n && b[i+1] == '?' {
				branco(i)
				branco(i + 1)
				i++
				st = norm
			} else {
				branco(i)
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
			// Em masc o interior fica visível (blob base64, /e); em mascCod ele é
			// apagado, porque aspa simples não interpola e o taint não deve ver
			// `$var` nem `$_GET` escritos ali como código. O escape pula o char.
			if c == '\\' {
				brancoCod(i)
				brancoCod(i + 1)
				i++
			} else if c == '\'' {
				st = norm
			} else {
				brancoCod(i)
			}
		case aspaD:
			if c == '\\' {
				brancoCod(i)
				brancoCod(i + 1)
				i++
			} else if c == '"' {
				st = norm
			} else {
				brancoCod(i)
			}
		case crase:
			if c == '\\' {
				i++
			} else if c == '`' {
				st = norm
			}
		}
	}
	masc, mascDyn = string(b), string(bc)
	return masc, mascDyn, crases
}

// pulaHeredoc devolve o offset do FIM de um heredoc/nowdoc que começa no `<<<`
// em `ini` — o rótulo repetido no começo de uma linha. Devolve false quando não
// é heredoc (ou não termina), e aí quem chama segue a leitura normal: perder o
// resto do arquivo por um rótulo que nunca fecha seria pior que o problema.
func pulaHeredoc(b []byte, ini int) (int, bool) {
	n := len(b)
	i := ini + 3
	for i < n && (b[i] == ' ' || b[i] == '\t') {
		i++
	}
	var aspa byte
	if i < n && (b[i] == '\'' || b[i] == '"') {
		aspa = b[i]
		i++
	}
	rot := i
	for i < n && isWordByte(b[i]) {
		i++
	}
	if i == rot {
		return 0, false // `<<<` sem rótulo: não é heredoc
	}
	label := b[rot:i]
	if aspa != 0 {
		if i >= n || b[i] != aspa {
			return 0, false
		}
		i++
	}
	if i < n && b[i] == '\r' {
		i++
	}
	if i >= n || b[i] != '\n' {
		return 0, false // o rótulo tem de terminar a linha
	}
	// procura o rótulo no começo de uma linha (só espaço antes, desde PHP 7.3)
	for j := i; j < n; {
		j++ // primeiro byte da linha
		k := j
		for k < n && (b[k] == ' ' || b[k] == '\t') {
			k++
		}
		if k+len(label) <= n && string(b[k:k+len(label)]) == string(label) &&
			(k+len(label) == n || !isWordByte(b[k+len(label)])) {
			return k + len(label) - 1, true
		}
		nl := indexByteFrom(b, j, '\n')
		if nl < 0 {
			return 0, false
		}
		j = nl
	}
	return 0, false
}

// indexByteFrom é o IndexByte a partir de um offset, sem alocar sub-slice.
func indexByteFrom(b []byte, de int, c byte) int {
	for i := de; i < len(b); i++ {
		if b[i] == c {
			return i
		}
	}
	return -1
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
// Teto por arquivo: um webshell cabe em bytes; um bundle minificado de 40 MB é
// ruído e custo. O que passar disso é dito.
const maxCodigoBytes = 2 << 20

// maxCodigoDepth é o teto de profundidade — freio contra laço por symlink, e
// declarado quando bate. var (não const) só para o teste baixá-lo.
var maxCodigoDepth = 12

// maxCodigoDirs e maxCodigoArquivos são o teto POR RAIZ. São var, não const,
// só para o teste poder baixá-los e exercitar a exaustão sem plantar 20 mil
// arquivos.
//
// Os dois tetos medem CUSTOS diferentes, e por isso são MUITO diferentes.
// Listar um diretório é um readdir — barato; LER e analisar um arquivo de
// código é I/O mais regex — caro. O teto de diretórios existe só como freio
// contra laço patológico (o tempo e a profundidade já limitam o resto), e por
// isso é alto. O de arquivos é o que de fato limita o trabalho caro.
//
// Medido num host real (meteorologia, /data com arquivo de imagens e dados de
// anos): o teto de diretórios em 20 mil ESTOURAVA na árvore de dados e o código
// servido de uma aplicação IRMÃ — /data/local/www/data/consultoria/app/
// bootstrap.php, com um webshell de crase de verdade — nunca era alcançado. A
// varredura DECLAROU a lacuna (não mentiu "limpo"), mas declarar não é achar. O
// teto baixo tratava um readdir como se custasse o mesmo que ler um arquivo.
var (
	maxCodigoDirs     = 300000
	maxCodigoArquivos = 40000
)

// codigoRaizes são as árvores onde código SERVIDO mora — é ali que um webshell
// tem para que existir. Deliberadamente não é "/" inteiro: varrer a raiz
// arrasta /usr e /proc sem acrescentar sinal, e o custo de I/O explodiria.
//
// A lista precisa ser COMPLETA para o host, e é aqui que uma raiz faltando vira
// cegueira silenciosa: /usr/local/www é o web root PADRÃO de FreeBSD/BSD, e num
// host real o código só apareceu porque o home de uma conta apontava para lá —
// frágil. Cada distribuição/painel tem o seu, então a lista cobre os que se vê
// na prática. Os homes de /etc/passwd entram por fora (homeDirs).
//
// LIMITE conhecido: um docroot em lugar fora desta lista (um Alias de Apache, um
// root de vhost do nginx apontando para /home/cliente/app, um caminho exótico)
// NÃO é varrido. O jeito honesto de fechar isso é derivar o docroot da config do
// servidor web — trabalho à parte; até lá, a lista é estática e este é o buraco.
var codigoRaizes = []string{
	"/var/www", "/srv", "/usr/share/nginx", "/data", "/opt",
	"/usr/local/www",            // FreeBSD/BSD: o web root padrão
	"/usr/local/apache2",        // build de Apache pela fonte (htdocs embaixo)
	"/usr/local/nginx",          // build de nginx pela fonte (html embaixo)
	"/usr/local/lsws",           // LiteSpeed
	"/www", "/web", "/websites", // painéis (aaPanel, VestaCP e afins)
	"/home/www", "/var/lib/nginx",
}

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
	profundidade      bool
	grandesPulados    int
	dirsIlegiveis     int
	arquivosIlegiveis int
}

func collectCodigo(f *Facts, e *env.Env) {
	// pularAbs são caminhos ABSOLUTOS que a varredura não desce — distinto do
	// pularNoCodigo, que casa por NOME em qualquer nível. Aqui entram o --ignore
	// (escolha do operador) e, no modo --all-fs, os pseudo-FS e as montagens de
	// rede. Casar por caminho absoluto é o que permite pular /proc sem pular um
	// diretório chamado "proc" no meio de uma aplicação.
	pularAbs := map[string]bool{}
	for _, ig := range e.Ignorados() {
		pularAbs[ig] = true
	}

	var raizes []string
	if e.CodigoTudo {
		// --all-fs: a FS montada INTEIRA, a partir de /. O discriminador tier-2
		// (sink sobre entrada de request) quase não dispara em código de
		// sistema, então varrer /usr sai limpo — o preço é tempo, não ruído.
		raizes = []string{"/"}
		// Pseudo-FS: não são arquivos de verdade, e /proc sozinho tem centenas
		// de milhares de entradas. Pulados por caminho, e isto vale até em modo
		// image (onde não há mountinfo).
		for _, p := range []string{"/proc", "/sys", "/dev", "/run"} {
			pularAbs[p] = true
		}
		// Montagem de REDE trava a varredura (NFS/CIFS/sshfs podem pendurar) e
		// não é "a FS deste host": pulada e DECLARADA. Montagem local (ext4,
		// xfs, btrfs, e o overlay de contêiner em disco) é atravessada — é onde
		// código servido de verdade mora. f.Mounts já foi coletado (a ordem em
		// facts.go garante).
		var rede []string
		for i := range f.Mounts {
			m := &f.Mounts[i]
			if fsDeRede[m.Tipo] {
				pularAbs[m.Ponto] = true
				rede = append(rede, m.Ponto+" ("+m.Tipo+")")
			}
		}
		if n := len(rede); n > 0 {
			sort.Strings(rede)
			if len(rede) > 6 {
				rede = append(rede[:6:6], "…")
			}
			f.denyPersist("codigo", "--all-fs: "+itoa(n)+" montagem(ns) de "+
				"REDE NÃO foram varridas (podem pendurar a varredura, e não são a FS "+
				"deste host): "+strings.Join(rede, ", ")+". Aponte `scan --root` nelas "+
				"se precisar")
		}
	} else {
		raizes = append([]string{}, codigoRaizes...)
		raizes = append(raizes, homeDirs(e)...)
	}

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
		if r == "" || vistos[r] || pularAbs[r] || e.Ignorado(r) {
			continue
		}
		vistos[r] = true
		porRaiz := varreduraCodigo{tempo: st.tempo}
		varrerCodigo(f, e, r, 0, &porRaiz, vistos, pularAbs)
		st.truncado = st.truncado || porRaiz.truncado
		st.tempo = st.tempo || porRaiz.tempo
		st.profundidade = st.profundidade || porRaiz.profundidade
		st.grandesPulados += porRaiz.grandesPulados
		st.dirsIlegiveis += porRaiz.dirsIlegiveis
		st.arquivosIlegiveis += porRaiz.arquivosIlegiveis
	}

	if st.truncado {
		f.denyPersist("codigo", "a varredura de código atingiu o teto BACKSTOP de "+
			itoa(maxCodigoDirs)+" diretórios ou "+itoa(maxCodigoArquivos)+
			" arquivos de código em ALGUMA raiz (o teto é por raiz, e a varredura "+
			"é por nível — o código raso foi coberto primeiro): uma árvore MUITO "+
			"grande não coube inteira, e um webshell mais fundo nela passa. Rode "+
			"`scan --fs-budget 0` (já é o padrão) num host com disco rápido, ou "+
			"aponte `scan --root` direto na árvore suspeita")
	}
	if st.tempo {
		f.denyPersist("codigo", "a varredura de código parou pelo orçamento de "+
			"tempo: o que faltou NÃO foi analisado — rode `scan` sem teto")
	}
	if st.profundidade {
		f.denyPersist("codigo", "a varredura de código não desceu além de "+
			itoa(maxCodigoDepth)+" níveis: código MAIS FUNDO que isso NÃO foi "+
			"analisado — um webshell aninhado muito fundo passa. Aponte "+
			"`scan --root` na subárvore suspeita")
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
	declararIgnore(f, e, "codigo")
}

// declararIgnore anota, na cobertura do check dado, os caminhos que o operador
// excluiu com --ignore. Toda varredura de FS que honra e.Ignorado precisa
// declarar isto: excluir e ler "limpo" sobre o excluído é a cegueira silenciosa
// que a ferramenta combate. Chamado por código, SUID e git-hooks.
func declararIgnore(f *Facts, e *env.Env, check string) {
	ig := e.Ignorados()
	if len(ig) == 0 {
		return
	}
	mostra := append([]string{}, ig...)
	if len(mostra) > 8 {
		mostra = append(mostra[:8:8], "…")
	}
	f.denyPersist(check, "--ignore: "+itoa(len(ig))+" caminho(s) foram EXCLUÍDOS "+
		"da varredura por sua escolha ("+strings.Join(mostra, ", ")+"): o que "+
		"havia neles NÃO foi procurado")
}

func varrerCodigo(f *Facts, e *env.Env, raiz string, prof int, st *varreduraCodigo, vistos, pularAbs map[string]bool) {
	// BFS por PROFUNDIDADE, não DFS. O código SERVIDO — o index.php, o
	// bootstrap.php, o painel — mora raso, na raiz de cada aplicação; o que é
	// fundo é dado, upload, cache, build. A recursão em profundidade mergulhava
	// numa árvore de dados IRMÃ e gastava o orçamento antes de listar a
	// aplicação ao lado (medido: o webshell de /data/local/www/data/consultoria
	// passou porque uma árvore de dados vizinha consumiu o teto primeiro). A
	// fila por nível gasta o orçamento no raso primeiro — onde o webshell de
	// ponto-de-entrada está —, seja qual for a ordem que o readdir devolveu.
	//
	// Os arquivos de um diretório são analisados AO tirá-lo da fila; os
	// subdiretórios só entram na fila (nível+1). Assim os arquivos de um nível
	// vêm sempre antes do CONTEÚDO de qualquer subdiretório dele.
	type pendente struct {
		dir  string
		prof int
	}
	fila := []pendente{{raiz, prof}}
	for len(fila) > 0 {
		at := fila[0]
		fila = fila[1:]
		e.Detalhe(at.dir)
		if at.prof > maxCodigoDepth || st.truncado || st.tempo {
			continue
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
		ents, err := e.ReadDir(at.dir)
		if err != nil {
			if env.EhLacuna(err) {
				st.dirsIlegiveis++
			}
			continue
		}
		var subdirs []string
		for _, ent := range ents {
			n := ent.Name()
			p := at.dir + "/" + n
			if at.dir == "/" { // raiz do --all-fs: evita a barra dupla "//data"
				p = "/" + n
			}
			// Caminho absoluto excluído — ANTES de qualquer stat: --ignore do
			// operador, ou pseudo-FS e montagem de REDE no --all-fs. Checar antes
			// do IsDir é o que impede TOCAR (e pendurar em) uma montagem de rede.
			// Distinto do pularNoCodigo, que casa por NOME.
			if pularAbs[p] || e.Ignorado(p) {
				continue
			}
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
				subdirs = append(subdirs, p) // fundo, DEPOIS dos arquivos deste nível
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
		for _, p := range subdirs {
			if at.prof+1 > maxCodigoDepth {
				st.profundidade = true // código mais fundo que o teto: DECLARADO
				continue
			}
			fila = append(fila, pendente{p, at.prof + 1})
		}
	}
}

// pularNoCodigo são as árvores de dependência que não se percorre: varrê-las
// inteiras é o custo de I/O que já mordeu a varredura de SUID.
// fsDeRede são os tipos de filesystem que o modo --all-fs NÃO atravessa: podem
// PENDURAR a varredura (o servidor remoto não responde) e não são a FS deste
// host. Pulados e declarados; o operador aponta `--root` neles se precisar.
var fsDeRede = map[string]bool{
	"nfs": true, "nfs4": true, "cifs": true, "smb3": true, "smbfs": true,
	"ceph": true, "glusterfs": true, "afs": true, "9p": true, "ncpfs": true,
	"fuse.sshfs": true, "fuse.s3fs": true, "fuse.rclone": true,
	"fuse.glusterfs": true, "fuse.cephfs": true, "davfs": true,
}

var pularNoCodigo = map[string]bool{
	"node_modules": true, "vendor": true, ".git": true, ".cache": true,
	".svn": true, "bower_components": true, ".npm": true,
}

// ehSinkInclude diz se o nome do sink casado é include/require — o único sink em
// que um validador de caminho (validate_file) rebaixa: ele confina o path, mas
// não sanitiza comando nem código.
func ehSinkInclude(nome string) bool {
	return strings.Contains(nome, "include") || strings.Contains(nome, "require")
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
		// `.m()`, `->m()` e `::m()` são método, não função livre. UM dois-pontos
		// só, não: esse é rótulo de `case` ou ternário, e barrar por ele fazia
		// `switch($x){case 'a': $x();}` numa linha só passar batido.
		if c := s[i]; c == '.' || c == '>' || (c == ':' && i > 0 && s[i-1] == ':') {
			return false
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
