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
