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
	for _, linha := range []string{
		"// perigo: eval($_POST['x'])",
		"# system($_GET['cmd'])",
		" * assert($_REQUEST['y'])",
	} {
		if ms := analisarConteudo(linha, "php"); len(ms) != 0 {
			t.Errorf("comentário não pode disparar: %q -> %+v", linha, ms)
		}
	}
}

// Node e Python: o mesmo formato de co-ocorrência.
func TestNodeEPython(t *testing.T) {
	if ms := analisarConteudo(`const r = require('child_process').execSync(req.query.cmd);`, "js"); !tem(ms, 2, "child_process") {
		t.Errorf("node: exec sobre req.query tinha de ser TIER 2: %+v", ms)
	}
	if ms := analisarConteudo(`eval(req.body.payload)`, "js"); !tem(ms, 2, "eval sobre entrada") {
		t.Errorf("node: eval sobre req.body: %+v", ms)
	}
	if ms := analisarConteudo(`os.system(request.args['c'])`, "python"); !tem(ms, 2, "os.system") {
		t.Errorf("python: os.system sobre request: %+v", ms)
	}
	if ms := analisarConteudo(`data = pickle.loads(request.data)`, "python"); !tem(ms, 2, "pickle") {
		t.Errorf("python: pickle.loads sobre request: %+v", ms)
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
		if ms := analisarConteudo(linha, "python"); !tem(ms, 2, "subprocess") {
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
