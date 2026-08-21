package facts

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/lex0c/aletheia/internal/env"
)

// A análise de código passou a ser PARALELA, e o que ela não pode perder é o
// determinismo: a caminhada continua serial (é ela que gasta os tetos e decide
// onde a varredura corta), e os achados são escritos em posições fixas de um
// vetor indexado pela ordem da fila — nunca anexados na ordem em que os
// trabalhadores terminam.
//
// Sem esta trava, o mesmo host produziria relatórios com os achados em ordem
// diferente a cada execução, e diff de relatório é como se compara host com ele
// mesmo ao longo do tempo.
func TestAnaliseDeCodigoEhParalelaEDeterministica(t *testing.T) {
	dir := t.TempDir()

	// Um número de arquivos maior que o de trabalhadores, para que a ordem de
	// conclusão realmente embaralhe.
	const n = 64
	for i := 0; i < n; i++ {
		nome := filepath.Join(dir, "s"+strconv.Itoa(i)+".php")
		conteudo := "<?php $c = $_POST['c']; system($c);\n"
		if err := os.WriteFile(nome, []byte(conteudo), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// E um arquivo limpo no meio, para provar que a peneira não passou a
	// carimbar tudo.
	if err := os.WriteFile(filepath.Join(dir, "limpo.php"),
		[]byte("<?php echo 'oi';\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	e := env.Probe(env.Options{Root: dir})
	defer e.Close()

	varrer := func() []string {
		f := &Facts{}
		var st varreduraCodigo
		varrerCodigo(f, e, "/", 0, &st, map[string]bool{}, map[string]bool{})
		if len(st.fila) != n+1 {
			t.Fatalf("a caminhada selecionou %d arquivos, esperava %d", len(st.fila), n+1)
		}
		analisarFila(f, e, &st)
		var paths []string
		for _, c := range f.CodigoSuspeito {
			paths = append(paths, c.Path)
		}
		return paths
	}

	primeira := varrer()
	if len(primeira) != n {
		t.Fatalf("achou %d arquivos suspeitos, esperava %d — o webshell de duas "+
			"linhas é a forma mais copiada que existe", len(primeira), n)
	}

	// Determinismo: dez voltas precisam dar exatamente a mesma sequência.
	for volta := 0; volta < 10; volta++ {
		outra := varrer()
		if len(outra) != len(primeira) {
			t.Fatalf("volta %d: %d achados, a primeira teve %d",
				volta, len(outra), len(primeira))
		}
		for i := range outra {
			if outra[i] != primeira[i] {
				t.Fatalf("volta %d: a ORDEM dos achados mudou na posição %d "+
					"(%q vs %q) — o paralelismo vazou para o resultado",
					volta, i, outra[i], primeira[i])
			}
		}
	}
}

// A separação entre SELECIONAR e ANALISAR não pode mudar quem é selecionado: os
// tetos continuam sendo gastos na caminhada, serial e em ordem de BFS.
func TestOsTetosContinuamSendoGastosNaCaminhadaSerial(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 5; i++ {
		if err := os.WriteFile(filepath.Join(dir, "a"+strconv.Itoa(i)+".php"),
			[]byte("<?php echo 1;\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Extensão que a peneira não conhece: não pode entrar na fila.
	if err := os.WriteFile(filepath.Join(dir, "imagem.jpg"),
		[]byte("\xff\xd8\xff"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Árvore podada por NOME: não pode entrar nem ser descida.
	nm := filepath.Join(dir, "node_modules")
	if err := os.MkdirAll(nm, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nm, "dep.php"),
		[]byte("<?php system($_GET['c']);\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	e := env.Probe(env.Options{Root: dir})
	defer e.Close()

	f := &Facts{}
	var st varreduraCodigo
	varrerCodigo(f, e, "/", 0, &st, map[string]bool{}, map[string]bool{})

	if len(st.fila) != 5 {
		t.Errorf("a fila tem %d arquivos, esperava os 5 .php da raiz: o .jpg e a "+
			"árvore podada não podem entrar", len(st.fila))
	}
	for _, a := range st.fila {
		if filepath.Ext(a.path) != ".php" {
			t.Errorf("entrou na fila um arquivo que a peneira de extensão devia "+
				"ter barrado: %q", a.path)
		}
	}
}
