package checks

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

// A pureza dos checks deixou de ser estilo e virou PREMISSA.
//
// Enquanto a ferramenta só rodava ao vivo, um check que abrisse um arquivo por
// conta própria seria feio e funcionaria. Com o `analyze`, ele passa a ler o
// disco de QUEM ANALISA e a atribuir o resultado ao host que foi coletado — um
// achado sobre a estação do respondedor sairia com o hostname do servidor
// comprometido, e nada na saída denunciaria a troca.
//
// O mesmo vale para syscall: perguntar ao kernel local sobre um retrato tirado
// em outra máquina, meses antes, é a mesma mentira por outro caminho.
//
// Por isso a regra é verificada, e não combinada: todo fato entra por
// `*facts.Facts`, e toda capacidade entra por `*env.Env`.
func TestChecksNaoTocamNoHost(t *testing.T) {
	// A lista é de PACOTES que falam com o mundo. `path/filepath`, `strings`,
	// `sort` e afins manipulam texto e continuam liberados — é o que um check
	// faz o dia inteiro.
	proibidos := map[string]string{
		"os":         "abrir arquivo aqui lê o disco de quem ANALISA, e atribui ao host coletado",
		"os/exec":    "a ferramenta não executa nada do host (§4): o binário do alvo pode ser o implante",
		"os/user":    "resolver usuário consulta o NSS local — o do analista, não o do alvo",
		"syscall":    "perguntar ao kernel local sobre um retrato de outra máquina",
		"net":        "sem rede e sem DNS: consulta avisa o atacante (runbook §2.1)",
		"io/ioutil":  "mesmo caso do os",
		"os/signal":  "check não tem ciclo de vida próprio",
		"math/rand":  "check é função determinística sobre os fatos: duas execuções sobre o mesmo dump precisam concluir igual",
		"crypto/tls": "sem rede",
		"net/http":   "sem rede",
	}

	// As funções do kbpf que emitem bpf(2). O pacote é importado de propósito
	// pelos checks — mas só pelas tabelas e pela classificação, que são texto.
	sondasDoKernel := []string{
		"kbpf.Sonda", "kbpf.Programas", "kbpf.Links", "kbpf.ProgsPorTailCall",
		"kbpf.ObjetoDoPin", "kbpf.IDsDePrograma", "kbpf.Existe",
		"kbpf.ProgramaPorID", "kbpf.BytecodeDePrograma",
	}

	fset := token.NewFileSet()
	ents, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var vistos int
	for _, ent := range ents {
		nome := ent.Name()
		if !strings.HasSuffix(nome, ".go") || strings.HasSuffix(nome, "_test.go") {
			continue
		}
		vistos++
		arq, err := parser.ParseFile(fset, nome, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("%s: %v", nome, err)
		}
		for _, imp := range arq.Imports {
			caminho, _ := strconv.Unquote(imp.Path.Value)
			if porque, proibido := proibidos[caminho]; proibido {
				t.Errorf("%s importa %q: %s", nome, caminho, porque)
			}
		}

		// O corpo, para as sondas de kernel: o import de kbpf é legítimo.
		corpo, err := parser.ParseFile(fset, nome, nil, 0)
		if err != nil {
			t.Fatalf("%s: %v", nome, err)
		}
		ast.Inspect(corpo, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			chamada := pkg.Name + "." + sel.Sel.Name
			for _, s := range sondasDoKernel {
				if chamada == s {
					t.Errorf("%s chama %s: isso pergunta ao kernel LOCAL. "+
						"O que a coleta enumerou está em facts.BPF", nome, chamada)
				}
			}
			return true
		})
	}
	if vistos < 10 {
		t.Fatalf("só %d arquivos varridos — o teste está olhando o diretório errado", vistos)
	}
}
