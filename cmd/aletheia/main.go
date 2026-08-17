// Command aletheia — triagem de resposta a incidente em Linux.
//
// alḗtheia (ἀλήθεια): des-ocultamento. A propriedade central desta ferramenta
// é distinguir "nada estava escondido" de "eu não consegui ver" — e é por isso
// que cobertura incompleta chega até o exit code.
//
// Sem framework de CLI: para poucos subcomandos, flag da stdlib mais um switch
// bastam, e o texto de --help é documentação da ferramenta, não saída gerada.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/lex0c/aletheia/internal/check"
	_ "github.com/lex0c/aletheia/internal/checks" // registra os checks
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
	"github.com/lex0c/aletheia/internal/report"
)

// version é injetada no build: -ldflags "-X main.version=…". O relatório a
// imprime junto do hash do binário, para o war log saber qual ferramenta
// produziu cada achado (runbook §39.3).
var version = "dev"

// selfMarker: qualquer arquivo que contenha esta string é uma cópia desta
// ferramenta, ou algo que se declara detector. Um scanner que carrega os
// próprios indicadores sinaliza a si mesmo se não tiver isso.
const selfMarker = "aletheia-self-id:detector-not-implant"

const usage = `aletheia ` + `— triagem de resposta a incidente em Linux

USO
  aletheia <comando> [flags]

COMANDOS
  scan          coleta e analisa este host (modo normal)
  wtf           overview em ~1s: este host está pegando fogo?
  checks        catálogo: id, §ref, modo, grupo, requires, falsos positivos
  version       versão e hash deste binário

FLAGS DE scan / wtf
  --root PATH   analisar uma imagem montada read-only em vez do host vivo.
                Ali o kernel é o SEU: ocultamento de arquivo não acontece (§35.6)
  --only G,G    escopo por subsistema: proc net persist priv integrity kernel app cloud
  --mode M      auto | manual
  --json FILE   JSONL; "-" = stdout. NUNCA afetado pela verbosidade
  -v, -vv       evidência por achado / + INFO e detalhe de cobertura

EXIT CODES
  0  OK          zero achados E cobertura completa
  1  WARNING     achado que precisa de olhar humano, OU cobertura incompleta
  2  CRITICAL    indicador de alta confiança
  3  ERROR       argumento ou ambiente inválido

  Exit 0 exige as DUAS condições. Uma execução sem root e sem debugfs não sai
  zero — seria a ferramenta contradizendo o próprio nome.

LIMITES — leia antes de confiar num resultado limpo
  * "RESULT: OK" significa que nenhum indicador COBERTO disparou. Não é prova
    de host limpo: rootkit em kernel mente para todos os checks (runbook §35).
  * Read-only: não mata processo, não apaga arquivo, não altera regra ou serviço.
    Só o subcomando preserve escreve, e apenas em --out.
  * Sem rede e sem DNS: consulta avisa o atacante (runbook §2.1).
  * Este binário vira artefato na sua timeline: é um ELF estático, fora de
    pacote, com ctime de agora. Registre caminho e hash no war log (§39.3).
`

func main() {
	// Um panic não tratado sai com status 2 — que o contrato desta ferramenta
	// define como "CRITICAL: indicador de alta confiança". Um defeito nosso
	// seria lido pela automação de frota como host comprometido.
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr,
				"aletheia falhou: %v\n"+
					"Isto é defeito da FERRAMENTA, não achado sobre o host.\n"+
					"Exit 3 (ERROR) — nada foi concluído sobre este alvo.\n", r)
			os.Exit(3)
		}
	}()

	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(3)
	}

	switch os.Args[1] {
	case "scan":
		os.Exit(runScan(os.Args[2:], false))
	case "wtf", "quick":
		os.Exit(runScan(os.Args[2:], true))
	case "checks":
		os.Exit(runChecks(os.Args[2:]))
	case "version":
		e := env.Probe(env.Options{Version: version})
		fmt.Printf("aletheia %s\n%s\nsha256=%s\n", version, e.ToolPath, e.ToolSHA256)
		return
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "comando desconhecido: %s\n\n", os.Args[1])
		fmt.Fprint(os.Stderr, usage)
		os.Exit(3)
	}
}

func runScan(args []string, wtf bool) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var (
		root     = fs.String("root", "", "analisar imagem montada em PATH")
		only     = fs.String("only", "", "grupos, separados por vírgula")
		mode     = fs.String("mode", "", "auto | manual")
		jsonOut  = fs.String("json", "", "escrever JSONL em FILE ('-' = stdout)")
		verbose  = fs.Bool("v", false, "evidência por achado")
		verbose2 = fs.Bool("vv", false, "+ INFO e detalhe de cobertura")
	)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	if err := fs.Parse(args); err != nil {
		return 3
	}

	if *mode != "" && *mode != "auto" && *mode != "manual" {
		fmt.Fprintln(os.Stderr, "--mode aceita apenas: auto, manual")
		return 3
	}
	if *root != "" {
		if fi, err := os.Stat(*root); err != nil || !fi.IsDir() {
			fmt.Fprintf(os.Stderr, "--root: %s não é um diretório acessível\n", *root)
			return 3
		}
	}

	e := env.Probe(env.Options{Root: *root, Version: version})
	defer e.Close()
	if e.Source == env.SourceImage && !e.Has(env.CapFilesystem) {
		fmt.Fprintf(os.Stderr, "não foi possível abrir --root com raiz travada: %v\n", e.RootErr)
		return 3
	}
	f := facts.Collect(e)

	sel := check.Selection{Mode: *mode, Wtf: wtf}
	if *only != "" {
		sel.Groups = strings.Split(*only, ",")
		// Grupo inexistente encolhe o DENOMINADOR em silêncio, e o denominador
		// É a alegação de cobertura (SPEC 7.9). Sem esta validação,
		// `--only proc,net,kernel` imprimia "3/3 · RESULT: OK" e o operador
		// concluía que rede e kernel foram varridos e estão limpos.
		if unknown := check.UnknownGroups(sel.Groups); len(unknown) > 0 {
			fmt.Fprintf(os.Stderr, "grupo inexistente em --only: %s\n", strings.Join(unknown, ", "))
			fmt.Fprintf(os.Stderr, "grupos com checks registrados: %s\n", strings.Join(check.Groups(), " "))
			return 3
		}
	}
	selected := check.Select(sel)
	if len(selected) == 0 {
		fmt.Fprintln(os.Stderr, "nenhum check corresponde à seleção")
		return 3
	}

	r := check.Run(selected, f, e)

	// Falha de coleta é cobertura degradada num eixo próprio: não é um check
	// que deixou de rodar, é dado que não pôde ser lido. Some da aritmética de
	// checks, mas continua impedindo um veredito de OK.
	for collector, reasons := range f.Partial {
		for _, reason := range reasons {
			r.Coverage.CollectorGaps = append(r.Coverage.CollectorGaps, collector+": "+reason)
		}
	}

	v := 0
	if *verbose {
		v = 1
	}
	if *verbose2 {
		v = 2
	}
	// Com --json -, o JSONL é o produto do stdout e o relatório humano vai para
	// stderr. Misturar os dois no mesmo descritor tornava
	// `scan --json - > out.jsonl` um arquivo inválido — e é assim que a
	// agregação de frota consome a saída.
	humanOut := io.Writer(os.Stdout)
	if *jsonOut == "-" {
		humanOut = os.Stderr
	}
	report.Human(humanOut, r, f, e, report.Options{Verbose: v})

	if *jsonOut != "" {
		w := os.Stdout
		if *jsonOut != "-" {
			fh, err := openJSONOut(*jsonOut)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 3
			}
			defer fh.Close()
			w = fh
		}
		if err := report.JSONL(w, r, f, e); err != nil {
			fmt.Fprintf(os.Stderr, "erro ao escrever JSONL: %v\n", err)
			return 3
		}
	}

	return r.Exit()
}

// openJSONOut abre o destino do JSONL sem NUNCA destruir dado do host.
//
// A regra é por TIPO de arquivo, não por existência. O perigo real é
// `scan --json /var/log/auth.log` — um deslize de completion que zerava aquele
// log antes do primeiro check rodar. Isso vale para arquivo REGULAR. Escrever
// num device, fifo ou socket (/dev/stdout, /dev/console, um pipe nomeado) não
// destrói nada e é uso legítimo: recusar ali só quebra a ferramenta em ambiente
// automatizado, sem proteger coisa alguma.
func openJSONOut(path string) (*os.File, error) {
	if fi, err := os.Stat(path); err == nil {
		if fi.Mode().IsRegular() {
			return nil, fmt.Errorf(
				"%s é um arquivo existente. Esta ferramenta nunca sobrescreve arquivo no\n"+
					"host sob investigação: escolha outro nome, ou use --json - para stdout.", path)
		}
		// device, fifo ou socket: escreve sem criar e sem truncar
		fh, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			return nil, fmt.Errorf("não foi possível escrever %s: %v", path, err)
		}
		return fh, nil
	}
	fh, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("não foi possível criar %s: %v", path, err)
	}
	return fh, nil
}

func runChecks(args []string) int {
	fs := flag.NewFlagSet("checks", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return 3
	}

	all := check.All()
	fmt.Printf("%-28s %-6s %-11s %-10s %-24s %s\n",
		"ID", "§REF", "MODO", "GRUPO", "REQUIRES", "FALSOS POSITIVOS")
	for _, c := range all {
		req := c.Requires.String()
		if req == "" {
			req = "—"
		}
		fp := "—"
		if len(c.FalsePositives) > 0 {
			fp = c.FalsePositives[0]
			if len(fp) > 52 {
				fp = fp[:49] + "…"
			}
		}
		fmt.Printf("%-28s %-6s %-11s %-10s %-24s %s\n",
			c.ID, c.Ref, c.Mode, c.Group, req, fp)
	}
	fmt.Printf("\n%d checks registrados. A coluna de falso positivo é o que o operador\n", len(all))
	fmt.Println("lê ANTES de decidir se vale investigar um achado.")
	return 0
}
