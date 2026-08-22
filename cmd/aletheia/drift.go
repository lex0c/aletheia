package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/drift"
	"github.com/lex0c/aletheia/internal/dump"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
	"github.com/lex0c/aletheia/internal/progress"
	"github.com/lex0c/aletheia/internal/report"
)

// drift: o que MUDOU desde um estado conhecido.
//
// # A pergunta, e por que ela é diferente das outras duas
//
//	scan     há evidência de comprometimento AGORA?
//	watch    quando isto aconteceu, enquanto eu olhava?
//	drift    o que mudou desde um retrato que eu tinha?
//
// As três se completam, e a terceira alcança o que as outras duas não podem: a
// mudança para a qual NÃO EXISTE check a escrever. Um `ExecStart` que passa a
// apontar para outro binário de pacote, uma chave de SSH trocada por outra bem
// formada — as duas pontas são legítimas em forma, e só a transição denuncia.
//
// # Não há artefato novo
//
// O estado anterior é um DUMP, o mesmo do `collect`/`analyze`. Foi decisão, e
// não economia: um formato próprio de baseline traria o próprio schema, a
// própria versão, o próprio teto de leitura e a própria história de assinatura
// — quatro coisas para manter em sincronia com um artefato que já existe e já
// carrega tudo isso, inclusive o sidecar `.sha256` que o `analyze` confere.
//
// # O que ele NÃO faz
//
// Não guarda estado no host. Quem aponta para o retrato anterior é quem roda, e
// o retrato que você escolhe É a pergunta que você está fazendo: contra o dump
// de ontem, "o que mudou desde ontem"; contra o da instalação, "quanto este
// host se afastou do que saiu de fábrica". Um gerenciador de golden/previous/
// history responderia as duas piores.
//
// E vale dizer em voz alta, porque é a parte desconfortável: uma referência
// guardada NO host que ela descreve vale o que aquele host vale. Root apaga a
// diferença entre "nada mudou" e "eu reescrevi o que você sabia". Assinar o
// dump ajuda contra adulteração posterior; o que resolve é a referência morar
// fora do host.
func runDrift(args []string) int {
	fs := flag.NewFlagSet("drift", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var (
		root     = fs.String("root", "", "comparar contra uma imagem montada em PATH")
		jsonOut  = fs.String("json", "", "escrever JSONL em FILE ('-' = stdout)")
		only     = fs.String("only", "", "grupos, separados por vírgula")
		verbose  = fs.Bool("v", false, "evidência por achado")
		verbose2 = fs.Bool("vv", false, "evidência + INFO")
		coverage = fs.Bool("coverage", false, "mostrar a seção de cobertura")
		noProg   = fs.Bool("no-progress", false, "não mostrar o progresso da coleta")
		tudo     = fs.Bool("all-checks", false, "rodar TODOS os checks, e não só os de drift")
	)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	// Flag DEPOIS do posicional também vale — ver parseComPosicionais.
	pos, errp := parseComPosicionais(fs, args)
	if errp != nil {
		return 3
	}
	if len(pos) < 1 || len(pos) > 2 {
		fmt.Fprintln(os.Stderr, "uso: aletheia drift ANTES.json [DEPOIS.json]")
		fmt.Fprintln(os.Stderr, "  sem DEPOIS, o estado atual é coletado agora")
		return 3
	}

	jsonFH, err := abrirSaidaJSON(*jsonOut)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 3
	}

	antes, _, code := ladoDeDump(pos[0])
	if code != 0 {
		return code
	}

	var depois drift.Lado
	var f *facts.Facts
	var e *env.Env
	var analise *report.AnaliseInfo

	if len(pos) == 2 {
		// DOIS RETRATOS: nenhum host é tocado, e a análise roda do lado limpo.
		//
		// O dump é lido UMA vez. A versão anterior chamava `ladoDeDump` e
		// `dump.Carregar` sobre o mesmo caminho: dois parses de um artefato cujo
		// teto é 512 MB, e — pior que o custo — duas cópias vivas dos mesmos
		// fatos, com a comparação usando uma e os checks a outra. Hoje são
		// equivalentes; era armadilha para quem mexesse depois.
		var d *dump.Dump
		depois, d, code = ladoDeDump(pos[1])
		if code != 0 {
			return code
		}
		local := env.Probe(env.Options{Version: version})
		defer local.Close()
		var err error
		if e, err = d.Env(local); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 3
		}
		f = d.Facts
		analise = &report.AnaliseInfo{
			Arquivo:      pos[1],
			ColetadoEm:   d.Ambiente.CollectedAt,
			ColetadoPor:  "aletheia/" + ouEntao(d.Ambiente.Tool, "dev"),
			ColetaSHA:    d.Ambiente.ToolSHA,
			AnalisadoPor: "aletheia/" + ouEntao(version, "dev"),
			AnalisadoEm:  local.Now.Format(time.RFC3339),
			Estranhas:    d.Estranhas(),
		}
	} else {
		// UM RETRATO E O AGORA: coleta igual à do scan. Uma coleta menor aqui
		// descreveria menos do que o retrato anterior descreve, e a diferença
		// sairia como mudança sem nada ter mudado.
		if *root != "" {
			if fi, err := os.Stat(*root); err != nil || !fi.IsDir() {
				fmt.Fprintf(os.Stderr, "--root: %s não é um diretório acessível\n", *root)
				return 3
			}
		}
		e = env.Probe(env.Options{Root: *root, Version: version})
		defer e.Close()
		aoInterromper()
		prog := progress.New(os.Stderr, time.Now(), *noProg, corHabilitada(os.Stderr))
		e.Progress = prog
		f = facts.Collect(e)
		prog.Stop()
		depois = drift.Lado{
			F: f, Caps: e.Caps, Host: f.Host.Hostname,
			Quando: e.Now.UTC().Format(time.RFC3339),
		}
	}

	if code := ordemDosRetratos(antes, depois); code != 0 {
		return code
	}

	dr := drift.Comparar(antes, depois)
	f.DriftDados = &dr

	sel := check.Selection{Drift: !*tudo}
	if *only != "" {
		sel.Groups = strings.Split(*only, ",")
		if unknown := check.UnknownGroups(sel.Groups); len(unknown) > 0 {
			fmt.Fprintf(os.Stderr, "grupo inexistente em --only: %s\n", strings.Join(unknown, ", "))
			return 3
		}
	}
	selected := check.Select(sel)
	if len(selected) == 0 {
		fmt.Fprintln(os.Stderr, "nenhum check corresponde à seleção")
		return 3
	}

	r := check.Run(selected, f, e)
	return emitir(r, f, e, saida{
		jsonOut: *jsonOut,
		jsonFH:  jsonFH,
		verbose: nivel(*verbose, *verbose2),
		// A cobertura DESTA execução é a da comparação, e ela é o que separa
		// "nada mudou" de "nada foi comparado".
		coverage: *coverage,
		analise:  analise,
	})
}

// ladoDeDump lê um retrato e leva junto as CONDIÇÕES em que ele foi tirado.
//
// Os caps viajam porque a comparação depende deles: sem saber o que cada ponta
// pôde enxergar, "sumiu" não distingue o que saiu do host do que ninguém
// olhou — e essa é a diferença que a ferramenta inteira existe para não perder.
func ladoDeDump(caminho string) (drift.Lado, *dump.Dump, int) {
	d, err := dump.Carregar(caminho)
	if err != nil {
		fmt.Fprintf(os.Stderr, "drift: %s: %v\n", caminho, err)
		return drift.Lado{}, nil, 3
	}
	conferirSoma(os.Stderr, caminho)
	caps, desconhecidas := env.CapsDeNomes(d.Ambiente.Caps)
	if len(desconhecidas) > 0 {
		// Capacidade que esta versão não conhece: o dump é de uma versão MAIS
		// NOVA. Dizer em voz alta, porque a comparação vai tratar aquela
		// família como não coletada.
		fmt.Fprintf(os.Stderr, "drift: %s declara capacidade(s) que esta versão não "+
			"conhece (%s): a comparação as trata como ausentes\n",
			caminho, strings.Join(desconhecidas, ", "))
	}
	host := ""
	if d.Facts != nil {
		host = d.Facts.Host.Hostname
	}
	return drift.Lado{
		F: d.Facts, Caps: caps, Host: host, Quando: d.Ambiente.CollectedAt,
	}, d, 0
}

// ordemDosRetratos recusa a comparação invertida.
//
// `aletheia drift NOVO.json VELHO.json` não era recusado, e o resultado era um
// relatório coerente e AO CONTRÁRIO: o que foi removido saía como "apareceu", e
// o intervalo era impresso com confiança total —
//
//	mudou ENTRE 2026-08-21T20:55:50Z e 2026-08-21T20:55:37Z
//
// Trocar a ordem de dois caminhos parecidos é o erro mais fácil de cometer
// nesta CLI, e o único jeito de perceber era ler os carimbos de hora na
// evidência.
//
// A recusa vale para o MESMO host, onde o relógio é um só e a ordem é
// confiável. Entre hosts diferentes o desencontro pode ser deriva de relógio, e
// aí a resposta é dizer em voz alta em vez de recusar: recusar comparação
// legítima é tão ruim quanto aceitar comparação invertida.
func ordemDosRetratos(antes, depois drift.Lado) int {
	ta, erra := time.Parse(time.RFC3339, antes.Quando)
	td, errd := time.Parse(time.RFC3339, depois.Quando)
	if erra != nil || errd != nil || !ta.After(td) {
		return 0
	}
	if antes.Host != "" && antes.Host == depois.Host {
		fmt.Fprintf(os.Stderr, "drift: o primeiro retrato é MAIS NOVO que o segundo "+
			"(%s > %s), no mesmo host.\n", antes.Quando, depois.Quando)
		fmt.Fprintln(os.Stderr, "       ANTES vem primeiro: com a ordem trocada, o que "+
			"foi REMOVIDO sai como \"apareceu\" e o intervalo sai negativo.")
		fmt.Fprintln(os.Stderr, "       inverta os dois argumentos.")
		return 3
	}
	fmt.Fprintf(os.Stderr, "drift: o primeiro retrato é mais novo que o segundo "+
		"(%s > %s), mas são hosts diferentes (%s, %s): pode ser deriva de relógio, "+
		"pode ser ordem trocada — a comparação segue, e o intervalo sai como está\n",
		antes.Quando, depois.Quando, nz(antes.Host, "?"), nz(depois.Host, "?"))
	return 0
}

// aplicarDrift é o `--drift` do scan e do analyze: carrega o retrato anterior,
// compara com o estado desta execução e deixa o resultado nos fatos.
//
// Existe num lugar só pela mesma razão que o `emitir` existe: um passo
// acrescentado num caminho e esquecido no outro produziria dois relatórios
// diferentes para os mesmos fatos, e a diferença apareceria como conclusão.
//
// Devolve código != 0 quando a comparação não deve acontecer — e a recusa é
// ANTES dos checks, porque um drift invertido é pior que drift nenhum.
func aplicarDrift(caminho string, f *facts.Facts, caps env.Cap, quando string) int {
	if caminho == "" {
		return 0
	}
	antes, _, code := ladoDeDump(caminho)
	if code != 0 {
		return code
	}
	host := ""
	if f != nil {
		host = f.Host.Hostname
	}
	depois := drift.Lado{F: f, Caps: caps, Host: host, Quando: quando}
	if code := ordemDosRetratos(antes, depois); code != 0 {
		return code
	}
	d := drift.Comparar(antes, depois)
	f.DriftDados = &d
	return 0
}
