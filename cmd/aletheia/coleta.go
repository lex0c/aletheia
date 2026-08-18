package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/dump"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
	"github.com/lex0c/aletheia/internal/ioc"
	"github.com/lex0c/aletheia/internal/report"
)

// runCollect tira o retrato e vai embora.
//
// O `scan` faz as duas coisas — coleta e conclui — e por isso passa segundos no
// alvo com os checks do dia. Separar as duas resolve três coisas de uma vez:
// menos tempo no host comprometido, análise do lado limpo, e o mesmo artefato
// vira fixture (SPEC 5.3, 11.1).
//
// O que ele NÃO faz: concluir. Aqui não há veredito, não há achado e não há exit
// code de severidade — sair 0 significa que o arquivo foi escrito, e nada mais.
func runCollect(args []string) int {
	fs := flag.NewFlagSet("collect", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var (
		root = fs.String("root", "", "coletar de imagem montada em PATH")
		out  = fs.String("out", "", "arquivo do dump ('-' = stdout) — obrigatório")
	)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	if err := fs.Parse(args); err != nil {
		return 3
	}
	if *out == "" {
		fmt.Fprintln(os.Stderr, "collect: --out é obrigatório — este comando "+
			"existe para produzir um arquivo, e não escolhe onde")
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
	d := dump.De(e, f)

	w := io.Writer(os.Stdout)
	if *out != "-" {
		fh, err := openJSONOut(*out)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 3
		}
		defer fh.Close()
		w = fh
	}
	if err := d.Escrever(w); err != nil {
		fmt.Fprintf(os.Stderr, "collect: erro ao escrever o dump: %v\n", err)
		return 3
	}

	resumoDaColeta(os.Stderr, e, f, *out)
	return 0
}

// resumoDaColeta é o único texto que o `collect` imprime, e ele existe por uma
// razão: a coleta é feita com pressa, e o que ficou de fora dela fica de fora
// PARA SEMPRE — a máquina pode não existir mais quando alguém for analisar.
//
// Dizer isso depois de escrever o arquivo é tarde demais para aquele dump, mas é
// cedo o bastante para o operador rodar de novo com sudo.
func resumoDaColeta(w io.Writer, e *env.Env, f *facts.Facts, arquivo string) {
	fmt.Fprintf(w, "coletado %s · %s · modo %s · %d processo(s), %d socket(s), %d unit(s)\n",
		report.Safe(ouEntao(f.Host.Hostname, "host-desconhecido")),
		e.Now.Format("2006-01-02T15:04:05Z"), e.Source,
		len(f.Processes), len(f.Sockets), len(f.Units))
	fmt.Fprintf(w, "dump em %s\n", report.Safe(arquivo))

	faltando := env.Cap(0)
	for _, n := range env.TodasAsCaps() {
		c, _ := env.CapDeNome(n)
		if !e.Has(c) {
			faltando |= c
		}
	}
	if faltando == 0 {
		fmt.Fprintln(w, "ambiente completo: a análise deste dump não terá lacuna de capacidade")
		return
	}
	fmt.Fprintf(w, "\nO QUE ESTA COLETA NÃO VIU — e nenhuma análise vai recuperar depois:\n")
	// O mesmo motivo chega por dois caminhos: a capacidade que o probe negou e
	// o coletor que desistiu por causa dela. Repeti-lo dá ao operador a
	// impressão de dois buracos onde há um, e a lista existe para ele decidir
	// se vale recoletar.
	dito := map[string]bool{}
	linha := func(quem, motivo string) {
		if dito[motivo] {
			return
		}
		dito[motivo] = true
		fmt.Fprintf(w, "  %-11s %s\n", quem, report.Safe(motivo))
	}
	for _, n := range faltando.Names() {
		c, _ := env.CapDeNome(n)
		linha(n, e.Reason(c))
	}
	// Ordem fixa: `f.Partial` é mapa, e sem ordenar as chaves duas execuções
	// idênticas imprimem a mesma lista embaralhada.
	coletores := make([]string, 0, len(f.Partial))
	for c := range f.Partial {
		coletores = append(coletores, c)
	}
	sort.Strings(coletores)
	for _, coletor := range coletores {
		for _, m := range f.Partial[coletor] {
			linha(coletor, m)
		}
	}
	fmt.Fprintln(w, "\nse der para recoletar com mais privilégio, recolete: o retrato é único")
}

// runAnalyze responde a mesma pergunta do scan, sobre um retrato.
//
// A propriedade que decide tudo aqui é a de dump.Env: as capacidades vêm do
// ARQUIVO, nunca da máquina onde a análise roda. Sondar o ambiente local seria
// declarar cobertura sobre um host que ninguém olhou — e como o efeito é
// silencioso (números maiores, veredito melhor), ninguém revisaria.
func runAnalyze(args []string) int {
	fs := flag.NewFlagSet("analyze", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var (
		only     = fs.String("only", "", "grupos, separados por vírgula")
		mode     = fs.String("mode", "", "auto | manual")
		jsonOut  = fs.String("json", "", "escrever JSONL em FILE ('-' = stdout)")
		verbose  = fs.Bool("v", false, "evidência por achado")
		verbose2 = fs.Bool("vv", false, "+ INFO e detalhe de cobertura")
		base     = fs.String("baseline", "", "comparar com a baseline em FILE")
		iocFile  = fs.String("ioc", "", "casar os indicadores DESTE incidente, do arquivo FILE")
		since    = fs.String("since", "", "janela de investigação, ancorada na COLETA")
	)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	if err := fs.Parse(args); err != nil {
		return 3
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "analyze: informe UM dump (o arquivo de `collect --out`, "+
			"ou '-' para a entrada padrão)")
		return 3
	}
	if *mode != "" && *mode != "auto" && *mode != "manual" {
		fmt.Fprintln(os.Stderr, "--mode aceita apenas: auto, manual")
		return 3
	}

	lista, code := carregarIOC(*iocFile)
	if code != 0 {
		return code
	}

	d, err := dump.Carregar(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "analyze: %v\n", err)
		return 3
	}

	// O ambiente LOCAL serve para duas coisas e nenhuma delas é cobertura:
	// levar a lista de indicadores desta execução, e dizer quem está analisando.
	local := env.Probe(env.Options{Version: version, IOC: lista})
	defer local.Close()
	e := d.Env(local)
	f := d.Facts

	// A JANELA É ANCORADA NA COLETA, não no relógio de quem analisa.
	//
	// `--since 72h` sobre um dump de uma semana atrás significa "as 72 horas
	// anteriores ao retrato" — que é a pergunta que faz sentido. Ancorar em
	// agora recortaria tudo, e o relatório sairia vazio dizendo que nada
	// aconteceu na janela.
	agora := e.Now
	if agora.IsZero() {
		agora = time.Now().UTC()
	}
	janela, err := check.ParseJanela(*since, agora)
	if err != nil {
		fmt.Fprintf(os.Stderr, "--since %q: %v\n", *since, err)
		return 3
	}

	sel := check.Selection{Mode: *mode}
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

	declararLacunaDeIOC(f, lista)

	r := check.Run(selected, f, e)
	return emitir(r, f, e, saida{
		baseline: *base,
		janela:   janela,
		ioc:      lista,
		jsonOut:  *jsonOut,
		verbose:  nivel(*verbose, *verbose2),
		analise: &report.AnaliseInfo{
			Arquivo:      fs.Arg(0),
			ColetadoEm:   d.Ambiente.CollectedAt,
			ColetadoPor:  "aletheia/" + ouEntao(d.Ambiente.Tool, "dev"),
			ColetaSHA:    d.Ambiente.ToolSHA,
			AnalisadoPor: "aletheia/" + ouEntao(version, "dev"),
			AnalisadoEm:  local.Now.Format(time.RFC3339),
			Estranhas:    d.Estranhas(),
		},
	})
}

// declararLacunaDeIOC cobre o único indicador que a análise não consegue
// procurar sozinha.
//
// IP, caminho, usuário e string são casados contra fatos que já estão no dump. O
// HASH não: ele é calculado durante a COLETA, e só sobre os arquivos que aquela
// varredura considerou interessantes — e só quando a coleta já tinha a lista.
//
// Uma lista trazida depois, com hashes, casaria contra nada e sairia sem achado
// nenhum: "não encontrei" onde o certo é "não procurei". Isto entra como lacuna
// de coleta, com o motivo escrito.
func declararLacunaDeIOC(f *facts.Facts, l *ioc.Lista) {
	if l == nil || len(f.HashesIOC) > 0 {
		return
	}
	var hashes int
	for _, it := range l.Itens {
		if it.Tipo == ioc.Hash {
			hashes++
		}
	}
	if hashes == 0 {
		return
	}
	if f.Partial == nil {
		f.Partial = map[string][]string{}
	}
	f.Partial["ioc"] = append(f.Partial["ioc"], fmt.Sprintf(
		"%d hash(es) da lista NÃO foram procurados: hash se calcula durante a "+
			"coleta, e este dump foi feito sem esta lista. Para procurá-los, "+
			"rode `aletheia scan --ioc` no host, ou recolete com a lista", hashes))
}

// saida é o que o `scan` e o `analyze` fazem IGUAL depois que os checks rodam.
//
// Estar num lugar só não é economia de linha: é a garantia de que os dois
// caminhos não divergem. Um passo acrescentado ao scan e esquecido no analyze
// produziria dois relatórios diferentes para os mesmos fatos, e a diferença
// apareceria como conclusão, não como bug.
type saida struct {
	baseline string
	janela   check.Janela
	ioc      *ioc.Lista
	jsonOut  string
	verbose  int
	analise  *report.AnaliseInfo
}

func emitir(r *check.Report, f *facts.Facts, e *env.Env, o saida) int {
	collectorGaps(r, f)

	bl, code := aplicarBaseline(r, f, e, o.baseline)
	if code != 0 {
		return code
	}
	jn := aplicarJanela(r, o.janela)

	humanOut := io.Writer(os.Stdout)
	if o.jsonOut == "-" {
		humanOut = os.Stderr
	}
	report.Human(humanOut, r, f, e, report.Options{
		Verbose: o.verbose, Baseline: bl, IOC: infoIOC(o.ioc),
		Janela: jn, Analise: o.analise,
	})

	if o.jsonOut != "" {
		if code := writeJSONL(o.jsonOut, r, f, e, bl, jn, o.analise); code != 0 {
			return code
		}
	}
	return r.Exit()
}

func nivel(v, vv bool) int {
	switch {
	case vv:
		return 2
	case v:
		return 1
	}
	return 0
}

// ouEntao é o `nz` do report, que não é exportado. Duplicar três linhas é
// melhor que exportar um detalhe de formatação do pacote de relatório.
func ouEntao(s, padrao string) string {
	if s == "" {
		return padrao
	}
	return s
}
