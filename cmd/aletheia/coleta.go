package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/dump"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
	"github.com/lex0c/aletheia/internal/ioc"
	"github.com/lex0c/aletheia/internal/progress"
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
		root   = fs.String("root", "", "coletar de imagem montada em PATH")
		out    = fs.String("out", "", "arquivo do dump ('-' = stdout) — obrigatório")
		noProg = fs.Bool("no-progress", false, "não mostrar o progresso da coleta")
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

	aoInterromper()
	prog := progress.New(os.Stderr, time.Now(), *noProg)
	e.Progress = prog
	defer prog.Stop()
	coletaInicio := time.Now()
	f := facts.Collect(e)
	coletaFim := time.Now()
	prog.Stop() // a linha some antes de o dump começar a sair
	relatarTempoDeColeta(e, f, coletaInicio, coletaFim)
	d := dump.De(e, f)

	// O hash é calculado DURANTE a escrita, e não relendo o arquivo depois.
	//
	// Reler introduz uma janela: entre escrever e reler, o host — que é o
	// suspeito — pode ter trocado o conteúdo. É a mesma razão pela qual o
	// `preserve` hasheia em fluxo enquanto copia.
	soma := sha256.New()
	w := io.Writer(io.MultiWriter(os.Stdout, soma))
	if *out != "-" {
		fh, err := openJSONOut(*out)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 3
		}
		defer fh.Close()
		w = io.MultiWriter(fh, soma)
	}
	if err := d.Escrever(w); err != nil {
		fmt.Fprintf(os.Stderr, "collect: erro ao escrever o dump: %v\n", err)
		return 3
	}
	hash := hex.EncodeToString(soma.Sum(nil))

	// O arquivo ao lado existe para o `analyze` conferir sozinho. Ele NÃO
	// autentica nada: quem editar o dump edita o `.sha256` junto. O que ele
	// pega é alteração acidental e corrupção de transporte — e o hash IMPRESSO
	// é o que vale como custódia, porque vai para o war log, para o ticket e
	// para a cabeça de quem coletou, que é fora do alcance do host.
	if *out != "-" {
		if err := os.WriteFile(*out+".sha256", []byte(hash+"  "+
			filepath.Base(*out)+"\n"), 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "collect: o dump foi escrito, mas o arquivo de "+
				"soma não: %v\n", err)
		}
	}

	resumoDaColeta(os.Stderr, e, f, *out, hash)
	return 0
}

// resumoDaColeta é o único texto que o `collect` imprime, e ele existe por uma
// razão: a coleta é feita com pressa, e o que ficou de fora dela fica de fora
// PARA SEMPRE — a máquina pode não existir mais quando alguém for analisar.
//
// Dizer isso depois de escrever o arquivo é tarde demais para aquele dump, mas é
// cedo o bastante para o operador rodar de novo com sudo.
func resumoDaColeta(w io.Writer, e *env.Env, f *facts.Facts, arquivo, hash string) {
	fmt.Fprintf(w, "coletado %s · %s · modo %s · %d processo(s), %d socket(s), %d unit(s)\n",
		report.Safe(ouEntao(f.Host.Hostname, "host-desconhecido")),
		e.Now.Format("2006-01-02T15:04:05Z"), e.Source,
		len(f.Processes), len(f.Sockets), len(f.Units))
	fmt.Fprintf(w, "dump em %s\n", report.Safe(arquivo))
	// ANOTE ESTE NÚMERO FORA DO HOST. É o que separa "este é o dump que eu
	// coletei" de "este é um arquivo que apareceu com esse nome" — e a única
	// cópia dele que o alvo não alcança é a que sai daqui para o seu caderno.
	fmt.Fprintf(w, "sha256 %s   ← anote no war log (runbook §39.3)\n", hash)

	faltando := env.Cap(0)
	for _, n := range env.TodasAsCaps() {
		c, _ := env.CapDeNome(n)
		if !e.Has(c) {
			faltando |= c
		}
	}
	// Capacidade ausente e lacuna de COLETOR são dois buracos diferentes: o
	// primeiro é "não me deixaram olhar", o segundo é "olhei e parei antes"
	// (varredura de SUID truncada, prazo, teto de código). Só declarar
	// "ambiente completo" quando NENHUM dos dois existe — senão o resumo diz
	// "completo" com a varredura truncada por baixo, que é a confusão entre
	// "não achei" e "não terminei de olhar" cometida no próprio resumo.
	temGapDeColetor := len(f.Partial) > 0 || len(f.PersistDenied) > 0
	if faltando == 0 && !temGapDeColetor {
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
	// OS DOIS mapas de lacuna, e o resumo precisa dos dois. `f.Partial` guarda
	// "não pude olhar" (proc, cross); `f.PersistDenied` guarda "olhei e parei
	// antes" (varredura de SUID truncada, código, teto de log). No scan os
	// checks repassam o PersistDenied para a cobertura; o `collect` NÃO roda
	// check, então se o resumo lê só o primeiro, a truncagem some — a mesma
	// confusão entre "não achei" e "não terminei", desta vez no resumo.
	// Ordem fixa: mapa embaralha, e duas execuções idênticas têm de imprimir
	// igual.
	imprimirGaps := func(m map[string][]string) {
		coletores := make([]string, 0, len(m))
		for c := range m {
			coletores = append(coletores, c)
		}
		sort.Strings(coletores)
		for _, coletor := range coletores {
			for _, msg := range m[coletor] {
				linha(coletor, msg)
			}
		}
	}
	imprimirGaps(f.Partial)
	imprimirGaps(f.PersistDenied)
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
	conferirSoma(os.Stderr, fs.Arg(0))

	// O ambiente LOCAL serve para duas coisas e nenhuma delas é cobertura:
	// levar a lista de indicadores desta execução, e dizer quem está analisando.
	local := env.Probe(env.Options{Version: version, IOC: lista})
	defer local.Close()
	e, err := d.Env(local)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 3
	}
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

// conferirSoma confere o dump contra o arquivo de soma escrito pelo `collect`.
//
// O que isto NÃO é: autenticação. Quem edita o dump edita o `.sha256` ao lado,
// e nenhum dos dois carrega chave nenhuma. O que ele pega é alteração acidental
// e corrupção de transporte — que num dump que atravessou scp, pendrive e três
// máquinas não é hipótese remota.
//
// A custódia de verdade é o número IMPRESSO na coleta: a cópia dele que vale é
// a que foi para o war log, e essa o alvo não alcança. Por isso a divergência
// aqui não interrompe a análise: ela informa em voz alta e deixa a decisão com
// quem tem o caderno.
func conferirSoma(w io.Writer, caminho string) {
	if caminho == "-" {
		return
	}
	esperado, err := os.ReadFile(caminho + ".sha256")
	if err != nil {
		return // sem arquivo de soma: dump de outra versão, ou de stdout
	}
	campos := strings.Fields(string(esperado))
	if len(campos) == 0 {
		return
	}
	fh, err := os.Open(caminho)
	if err != nil {
		return
	}
	defer fh.Close()
	h := sha256.New()
	if _, err := io.Copy(h, fh); err != nil {
		return
	}
	obtido := hex.EncodeToString(h.Sum(nil))
	if obtido == campos[0] {
		fmt.Fprintf(w, "dump confere com %s\n", report.Safe(filepath.Base(caminho)+".sha256"))
		return
	}
	fmt.Fprintf(w, "\n⚠ O DUMP NÃO CONFERE COM A SOMA ESCRITA NA COLETA\n")
	fmt.Fprintf(w, "  esperado %s\n  obtido   %s\n", report.Safe(campos[0]), obtido)
	fmt.Fprintln(w, "  o arquivo mudou depois de coletado. Compare com o número que foi")
	fmt.Fprintln(w, "  para o war log: se ele bater com o ESPERADO, o dump foi alterado;")
	fmt.Fprintln(w, "  se não bater com nenhum dos dois, os dois foram.")
	fmt.Fprintln(w, "  A análise continua — mas o que sair dela descreve outro arquivo.")
	fmt.Fprintln(w)
}
