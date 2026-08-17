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
	"strconv"
	"strings"
	"time"

	"github.com/lex0c/aletheia/internal/baseline"
	"github.com/lex0c/aletheia/internal/check"
	_ "github.com/lex0c/aletheia/internal/checks" // registra os checks
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
	"github.com/lex0c/aletheia/internal/ioc"
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
  watch         varre em ciclo e reporta só o que MUDAR: o eixo do tempo
  baseline      captura o estado atual como referência para comparar depois
  checks        catálogo: id, §ref, modo, grupo, requires, falsos positivos
  version       versão e hash deste binário

FLAGS DE scan E wtf
  --root PATH   analisar uma imagem montada read-only em vez do host vivo.
                Ali o kernel é o SEU: ocultamento de arquivo não acontece (§35.6)
  --json FILE   JSONL; "-" = stdout. NUNCA afetado pela verbosidade
  --baseline F  compara com a baseline em F: o que já estava lá desce um nível
                de severidade e CONTINUA no relatório, com a data

FLAGS DE scan
  --ioc FILE    casa os indicadores DESTE incidente contra o que foi coletado
                (§23). Aceita "ips: [a, b]", bloco com "- item", ou um indicador
                por linha; o tipo é deduzido pela forma quando não vem dito.
                Achado por indicador é CRÍTICO — e vale o que a lista valer
  --since S     janela de investigação (§9): instante (2026-04-30T18:00Z,
                2026-04-30) ou duração (72h, 7d). O que tem data e cai FORA sai
                do relatório e é CONTADO; o que não tem data FICA
  --only G,G    escopo por subsistema: proc net persist priv integrity kernel app cloud ioc
  --mode M      auto | manual
  -v, -vv       evidência por achado / + INFO e detalhe de cobertura

FLAGS DE watch
  --interval D  entre AMOSTRAS de /proc e sockets (padrão 5s). Barato: é o que
                pega beacon curto e processo efêmero
  --full D      entre VARREDURAS completas dos 70 checks (padrão 60s)
  --for D       duração total (padrão: até Ctrl-C)
  --only G,G    igual ao scan
  --baseline F  o que a baseline já conhece não conta como novidade

  O exit code vem da PIOR severidade vista em QUALQUER ciclo, não do último:
  um implante que rodou às 03:00 e saiu não está no ciclo final.

  Amostragem por polling PERDE o que dura menos que o intervalo, e o resumo diz
  isso. Detecção contínua de verdade se instala ANTES do incidente, com eBPF.

FLAGS DE baseline
  --root PATH   capturar de imagem montada em vez do host vivo
  -o FILE       arquivo de saída ("-" = stdout)

FLAGS DE wtf
  --oneline     UMA linha: veredito + alvos. Para triagem de FROTA por ssh
  --budget D    teto de tempo (padrão 2s). O que estourar vira NÃO VERIFICADO

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
		os.Exit(runWtf(os.Args[2:]))
	case "watch":
		os.Exit(runWatch(os.Args[2:]))
	case "baseline":
		os.Exit(runBaseline(os.Args[2:]))
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

// wtfBudget é o teto rígido da SPEC 6.1. O wtf não pode mentir para ser
// rápido: o check que não couber vira NÃO VERIFICADO e sai no rodapé.
//
// O prazo é cobrado na fronteira dos CHECKS, não no meio da coleta, e isso é
// deliberado: uma lista de processos pela metade quebra correlação — o pivô e o
// reverse shell dependem de cruzar processo com socket, e cruzar com metade dos
// processos produz conclusão errada, não conclusão parcial. Coleta é tudo ou
// nada; o que o operador recebe quando ela demora é o tempo REAL impresso no
// RESULT, não um número inventado.
//
// Sob cota apertada de cgroup a coleta pode passar do teto. É por isso que a
// cota entra no cabeçalho: um `wtf` de 5s num contêiner de meia CPU é o
// ambiente, não a ferramenta.
const wtfBudget = 2 * time.Second

// runWtf responde uma pergunta diferente do scan — este host está pegando
// fogo? Mesma coleta, seleção menor, renderização e orçamento próprios.
func runWtf(args []string) int {
	fs := flag.NewFlagSet("wtf", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var (
		root    = fs.String("root", "", "analisar imagem montada em PATH")
		oneline = fs.Bool("oneline", false, "uma linha por host, para triagem de frota")
		budget  = fs.Duration("budget", wtfBudget, "teto de tempo")
		jsonOut = fs.String("json", "", "escrever JSONL em FILE ('-' = stdout)")
		base    = fs.String("baseline", "", "comparar com a baseline em FILE")
	)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	if err := fs.Parse(args); err != nil {
		return 3
	}
	if *root != "" {
		if fi, err := os.Stat(*root); err != nil || !fi.IsDir() {
			fmt.Fprintf(os.Stderr, "--root: %s não é um diretório acessível\n", *root)
			return 3
		}
	}

	// O relógio começa a contar ANTES da coleta: a coleta é a parte cara, e um
	// orçamento que só cobre os checks mediria a parte errada.
	start := time.Now()

	e := env.Probe(env.Options{Root: *root, Version: version})
	defer e.Close()
	// Mesma recusa do scan: --root que não abre é ERRO de invocação, não host
	// suspeito. Sem isto o wtf saía 1 (WARNING) para um caminho digitado
	// errado, e a triagem de frota ordena por exit code.
	if e.Source == env.SourceImage && !e.Has(env.CapFilesystem) {
		fmt.Fprintf(os.Stderr, "não foi possível abrir --root com raiz travada: %v\n", e.RootErr)
		return 3
	}
	f := facts.Collect(e)

	selected := check.Select(check.Selection{Wtf: true})
	if len(selected) == 0 {
		fmt.Fprintln(os.Stderr, "nenhum check cabe no orçamento do wtf")
		return 3
	}
	r := check.RunWith(selected, f, e, check.RunOptions{
		Deadline: start.Add(*budget),
		Budget:   *budget,
	})
	collectorGaps(r, f)

	bl, code := aplicarBaseline(r, f, e, *base)
	if code != 0 {
		return code
	}
	elapsed := time.Since(start)

	out := io.Writer(os.Stdout)
	if *jsonOut == "-" {
		out = os.Stderr
	}
	if *oneline {
		report.Oneline(out, r)
	} else {
		report.Wtf(out, r, f, e, elapsed, len(check.All()), bl)
	}

	if *jsonOut != "" {
		if code := writeJSONL(*jsonOut, r, f, e, bl, nil); code != 0 {
			return code
		}
	}
	return r.Exit()
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
		base     = fs.String("baseline", "", "comparar com a baseline em FILE")
		iocFile  = fs.String("ioc", "", "casar os indicadores DESTE incidente, do arquivo FILE")
		since    = fs.String("since", "", "janela de investigação: instante (2026-04-30T18:00Z) ou duração (72h, 7d)")
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

	// Os dois argumentos que mudam o RESULTADO são validados antes da coleta:
	// falhar depois de gastar a parte cara para recusar um formato é desperdício,
	// e seguir em silêncio com um deles mal entendido é pior.
	lista, code := carregarIOC(*iocFile)
	if code != 0 {
		return code
	}
	janela, err := check.ParseJanela(*since, time.Now().UTC())
	if err != nil {
		fmt.Fprintf(os.Stderr, "--since %q: %v\n", *since, err)
		return 3
	}

	e := env.Probe(env.Options{Root: *root, Version: version, IOC: lista})
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

	collectorGaps(r, f)

	bl, code := aplicarBaseline(r, f, e, *base)
	if code != 0 {
		return code
	}

	// A janela é aplicada DEPOIS da baseline: ela conta por severidade o que
	// removeu, e a baseline é quem decide a severidade final.
	jn := aplicarJanela(r, janela)

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
	report.Human(humanOut, r, f, e, report.Options{
		Verbose: v, Baseline: bl, IOC: infoIOC(lista), Janela: jn,
	})

	if *jsonOut != "" {
		if code := writeJSONL(*jsonOut, r, f, e, bl, jn); code != 0 {
			return code
		}
	}

	return r.Exit()
}

// aplicarJanela recorta o relatório e monta o que precisa ser DITO sobre o
// recorte. Nada aqui é silencioso: o que saiu é contado por severidade, o que
// não tinha data é contado à parte, e o âncora declara de onde veio.
func aplicarJanela(r *check.Report, j check.Janela) *report.JanelaInfo {
	rec := r.Aplicar(j)
	anc := r.DerivarAncora(j)
	if !j.Ativa && anc.Quando == "" {
		return nil // sem janela e sem achado datável: não há o que declarar
	}
	info := &report.JanelaInfo{
		Fora: rec.Fora, SemData: rec.SemData, MaisRecente: rec.MaisRecente,
		ForaTexto:    porSeveridade(rec.ForaSev),
		Ancora:       anc.Quando,
		AncoraOrigem: anc.Origem,
		AncoraDe:     anc.De,
	}
	if j.Ativa {
		info.Desde, info.Spec = j.Desde.Format(time.RFC3339), j.Spec
	}
	return info
}

// porSeveridade descreve o que ficou de fora. O número sozinho não serve: três
// achados fora da janela é rotina, e um crítico entre eles é uma frase que o
// operador precisa ler.
func porSeveridade(m map[check.Severity]int) string {
	var partes []string
	for _, s := range []check.Severity{check.SevCritical, check.SevWarn, check.SevManual, check.SevInfo} {
		if m[s] > 0 {
			partes = append(partes, strconv.Itoa(m[s])+" "+s.String())
		}
	}
	return strings.Join(partes, " · ")
}

// carregarIOC lê a lista de indicadores, ou falha alto.
//
// Os três desfechos são diferentes e todos são ditos:
//
//	arquivo não abre   erro: o operador apontou para o lugar errado
//	lista vazia        erro: um arquivo que não produziu indicador nenhum é o
//	                   pior caso — a varredura seguiria limpa e ele leria
//	                   "nada encontrado" achando que procurou
//	linhas estranhas   segue, e o relatório IMPRIME o que não foi entendido
func carregarIOC(caminho string) (*ioc.Lista, int) {
	if caminho == "" {
		return nil, 0
	}
	l, err := ioc.Carregar(caminho)
	if err != nil {
		fmt.Fprintf(os.Stderr, "--ioc: %v\n", err)
		if l != nil {
			for _, a := range l.Avisos {
				fmt.Fprintf(os.Stderr, "  %s\n", a)
			}
			fmt.Fprintln(os.Stderr, "  formatos aceitos: `ips: [a, b]`, bloco com `- item`, "+
				"ou um indicador por linha")
		}
		return nil, 3
	}
	return l, 0
}

func infoIOC(l *ioc.Lista) *report.IOCInfo {
	if l == nil {
		return nil
	}
	return &report.IOCInfo{
		Arquivo: l.Arquivo, Total: len(l.Itens),
		Resumo: l.Resumo(), Avisos: l.Avisos,
	}
}

// aplicarBaseline carrega e aplica a baseline, ou falha alto.
//
// Falhar alto e não seguir sem ela é deliberado: quem pediu `--baseline`
// pediu uma comparação, e uma execução que ignora o arquivo em silêncio
// devolve um relatório com severidades diferentes do esperado sem dizer por
// quê — e é exatamente esse relatório que vai para a automação de frota.
func aplicarBaseline(r *check.Report, f *facts.Facts, e *env.Env, caminho string) (*report.BaselineInfo, int) {
	if caminho == "" {
		return nil, 0
	}
	bl, err := baseline.Carregar(caminho)
	if err != nil {
		fmt.Fprintf(os.Stderr, "--baseline: %v\n", err)
		return nil, 3
	}
	n := bl.Aplicar(r, f)
	return &report.BaselineInfo{
		Host:       bl.Host,
		CapturedAt: bl.CapturedAt,
		Conhecidos: len(bl.Keys),
		Rebaixados: n,
		Ressalvas:  bl.Ressalvas(f.Host.Hostname, e.Now),
	}, 0
}

// runBaseline captura o estado deste host como referência para comparações
// futuras.
//
// Roda a MESMA coleta e o MESMO conjunto de checks de um scan: uma baseline
// montada com seleção menor descreveria menos do que o scan vai perguntar
// depois, e a diferença apareceria como novidade sem ter nascido.
func runBaseline(args []string) int {
	fs := flag.NewFlagSet("baseline", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var (
		root = fs.String("root", "", "capturar de imagem montada em PATH")
		out  = fs.String("o", "-", "arquivo de saída ('-' = stdout)")
	)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	if err := fs.Parse(args); err != nil {
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
	f := facts.Collect(e)

	selected := check.Select(check.Selection{})
	r := check.Run(selected, f, e)
	collectorGaps(r, f)

	bl := baseline.Capturar(r, f, f.Host.Hostname, version, e.Now)

	w := io.Writer(os.Stdout)
	if *out != "-" {
		fh, err := os.Create(*out)
		if err != nil {
			fmt.Fprintf(os.Stderr, "baseline: %v\n", err)
			return 3
		}
		defer fh.Close()
		w = fh
	}
	if err := bl.Escrever(w); err != nil {
		fmt.Fprintf(os.Stderr, "baseline: %v\n", err)
		return 3
	}

	// A captura DIZ o que viu. Uma baseline montada em execução degradada
	// descreve menos do que parece, e quem a usar depois merece saber disso
	// antes, não quando o relatório vier cheio de novidade.
	fmt.Fprintf(os.Stderr, "baseline: %d achados conhecidos · cobertura %s%s\n",
		len(bl.Keys), bl.CoberturaTxt, seNao(bl.Completa, " — INCOMPLETA"))
	return 0
}

func seNao(ok bool, texto string) string {
	if ok {
		return ""
	}
	return texto
}

// collectorGaps move a falha de COLETA para o eixo próprio dela: não é um check
// que deixou de rodar, é dado que não pôde ser lido. Sai da aritmética de
// checks e continua impedindo um veredito de OK.
func collectorGaps(r *check.Report, f *facts.Facts) {
	for collector, reasons := range f.Partial {
		for _, reason := range reasons {
			r.Coverage.CollectorGaps = append(r.Coverage.CollectorGaps, collector+": "+reason)
		}
	}
}

func writeJSONL(path string, r *check.Report, f *facts.Facts, e *env.Env, bl *report.BaselineInfo, jn *report.JanelaInfo) int {
	w := os.Stdout
	if path != "-" {
		fh, err := openJSONOut(path)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 3
		}
		defer fh.Close()
		w = fh
	}
	if err := report.JSONL(w, r, f, e, bl, jn); err != nil {
		fmt.Fprintf(os.Stderr, "erro ao escrever JSONL: %v\n", err)
		return 3
	}
	return 0
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
