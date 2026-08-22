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
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/lex0c/aletheia/internal/baseline"
	"github.com/lex0c/aletheia/internal/check"
	_ "github.com/lex0c/aletheia/internal/checks" // registra os checks
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
	"github.com/lex0c/aletheia/internal/ioc"
	"github.com/lex0c/aletheia/internal/progress"
	"github.com/lex0c/aletheia/internal/report"
)

// A IDENTIDADE DA BUILD, injetada por -ldflags. O relatório a imprime junto do
// hash do binário, para o war log saber qual ferramenta produziu cada achado
// (runbook §39.3).
//
// commitTime é a data do COMMIT, e não a do build. A diferença é a promessa de
// reprodutibilidade: o toolchain é fixado no go.mod para que dois builds da
// mesma tag produzam o mesmo binário, e carimbar o relógio de quem compilou
// destruiria isso — dois hashes diferentes para o mesmo código, e a conferência
// documentada em "Reconstruir e conferir" passaria a falhar sempre. A data do
// commit responde a mesma pergunta ("de quando é este código?") e é a mesma em
// qualquer máquina que reconstrua.
//
// Vazias em build de desenvolvimento: o `make build` local não passa por git, e
// inventar valor seria pior que declarar ausência.
var (
	version    = "dev"
	commit     = ""
	commitTime = ""
)

// kernelFloor é o piso de RUNTIME deste binário: o kernel mínimo que o toolchain
// Go atual sustenta (Go >= 1.24 exige Linux 3.2). É declarado — não escondido —
// porque a física manda na promessa: num kernel mais antigo o binário NÃO roda,
// e alegar 2.6.32 era herança errada. Um host de RHEL 6 ainda pode ser ANALISADO
// pela imagem (`--root`, do lado limpo); rodar aqui dentro, não. Sobe junto com
// o toolchain — se o mínimo do Go mudar, esta string muda com ele.
const kernelFloor = "Linux 3.2"

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
  drift         o que MUDOU desde um retrato anterior — a mudança para a qual
                não existe check a escrever
  collect       só coleta: tira o retrato do host e sai. Não conclui nada
  analyze       só analisa: roda os checks sobre um retrato, do lado limpo
  preserve      guarda a evidência antes que ela suma — inclusive tráfego
                (--pcap). O ÚNICO que escreve
  info          responde sobre UM alvo: process, net, git, ip, port, file
  mcp           serve um retrato a um agente por MCP, sobre stdio. Concede
                OBSERVAÇÃO, não execução
  checks        catálogo: id, §ref, modo, grupo, requires, falsos positivos
  version       versão e hash deste binário

FLAGS DE scan E wtf
  --root PATH   analisar uma imagem montada read-only em vez do host vivo.
                Ali o kernel é o SEU: ocultamento de arquivo não acontece
  --json FILE   JSONL; "-" = stdout. NUNCA afetado pela verbosidade
  --baseline F  compara com a baseline em F: o que já estava lá desce um nível
                de severidade e CONTINUA no relatório, com a data
  --drift F     compara com o RETRATO em F (um dump do collect): o que MUDOU
                desde ele. Eixo diferente do --baseline — aquele fala do
                ACHADO ("já estava na lista?"), este fala do OBJETO ("a unit
                executa outra coisa agora?"). Um achado velho sobre um objeto
                que mudou ontem sai marcado, e a severidade NÃO sobe: "mudou
                desde ontem" tem a forma de um deploy
  --no-progress cala o batimento da coleta. Ele já só aparece em terminal —
                pipe e 2>arquivo nunca o recebem —, esta flag desliga na mão
  --ignore PATH exclui um caminho da varredura de filesystem (repetível): não
                desce nele nem embaixo dele. Para tirar uma árvore grande e
                irrelevante (--ignore /data/xmls) do custo. A exclusão é
                DECLARADA — um backdoor ali dentro NÃO foi procurado. Vale em
                scan, wtf e collect

FLAGS DE scan
  --ioc FILE    casa os indicadores DESTE incidente contra o que foi coletado
               . Aceita "ips: [a, b]", bloco com "- item", ou um indicador
                por linha; o tipo é deduzido pela forma quando não vem dito.
                Achado por indicador é CRÍTICO — e vale o que a lista valer
  --since S     janela de investigação: instante (2026-04-30T18:00Z,
                2026-04-30) ou duração (72h, 7d). O que tem data e cai FORA sai
                do relatório e é CONTADO; o que não tem data FICA
  --only G,G    escopo por subsistema: proc net persist priv integrity kernel app cloud ioc
  --fs-budget D teto de tempo da varredura de filesystem num FS grande (ex: 10s).
                O que não couber vira lacuna DECLARADA — a cobertura cai, e o
                relatório diz onde parou. 0 = sem teto (padrão)
  --all-fs      varre CÓDIGO na FS montada inteira (a partir de /), não só os web
                roots. Acha webshell em docroot fora da lista (Alias de Apache,
                vhost em /home). Pseudo-FS e montagem de REDE são pulados e
                declarados; contêiner rodando, >2 MB e ofuscado seguem de fora.
                Mais caro — combine com --fs-budget e --ignore
  --mode M      auto | manual
  --coverage    mostrar a seção de cobertura (causas e gaps); o NÚMERO já fica no resumo
  -v, -vv       evidência por achado / + INFO e detalhe de cobertura

FLAGS DE watch
  --interval D  entre AMOSTRAS de /proc e sockets (padrão 5s). Barato: é o que
                pega beacon curto e processo efêmero
  --full D      entre VARREDURAS completas da varredura completa (padrão 60s)
  --for D       duração total (padrão: até Ctrl-C)
  --only G,G    igual ao scan
  --baseline F  o que a baseline já conhece não conta como novidade

  O exit code vem da PIOR severidade vista em QUALQUER ciclo, não do último:
  um implante que rodou às 03:00 e saiu não está no ciclo final.

  Amostragem por polling PERDE o que dura menos que o intervalo, e o resumo diz
  isso. Detecção contínua de verdade se instala ANTES do incidente, com eBPF.

DRIFT — o que mudou desde um estado conhecido
  aletheia drift ANTES.json [DEPOIS.json]

  ANTES é um dump do collect. Sem DEPOIS, o estado atual é coletado agora.
  Só os checks de drift rodam (--all-checks roda todos).

  scan  há evidência de comprometimento AGORA?
  watch quando isto aconteceu, enquanto eu olhava?
  drift o que mudou desde um retrato que eu tinha?

  Ele alcança o que nenhum check alcança: a mudança de uma forma legítima para
  OUTRA forma legítima. ExecStart que passa a apontar para outro binário de
  pacote, chave de SSH trocada por outra bem formada, command= retirado de uma
  chave existente — não há regra a escrever, e o que denuncia é a transição.

  Os DOIS retratos precisam ter sido feitos com o mesmo alcance: comparar um com
  root contra um sem root fabricaria "sumiu" para tudo que só root enxerga. As
  famílias afetadas são declaradas NÃO COMPARADAS, e o silêncio delas deixa de
  valer como resposta.

  A mudança é datada por INTERVALO ("entre t0 e t1"), nunca por instante: a
  ferramenta não estava presente na hora, e fingir precisão no eixo do tempo
  manda quem investiga para a hora errada.

  --root PATH   comparar contra uma imagem montada
  --only G,G    igual ao scan
  --all-checks  roda o catálogo inteiro, e não só os de drift

FLAGS DE baseline
  --root PATH   capturar de imagem montada em vez do host vivo
  -o FILE       arquivo de saída ("-" = stdout)

FLAGS DE wtf
  --oneline     UMA linha: veredito + alvos. Para triagem de FROTA por ssh
  --budget D    teto de tempo (padrão 2s). O que estourar vira NÃO VERIFICADO

INFO — a pergunta que vem ANTES do veredito
  aletheia info process         censo: quem roda o quê, e contra que TETO
  aletheia info process 812     o dossiê de um processo
  aletheia info net             censo de rede: o que expõe, com quem fala, contra que TETO
  aletheia info git [dir]       censo de um repositório: o que ele EXECUTA e o que foi reescrito
  aletheia info ip 198.51.100.241
  aletheia info port 4100
  aletheia info file /usr/sbin/nginx
  --from DUMP   responder sobre um retrato do collect, do lado limpo
  --root PATH   responder sobre uma imagem montada

  Junta o que hoje custa ps, ss, lsof, stat, getcap, lsattr e dpkg -S
  encadeados, e diz o que cada número SIGNIFICA. Não conclui nada: quem conclui
  é o scan, que traz os falsos positivos junto.

  O censo compara as tarefas de cada uid com o RLIMIT_NPROC dele — é o número
  que explica Resource temporarily unavailable em su, fork e execve — e NOMEIA
  a repetição quando ela tem forma conhecida (cron que se sobrepõe, pool).

MCP — a pergunta que a IA faz DE VOLTA
  aletheia mcp --snapshot host.json
  aletheia mcp --snapshot antes.json --snapshot depois.json

  Serve os retratos a um agente pelo Model Context Protocol, em stdio. O ciclo
  que ele fecha é hipótese → adquirir a evidência → correlacionar → pedir a
  próxima aquisição, sem entregar um shell.

  A regra: o servidor concede OBSERVAÇÃO, não EXECUÇÃO. Não existe tool que
  escreva, execute comando, mate processo, resolva nome ou abra conexão. Dado do
  host é entrada ADVERSÁRIA — o argv que o implante escolheu pode conter texto
  endereçado ao modelo —, e por isso ele chega sempre marcado como não confiável,
  nunca no nome nem na descrição de uma tool.

  --snapshot F  o retrato a servir (REPETÍVEL). Tudo que este processo poderá
                abrir é fixado aqui: nenhuma tool aceita caminho de arquivo, ou
                o modelo ganharia leitura arbitrária na estação de quem investiga
  --live        o agente tira o retrato dele, com snapshot.capture. Duas únicas
                tools leem o host; todo o resto responde sobre um RETRATO, que é
                o que impede trinta chamadas de misturar instantes diferentes
  --root PATH   o mesmo, sobre uma imagem montada
  --allow-root  autoriza rodar como root. Sem ela, "sudo aletheia mcp" FALHA: o
                servidor herda o privilégio do processo e nunca o adquire, e
                rodar privilegiado é decisão dita, não acidente de sudo
  --audit-log F grava a trilha de invocações também em F. Ela sempre sai no
                stderr; arquivo só quando pedido, porque preserve continua
                sendo o único comando que escreve por padrão

  Na aquisição, scope=volatile lê /proc e sockets e é ~9x mais barato — e NÃO
  sustenta achado: o motor recusa rodar check sobre coleta parcial, e a resposta
  é zero achados COM o catálogo inteiro declarado não verificado. scope=complete
  é a varredura inteira. Enquanto ela roda, o servidor não responde outra
  chamada: os coletores não são interrompíveis, e isso é dito em vez de fingido.

  Toda resposta em forma de achado carrega o VEREDITO e a COBERTURA, e o schema
  os exige. É a promessa do exit code traduzida para um canal que não tem exit
  code: uma lista de achados vazia com INCOMPLETE significa "não consegui
  olhar", e sem esses dois campos ela chegaria ao modelo como "host limpo".

  --profile full ainda não destrava tool nenhuma (leitura de conteúdo de arquivo
  e environ sem redação são a entrega seguinte), e por isso é RECUSADO: flag de
  segurança sem efeito é pior que flag nenhuma.

FLAGS DE collect E analyze
  collect --out F [--root PATH] [--ignore PATH] [--all-fs]   escreve o dump ("-" = stdout)
  analyze DUMP [--ioc F] [--since S] [--only G,G] [--mode M] [--baseline F]
               [--json F] [-v|-vv]

  Existem para separar o tempo NO HOST do tempo de análise: a coleta é curta, e
  a análise acontece do lado limpo, quantas vezes for preciso, com checks mais
  novos e com a lista de indicadores que só apareceu depois.

  A ANÁLISE HERDA A COBERTURA DA COLETA e não pode melhorá-la. Um dump feito sem
  root continua sem root quando analisado numa estação com root: o que ninguém
  olhou continua não olhado, e o relatório diz isso.

  O --since do analyze é ancorado no instante da COLETA, não no relógio de quem
  analisa: "as 72h anteriores ao retrato" é a pergunta que faz sentido.

  Hash de indicador é a única coisa que o analyze não procura sozinho: hash se
  calcula durante a coleta. Uma lista com hashes sobre um dump que não os
  calculou vira lacuna DECLARADA, não "nada encontrado".

FLAGS DE preserve
  --out DIR     onde escrever. OBRIGATÓRIO: este comando não escolhe o lugar.
                O diretório precisa já existir, e nada nele é sobrescrito
  --pid N       preserva /proc/N/exe — que ainda abre o binário depois de
                apagado, e é a ÚNICA cópia quando ele veio de memfd. Repetível
  --file PATH   preserva um arquivo comum. Repetível
  --bpf ID      preserva o bytecode do programa eBPF: não existe arquivo para
                copiar, e ele some no próximo boot. Repetível
  --mem         dump do que só existe na MEMÓRIA dos --pid: regiões anônimas
                (código injetado) E o código de arquivo APAGADO ainda mapeado
                (dlopen+unlink), que o disco não tem mais. Sem ptrace: não para o
                processo nem seta TracerPid. Arquivo VIVO por trás use --file
  --mem-max S   teto do dump (padrão 512M). O que não couber é DECLARADO
  --json FILE   manifesto em JSONL ("-" = stdout)

  --pcap        captura tráfego para .pcap, sem tcpdump e sem libpcap. Em imagem
                mínima o tcpdump não existe, e instalá-lo mexe na base de
                pacotes — que é a evidência da §24
  --iface NAME  interface da captura. OBRIGATÓRIA: capturar em "qualquer
                interface" mistura enlaces no mesmo arquivo, e um pcap rotulado
                errado é decodificado com confiança total a partir do byte errado
  --host IP     filtro: só este endereço, como origem OU destino. IP, não nome:
                resolver DNS avisa o atacante
  --port N      filtro: só esta porta, em TCP e em UDP
  --proto P     filtro: tcp | udp | icmp
  --all         capturar SEM filtro. Precisa ser pedido: tráfego bruto carrega
                credencial em claro de terceiros, e o arquivo não tem como ser
                redigido depois
  --duration D  duração da captura (padrão 60s)
  --snaplen N   bytes por pacote (0 = pacote inteiro)
  --pcap-max S  teto do arquivo (padrão 256M)

  O filtro roda em ESPAÇO DE USUÁRIO. Um filtro de kernel errado descarta o que
  você pediu e a captura sai legitimamente vazia — ninguém revisa arquivo vazio.
  Aqui o preço é o kernel entregar tudo, e ele é MEDIDO: o contador de descartes
  do próprio kernel entra no manifesto, e captura que perdeu pacote é declarada
  incompleta.

  Se houver eBPF hostil em xdp/tc, a captura MENTE: o pacote é escondido antes
  do socket. O modo promíscuo não é ligado — seria alterar o estado da
  interface, e a §2.6 trata interface promíscua como achado.

  O manifesto traz o hash da ORIGEM e o da CÓPIA. Divergência não é erro de
  cópia: é o artefato tendo mudado durante a leitura — e sai com exit 2.

EXIT CODES
  0  OK          zero achados E cobertura completa
  1  WARNING     achado que precisa de olhar humano, OU cobertura incompleta
  2  CRITICAL    indicador de alta confiança
  3  ERROR       argumento ou ambiente inválido

  Exit 0 exige as DUAS condições. Uma execução sem root e sem debugfs não sai
  zero — seria a ferramenta contradizendo o próprio nome.

  No preserve a escala é a mesma, sobre a coleta: 0 guardou tudo o que foi
  pedido, 1 alguma peça ficou de fora (e está no manifesto), 2 a origem mudou
  durante a cópia, 3 invocação inválida — nada foi escrito.

  O collect não conclui nada: 0 significa que o dump foi escrito, e só. O
  veredito vem do analyze, na escala de sempre.

LIMITES — leia antes de confiar num resultado limpo
  * "RESULT: OK" significa que nenhum indicador COBERTO disparou. Não é prova
    de host limpo: rootkit em kernel mente para todos os checks.
  * Read-only: não mata processo, não apaga arquivo, não altera regra ou serviço.
    Só o subcomando preserve escreve, e apenas em --out.
  * Sem rede e sem DNS: consulta avisa o atacante.
  * Este binário vira artefato na sua timeline: é um ELF estático, fora de
    pacote, com ctime de agora. Registre caminho e hash no war log.
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
	case "drift":
		os.Exit(runDrift(os.Args[2:]))
	case "baseline":
		os.Exit(runBaseline(os.Args[2:]))
	case "preserve":
		os.Exit(runPreserve(os.Args[2:]))
	case "collect":
		os.Exit(runCollect(os.Args[2:]))
	case "analyze":
		os.Exit(runAnalyze(os.Args[2:]))
	case "info":
		os.Exit(runInfo(os.Args[2:]))
	case "checks":
		os.Exit(runChecks(os.Args[2:]))
	case "mcp":
		os.Exit(runMCP(os.Args[2:]))
	case "version":
		e := env.Probe(env.Options{Version: version})
		fmt.Printf("aletheia %s\n%s\nsha256=%s\n", version, e.ToolPath, e.ToolSHA256)
		// Identidade da build só sai quando existe. Linha com "desconhecido"
		// ocuparia espaço para não dizer nada, e a ausência já é a resposta:
		// build local, fora de tag.
		if commit != "" {
			fmt.Printf("commit=%s\n", commit)
		}
		if commitTime != "" {
			fmt.Printf("commit-em=%s\n", commitTime)
		}
		fmt.Printf("kernel mínimo (runtime): %s\n", kernelFloor)
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
// aoInterromper deixa o Ctrl-C dos comandos de UMA tacada — scan, wtf, collect,
// baseline — apagar a linha de progresso e sair na hora com 130 (128+SIGINT).
//
// Sem handler o default do runtime já mata, mas mata no meio do desenho do
// spinner, deixando a linha pendurada. E quando um estágio trava num syscall
// ININTERRUPTÍVEL — o stat de um mount morto —, o processo não morre nem assim:
// o que este handler acrescenta ali é o AVISO impresso de OUTRA thread, dizendo
// que o sinal chegou e que quem prende é o kernel, não a ferramenta. É a
// diferença entre "travou e me ignora" e "travou no mount, e ela sabe".
func aoInterromper() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Fprint(os.Stderr, "\r\033[K\ninterrompido\n")
		os.Exit(130)
	}()
}

// relatarTempoDeColeta diz, no stderr, ONDE o tempo da coleta foi — mas só
// quando ela foi lenta. Num host rápido não aparece; num FS grande responde
// "por que demorou" sem o operador ter de adivinhar, e aponta a saída.
func relatarTempoDeColeta(e *env.Env, f *facts.Facts, inicio, fim time.Time) {
	total := fim.Sub(inicio)
	if total < 3*time.Second {
		return
	}
	var partes []string
	for _, t := range e.Timings(fim) {
		if t.Dur < 100*time.Millisecond {
			continue
		}
		p := t.Nome + " " + t.Dur.Round(time.Millisecond).String()
		if t.Nome == "varredura de filesystem" && f.SuidArquivos > 0 {
			p += fmt.Sprintf(" (%d arq)", f.SuidArquivos)
		}
		partes = append(partes, p)
	}
	fmt.Fprintf(os.Stderr, "\ncoleta %s — %s\n", total.Round(time.Second), strings.Join(partes, " · "))
	if f.SuidArquivos > 200000 {
		fmt.Fprintln(os.Stderr, "  → varredura pesada; `scan --fs-budget 30s` limita no tempo")
	}
}

// listaCaminhos é uma flag REPETÍVEL de caminhos: `--ignore /a --ignore /b`, e
// também aceita vírgula. Existe para o --ignore, que exclui árvores da
// varredura de filesystem.
type listaCaminhos []string

func (l *listaCaminhos) String() string { return strings.Join(*l, ",") }
func (l *listaCaminhos) Set(v string) error {
	*l = append(*l, v)
	return nil
}

// ignoreRecusado recusa `--ignore /`: ignorar a raiz esvaziaria a varredura, e
// aceitar isso em silêncio faria o operador achar que excluiu algo quando na
// verdade desligou tudo. Erro de invocação, não host suspeito.
func ignoreRecusado(ignore listaCaminhos) bool {
	for _, p := range ignore {
		for _, item := range strings.Split(p, ",") {
			if filepath.Clean(strings.TrimSpace(item)) == "/" {
				fmt.Fprintln(os.Stderr, "--ignore /: isso esvaziaria a varredura — recusado")
				return true
			}
		}
	}
	return false
}

func runWtf(args []string) int {
	fs := flag.NewFlagSet("wtf", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var (
		root     = fs.String("root", "", "analisar imagem montada em PATH")
		oneline  = fs.Bool("oneline", false, "uma linha por host, para triagem de frota")
		budget   = fs.Duration("budget", wtfBudget, "teto de tempo")
		jsonOut  = fs.String("json", "", "escrever JSONL em FILE ('-' = stdout)")
		base     = fs.String("baseline", "", "comparar com a baseline em FILE")
		noProg   = fs.Bool("no-progress", false, "não mostrar o progresso da coleta")
		autoload = fs.Bool("allow-kernel-autoload", false, "permitir consulta por netlink que pode AUTOCARREGAR o módulo de diagnóstico (altera o host)")
	)
	var ignore listaCaminhos
	fs.Var(&ignore, "ignore", "excluir caminho da varredura de FS (repetível): --ignore /data/xmls")
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
	if ignoreRecusado(ignore) {
		return 3
	}
	// O destino do --json é aberto AQUI, junto das outras validações e antes da
	// parte cara. Ver abrirSaidaJSON.
	jsonFH, err := abrirSaidaJSON(*jsonOut)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 3
	}

	// O relógio começa a contar ANTES da coleta: a coleta é a parte cara, e um
	// orçamento que só cobre os checks mediria a parte errada.
	start := time.Now()
	aoInterromper()

	e := env.Probe(env.Options{Root: *root, Version: version, PermitirAutoload: *autoload})
	defer e.Close()
	e.Ignorar(ignore)
	// Mesma recusa do scan: --root que não abre é ERRO de invocação, não host
	// suspeito. Sem isto o wtf saía 1 (WARNING) para um caminho digitado
	// errado, e a triagem de frota ordena por exit code.
	if e.Source == env.SourceImage && !e.Has(env.CapFilesystem) {
		fmt.Fprintf(os.Stderr, "não foi possível abrir --root com raiz travada: %v\n", e.RootErr)
		return 3
	}
	// O prazo da varredura de filesystem cabe DENTRO do orçamento do wtf: sem
	// ele a coleta — a parte cara — estourava os ~2s num FS grande, e o
	// "overview em ~1s" virava minutos. Reserva um quarto do orçamento para os
	// outros coletores e os checks, que são baratos sobre fatos já coletados. O
	// que a varredura não terminar no prazo vira lacuna declarada, nunca "nada
	// encontrado". (Faltava: o comentário de Env prometia isto e o código não
	// cumpria — só o scan ligava o WalkDeadline.)
	e.WalkDeadline = start.Add(*budget * 3 / 4)
	prog := progress.New(os.Stderr, start, *noProg, corHabilitada(os.Stderr))
	e.Progress = prog
	defer prog.Stop()
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

	bl, code := aplicarBaseline(r, f, e, *base)
	if code != 0 {
		return code
	}
	elapsed := time.Since(start)

	prog.Stop() // a linha some antes do relatório nascer
	out := io.Writer(os.Stdout)
	if *jsonOut == "-" {
		out = os.Stderr
	}
	if *oneline {
		report.Oneline(out, r)
	} else {
		report.Wtf(out, r, f, e, elapsed, len(check.All()), bl, corHabilitada(out))
	}

	return writeJSONL(jsonFH, r.Exit(), r, f, e, bl, nil, nil)
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
		coverage = fs.Bool("coverage", false, "mostrar a seção de cobertura (causas e gaps)")
		base     = fs.String("baseline", "", "comparar com a baseline em FILE")
		driftDe  = fs.String("drift", "", "comparar com o RETRATO anterior em FILE: o que mudou desde ele")
		iocFile  = fs.String("ioc", "", "casar os indicadores DESTE incidente, do arquivo FILE")
		since    = fs.String("since", "", "janela de investigação: instante (2026-04-30T18:00Z) ou duração (72h, 7d)")
		noProg   = fs.Bool("no-progress", false, "não mostrar o progresso da coleta")
		fsBudget = fs.Duration("fs-budget", 0, "teto de tempo da varredura de filesystem (0 = sem teto)")
		allFS    = fs.Bool("all-fs", false, "varrer código na FS montada INTEIRA (a partir de /), não só os web roots")
		autoload = fs.Bool("allow-kernel-autoload", false, "permitir consulta por netlink que pode AUTOCARREGAR o módulo de diagnóstico (altera o host)")
	)
	var ignore listaCaminhos
	fs.Var(&ignore, "ignore", "excluir caminho da varredura de FS (repetível): --ignore /data/xmls")
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
	if ignoreRecusado(ignore) {
		return 3
	}
	// O --json é o produto consumido por MÁQUINA, e entra na mesma regra: um
	// destino que não abre precisa recusar aqui, não depois de a varredura ter
	// achado dois críticos.
	jsonFH, err := abrirSaidaJSON(*jsonOut)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 3
	}

	e := env.Probe(env.Options{Root: *root, Version: version, IOC: lista, PermitirAutoload: *autoload})
	defer e.Close()
	if e.Source == env.SourceImage && !e.Has(env.CapFilesystem) {
		fmt.Fprintf(os.Stderr, "não foi possível abrir --root com raiz travada: %v\n", e.RootErr)
		return 3
	}
	e.Ignorar(ignore)
	e.CodigoTudo = *allFS
	aoInterromper()
	// Num FS grande, quem tem pressa limita a varredura no tempo; o que ela não
	// terminar vira lacuna declarada, e a cobertura cai — nunca "nada achado".
	if *fsBudget > 0 {
		e.WalkDeadline = time.Now().Add(*fsBudget)
	}
	prog := progress.New(os.Stderr, time.Now(), *noProg, corHabilitada(os.Stderr))
	e.Progress = prog
	defer prog.Stop()
	coletaInicio := time.Now()
	f := facts.Collect(e)
	coletaFim := time.Now()

	// DEPOIS do relógio de coleta parar, e isso não é detalhe: o número que o
	// `relatarTempoDeColeta` imprime existe para dizer quanto tempo a
	// ferramenta ficou TOCANDO a máquina comprometida, e é por ele que se
	// julga o rastro deixado na timeline. Ler e comparar um retrato anterior —
	// um arquivo de até 512 MB, que pode nem estar no host — não é tempo no
	// host, e contá-lo ali fazia o número medir outra coisa.
	//
	// O drift entra ANTES DOS CHECKS porque ele é um FATO: os checks de drift o
	// leem como leem qualquer outro, e a correlação liga o que mudou aos
	// achados que falam da mesma coisa.
	if code := aplicarDrift(*driftDe, f, e.Caps, e.Now.UTC().Format(time.RFC3339)); code != 0 {
		return code
	}

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

	// A cauda é a MESMA do `analyze`, de propósito: ver `emitir`. A janela é
	// aplicada depois da baseline — ela conta por severidade o que removeu, e a
	// baseline é quem decide a severidade final. E com `--json -` o JSONL é o
	// produto do stdout, com o relatório humano indo para stderr: misturar os
	// dois tornava `scan --json - > out.jsonl` um arquivo inválido, que é como a
	// agregação de frota consome a saída.
	prog.Stop() // a linha some antes do relatório nascer
	code = emitir(r, f, e, saida{
		baseline: *base,
		janela:   janela,
		ioc:      lista,
		jsonOut:  *jsonOut,
		jsonFH:   jsonFH,
		verbose:  nivel(*verbose, *verbose2),
		coverage: *coverage,
	})
	// O timing vem DEPOIS do relatório: a identidade do host é a primeira coisa
	// que o operador quer ver, não o profiling da coleta. Vira rodapé no stderr.
	relatarTempoDeColeta(e, f, coletaInicio, coletaFim)
	return code
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
	n, semChave := bl.Aplicar(r, f)
	return &report.BaselineInfo{
		Host:       bl.Host,
		CapturedAt: bl.CapturedAt,
		Conhecidos: len(bl.Keys),
		Rebaixados: n,
		SemChave:   semChave,
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
		root   = fs.String("root", "", "capturar de imagem montada em PATH")
		out    = fs.String("o", "-", "arquivo de saída ('-' = stdout)")
		noProg = fs.Bool("no-progress", false, "não mostrar o progresso da coleta")
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
	aoInterromper()
	prog := progress.New(os.Stderr, time.Now(), *noProg, corHabilitada(os.Stderr))
	e.Progress = prog
	defer prog.Stop()
	f := facts.Collect(e)

	selected := check.Select(check.Selection{})
	r := check.Run(selected, f, e)
	prog.Stop() // a linha some antes de escrever a baseline

	bl := baseline.Capturar(r, f, f.Host.Hostname, version, e.Now)

	w := io.Writer(os.Stdout)
	if *out != "-" {
		// openJSONOut e não os.Create: aquele é O_TRUNC e SEGUE symlink — um erro
		// de digitação apagaria um arquivo do host, e um symlink plantado
		// redirecionaria a escrita. A baseline é capturada em máquina possivelmente
		// comprometida; vale a mesma regra de "nunca destruir dado do host" do
		// scan --json.
		fh, err := openJSONOut(*out)
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

// abrirSaidaJSON valida e ABRE o destino do --json ANTES da parte cara.
//
// Ele era aberto depois da coleta, dos checks e do relatório humano: numa
// segunda execução com o mesmo --json, a varredura inteira rodava, os críticos
// eram impressos, e só então openJSONOut recusava o arquivo existente — o
// código de erro apagava r.Exit() e o host comprometido virava "erro de
// invocação" para a automação de frota que ordena por exit code. O --ioc e o
// --since já eram validados antes da parte cara por esse mesmo princípio, e o
// --json, que é o produto consumido por máquina, ficou de fora.
func abrirSaidaJSON(path string) (*os.File, error) {
	switch path {
	case "":
		return nil, nil
	case "-":
		return os.Stdout, nil
	}
	return openJSONOut(path)
}

// writeJSONL escreve no destino JÁ ABERTO. Devolve o exit code final, que NUNCA
// rebaixa o veredito: uma falha de escrita é reportada em voz alta, mas um host
// com crítico continua saindo 2 — trocá-lo por 3 esconderia o comprometimento
// atrás de um problema de disco.
func writeJSONL(fh *os.File, veredito int, r *check.Report, f *facts.Facts, e *env.Env, bl *report.BaselineInfo, jn *report.JanelaInfo, an *report.AnaliseInfo) int {
	if fh == nil {
		return veredito
	}
	err := report.JSONL(fh, r, f, e, bl, jn, an)
	if fh != os.Stdout {
		if cerr := fh.Close(); err == nil {
			err = cerr
		}
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "erro ao escrever JSONL: %v\n", err)
		if veredito >= 2 {
			return veredito
		}
		return 3
	}
	return veredito
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
					"host sob investigação: escolha outro nome, ou use '-' para a saída padrão.", path)
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
