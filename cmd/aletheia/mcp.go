package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/mcp"
	"github.com/lex0c/aletheia/internal/report"
)

// runMCP serve o Aletheia a um agente por MCP, sobre stdio.
//
// # O que este comando promete
//
//	observação, não execução   não existe tool que escreva, execute comando,
//	                           mate processo, resolva nome ou abra conexão
//	privilégio herdado         o servidor nunca ganha privilégio; ele herda o
//	                           do processo, e rodar como root é CONSENTIMENTO
//	                           explícito, não um acidente de sudo
//	sem porta                  stdio apenas: nenhum daemon, nenhum TLS, nenhum
//	                           token, nenhum egress
//
// # stdout é do protocolo
//
// A spec é literal: o servidor NÃO pode escrever em stdout nada que não seja
// mensagem MCP. Todo diagnóstico deste comando sai em stderr — que o cliente
// pode capturar, encaminhar ou ignorar, e que ele NÃO deve tratar como sinal de
// erro. É também onde sai a trilha de auditoria.
func runMCP(args []string) int {
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var (
		retratos     caminhos
		vivo         = fs.Bool("live", false, "adquirir do host vivo")
		raiz         = fs.String("root", "", "adquirir de uma imagem montada em PATH")
		perfil       = fs.String("profile", "standard", "standard | full")
		permitirRoot = fs.Bool("allow-root", false, "autorizar a execução como root")
		permitirSeg  = fs.Bool("allow-secrets", false, "autorizar bytes crus a sair (exige --profile full, exceto em --snapshot)")
		auditoria    = fs.String("audit-log", "", "gravar a trilha de auditoria em FILE além do stderr")
		orcamento    = fs.Duration("capture-budget", mcp.OrcamentoDeColetaPadrao,
			"tempo total de leitura do host que esta sessão pode gastar em snapshot.capture")
	)
	fs.Var(&retratos, "snapshot", "servir um dump do collect (repetível)")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	if err := fs.Parse(args); err != nil {
		return 3
	}

	pol, code := policyDeFlags(retratos, *vivo, *raiz, *perfil, *permitirRoot, *permitirSeg)
	if code != 0 {
		return code
	}
	// O orçamento de TRABALHO é do operador: é a máquina dele que paga a
	// varredura. Um teto que ele não pode levantar viraria armadilha numa
	// investigação longa; um que ele não pode baixar, numa máquina em produção.
	//
	// Zero DITO é diferente de zero por omissão, e por isso a distinção vem do
	// fs.Visit e não do valor: Padroes() troca o zero silencioso pelo padrão, e
	// sem esta separação `--capture-budget=0` imprimia "desliga o teto" e subia
	// com dez minutos.
	if *orcamento < 0 {
		fmt.Fprintln(os.Stderr, "mcp: --capture-budget não pode ser negativo")
		return 3
	}
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "capture-budget" && *orcamento == 0 {
			pol.SemTetoDeColeta = true
		}
	})
	pol.OrcamentoDeColeta = *orcamento
	if pol.Modo != mcp.ModoSnapshot && pol.SemTetoDeColeta {
		fmt.Fprintln(os.Stderr,
			"mcp: --capture-budget=0 desliga o orçamento de trabalho da aquisição.\n"+
				"Capturar e liberar em laço passa a poder varrer o host investigado\n"+
				"sem fim, e o teto de retratos vivos não impede isso — ele limita\n"+
				"memória, não trabalho.")
	}

	// O PORTÃO DE ROOT. Ele fica aqui e não em `env`, que só sonda: a decisão
	// de rodar privilegiado é do operador, e precisa ser dita antes de o
	// servidor abrir a boca. `sudo aletheia mcp` falha; só passa quem escreveu
	// --allow-root.
	// O PORTÃO OLHA O PRIVILÉGIO EFETIVO, e não o euid.
	//
	// Ele conferia `os.Geteuid() == 0` enquanto o session.status do mesmo
	// binário explica, em prosa, que euid NÃO BASTA: um uid=1000 com
	// CAP_DAC_READ_SEARCH lê /etc/shadow, com CAP_SYS_PTRACE lê a memória de
	// qualquer processo, com CAP_BPF enumera programas eBPF. O servidor
	// afirmava uma coisa e o portão media outra.
	//
	// A contradição custa mais no --live, que é justamente onde a capability
	// muda o que a captura consegue mandar para o modelo.
	//
	// A flag continua se chamando --allow-root porque ela é documentada, mas o
	// que o operador autoriza é ALCANCE DE OBSERVAÇÃO PRIVILEGIADO — e a
	// mensagem diz isso.
	priv := mcp.LerPrivilegio()
	exige, porQue := mcp.ExigeConsentimento(priv, pol.Modo)
	if exige && !pol.PermitirRoot {
		fmt.Fprintln(os.Stderr,
			"mcp: recusei iniciar com observação privilegiada.\n"+
				porQue+"\n"+
				"O servidor herda o privilégio deste processo, e com ele enxerga mais do\n"+
				"host — incluindo o que uma tool de inspeção devolveria a um modelo\n"+
				"remoto. Isso é decisão sua, e precisa ser dita:\n\n"+
				"    sudo -n aletheia mcp --allow-root ...\n\n"+
				"Sem sudo interativo: a senha viria pelo stdin, que é o canal do protocolo.\n"+
				"Rode `sudo -v` antes.")
		for _, m := range priv.Explicacao {
			fmt.Fprintln(os.Stderr, "  · "+m)
		}
		return 3
	}

	acervo := mcp.NovoAcervo()
	// A REDAÇÃO DE INGRESSO é imposta por padrão, e só o operador a dispensa.
	//
	// O carimbo do artefato é procedência, não barreira: quem escreve o arquivo
	// escolhe o que ele diz. Sem esta linha, um dump que se declarasse não
	// redigido — ou que mentisse que foi, carregando texto cru — era servido
	// pelas tools comuns sem consentimento nenhum, contornando o --allow-secrets
	// pela porta do --snapshot.
	acervo.ServirCru = pol.PermitirSegredos
	// TETO DE RETRATOS VIVOS. Cada um segura os fatos INTEIROS na memória de um
	// processo que roda no host investigado, e a ferramenta promete passar pouco
	// recurso ali. Em modo snapshot não há teto: o operador declarou os arquivos
	// no lançamento, e limitar o que ele mesmo pediu não protege ninguém.
	if pol.Modo != mcp.ModoSnapshot {
		acervo.Teto = tetoDeRetratosVivos
	}
	for _, c := range retratos {
		r, err := acervo.Carregar(c)
		if err != nil {
			fmt.Fprintf(os.Stderr, "mcp --snapshot %s: %v\n", c, err)
			return 3
		}
		// Em stderr, para o operador saber o que o servidor está servindo. O
		// modelo recebe o mesmo por snapshot.list, sem o caminho local.
		//
		// COM report.Safe: o rótulo é `hostname · data` lido verbatim do dump, e
		// o hostname é escolhido por quem controla o alvo. Sem sanitizar, um
		// `/etc/hostname` com ESC limpa a tela do analista no lançamento e pinta
		// um banner forjado — e esta é a ÚNICA linha em que ele descobre qual
		// arquivo virou qual snapshot_id. Todo outro print de hostname no
		// repositório passa por aqui (report.Human, wtf, info, coleta).
		fmt.Fprintf(os.Stderr, "mcp: %s = %s (%s)\n",
			r.ID, report.Safe(r.Rotulo), report.Safe(c))

		// A SOMA. `analyze` e `drift` conferem o sidecar antes de concluir
		// qualquer coisa; o servidor MCP era o único caminho de carga que
		// pulava — e é justamente ele que entrega o retrato a um modelo, com um
		// bloco de procedência que afirma cadeia de custódia inteira.
		switch r.Soma {
		case mcp.SomaDivergente:
			fmt.Fprintf(os.Stderr,
				"\n⚠ O DUMP NÃO CONFERE COM A SOMA ESCRITA NA COLETA: %s\n"+
					"  o arquivo mudou depois de coletado. Compare com o número que foi\n"+
					"  para o war log. O servidor SEGUE — e o que sair dele descreve\n"+
					"  outro arquivo. A procedência de toda resposta diz sidecar_mismatch.\n\n", c)
		case mcp.SomaAusente:
			fmt.Fprintf(os.Stderr, "mcp: %s sem arquivo de soma ao lado: "+
				"NÃO foi possível conferir se ele mudou desde a coleta\n", c)
		}
	}

	aud, fecharAud, code := abrirAuditoria(*auditoria)
	if code != 0 {
		return code
	}
	defer fecharAud()

	// A AQUISIÇÃO. Ela vem daqui e não de internal/mcp porque é decisão de linha
	// de comando: a versão do binário, o --root, e a recusa de autoload.
	//
	// PermitirAutoload fica FALSO e não é configurável: consultar o sock_diag
	// pode fazer o kernel rodar `modprobe`, e um efeito colateral no host
	// investigado não pode nascer de uma chamada de tool. Quem quer aquele
	// alcance roda `aletheia scan --allow-kernel-autoload` e serve o retrato.
	var adquirir mcp.Aquisicao
	if pol.Modo != mcp.ModoSnapshot {
		adquirir = func() (*env.Env, error) {
			e := env.Probe(env.Options{Root: *raiz, Version: version})
			// O CONSENTIMENTO ATRAVESSA A COLETA.
			//
			// Sem isto, --allow-secrets destravaria as tools que servem dado cru
			// e a coleta continuaria descartando os valores do environ na
			// leitura — o servidor prometeria o environ completo e entregaria a
			// allowlist, com forma de resposta completa. Uma flag que destrava a
			// porta e não destrava o que está atrás dela é pior que a recusa.
			//
			// Do lado da escrita, dump.De vê o mesmo campo e dispensa a redação,
			// carimbando o artefato como cru. Uma flag, as duas metades.
			e.Segredos = pol.PermitirSegredos
			return e, nil
		}
	}

	srv := mcp.NovoServidor(pol, acervo, version, aud, adquirir)
	fmt.Fprintf(os.Stderr, "mcp: modo %s · perfil %s · %d tool(s) · stdio\n",
		pol.Modo, pol.Perfil, len(srv.Ativas()))
	if pol.Modo != mcp.ModoSnapshot {
		fmt.Fprintf(os.Stderr, "mcp: nenhum retrato ainda — o agente tira o dele com "+
			"snapshot.capture (teto de %d vivos)\n", tetoDeRetratosVivos)
	}

	if err := srv.Servir(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "mcp: %v\n", err)
		return 3
	}
	return 0
}

// tetoDeRetratosVivos é quantas capturas cabem ao mesmo tempo.
//
// Quatro é folgado para a investigação que este servidor existe para sustentar
// — um retrato de referência, um atual, e espaço para comparar — e apertado o
// bastante para que um agente em laço não coma a memória do host investigado.
const tetoDeRetratosVivos = 4

// caminhos é a flag repetível de --snapshot.
type caminhos []string

func (c *caminhos) String() string { return strings.Join(*c, ",") }

func (c *caminhos) Set(v string) error {
	*c = append(*c, v)
	return nil
}

// policyDeFlags valida a combinação e monta a policy.
//
// # Por que uma flag de segurança ignorada é pior que uma recusada
//
// `--snapshot --allow-secrets` poderia "não ter efeito". Não pode: o operador
// que a escreveu acredita ter destravado algo, e vai ler a ausência de segredo
// no resultado como prova de que não havia nenhum. A recusa DIZ o que está
// acontecendo — o dump já saiu redigido do host —, e essa frase é a informação
// que ele precisava.
func policyDeFlags(retratos caminhos, vivo bool, raiz, perfil string,
	permitirRoot, permitirSeg bool) (mcp.Policy, int) {

	var pol mcp.Policy

	fontes := 0
	if len(retratos) > 0 {
		fontes++
	}
	if vivo {
		fontes++
	}
	if raiz != "" {
		fontes++
	}
	switch {
	case fontes == 0:
		fmt.Fprintln(os.Stderr,
			"mcp: diga de onde responder.\n\n"+
				"    aletheia mcp --snapshot host.json          # um retrato do collect\n"+
				"    aletheia mcp --snapshot antes.json --snapshot depois.json\n\n"+
				"A flag é repetível, e tudo que este processo poderá abrir é fixado aqui:\n"+
				"nenhuma tool aceita caminho de arquivo.")
		return pol, 3
	case fontes > 1:
		fmt.Fprintln(os.Stderr,
			"mcp: --snapshot, --live e --root são modos diferentes; escolha um")
		return pol, 3
	}

	switch perfil {
	case "standard":
		pol.Perfil = mcp.PerfilPadrao
	case "full":
		pol.Perfil = mcp.PerfilCompleto
	default:
		fmt.Fprintf(os.Stderr, "mcp --profile: %q não é standard nem full\n", perfil)
		return pol, 3
	}

	switch {
	case vivo:
		pol.Modo = mcp.ModoLive
	case raiz != "":
		if fi, err := os.Stat(raiz); err != nil || !fi.IsDir() {
			fmt.Fprintf(os.Stderr, "--root: %s não é um diretório acessível\n", raiz)
			return pol, 3
		}
		pol.Modo = mcp.ModoImagem
	default:
		pol.Modo = mcp.ModoSnapshot
	}

	// AS DUAS RECUSAS DO MODO SNAPSHOT — e elas são presas AO MODO.
	//
	// Não eram: as duas condições não olhavam pol.Modo, então disparavam também
	// em --live e --root, imprimindo um parágrafo sobre um dump que o operador
	// nunca carregou. Pior, elas tornavam MORTOS os dois blocos escritos logo
	// abaixo para os modos de aquisição — as condições são idênticas, e `go vet`
	// não vê braço inalcançável por predicado, só por constante.
	//
	// Elas vêm ANTES da regra geral de --allow-secrets exigir --profile full.
	//
	// A ordem é o conserto de um caminho que mandava o operador ao lugar
	// errado: `--snapshot --allow-secrets` batia na regra geral, respondia
	// "exige --profile full", e o operador acrescentava a flag — para então
	// descobrir que --profile full também é recusado em snapshot. Duas idas
	// para aprender o que a primeira mensagem já podia dizer: em snapshot
	// NENHUMA das duas significa coisa alguma, porque o artefato não carrega
	// nem segredo nem conteúdo de arquivo.
	// --snapshot --allow-secrets DEIXOU DE SER RECUSA, e virou consentimento.
	//
	// A recusa dizia "o dump já foi redigido na origem, não há o que
	// destravar". Aquilo tratava o CARIMBO do artefato como fato — e um dump
	// não é autenticado. O próprio envelope deste servidor diz isso.
	//
	// A propriedade nova é outra: o servidor RE-REDIGE no ingresso, sempre,
	// independentemente do que o arquivo afirme sobre si. A flag agora autoriza
	// pular essa imposição, e ela não promete recuperar segredo nenhum: o que
	// saiu redigido do host continua redigido. Ela diz "sirva o que estiver
	// cru aí dentro".
	//
	// Não exige --profile full porque não há tool de leitura a destravar sobre
	// um artefato; o que ela governa aqui é o INGRESSO, não a superfície.
	if pol.Modo == mcp.ModoSnapshot && pol.Perfil == mcp.PerfilCompleto {
		fmt.Fprintln(os.Stderr,
			"mcp --snapshot --profile full: recusado, e o motivo importa.\n\n"+
				"O perfil completo destrava LER O HOST por um caminho que o modelo\n"+
				"escolhe, e o environ completo de um processo. Um dump não carrega\n"+
				"conteúdo de arquivo — nunca carregou, e não deve carregar —, e o environ\n"+
				"dele já saiu do coletor sem os valores.\n\n"+
				"Sobre um artefato não há o que ler. Use --live ou --root.")
		return pol, 3
	}

	// Nos modos de AQUISIÇÃO, --allow-secrets sem --profile full não significa
	// nada: quem serve dado cru ali é a classe DadosCrus, e ela mora atrás do
	// perfil. Em snapshot ela governa o ingresso e vale sozinha.
	if permitirSeg && pol.Modo != mcp.ModoSnapshot && pol.Perfil != mcp.PerfilCompleto {
		fmt.Fprintln(os.Stderr,
			"mcp --allow-secrets exige --profile full.\n\n"+
				"O perfil é que destrava LER O HOST por caminho; --allow-secrets é que\n"+
				"destrava os bytes crus saírem daqui. Sozinha, ela desligaria uma\n"+
				"projeção que nenhuma tool servida usa.")
		return pol, 3
	}

	pol.PermitirRoot = permitirRoot
	pol.PermitirSegredos = permitirSeg
	return pol, 0
}

// abrirAuditoria devolve o destino da trilha.
//
// stderr SEMPRE; arquivo só quando pedido. O README promete que `preserve` é o
// único comando que escreve, e uma trilha que nasce criando arquivo no host
// investigado quebraria a promessa em silêncio — durante um incidente, num
// diretório que o investigador não escolheu.
func abrirAuditoria(caminho string) (*mcp.Auditoria, func(), int) {
	if caminho == "" {
		return mcp.NovaAuditoria(os.Stderr), func() {}, 0
	}
	// STDOUT É O CANAL DO PROTOCOLO, e a trilha não pode entrar nele.
	//
	// `openJSONOut` aceita "-" como stdout e abre /dev/stdout como um arquivo
	// qualquer — nos dois casos as linhas de auditoria sairiam INTERLEAVADAS
	// entre as mensagens MCP, e todo cliente quebraria numa linha que não é
	// mensagem. É a mesma recusa que --snapshot - já faz, do outro lado do
	// mesmo descritor. ("-" ainda criaria um arquivo chamado "-" no diretório
	// corrente, que é a segunda forma de errar sem perceber.)
	for _, proibido := range []string{"-", "/dev/stdout", "/dev/fd/1", "/proc/self/fd/1"} {
		if caminho == proibido {
			fmt.Fprintf(os.Stderr,
				"mcp --audit-log %s: a saída padrão é o canal do protocolo MCP.\n"+
					"A trilha já sai no stderr; use --audit-log com um ARQUIVO.\n", caminho)
			return nil, nil, 3
		}
	}
	fh, err := openJSONOut(caminho)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mcp --audit-log: %v\n", err)
		return nil, nil, 3
	}
	// E a conferência no DESCRITOR, que é a que vale: o caminho pode chegar
	// aqui por um symlink ou por um /dev/fd/N que a lista acima não nomeia.
	if fi, err := fh.Stat(); err == nil && !fi.Mode().IsRegular() {
		fh.Close()
		fmt.Fprintf(os.Stderr,
			"mcp --audit-log %s: não é arquivo comum. A trilha vai para arquivo ou "+
				"para o stderr — nunca para um descritor que possa ser o do protocolo.\n",
			caminho)
		return nil, nil, 3
	}
	return mcp.NovaAuditoria(io.MultiWriter(os.Stderr, fh)), func() { fh.Close() }, 0
}
