package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/lex0c/aletheia/internal/mcp"
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
		permitirSeg  = fs.Bool("allow-secrets", false, "desligar a redação (exige --profile full)")
		auditoria    = fs.String("audit-log", "", "gravar a trilha de auditoria em FILE além do stderr")
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

	// O PORTÃO DE ROOT. Ele fica aqui e não em `env`, que só sonda: a decisão
	// de rodar privilegiado é do operador, e precisa ser dita antes de o
	// servidor abrir a boca. `sudo aletheia mcp` falha; só passa quem escreveu
	// --allow-root.
	if os.Geteuid() == 0 && !pol.PermitirRoot {
		fmt.Fprintln(os.Stderr,
			"mcp: recusei iniciar como root.\n"+
				"O servidor herda o privilégio deste processo, e como root ele enxerga o\n"+
				"host inteiro — incluindo o que uma tool de inspeção devolveria a um modelo\n"+
				"remoto. Isso é decisão sua, e precisa ser dita:\n\n"+
				"    sudo -n aletheia mcp --allow-root ...\n\n"+
				"Sem sudo interativo: a senha viria pelo stdin, que é o canal do protocolo.\n"+
				"Rode `sudo -v` antes.")
		return 3
	}

	acervo := mcp.NovoAcervo()
	for _, c := range retratos {
		r, err := acervo.Carregar(c)
		if err != nil {
			fmt.Fprintf(os.Stderr, "mcp --snapshot %s: %v\n", c, err)
			return 3
		}
		// Em stderr, para o operador saber o que o servidor está servindo. O
		// modelo recebe o mesmo por snapshot.list, sem o caminho local.
		fmt.Fprintf(os.Stderr, "mcp: %s = %s (%s)\n", r.ID, r.Rotulo, c)
	}

	aud, fecharAud, code := abrirAuditoria(*auditoria)
	if code != 0 {
		return code
	}
	defer fecharAud()

	srv := mcp.NovoServidor(pol, acervo, version, aud)
	fmt.Fprintf(os.Stderr, "mcp: modo %s · perfil %s · %d tool(s) · stdio\n",
		pol.Modo, pol.Perfil, len(srv.Ativas()))

	if err := srv.Servir(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "mcp: %v\n", err)
		return 3
	}
	return 0
}

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
	case vivo, raiz != "":
		fmt.Fprintln(os.Stderr,
			"mcp: --live e --root ainda não estão implementados.\n\n"+
				"A aquisição ao vivo é a entrega 2, e ela vem depois de o modo snapshot\n"+
				"estar sólido de propósito: começar pelo host vivo faria depurar protocolo\n"+
				"e depurar segurança serem o mesmo problema.\n\n"+
				"Tire um retrato e sirva ele:\n\n"+
				"    aletheia collect --out /tmp/host.json\n"+
				"    aletheia mcp --snapshot /tmp/host.json")
		return pol, 3
	default:
		pol.Modo = mcp.ModoSnapshot
	}

	// AS DUAS RECUSAS DO MODO SNAPSHOT, e elas vêm ANTES da regra geral de
	// --allow-secrets exigir --profile full.
	//
	// A ordem é o conserto de um caminho que mandava o operador ao lugar
	// errado: `--snapshot --allow-secrets` batia na regra geral, respondia
	// "exige --profile full", e o operador acrescentava a flag — para então
	// descobrir que --profile full também é recusado em snapshot. Duas idas
	// para aprender o que a primeira mensagem já podia dizer: em snapshot
	// NENHUMA das duas significa coisa alguma, porque o artefato não carrega
	// nem segredo nem conteúdo de arquivo.
	if permitirSeg {
		fmt.Fprintln(os.Stderr,
			"mcp --snapshot --allow-secrets: recusado, e o motivo importa.\n\n"+
				"O dump JÁ foi redigido na origem: argv, linha de cron, variável de crontab\n"+
				"e ExecStart saíram do host mascarados, e o environ já sai do coletor só com\n"+
				"os NOMES das variáveis mais uma allowlist de valores. Não há o que\n"+
				"destravar aqui — o segredo não está no arquivo.\n\n"+
				"Ignorar a flag em silêncio seria pior: você leria a ausência de segredo no\n"+
				"resultado como prova de que não havia nenhum.")
		return pol, 3
	}
	if pol.Perfil == mcp.PerfilCompleto {
		fmt.Fprintln(os.Stderr,
			"mcp --snapshot --profile full: recusado.\n\n"+
				"O perfil completo destrava leitura de arquivo e environ sem redação, e o\n"+
				"dump não carrega nem um nem outro. A lista de tools sairia idêntica à do\n"+
				"perfil padrão, e a flag prometeria um alcance que não existe.")
		return pol, 3
	}

	// A regra geral, para os modos de aquisição: desligar a redação sob o
	// perfil padrão seria uma trava sem porta.
	if permitirSeg && pol.Perfil != mcp.PerfilCompleto {
		fmt.Fprintln(os.Stderr, "mcp --allow-secrets exige --profile full")
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
	fh, err := openJSONOut(caminho)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mcp --audit-log: %v\n", err)
		return nil, nil, 3
	}
	return mcp.NovaAuditoria(multi{os.Stderr, fh}), func() { fh.Close() }, 0
}

// multi escreve nos dois destinos. Falha em um não impede o outro: perder a
// trilha é ruim, perder a investigação por causa dela é pior.
type multi []interface{ Write([]byte) (int, error) }

func (m multi) Write(b []byte) (int, error) {
	for _, w := range m {
		_, _ = w.Write(b)
	}
	return len(b), nil
}
