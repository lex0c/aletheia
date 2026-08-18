// Package tools é o catálogo de FAMÍLIAS de ferramenta (runbook §5.10).
//
// Fica em pacote próprio porque é consumido dos dois lados: o coletor procura
// os artefatos em disco, e o check decide o que fazer com o que foi achado.
// Assim o check continua sendo função PURA sobre Facts — se ele fosse ao
// filesystem sozinho, a suíte inteira deixaria de rodar sem um host de verdade.
package tools

// Catálogo de FAMÍLIAS de ferramenta (runbook §5.10).
//
// Descobrir o nome é o atalho mais barato do runbook inteiro: alguém já fez a
// engenharia reversa e publicou, e o que a ferramenta SABE FAZER é o teto do
// que pode ter acontecido neste host — antes de provar cada capacidade.
//
// # O critério de entrada, e por que ele é estreito
//
// Só entra ferramenta PÚBLICA, com caminho ou variável DOCUMENTADOS pelo
// próprio projeto. Nada de hash, nada de nome de amostra: isso é catálogo de
// antivírus, envelhece em semanas, e uma ferramenta de resposta a incidente que
// depende de assinatura atualizada é uma ferramenta que mente em silêncio
// quando a assinatura ficou velha.
//
// Nome de projeto e caminho de config são estáveis por anos. É a diferença
// entre catalogar SAMPLES e catalogar FERRAMENTAS.
//
// E cada entrada precisa dizer o que o nome MUDA na resposta. Um nome que não
// redireciona a investigação não paga a linha que ocupa.
//
// # Todas são legítimas
//
// Não há malware nesta lista. São ferramentas de administração, túnel e
// sincronização com uso dual documentado. O achado afirma que a CAPACIDADE está
// presente — capacidade não é prova de uso, e o veredito continua sendo o da
// §37.7.
//
// # As três rotas
//
//	Env    prefixo de variável no environ (§3.6). Só o processo vivo.
//	Paths  config e estado em disco (§7). Funciona em IMAGEM MONTADA, que é o
//	       caminho da §35.6 quando o userland do alvo não é confiável.
//	Bins   nome do executável, no exe de processo e no Exec= de unit.
//
// A rota de disco cobre muito mais família que a de env: a maioria dos
// implantes não usa variável de ambiente — usa arquivo de config.
// Risk é a leitura da PRESENÇA, não do uso. Alto = não há por que isto estar
// num servidor de produção; médio = ferramenta legítima cuja capacidade muda o
// escopo da investigação.
type Risk string

const (
	RiskAlto  Risk = "alto"
	RiskMedio Risk = "medio"
)

type Family struct {
	Name string
	Risk Risk
	Nota string

	Env   []string // prefixos de variável
	Paths []string // "~" é expandido para cada home do passwd DO ALVO
	Bins  []string // basename de executável, casado INTEIRO

	// BinsPrefixo é para o executável cujo nome carrega sufixo VARIÁVEL —
	// identificador de organização, de tenant ou de versão. O Explorer do
	// runZero se instala como `runzero-agent-<uuid da organização>`, e um
	// catálogo que só casa nome inteiro passa direto por ele: o sufixo muda em
	// cada instalação, e é exatamente por isso que ele não pode ser a chave.
	BinsPrefixo []string
}

// All é o catálogo.
var All = []Family{
	// ---------------------------------------------------------------- canal C2
	{
		Name: "GSocket / gs-netcat",
		Risk: RiskAlto,
		Nota: "canal por rede global de relay, SEM IP fixo de C2: bloquear IP não " +
			"resolve (runbook §18.1), só egress default-deny corta (§34.3). Conecta " +
			"nos dois sentidos sem porta aberta, então não procure listener (§2) — " +
			"procure a SAÍDA. Shell, transferência de arquivo e port-forward entram " +
			"no escopo por padrão (§37, §12.2)",
		Env:   []string{"GSOCKET_", "GS_"},
		Paths: []string{"~/.config/gsocket", "~/.gsocket", "/etc/gsocket"},
		Bins:  []string{"gs-netcat", "gsocket", "gs-sftp", "gs-mount"},
	},

	// ------------------------------------------- descoberta e mapeamento de REDE
	//
	// Aqui a capacidade não é acesso: é CONHECIMENTO. Quem mapeia a rede interna
	// está respondendo "para onde eu vou daqui", e o resultado desse mapeamento
	// é o que decide o resto do incidente. Encontrar isto num host invadido
	// muda a pergunta de "o que foi feito nesta máquina" para "o que já foi
	// aprendido sobre TODAS as outras" — e o inventário que a ferramenta
	// produziu já saiu daqui.
	{
		Name: "runZero Explorer",
		// Produto legítimo, e comum: é scanner de inventário de ativos, com
		// licença gratuita para redes pequenas. Numa VM de aplicação, porém,
		// ele não tem por que estar — quem faz inventário de rede o instala em
		// host de gestão, não num servidor web.
		Risk: RiskAlto,
		Nota: "scanner de DESCOBERTA de rede: varre faixa inteira, identifica " +
			"serviço e sistema operacional e monta inventário. Num host de gestão " +
			"é a função dele; numa VM de aplicação invadida é reconhecimento " +
			"interno pronto (§23). Ele usa SYN e socket RAW, então a varredura " +
			"quase não deixa conexão ESTABELECIDA para se ver depois — procure o " +
			"socket de pacote (§2.6) e a CAPABILITY de rede (§3.7), e trate o " +
			"resultado do scan como EXFILTRADO: o inventário sobe para o serviço",
		Env:   []string{"RUNZERO_"},
		Paths: []string{"/opt/runzero", "/etc/runzero", "/var/log/runzero.log", "/var/log/runzero.err"},
		Bins:  []string{"runzero-agent.bin", "runzero", "runzero-explorer"},
		// O nome real de instalação: `runzero-agent-<uuid da organização>`.
		BinsPrefixo: []string{"runzero-agent-"},
	},

	// ------------------------------------------------------ túnel de INGRESSO
	//
	// Dão alcance de FORA para dentro sem abrir porta nenhuma. A §2 (procurar
	// listener) não acha nada; o rastro é a saída persistente para a borda do
	// fornecedor.
	{
		Name: "ngrok",
		Risk: RiskMedio,
		Nota: "túnel de INGRESSO: expõe serviço interno para a internet sem abrir " +
			"porta. Procurar listener (runbook §2) não acha — o rastro é a saída " +
			"persistente, e a conta usada é IOC de frota (§23)",
		Env:   []string{"NGROK_"},
		Paths: []string{"~/.ngrok2", "~/.config/ngrok", "/etc/ngrok.yml"},
		Bins:  []string{"ngrok"},
	},
	{
		Name: "cloudflared",
		Risk: RiskMedio,
		Nota: "túnel de ingresso pela Cloudflare: mesmo efeito do ngrok, invisível " +
			"para varredura de porta. O token identifica a conta e vale como IOC (§23)",
		Env:   []string{"TUNNEL_TOKEN", "CLOUDFLARED_"},
		Paths: []string{"~/.cloudflared", "/etc/cloudflared"},
		Bins:  []string{"cloudflared"},
	},
	{
		Name: "frp (fast reverse proxy)",
		Risk: RiskMedio,
		Nota: "proxy reverso que atravessa NAT: o cliente sai, e o servidor do " +
			"atacante publica a porta. Como o ngrok, não deixa listener local para " +
			"a §2 encontrar",
		Paths: []string{"/etc/frp", "~/.frpc", "~/.config/frp"},
		Bins:  []string{"frpc", "frps"},
	},
	{
		Name: "Tailscale",
		Risk: RiskMedio,
		Nota: "VPN de malha. Uso legítimo é comum; como persistência, dá acesso " +
			"contínuo por rede paralela que o firewall de borda não vê (§18, §34.3). " +
			"A chave de autenticação é IOC de frota (§23)",
		Env:   []string{"TS_AUTHKEY"},
		Paths: []string{"/var/lib/tailscale", "~/.config/tailscale"},
		Bins:  []string{"tailscaled", "tailscale"},
	},

	// ------------------------------------------------------------ exfiltração
	{
		Name: "rclone",
		Risk: RiskMedio,
		Nota: "cliente de armazenamento em nuvem, e a ferramenta padrão de " +
			"exfiltração em massa: com ele presente, a §37 sai de 'improvável' e " +
			"vira 'presumir até provar o contrário'. O DESTINO está na config, não " +
			"no binário — leia o rclone.conf",
		Env:   []string{"RCLONE_CONFIG"},
		Paths: []string{"~/.config/rclone", "/etc/rclone.conf"},
		Bins:  []string{"rclone"},
	},

	// ----------------------------------------------------------- minerador
	//
	// O comprometimento nº 1 em VM de nuvem, e o mais fácil de confirmar: o
	// load médio já denuncia (§1).
	{
		Name: "XMRig",
		Risk: RiskAlto,
		Nota: "minerador. É oportunista, não dirigido (runbook §39.1) — mas a rota " +
			"de entrada que ele usou é a mesma que outro usaria, e o load do host " +
			"já denuncia. A carteira e o pool na config são IOC de frota (§23)",
		Paths: []string{"/etc/xmrig", "~/.xmrig.json", "~/.config/xmrig"},
		Bins:  []string{"xmrig", "xmrigDaemon", "xmr-stak"},
	},

	// ---------------------------------------------- acesso remoto de mercado
	{
		Name: "RMM de mercado usado como backdoor",
		Risk: RiskMedio,
		Nota: "ferramenta comercial de acesso remoto. Instalada por um invasor, dá " +
			"sessão interativa com aparência de software corporativo — e passa por " +
			"allowlist de aplicação. Confirme se o time de TI a instalou",
		Paths: []string{
			"/etc/anydesk", "~/.anydesk",
			"/opt/teamviewer", "/etc/teamviewer",
			"/etc/rustdesk", "~/.config/rustdesk",
		},
		Bins: []string{"anydesk", "teamviewer", "teamviewerd", "rustdesk"},
	},
}
