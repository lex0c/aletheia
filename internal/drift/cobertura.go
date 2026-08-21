package drift

// A TABELA DE COBERTURA: o que tem drift, o que NÃO tem, e por quê.
//
// # A pergunta que nenhuma outra catraca responde
//
// Este pacote já é cercado por invariantes fortes — todo campo que decide é
// extraído, toda família é lida por algum check, toda classe declara de que
// depende. Nenhuma delas responde a pergunta que aparece seis meses depois:
//
//	"por que Audit não tem drift?"
//
// Sem um lugar onde a resposta esteja escrita, ninguém sabe se foi DECISÃO ou
// ESQUECIMENTO — e as duas exigem ações opostas. A tabela abaixo é esse lugar, e
// o teste que a acompanha impede que ela apodreça: família registrada que não
// está aqui falha, e entrada aqui que não corresponde a superfície nenhuma
// também.
//
// # Por que não é gerada por reflexão sobre facts.Facts
//
// Porque produziria lixo. `Facts` tem 78 campos, e a maioria não é ESTADO: é
// evidência (logs, histórico), é runtime volátil (conexões, PIDs), ou é
// derivada de outra coisa. Uma lista automática diria "faltam 60 famílias" e
// estaria errada sobre todas.
//
// A pergunta certa não é "todo fato tem drift?". É:
//
//	todo ESTADO ESTÁVEL cujo desvio tem significado de segurança tem drift?
//
// E essa pergunta um humano responde, uma linha por vez.
type Superficie struct {
	// Nome é a superfície como um operador a chamaria.
	Nome string
	// Tipo é a família registrada quando Coberta; vazio quando não é.
	Tipo string
	// Porque é obrigatório quando NÃO coberta: é a razão da exclusão, e é ela
	// que separa decisão de esquecimento.
	Porque string
}

// Cobertas são as superfícies com família de drift. O Tipo tem de existir no
// registro — o teste confere nos dois sentidos.
var Cobertas = []Superficie{
	{Nome: "unit do systemd", Tipo: "systemd.unit"},
	{Nome: "agendamento (cron/at)", Tipo: "cron"},
	{Nome: "regra de sudo", Tipo: "sudoers"},
	{Nome: "regra de doas", Tipo: "doas"},
	{Nome: "chave autorizada de SSH", Tipo: "ssh.authorized_key"},
	{Nome: "configuração do servidor SSH", Tipo: "ssh.servidor"},
	{Nome: "hook de execução do cliente SSH", Tipo: "ssh.cliente_exec"},
	{Nome: "conta local", Tipo: "conta"},
	{Nome: "grupo local", Tipo: "grupo"},
	{Nome: "pré-carga de código (ld.so.preload)", Tipo: "precarga"},
	{Nome: "hook de interpretador", Tipo: "hook_interp"},
	{Nome: "bit setuid/setgid", Tipo: "suid"},
	{Nome: "porta em escuta", Tipo: "porta"},
	{Nome: "módulo carregado", Tipo: "modulo"},
	{Nome: "interpretador do kernel (binfmt_misc)", Tipo: "binfmt"},
	{Nome: "linha de comando do kernel", Tipo: "boot"},
	{Nome: "endurecimento do kernel", Tipo: "kernel.protecao"},
	{Nome: "controle de acesso obrigatório (MAC)", Tipo: "mac"},
	{Nome: "auditoria (auditd)", Tipo: "audit"},
	{Nome: "âncora de confiança de TLS", Tipo: "ca"},
	{Nome: "módulo de resolução (NSS)", Tipo: "nss"},
	{Nome: "cadeia de resolução (nsswitch)", Tipo: "nss_servico"},
	{Nome: "nome fixado em /etc/hosts", Tipo: "hosts"},
	{Nome: "resolvedor de DNS", Tipo: "resolver"},
	{Nome: "confiança entre hosts (rhosts)", Tipo: "host_trust"},
	{Nome: "programa em execução", Tipo: "programa"},
}

// NaoCobertas são as superfícies que o coletor tem e o drift NÃO compara, cada
// uma com o motivo. Acrescentar família de drift só porque o fato existe piora
// a feature: o sinal dela vem de ser silenciosa em host saudável.
var NaoCobertas = []Superficie{
	{Nome: "processos individuais (PID, RSS, starttime)",
		Porque: "volatilidade de runtime: 160 de 315 processos deste desktop " +
			"diferiam entre duas coletas com segundos de intervalo. O que sobrevive " +
			"é o EXECUTÁVEL, e ele está coberto pela família `programa`"},
	{Nome: "conexões estabelecidas",
		Porque: "tráfego, não estado. O que ESCUTA é estado e está coberto por " +
			"`porta`; uma conexão que existia num retrato e não no outro é o " +
			"relógio, não o host"},
	{Nome: "pacotes instalados",
		Porque: "churn de atualização. MEDIDO: 38 pacotes atualizados num servidor " +
			"de referência produziram 21 mudanças contadas e UM achado — e o achado " +
			"veio da família `suid`, não de uma lista de pacotes. Comparar a lista " +
			"inteira daria centenas de linhas para dizer a mesma coisa"},
	{Nome: "árvore de arquivos / hashes",
		Porque: "mesma churn, em escala maior, e exige normalização própria (hash, " +
			"mtime e tamanho mudam JUNTOS numa atualização de pacote, e é essa " +
			"coincidência que a separa de alteração). Enquanto ela não existir, a " +
			"comparação seria ruído"},
	{Nome: "programas eBPF carregados",
		Porque: "o identificador é um número que o kernel recicla, e o conjunto " +
			"muda com qualquer ferramenta moderna de rede ou observabilidade. Sem " +
			"identidade estável, comparar produziria par surgiu+sumiu a cada coleta"},
	{Nome: "hooks de ftrace",
		Porque: "mesma razão do eBPF: o que o cross.ftrace_hook faz é CRUZAR duas " +
			"visões na mesma coleta, e essa pergunta não precisa de retrato anterior"},
	{Nome: "logs e histórico de shell",
		Porque: "append-only: eles são a EVIDÊNCIA da mudança, não o estado que " +
			"mudou. Comparar dois retratos de um log diria apenas que o tempo passou"},
	{Nome: "segmentos SysV SHM",
		Porque: "runtime volátil, e o segmento interessante é o que existe AGORA — " +
			"pergunta que o check pontual responde melhor que uma comparação"},
	{Nome: "arquivos temporários e árvores de upload",
		Porque: "existem para mudar. O que importa ali é o conteúdo executável, e " +
			"disso cuidam a varredura de código e o `app.web_config_exec`"},
}
