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
	// Campo é o nome JSON em facts.Facts. Vários campos podem apontar para a
	// mesma superfície, e uma superfície pode não ter campo (as derivadas).
	Campo string
	// Tipo é a família registrada quando Coberta; vazio quando não é.
	Tipo string
	// Porque é obrigatório quando NÃO coberta: é a razão da exclusão, e é ela
	// que separa decisão de esquecimento.
	Porque string
}

// Campo é o nome JSON do campo em facts.Facts. Ele existe para que a
// classificação seja conferível por CONSTRUÇÃO: o teste percorre a struct e
// exige que todo campo apareça em uma das três listas.
//
// Sem isso a tabela provava só consistência — "toda família registrada aparece
// aqui" —, e não COMPLETUDE. A diferença é a pergunta que ela existe para
// responder: um campo novo em Facts, security-sensitive e esquecido, passava
// sem que ninguém tivesse decidido nada.

// Cobertas são as superfícies com família de drift. O Tipo tem de existir no
// registro, e o Campo em facts.Facts — o teste confere nos dois sentidos.
var Cobertas = []Superficie{
	{Nome: "unit do systemd", Campo: "units", Tipo: "systemd.unit"},
	{Nome: "agendamento (cron/at)", Campo: "cron", Tipo: "cron"},
	{Nome: "regra de sudo", Campo: "sudoers", Tipo: "sudoers"},
	{Nome: "regra de doas", Campo: "doas", Tipo: "doas"},
	{Nome: "chave autorizada de SSH", Campo: "ssh_keys", Tipo: "ssh.authorized_key"},
	{Nome: "configuração do servidor SSH", Campo: "ssh", Tipo: "ssh.servidor"},
	{Nome: "hook de execução do cliente SSH", Campo: "ssh_client_exec", Tipo: "ssh.cliente_exec"},
	{Nome: "conta local", Campo: "accounts", Tipo: "conta"},
	{Nome: "grupo local", Campo: "groups", Tipo: "grupo"},
	{Nome: "pré-carga de código (ld.so.preload)", Campo: "loader", Tipo: "precarga"},
	{Nome: "hook de interpretador", Campo: "interpreter_hooks", Tipo: "hook_interp"},
	{Nome: "bit setuid/setgid", Campo: "suid", Tipo: "suid"},
	{Nome: "porta em escuta", Campo: "sockets", Tipo: "porta"},
	{Nome: "módulo carregado", Campo: "loaded_modules", Tipo: "modulo"},
	{Nome: "interpretador do kernel (binfmt_misc)", Campo: "binfmt", Tipo: "binfmt"},
	{Nome: "linha de comando do kernel", Campo: "boot_cmdline", Tipo: "boot"},
	{Nome: "endurecimento do kernel", Campo: "kernel_protection", Tipo: "kernel.protecao"},
	{Nome: "controle de acesso obrigatório (MAC)", Campo: "mac", Tipo: "mac"},
	{Nome: "auditoria (auditd)", Campo: "audit", Tipo: "audit"},
	{Nome: "âncora de confiança de TLS", Campo: "ca_certs", Tipo: "ca"},
	{Nome: "módulo de resolução (NSS)", Campo: "nss_modules", Tipo: "nss"},
	{Nome: "cadeia de resolução (nsswitch)", Campo: "nss_services", Tipo: "nss_servico"},
	{Nome: "nome fixado em /etc/hosts", Campo: "hosts", Tipo: "hosts"},
	{Nome: "resolvedor de DNS", Campo: "resolver", Tipo: "resolver"},
	{Nome: "confiança entre hosts (rhosts)", Campo: "host_trust", Tipo: "host_trust"},
	{Nome: "programa em execução", Campo: "processes", Tipo: "programa"},
	{Nome: "arquivo que executa em gatilho", Campo: "triggers", Tipo: "startup.trigger"},
	{Nome: "configuração de módulo (modprobe.d)", Campo: "modules", Tipo: "module.config"},
	{Nome: "programa que o kernel invoca", Campo: "kernel_helpers", Tipo: "kernel.helper"},
	{Nome: "interpretador declarado em arquivo", Campo: "binfmt_config", Tipo: "binfmt.config"},
	{Nome: "caminho de busca do loader", Campo: "loader", Tipo: "loader.path"},
	{Nome: "configuração por diretório do servidor web", Campo: "web_config", Tipo: "web.config"},
}

// NaoCobertas são as superfícies que o coletor tem e o drift NÃO compara, cada
// uma com o motivo. Acrescentar família de drift só porque o fato existe piora
// a feature: o sinal dela vem de ser silenciosa em host saudável.
var NaoCobertas = []Superficie{
	{Nome: "processos individuais (PID, RSS, starttime)", Campo: "processes",
		Porque: "volatilidade de runtime: 160 de 315 processos deste desktop " +
			"diferiam entre duas coletas com segundos de intervalo. O que sobrevive " +
			"é o EXECUTÁVEL, e ele está coberto pela família `programa`"},
	{Nome: "conexões estabelecidas", Campo: "sockets",
		Porque: "tráfego, não estado. O que ESCUTA é estado e está coberto por " +
			"`porta`; uma conexão que existia num retrato e não no outro é o " +
			"relógio, não o host"},
	{Nome: "pacotes instalados", Campo: "pkg",
		Porque: "churn de atualização. MEDIDO: 38 pacotes atualizados num servidor " +
			"de referência produziram 21 mudanças contadas e UM achado — e o achado " +
			"veio da família `suid`, não de uma lista de pacotes. Comparar a lista " +
			"inteira daria centenas de linhas para dizer a mesma coisa"},
	{Nome: "árvore de arquivos / hashes", Campo: "ownership",
		Porque: "mesma churn, em escala maior, e exige normalização própria (hash, " +
			"mtime e tamanho mudam JUNTOS numa atualização de pacote, e é essa " +
			"coincidência que a separa de alteração). Enquanto ela não existir, a " +
			"comparação seria ruído"},
	{Nome: "programas eBPF carregados", Campo: "bpf",
		Porque: "o identificador é um número que o kernel recicla, e o conjunto " +
			"muda com qualquer ferramenta moderna de rede ou observabilidade. Sem " +
			"identidade estável, comparar produziria par surgiu+sumiu a cada coleta"},
	{Nome: "hooks de ftrace", Campo: "ftrace_hooks",
		Porque: "mesma razão do eBPF: o que o cross.ftrace_hook faz é CRUZAR duas " +
			"visões na mesma coleta, e essa pergunta não precisa de retrato anterior"},
	{Nome: "logs e histórico de shell", Campo: "logs",
		Porque: "append-only: eles são a EVIDÊNCIA da mudança, não o estado que " +
			"mudou. Comparar dois retratos de um log diria apenas que o tempo passou"},
	{Nome: "segmentos SysV SHM", Campo: "sysvipc_shm",
		Porque: "runtime volátil, e o segmento interessante é o que existe AGORA — " +
			"pergunta que o check pontual responde melhor que uma comparação"},
	{Nome: "arquivos temporários e árvores de upload", Campo: "suspect_code",
		Porque: "existem para mudar. O que importa ali é o conteúdo executável, e " +
			"disso cuidam a varredura de código e o `app.web_config_exec`"},
	// --- METADADOS DA COLETA: não são estado do host, são as condições em que
	// ele foi olhado. Compará-los responderia "o tempo passou".
	{Nome: "versão do esquema", Campo: "schema_version", Porque: "metadado do artefato"},
	{Nome: "instante da coleta", Campo: "collected_at", Porque: "metadado do artefato"},
	{Nome: "origem (live/image)", Campo: "source", Porque: "metadado do artefato"},
	{Nome: "marca de coleta volátil", Campo: "volatile", Porque: "metadado do artefato"},
	{Nome: "identidade do host", Campo: "host", Porque: "hostname, kernel, uptime e load — " +
		"o primeiro é ressalva da comparação (ver Drift.DeHost) e o resto é runtime"},
	{Nome: "meta de acesso", Campo: "access_meta", Porque: "descreve o PRIVILÉGIO da " +
		"coleta, não o host"},

	// --- SINAIS DE COMPLETUDE: eles SÃO a cobertura da comparação, e compará-los
	// seria comparar o instrumento em vez do objeto.
	{Nome: "tabelas de socket incompletas", Campo: "sockets_incomplete", Porque: "sinal de cobertura"},
	{Nome: "passwd lido", Campo: "passwd_read", Porque: "sinal de cobertura"},
	{Nome: "group lido", Campo: "group_read", Porque: "sinal de cobertura"},
	{Nome: "shadow lido", Campo: "shadow_read", Porque: "sinal de cobertura"},
	{Nome: "sudoers lido", Campo: "sudoers_read", Porque: "sinal de cobertura"},
	{Nome: "doas lido", Campo: "doas_read", Porque: "sinal de cobertura"},
	{Nome: "sshd_config coletado", Campo: "ssh_server_collected", Porque: "sinal de cobertura"},
	{Nome: "sshd_config completo", Campo: "ssh_server_complete", Porque: "sinal de cobertura"},
	{Nome: "authorized_keys completo", Campo: "ssh_keys_complete", Porque: "sinal de cobertura"},
	{Nome: "config de cliente completo", Campo: "ssh_client_complete", Porque: "sinal de cobertura"},
	{Nome: "âncoras de TLS completas", Campo: "ca_complete", Porque: "sinal de cobertura"},
	{Nome: "hosts lido", Campo: "hosts_read", Porque: "sinal de cobertura"},
	{Nome: "resolver lido", Campo: "resolver_read", Porque: "sinal de cobertura"},
	{Nome: "confiança entre hosts completa", Campo: "host_trust_complete", Porque: "sinal de cobertura"},
	{Nome: "módulos lidos", Campo: "modules_read", Porque: "sinal de cobertura"},
	{Nome: "árvore de módulos lida", Campo: "module_tree_read", Porque: "sinal de cobertura"},
	{Nome: "nsswitch lido", Campo: "nss_read", Porque: "sinal de cobertura"},
	{Nome: "ld.so.preload lido", Campo: "loader_preload_read", Porque: "sinal de cobertura"},
	{Nome: "caminho do loader completo", Campo: "loader_path_complete", Porque: "sinal de cobertura"},
	{Nome: "binfmt vivo completo", Campo: "binfmt_live_complete", Porque: "sinal de cobertura"},
	{Nome: "binfmt.d completo", Campo: "binfmt_config_complete", Porque: "sinal de cobertura"},
	{Nome: "config de boot lida", Campo: "boot_config_read", Porque: "sinal de cobertura"},
	{Nome: "histórico de login lido", Campo: "login_history_read", Porque: "sinal de cobertura"},
	{Nome: "lacunas de persistência", Campo: "persist_denied", Porque: "sinal de cobertura"},
	{Nome: "lacunas por coletor", Campo: "partial", Porque: "sinal de cobertura"},

	// --- RUNTIME VOLÁTIL: muda sozinho entre duas leituras.
	{Nome: "sockets de pacote/raw", Campo: "raw_sockets", Porque: "runtime volátil, e o " +
		"que interessa é quem os tem AGORA"},
	{Nome: "processos que sumiram durante a coleta", Campo: "processes_gone",
		Porque: "runtime volátil por definição — é a própria coleta se descrevendo"},
	{Nome: "visão cruzada", Campo: "cross_view", Porque: "é a comparação de DUAS " +
		"visões na mesma coleta; não precisa de retrato anterior"},
	{Nome: "logins", Campo: "logins", Porque: "append-only: é a evidência da mudança, " +
		"não o estado que mudou"},
	{Nome: "vigias de arquivo (inotify)", Campo: "file_watchers", Porque: "runtime " +
		"volátil: o watcher vive no processo que o registrou"},
	{Nome: "taint do kernel", Campo: "kernel_taint", Porque: "acumulativo e não " +
		"reversível — só cresce, e o cross-view já o lê como contexto"},

	// --- CHURN DE PACOTE E DE ÁRVORE: medido, e é a razão de a feature ser
	// silenciosa em host saudável.
	{Nome: "base de pacotes", Campo: "pkg", Porque: "churn de atualização (ver acima)"},
	{Nome: "propriedade de arquivo por pacote", Campo: "ownership", Porque: "churn de atualização"},
	{Nome: "censo de donos de arquivo", Campo: "file_owners", Porque: "amostragem: os " +
		"exemplos variam entre coletas sem nada mudar"},
	{Nome: "diretórios varridos por SUID", Campo: "suid_dirs", Porque: "contador da varredura"},
	{Nome: "arquivos varridos por SUID", Campo: "suid_files", Porque: "contador da varredura"},
	{Nome: "arquivos de módulo em disco", Campo: "module_files", Porque: "churn de kernel novo"},
	{Nome: "módulos fora da árvore", Campo: "module_files_external", Porque: "churn de kernel novo"},
	{Nome: "hashes conferidos", Campo: "hash_verified", Porque: "o conjunto depende do " +
		"que estava RODANDO na coleta — medido: /usr/bin/tail entrava e saía"},
	{Nome: "divergência de hash", Campo: "hash_mismatch", Porque: "derivado do pacote, " +
		"e o check pontual já responde"},
	{Nome: "reivindicação estranha de pacote", Campo: "pkg_odd_claims", Porque: "derivado do pacote"},
	{Nome: "código suspeito", Campo: "suspect_code", Porque: "árvore servida: existe " +
		"para mudar. O que EXECUTA ali está coberto por web.config"},
	{Nome: "repositórios git", Campo: "git_repos", Porque: "árvore de trabalho muda a " +
		"cada commit; o que executa (hooks) é gatilho e está em startup.trigger"},

	// --- DERIVADOS DE FAMÍLIA JÁ COBERTA.
	{Nome: "alvos que root executa", Campo: "root_targets", Porque: "derivado de unit e " +
		"cron, que já são comparadas"},
	{Nome: "execução oculta", Campo: "hidden_exec", Porque: "derivado dos processos"},
	{Nome: "timestomp", Campo: "timestomps", Porque: "é sobre o TEMPO do arquivo, e a " +
		"comparação já data a mudança por intervalo"},
	{Nome: "atributos de inode", Campo: "inode_attrs", Porque: "derivado da varredura de " +
		"arquivo, com a mesma churn"},
	{Nome: "artefatos de ferramenta", Campo: "tool_artifacts", Porque: "presença de " +
		"ferramenta de ataque — pergunta pontual, e o IOC responde melhor"},
	{Nome: "hashes de IOC", Campo: "ioc_hashes", Porque: "é a LISTA de quem investiga, " +
		"não estado do host"},
	{Nome: "known_hosts", Campo: "known_hosts", Porque: "append-only: cresce a cada " +
		"conexão nova, e é evidência de para onde se conectou"},
	{Nome: "histórico de shell", Campo: "shell_history", Porque: "append-only"},
	{Nome: "logs", Campo: "logs", Porque: "append-only"},

	// --- CANDIDATOS DECLARADOS: têm estado estável e significado de segurança,
	// e ficaram de fora por churn conhecida. São os próximos, se alguém medir a
	// churn e ela couber.
	{Nome: "interfaces de rede", Campo: "interfaces", Porque: "CANDIDATO: um túnel novo " +
		"é sinal real, e a churn de contêiner, VPN e DHCP é alta o bastante para " +
		"exigir normalização própria antes"},
	{Nome: "montagens", Campo: "mounts", Porque: "CANDIDATO: um bind mount sobre /etc é " +
		"sinal forte, e a churn de contêiner e de autofs é alta"},
	{Nome: "limites de rede", Campo: "net_limits", Porque: "contadores (conntrack) " +
		"misturados com limites; os contadores dominam"},
	{Nome: "chaves privadas", Campo: "private_keys", Porque: "CANDIDATO: chave nova é " +
		"sinal, e a varredura de home tem churn de ferramenta de desenvolvimento"},
	{Nome: "arquivos de segredo", Campo: "secret_files", Porque: "CANDIDATO: mesma " +
		"razão das chaves privadas"},
	{Nome: "initramfs", Campo: "initramfs", Porque: "CANDIDATO: o initramfs é " +
		"reconstruído a cada atualização de kernel e de microcódigo, e comparar o " +
		"conteúdo exige normalização própria"},
}
