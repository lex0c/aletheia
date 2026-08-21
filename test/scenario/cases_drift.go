package scenario

// DRIFT: a mudança para a qual NÃO EXISTE check a escrever.
//
// Os cenários do resto da suíte plantam uma FORMA suspeita e exigem que a
// ferramenta a reconheça. Estes plantam uma forma perfeitamente legítima no
// lugar de outra forma perfeitamente legítima — e exigem que a ferramenta
// perceba a TRANSIÇÃO. É o eixo que nenhum retrato tem.
//
// O plantio roda duas vezes a ferramenta dentro do mesmo contêiner: uma para
// tirar o retrato ANTES, e a comparação depois. As duas coletas são feitas com
// o mesmo privilégio, no mesmo contêiner, no mesmo minuto — que é a condição
// que o próprio motor de drift exige para comparar sem inventar.

// driftPlantado: o retrato, a mudança e nada mais.
//
// Cada uma das quatro mudanças foi escolhida por ser INVISÍVEL para o catálogo:
//
//	ExecStart      trocado por outro caminho de sistema, igualmente banal
//	authorized_keys  a chave continua a MESMA — o que saiu foi o command=
//	cron           job novo, com comando que não tem forma suspeita nenhuma
//	sudoers        regra nova, restrita a um comando que não é primitiva
//
// Nenhuma delas dispara check. Todas mudam o que este host faz.
const driftPlantado = `
mkdir -p /etc/systemd/system /etc/cron.d /etc/sudoers.d /root/.ssh
printf '[Unit]\nDescription=metrics\n[Service]\nExecStart=/usr/bin/env sleep 30\n' \
    > /etc/systemd/system/metrics-agent.service
printf 'command="/usr/bin/rsync --server",restrict ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f backup@controller\n' \
    > /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
printf 'root ALL=(ALL:ALL) ALL\n@includedir /etc/sudoers.d\n' > /etc/sudoers
chmod 440 /etc/sudoers

/aletheia collect --out /tmp/antes.json >/dev/null 2>&1

# --- daqui para baixo, o que mudou ---

# 1. o ExecStart aponta para outro binário. Os dois são de sistema, os dois são
#    banais, e nenhum check tem o que dizer sobre a troca.
printf '[Unit]\nDescription=metrics\n[Service]\nExecStart=/usr/bin/env tail -f /dev/null\n' \
    > /etc/systemd/system/metrics-agent.service

# 2. A MESMA chave, sem o command= e sem o restrict. O arquivo continua com uma
#    linha, o fingerprint continua o mesmo, e a chave de tarefa única virou
#    acesso interativo irrestrito.
printf 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f backup@controller\n' \
    > /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys

# 3. agendamento novo, sem nada de suspeito no comando
printf '17 3 * * * root /usr/bin/env true\n' > /etc/cron.d/metrics-rotate

# 4. regra de sudo nova, restrita a um comando que não é primitiva de escalada
printf 'deploy ALL=(root) NOPASSWD: /usr/bin/env true\n' > /etc/sudoers.d/50-deploy
chmod 440 /etc/sudoers.d/50-deploy
sleep 0.2`

func init() {
	Register(Scenario{
		ID:   "DR1-drift-de-persistencia",
		Desc: "quatro mudanças legítimas em forma, invisíveis para o catálogo de checks",
		// A matriz inteira: o que se está provando é leitura de árvore de
		// systemd, de cron e de sudoers, e essas árvores têm layout diferente
		// entre Debian e Alpine.
		Images: matriz,
		Plant:  driftPlantado,
		Cmd:    "drift",
		// O `-vv` vem ANTES do posicional: o flag da stdlib para de parsear no
		// primeiro argumento que não é flag.
		Args: []string{"-vv", "/tmp/antes.json"},
		Expect: []Expect{
			// O ExecStart trocado. É o achado que resume a feature inteira: as
			// duas pontas são caminhos de sistema, e o que denuncia é a
			// transição.
			{ID: "persist.unit_drift", Sev: "WARN", Subject: "metrics-agent.service",
				Evidence: "o campo `exec` mudou"},
			{ID: "persist.unit_drift", Evidence: "sleep 30"},
			{ID: "persist.unit_drift", Evidence: "tail -f /dev/null"},

			// O `command=` retirado de uma chave que continua a mesma. É a
			// escalada mais silenciosa desta lista: nada foi acrescentado ao
			// arquivo, e o fingerprint não mudou.
			{ID: "persist.authorized_key_drift", Sev: "WARN",
				Evidence: "o campo `options` mudou"},
			{ID: "persist.authorized_key_drift", Evidence: "command="},

			{ID: "persist.cron_drift", Sev: "WARN", Evidence: "metrics-rotate"},
			{ID: "priv.sudo_drift", Sev: "WARN", Evidence: "50-deploy"},

			// A COBERTURA DA COMPARAÇÃO. Um drift vazio não distingue "nada
			// mudou" de "nada foi comparado", e este achado é quem responde.
			{ID: "integrity.drift_coverage", Evidence: "comparadas SEM restrição"},
		},
		// A janela é um INTERVALO, e nunca um instante: a ferramenta não estava
		// presente no momento da mudança.
		ExpectOutput: []string{"mudou ENTRE"},
		// MEDIDO: quatro mudanças plantadas, quatro avisos. O orçamento existe
		// para que uma quinta — vinda de ruído, e não do plantio — falhe aqui.
		MaxWarn: 4,
		Exit:    1,
	})

	Register(Scenario{
		ID: "DR2-drift-sem-mudanca-e-silencio",
		Desc: "duas coletas do MESMO contêiner parado: o drift precisa ser VAZIO, " +
			"senão a feature é ruído",
		Images: matriz,
		// O CONTRÁRIO do DR1, e vale tanto quanto: um detector de mudança que
		// acusa sem mudança é pior que nenhum, porque a primeira execução já
		// ensina a ignorá-lo.
		//
		// Este cenário mede o PISO DE RUÍDO da comparação. Foi ele que pegou o
		// defeito mais escorregadio da implementação: o dump é redigido ao ser
		// escrito e o host vivo não é, então `ExecStartPre=-plymouth` virava
		// `-p<redacted>` de um lado só — nove units "mudaram" sem nada ter
		// mudado. A normalização agora é a mesma nos dois lados.
		Plant: "\n/aletheia collect --out /tmp/antes.json >/dev/null 2>&1\nsleep 0.2",
		Cmd:   "drift",
		Args:  []string{"/tmp/antes.json"},
		Forbid: []string{
			"persist.unit_drift",
			"persist.cron_drift",
			"persist.authorized_key_drift",
			"priv.sudo_drift",
		},
		// A comparação em si continua sendo reportada: silêncio sobre o drift
		// não pode ser silêncio sobre o alcance dele.
		Expect: []Expect{
			{ID: "integrity.drift_coverage"},
		},
		MaxWarn: SemAvisos,
	})

	Register(Scenario{
		ID: "DR3-drift-com-a-ordem-trocada",
		Desc: "os dois retratos na ordem errada: a ferramenta precisa RECUSAR, " +
			"e não responder ao contrário",
		Images: minimal,
		// Trocar a ordem de dois caminhos parecidos é o erro mais fácil de
		// cometer nesta CLI, e o resultado era um relatório coerente e AO
		// CONTRÁRIO: o que foi removido saía como "apareceu", com um intervalo
		// negativo impresso com confiança total —
		//
		//	mudou ENTRE 2026-08-21T20:55:50Z e 2026-08-21T20:55:37Z
		//
		// O único jeito de perceber era ler os carimbos de hora na evidência.
		Plant: `
/aletheia collect --out /tmp/velho.json >/dev/null 2>&1
sleep 1.1
printf '17 3 * * * root /usr/bin/env true\n' > /etc/cron.d/depois
/aletheia collect --out /tmp/novo.json >/dev/null 2>&1`,
		Cmd:  "drift",
		Args: []string{"/tmp/novo.json", "/tmp/velho.json"},
		ExpectOutput: []string{
			"MAIS NOVO que o segundo",
			"inverta os dois argumentos",
		},
		// NADA de achado: a recusa é ANTES da comparação. Um relatório invertido
		// é pior que nenhum.
		ForbidOutput: []string{"mudou ENTRE"},
		Forbid:       []string{"persist.cron_drift", "integrity.drift_coverage"},
		Exit:         3,
		MaxWarn:      SemAvisos,
	})
}

// DR4: a segunda leva de famílias, e a CORRELAÇÃO.
//
// O plantio muda sete superfícies que o retrato anterior conhecia, e nenhuma
// delas depende de o kernel do contêiner cooperar. Duas coisas são provadas
// aqui e em nenhum outro lugar:
//
//	toda família comparada é LIDA por algum check — o motor passou a comparar
//	conta, porta, módulo e CA antes de existir check para elas, e o relatório
//	saía limpo sobre mudanças que a ferramenta tinha na mão
//
//	a mudança encontra o ACHADO que fala da mesma coisa — a conta uid 0 dispara
//	priv.uid_zero por conta própria, e o drift precisa marcá-la em vez de
//	produzir um segundo relatório paralelo sobre a mesma linha
const driftSegundaLeva = `
mkdir -p /boot/grub /etc/ssl/certs
printf 'menuentry x {\n\tlinux /vmlinuz root=/dev/sda1 ro quiet\n}\n' > /boot/grub/grub.cfg
printf 'passwd: files\ngroup: files\nhosts: files dns\n' > /etc/nsswitch.conf
cp /bin/sleep /usr/local/bin/agente 2>/dev/null || cp /bin/sleep /usr/bin/agente
/helper listen 127.0.0.1:9101 &
sleep 0.3

/aletheia collect --out /tmp/antes.json >/dev/null 2>&1

# --- daqui para baixo, o que mudou ---

# 1. CONTA com uid 0. Dispara priv.uid_zero por conta própria: é o par que a
#    correlação precisa para provar que ela liga as duas leituras.
printf 'suporte:x:0:0:suporte:/root:/bin/sh\n' >> /etc/passwd

# 2. GRUPO: alguém entra num grupo que equivale a root
printf 'plugdev:x:46:suporte\n' >> /etc/group

# 3. PRÉ-CARGA: uma linha que injeta código em todo processo dinâmico do host
printf '/tmp/.libx.so\n' > /etc/ld.so.preload

# 4. BIT SETUID num binário que não tinha
chmod u+s /usr/bin/agente 2>/dev/null || chmod u+s /usr/local/bin/agente

# 5. PORTA nova em escuta
/helper listen 127.0.0.1:9102 &

# 6. LINHA DE COMANDO DO KERNEL: o que o kernel foi mandado ser
printf 'menuentry x {\n\tlinux /vmlinuz root=/dev/sda1 ro quiet apparmor=0\n}\n' > /boot/grub/grub.cfg

# 7. NSS: uma lib nova no caminho de toda resolução de nome e de usuário
printf 'passwd: files extra\ngroup: files\nhosts: files dns\n' > /etc/nsswitch.conf

# 8. O MESMO programa passa a rodar TAMBÉM sob outra identidade. É a forma que
#    a família de programa existe para pegar — e a única que sobrevive à
#    volatilidade da presença.
#    O su fica em SEGUNDO PLANO inteiro, e nao o comando dentro dele: com o
#    ampersand do lado de dentro, o filho morre junto com o shell do su.
su -s /bin/sh nobody -c '/helper sleep 600' &
sleep 1.5`

func init() {
	Register(Scenario{
		ID:     "DR4-drift-das-sete-superficies",
		Desc:   "sete superfícies mudadas, e a mudança encontrando o achado que fala dela",
		Images: matriz,
		// SYS_PTRACE porque a família de programa depende de LER o exe de
		// processo alheio, e o contêiner não a tem por padrão: sem ela, root
		// dentro do contêiner recebe EACCES em /proc/<pid>/exe de outro
		// usuário, e o coletor declara `exe_denied` — que é a resposta certa e
		// deixa o processo sem identidade estável para comparar.
		Caps:  []string{"SYS_PTRACE"},
		Plant: driftSegundaLeva,
		Cmd:   "drift",
		// --all-checks porque a correlação só existe quando os DOIS lados estão
		// no mesmo relatório: o achado que acusa e a mudança que o data.
		Args: []string{"-vv", "--all-checks", "/tmp/antes.json"},
		Expect: []Expect{
			{ID: "priv.account_drift", Subject: "suporte"},
			{ID: "priv.account_drift", Subject: "plugdev"},
			{ID: "persist.preload_drift", Evidence: "/tmp/.libx.so"},
			{ID: "integrity.suid_drift", Evidence: "setuid"},
			{ID: "net.listen_drift", Evidence: "9102"},
			{ID: "kernel.surface_drift", Evidence: "apparmor=0"},
			{ID: "integrity.trust_drift", Evidence: "extra"},
			{ID: "proc.program_drift", Evidence: "uids"},

			// A CORRELAÇÃO: o achado que já existia sobre a conta uid 0 sai
			// MARCADO com a mudança que o data.
			{ID: "priv.uid_zero", Subject: "suporte",
				Evidence: "E O OBJETO DESTE ACHADO MUDOU"},
		},
		ExpectOutput: []string{"mudou desde o retrato"},
		Exit:         2,
		// MEDIDO: doze. O teto esteve em 24 sob o mesmo comentário — doze de
		// folga não travam ruído nenhum, e chamar de "medido" um número que
		// ninguém mediu é a mesma classe de afirmação falsa que o resto desta
		// base persegue.
		//
		// Os doze incluem DOIS de proc.program_drift, e os dois são
		// consequência real do plantio: o su roda o helper E um shell sob
		// nobody, então os dois executáveis passam a ter outro uid no conjunto.
		MaxWarn: 12,
	})
}
