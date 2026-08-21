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
