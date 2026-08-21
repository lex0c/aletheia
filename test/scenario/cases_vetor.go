package scenario

// As três perguntas que a auditoria contra o runbook mostrou que faltavam.
//
//	W1  §36.4  root executa o que outra pessoa escreve — a rota de escalada
//	           mais comum na prática, e a que menos gente enxerga
//	W2  §15    o backend que só o proxy local usa, e está aberto para a rede:
//	           quem vier de fora pula o WAF, a autenticação e o rate limit
//	W3  §14    a heurística que ELIMINA hipótese: o backdoor rodou como um
//	           usuário, e só serviço daquele usuário pode ser a entrada

func init() {
	Register(Scenario{
		ID:     "W1-root-executa-o-que-outro-escreve",
		Desc:   "cron de root chama um script cujo dono é outra conta, e outro que qualquer um escreve",
		Images: []string{"debian:12", "alpine:3.20"},
		// Não é vulnerabilidade de software: é permissão. Quem tiver a conta
		// `app` vira root no próximo minuto, sem exploit nenhum.
		// O `mkdir -p /etc/cron.d` não é detalhe: no Alpine o diretório não
		// existe de fábrica — o busybox crond usa /etc/crontabs —, e sem ele o
		// plantio falha em silêncio e o cenário provaria o contrário do que quer.
		Plant: `mkdir -p /opt/app /usr/local/lib/x /etc/cron.d
			printf '#!/bin/sh\nexit 0\n' > /opt/app/housekeeping.sh
			chmod 755 /opt/app/housekeeping.sh
			chown 1000:1000 /opt/app/housekeeping.sh
			printf '#!/bin/sh\nexit 0\n' > /usr/local/lib/x/rotate.sh
			chmod 777 /usr/local/lib/x/rotate.sh
			printf '*/5 * * * * root /opt/app/housekeeping.sh\n' > /etc/cron.d/app
			printf '17 3 * * * root /usr/local/lib/x/rotate.sh\n' >> /etc/cron.d/app`,
		Expect: []Expect{
			// Dono não-root: escala para AQUELA conta, e é a forma que mais
			// aparece em servidor de verdade.
			{ID: "priv.root_runs_writable", Sev: "WARN", Subject: "/opt/app/housekeeping.sh"},
			{ID: "priv.root_runs_writable", Evidence: "não é root, e o dono reescreve"},
			// Gravável por todos: não precisa de conta nenhuma antes.
			{ID: "priv.root_runs_writable", Sev: "CRITICAL", Subject: "/usr/local/lib/x/rotate.sh"},
			{ID: "priv.root_runs_writable", Evidence: "QUALQUER usuário"},
			// O que muda a AÇÃO do operador: a correção é um chown, não um
			// incidente de software. Estava sendo cobrado do relatório mesmo com
			// -v, e ali não cabe — é a terceira linha de evidência, e o -v corta
			// em maxEvidencia. No JSONL está inteira.
			{ID: "priv.root_runs_writable", Evidence: "não é vulnerabilidade de software: é permissão"},
		},
		Exit: 2,
	})

	Register(Scenario{
		ID:     "W2-backend-so-do-proxy-mas-aberto",
		Desc:   "serviço que só o loopback usa, escutando na rede inteira: o atacante pula o proxy",
		Images: []string{"debian:12"},
		// O par é o teste: um serviço aberto COM uso local (dispara) e um
		// aberto que recebe de fora (não dispara — é servidor mesmo).
		Plant: `ip addr add 203.0.113.7/32 dev lo 2>/dev/null || true
			/helper listen 0.0.0.0:4100 &
			/helper listen 0.0.0.0:8443 &
			sleep 0.4
			/helper connect 127.0.0.1:4100 &
			/helper connect 203.0.113.7:8443 &
			sleep 0.6`,
		Caps:      []string{"NET_ADMIN"},
		NoNetwork: true,
		Expect: []Expect{
			{ID: "net.backend_exposed", Sev: "WARN", Subject: "4100"},
			{ID: "net.backend_exposed", Evidence: "vêm todas do LOOPBACK"},
		},
		// A 8443 recebe de um endereço público: é servidor de verdade, e um
		// check que a acusasse acusaria todo nginx do mundo.
		ForbidOutput: []string{"0.0.0.0:8443"},
		Exit:         -1,
	})

	Register(Scenario{
		ID:     "W3-vetor-estreitado-pelo-usuario",
		Desc:   "o suspeito roda como um uid, e só o serviço daquele uid pode ser a porta de entrada",
		Images: []string{"debian:12"},
		// Dois serviços, dois usuários. O processo suspeito roda como um deles,
		// e é isso que elimina o outro da lista de hipóteses.
		// A conta precisa EXISTIR: `su` recusa uid que não está no passwd, e sem
		// isso o plantio falha em silêncio — os dois processos nasceriam como
		// root e o cenário provaria o contrário do que quer.
		Plant: `useradd -u 1000 -M -s /bin/sh app 2>/dev/null || true
			cp /helper /tmp/.x
			chown 1000:1000 /tmp/.x
			mkdir -p /opt/svc && cp /helper /opt/svc/app
			su app -s /bin/sh -c '/opt/svc/app listen 0.0.0.0:8080' &
			su app -s /bin/sh -c '/tmp/.x sleep 300' &
			/helper listen 0.0.0.0:9000 &
			sleep 1`,
		// SYS_PTRACE não é conveniência: ler /proc/<pid>/exe de processo de OUTRO
		// uid exige privilégio de ptrace, e o docker não o dá por padrão. Num
		// host de verdade o root o tem — sem esta linha, o cenário mediria a
		// limitação do contêiner em vez do check.
		Caps: []string{"SYS_PTRACE"},
		Expect: []Expect{
			{ID: "net.vector_same_user", Sev: "INFO", Subject: "uid 1000"},
			{ID: "net.vector_same_user", Evidence: "8080"},
		},
		// O serviço que roda como root não entra: um RCE nele daria root, não
		// o uid 1000 — e citá-lo seria o contrário de estreitar o vetor.
		Forbid: []string{},
		Exit:   -1,
	})
}
