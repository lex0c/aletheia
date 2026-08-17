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
		MaxWarn:        0,
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
			ip addr add 51.91.190.241/32 dev lo
			mkdir -p /usr/local/sbin /etc/systemd/system/ssh.service.d
			cp /helper /usr/local/sbin/systemd-netlinkd
			/helper listen 51.91.190.241:8443 &
			sleep 0.4
			/usr/local/sbin/systemd-netlinkd connect 51.91.190.241:8443 &
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
