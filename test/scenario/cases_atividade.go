package scenario

// ATIVIDADE: o que aconteceu no host, e até onde alguém olhou.
//
// É a superfície do comprometimento SEM MALWARE — credencial roubada,
// ferramenta legítima, nenhum arquivo para achar. O que estes cenários provam
// não é que a ferramenta acha algo: é que ela nunca transforma "não olhei" em
// "não aconteceu".
//
//	A1  btmp fechado sem root       LACUNA: NÃO EXAMINADAS, e nunca "0 recusas"
//	A1b btmp ausente                ESCOPO: o host não registra, e não é lacuna
//	A2  journald-only               ESCOPO declarado, com a via nomeada
//	A3  o mesmo login em duas fontes  UM evento, com as duas testemunhas
//	A4  --around                    a vizinhança do alerta, e só ela
//	A5  --summary                   os agregados contam o que a timeline mostra

func init() {
	Register(Scenario{
		ID:   "A1-btmp-fechado-e-lacuna-nunca-zero-recusas",
		Desc: "sem root o btmp é ilegível: o bloco de atividade do wtf diz NÃO EXAMINADAS, jamais nenhuma tentativa",
		// É o caminho PADRÃO de toda varredura sem privilégio, e não o exótico:
		// o btmp é 0660 root:utmp já na imagem de fábrica do Debian. "0 recusas"
		// ali seria a leitura tranquilizadora sobre um arquivo que ninguém
		// abriu — e é a forma exata de "não olhei" virando "não aconteceu".
		//
		// Sem plantio de propósito: o estado de fábrica JÁ é o caso. Plantar
		// aqui provaria que a ferramenta lê o que o cenário escreveu, e não o
		// que a distribuição entrega.
		Images: []string{"debian:12"},
		Cmd:    "wtf",
		User:   "1000",
		ExpectOutput: []string{
			"atividade · solicitado 24h",
			"NÃO EXAMINADAS",
			// O MOTIVO viaja junto: é ele que diz o que fazer a seguir.
			"permission denied",
		},
		ForbidOutput: []string{
			"recusadas  nenhuma",
			// "nova" afirma que o host NUNCA viu aquela origem; o que se sabe é
			// só que ela não está nos registros que sobraram. A produção diz
			// "não observadas anteriormente", e esta proibição é a trava para
			// quem for encurtar a frase um dia.
			"novas",
		},
		// Medido nas duas imagens: o contêiner de fábrica não produz aviso.
		MaxWarn: SemAvisos,
		// INCOMPLETE, porque sem root a cobertura cai — e é isso mesmo.
		Exit: -1,
	})

	Register(Scenario{
		ID:   "A1b-btmp-ausente-e-escopo-nao-lacuna",
		Desc: "onde o btmp não existe, o bloco diz que o host não registra tentativa recusada — escopo, não lacuna",
		// A outra metade do par, e a distinção que o resto da ferramenta já
		// sustenta em todo lugar: "este host não tem o arquivo" e "eu não pude
		// ler o arquivo" mandam o operador para lugares diferentes. O Alpine
		// não traz wtmp nem btmp.
		Images: []string{"alpine:3.20"},
		Cmd:    "wtf",
		User:   "1000",
		ExpectOutput: []string{
			"btmp ausente",
			"não há btmp neste host",
		},
		ForbidOutput: []string{
			// Ausência de FONTE não é lacuna de leitura, e trocar as duas faria
			// o operador procurar privilégio para ler um arquivo inexistente.
			"NÃO EXAMINADAS",
			"recusadas  nenhuma",
		},
		MaxWarn: SemAvisos,
		Exit:    -1,
	})

	Register(Scenario{
		ID:   "A2-journald-only-e-escopo-com-a-via-nomeada",
		Desc: "sem auth.log, a família sai FORA DE ESCOPO e o comando nomeia por onde ir — nunca silêncio com cara de resposta",
		// Debian 12, Fedora, RHEL moderno e Arch não instalam rsyslog. Num
		// comando chamado `activity`, deixar isso implícito seria o pior lugar
		// possível para um silêncio.
		Images: []string{"debian:12"},
		Cmd:    "activity",
		Args:   []string{"--since", "24h"},
		ExpectOutput: []string{
			"cobertura",
			// AMARRADO À FAMÍLIA. Sem o prefixo, o cenário passava por
			// `cron`/`audit`, que saem fora de escopo em qualquer contêiner —
			// e continuaria passando num host onde `auth` EXISTE, que é
			// exatamente o oposto do que ele afirma.
			"auth   FORA DE ESCOPO",
			// A via precisa ser EXECUTÁVEL, e não só conter a palavra: a
			// primeira versão imprimia `journalctl --since -±5m de …`.
			`journalctl --utc --since "`,
		},
		ForbidOutput: []string{
			"nenhuma atividade",
			"nada aconteceu",
			// Fora de escopo NÃO é lacuna de leitura, e trocar as duas manda o
			// operador procurar privilégio para ler um arquivo inexistente.
			"auth   NÃO EXAMINADA",
		},
		// O comando RECONSTRÓI e não conclui: sai 0 sempre, salvo erro de
		// invocação. É a mesma separação do `info`.
		Exit: 0,
	})

	Register(Scenario{
		ID:   "A3-mesmo-login-em-duas-fontes-e-um-evento",
		Desc: "o registro binário e a linha de texto do MESMO login viram um evento com duas testemunhas, ligadas pelo pid",
		// O produto do comando. O wtmp tem o instante em epoch e a tty; o log
		// tem o método e o fingerprint da chave. Sem a fusão, o operador vê o
		// mesmo login duas vezes e nenhuma das duas linhas está completa.
		//
		// O pid é a ligação: o ut_pid do wtmp É o pid do sshd da sessão, e o
		// envelope do syslog carrega o mesmo número. O helper escreve 1000+i.
		Images: []string{"debian:12"},
		Cmd:    "activity",
		Args:   []string{"--since", "24h"},
		Plant: `/helper utmp /var/log/wtmp 7 deploy 185.44.1.7 1
			printf '%s alvo sshd[1000]: Accepted publickey for deploy from 185.44.1.7 port 55123 ssh2: RSA SHA256:PlantadaNoCenario\n' \
				"$(date -u '+%b %e %H:%M:%S')" > /var/log/auth.log`,
		ExpectOutput: []string{
			// A prova da fusão: as duas testemunhas na MESMA linha. Sem ela
			// sairiam duas linhas, e nenhuma traria este par.
			"wtmp+log:/var/log/auth.log",
			// A FORÇA da ligação sai impressa: "mesmo pid" e "mesma conta e
			// origem no mesmo dia" não são a mesma evidência.
			"⇄pid",
			// O que só o LOG tem, sobrevivendo à fusão.
			"SHA256:PlantadaNoCenario",
			"publickey",
			// O que só o REGISTRO BINÁRIO tem.
			"pts/0",
		},
		Exit: 0,
	})

	Register(Scenario{
		ID:   "A4-around-recorta-a-vizinhanca-do-alerta",
		Desc: "--around centra a janela no horário do alerta: traz o que aconteceu perto e deixa fora o que não",
		// A flag de incidente. Descobre-se "o alerta foi 03:17" e pergunta-se o
		// que houve em volta — sem ter de calcular --since e --until de cabeça.
		Images: []string{"debian:12"},
		Cmd:    "activity",
		Args:   []string{"--around", "$(cat /tmp/t0)", "--window", "5m"},
		Plant: `date -u '+%Y-%m-%dT%H:%M:%SZ' > /tmp/t0
			{
			  printf '%s alvo sudo[2100]: perto : TTY=pts/2 ; PWD=/ ; USER=root ; COMMAND=/bin/perto\n' \
				"$(date -u -d '-2 minutes' '+%b %e %H:%M:%S')"
			  printf '%s alvo sudo[2200]: longe : TTY=pts/3 ; PWD=/ ; USER=root ; COMMAND=/bin/longe\n' \
				"$(date -u -d '-40 minutes' '+%b %e %H:%M:%S')"
			} > /var/log/auth.log`,
		ExpectOutput: []string{"/bin/perto"},
		ForbidOutput: []string{
			// Quarenta minutos está fora de um raio de cinco: se ele aparecer, o
			// recorte não recortou, e o operador leria como vizinhança do alerta
			// uma coisa que aconteceu meia hora antes.
			"/bin/longe",
		},
		Exit: 0,
	})

	Register(Scenario{
		ID:   "A5-agregados-contam-o-que-a-timeline-mostra",
		Desc: "--summary conta o que a linha do tempo mostra, e traz a cobertura junto",
		// Um agregado calculado por outro caminho daria dois números para a
		// mesma pergunta — o defeito que AgregadoDeLog documenta ter recusado.
		// E o rodapé de cobertura é obrigatório em TODAS as saídas: uma tabela
		// sem o alcance de quem a testemunhou afirma que aquilo é tudo.
		Images: []string{"debian:12"},
		Cmd:    "activity",
		Args:   []string{"--summary", "--since", "24h"},
		Plant: `/helper utmp /var/log/wtmp 7 deploy 185.44.1.7 3
			/helper utmp /var/log/btmp 7 root 203.0.113.9 9
			chmod 644 /var/log/btmp`,
		ExpectOutput: []string{
			// As CONTAGENS, e não só as chaves. Sem elas o cenário passava com
			// qualquer número — inclusive com a rajada de 9 recusas colapsada
			// em 1, que foi um defeito real desta feature.
			//
			// A forma entre parênteses do --summary é ESTÁVEL; a tabela do
			// --group-by alinha por coluna, e afirmar padding seria testar a
			// renderização achando que se testa o agregado. A tabela tem teste
			// de unidade em internal/report.
			"auth.login.accepted (3)",
			"auth.login.refused (9)",
			"185.44.1.7 (3)",
			"deploy (3)",
			"cobertura",
			"wtmp",
			"btmp",
		},
		Exit: 0,
	})
}
