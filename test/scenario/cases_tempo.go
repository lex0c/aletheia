package scenario

// O eixo do TEMPO.
//
// Toda esta ferramenta é um retrato, e o cenário A3 media a consequência: um
// implante que só acorda depois não existe para nenhuma varredura feita antes.
// Não era lacuna de técnica — era propriedade do modelo, e nenhum check novo
// resolvia.
//
// Estes cenários exercitam o `watch`, que roda o mesmo scan em ciclo e reporta
// só o que muda. O que eles precisam provar é o par:
//
//	K1  o scan NÃO vê, e o watch VÊ         senão o comando não se paga
//	K2  o watch não inventa em host quieto  senão o operador aprende a ignorá-lo
//
// K3 mede a forma mais interessante que o tempo revela e um retrato jamais
// mostra: algo que aparece, some e volta. Um binário assim está sendo executado
// por gatilho, e isso é a assinatura de implante agendado — não de serviço.

func init() {
	Register(Scenario{
		ID:   "K1-ativacao-adiada-o-scan-nao-ve",
		Desc: "implante que só conecta depois: o retrato não pega, a vigília pega",
		// A PROVA de que o comando se paga. O mesmo host, os mesmos checks: o
		// que muda é só o eixo do tempo.
		Images:    minimal,
		Caps:      []string{"NET_ADMIN"},
		NoNetwork: true,
		Cmd:       "watch",
		Args:      []string{"--interval", "5s", "--full", "5s", "--for", "16s"},
		Plant: `ip link set lo up
			ip addr add 51.91.190.241/32 dev lo
			mkdir -p /usr/local/sbin
			cp /helper /usr/local/sbin/systemd-timesyncd
			/helper listen 51.91.190.241:8443 &
			# O implante só acorda no SEGUNDO ciclo. No instante do ciclo 0 não
			# há processo, não há conexão, não há nada: um scan comum termina
			# com "nenhum indicador coberto disparou" e está certo.
			( sleep 8; /usr/local/sbin/systemd-timesyncd connect 51.91.190.241:8443 ) &
			sleep 0.3`,
		Expect: []Expect{
			// O achado NASCE durante a vigília. Ele não existe no ciclo 0.
			{ID: "net.egress_unowned"},
			{ID: "integrity.no_package_owner", Subject: "/usr/local/sbin/systemd-timesyncd"},
		},
		// E o resumo tem que dizer que apareceu DEPOIS — a palavra é o produto.
		ExpectOutput: []string{
			"APARECEU — não estava aqui quando a vigília começou",
			"VIGÍLIA concluído",
		},
		Exit: 1,
	})

	Register(Scenario{
		ID:   "K1b-o-mesmo-implante-invisivel-ao-scan",
		Desc: "o CONTROLE do K1: o mesmo plantio, visto por um retrato",
		// Sem este par, o K1 prova só que o watch encontra algo — não que o
		// scan não encontrava. A alegação inteira do comando está na diferença
		// entre os dois, e ela tem que estar dentro da suíte: medida uma vez na
		// mão vira folclore na primeira mudança de código.
		//
		// Plantio IDÊNTICO ao do K1, palavra por palavra. O que muda é só o
		// comando e o tempo que ele fica olhando.
		Images:    minimal,
		Caps:      []string{"NET_ADMIN"},
		NoNetwork: true,
		Plant: `ip link set lo up
			ip addr add 51.91.190.241/32 dev lo
			mkdir -p /usr/local/sbin
			cp /helper /usr/local/sbin/systemd-timesyncd
			/helper listen 51.91.190.241:8443 &
			( sleep 8; /usr/local/sbin/systemd-timesyncd connect 51.91.190.241:8443 ) &
			sleep 0.3`,
		// O implante não aparece em lugar nenhum do relatório: não há processo,
		// não há conexão, e o binário em disco e nunca executado é a §8 — que
		// exige varredura de filesystem e não está neste caminho.
		//
		// E o scan está CERTO. Ele não errou: ele respondeu com precisão a
		// pergunta "o que está acontecendo agora", e a resposta era "nada".
		ForbidOutput: []string{"systemd-timesyncd"},
		Forbid:       []string{"net.egress_unowned"},
		// O aviso que sobra é o listener do próprio rig.
		Exit:           1,
		MustBeComplete: true,
	})

	Register(Scenario{
		ID:   "K2-vigilia-em-host-quieto",
		Desc: "host limpo vigiado por quatro ciclos não pode inventar mudança",
		// O contrapeso, e ele importa tanto quanto o K1: um `watch` que reporta
		// ruído a cada ciclo ensina o operador a ignorá-lo, e aí o achado de
		// verdade chega numa tela que ninguém lê.
		//
		// A armadilha real que isto pegou: dois achados de mesma chave no MESMO
		// ciclo — o binário que escuta em duas portas — saíam como "novo" e
		// "VOLTOU" com um segundo de diferença.
		Images: matriz,
		Cmd:    "watch",
		Args:   []string{"--interval", "5s", "--full", "5s", "--for", "16s"},
		Plant:  `true`,
		ExpectOutput: []string{
			"nada mudou",
			// E a ressalva junto, porque o silêncio de uma vigília tem tamanho:
			// o que roda e sai entre dois ciclos não é visto por nenhum deles.
			"o intervalo é o tamanho do buraco",
		},
		ForbidOutput: []string{"APARECEU", "VOLTOU", "SUMIU"},
		Exit:         0,
	})

	Register(Scenario{
		ID:   "K3-implante-que-vai-e-volta",
		Desc: "processo que aparece, sai e reaparece: a forma de algo com gatilho",
		// O que só o tempo mostra. Um serviço legítimo fica de pé; um implante
		// agendado nasce, faz o que veio fazer e morre — e volta no próximo
		// disparo. Nenhum retrato distingue os dois, e a diferença é o que separa
		// "software instalado à mão" de "algo sendo executado por alguém".
		Images:    minimal,
		Caps:      []string{"NET_ADMIN"},
		NoNetwork: true,
		Cmd:       "watch",
		Args:      []string{"--interval", "5s", "--full", "5s", "--for", "26s"},
		Plant: `ip link set lo up
			ip addr add 51.91.190.241/32 dev lo
			mkdir -p /usr/local/sbin
			cp /helper /usr/local/sbin/systemd-timesyncd
			/helper listen 51.91.190.241:8443 &
			# dois disparos, com um vale no meio: é o ciclo de um agendamento
			( sleep 3;  /usr/local/sbin/systemd-timesyncd connect 51.91.190.241:8443 & sleep 5; kill %1 2>/dev/null ) &
			( sleep 17; /usr/local/sbin/systemd-timesyncd connect 51.91.190.241:8443 ) &
			sleep 0.3`,
		ExpectOutput: []string{
			"VOLTOU — sumiu e reapareceu: é a forma de algo executado por gatilho",
		},
		Exit: 1,
	})

	Register(Scenario{
		ID:   "K4-beacon-periodico-com-gatilho-nomeado",
		Desc: "beacon curto e regular: mede o ritmo e diz QUEM dispara",
		// O que só as duas cadências juntas dão, e nenhuma sozinha.
		//
		// O amostrador vê o ritmo DE FORA: um destino que aparece, some e volta
		// a cada ~8s. Ele não sabe de onde vem — é só uma conexão que pulsa. A
		// varredura completa sabe quais agendamentos existem nesta máquina.
		// Cruzar os dois transforma "há automação aqui" em "é este timer".
		//
		// E o beacon dura DOIS segundos por disparo: um scan tem 25% de chance
		// de pegá-lo, e mesmo pegando veria uma conexão, não um padrão.
		Images:    minimal,
		Caps:      []string{"NET_ADMIN"},
		NoNetwork: true,
		Cmd:       "watch",
		Args:      []string{"--interval", "1s", "--full", "60s", "--for", "30s"},
		Plant: `ip link set lo up
			ip addr add 51.91.190.241/32 dev lo
			mkdir -p /usr/local/sbin /etc/systemd/system
			cp /helper /usr/local/sbin/systemd-timesyncd
			/helper listen 51.91.190.241:8443 &
			# O gatilho DECLARADO, que a varredura completa vai ler.
			printf '[Timer]\nOnUnitActiveSec=8s\n[Install]\nWantedBy=timers.target\n' \
				> /etc/systemd/system/systemd-timesyncd.timer
			# E o pulso, no mesmo ritmo do gatilho: 2s conectado, 6s fora.
			( while :; do
				/usr/local/sbin/systemd-timesyncd connect 51.91.190.241:8443 &
				p=$!; sleep 2; kill $p 2>/dev/null; sleep 6
			  done ) &
			sleep 0.3`,
		ExpectOutput: []string{
			// mediu o ritmo…
			"intervalo constante é AUTOMAÇÃO, não pessoa",
			// …e nomeou quem dispara, cruzando com o que a coleta completa leu
			"casa com um gatilho já lido nesta máquina",
			"systemd-timesyncd.timer",
			// e a ressalva do método sai junto, sempre
			"polling perde processo muito curto",
		},
		Exit: -1,
	})
}
