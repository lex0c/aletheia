package scenario

// O comando `info` — a pergunta que vem ANTES do veredito.
//
// Ele não conclui nada, então não tem achado a afirmar: o contrato dele é o
// TEXTO. Por isso estes cenários usam ExpectOutput, e por isso o harness precisa
// tratá-los como o `preserve` — não há linha de cobertura porque não houve
// varredura.
//
//	I1  o censo, com o teto e o padrão nomeados
//	I2  o dossiê de um processo cujo nome mente

func init() {
	Register(Scenario{
		ID:     "I1-censo-com-teto-e-padrao",
		Desc:   "trinta cópias do mesmo comando sob um usuário: o censo conta as tarefas, compara com o teto e NOMEIA a repetição",
		Images: []string{"debian:12"},
		Cmd:    "info",
		Args:   []string{"process"},
		// Trinta cópias do MESMO comando, com o mesmo usuário. É a forma que o
		// caso real trouxe — 400 delas —, no tamanho que cabe num contêiner.
		Plant: `useradd -u 1500 -M -s /bin/sh app 2>/dev/null || true
			i=0
			while [ $i -lt 30 ]; do
				su app -s /bin/sh -c '/helper sleep 300' &
				i=$((i + 1))
			done
			sleep 1`,
		Caps: []string{"SYS_PTRACE"},
		ExpectOutput: []string{
			"CENSO",
			"tarefas (processos + threads)",
			// O nome, e não o número: é o nome que o operador digitou no comando
			// que falhou.
			"app",
			// A contagem por executável REAL — o que separa trinta cópias de um
			// implante de trinta cópias de um serviço.
			"por executável REAL",
			"/helper",
			// E a frase que o `ps` não dá.
			"PADRÃO RECONHECIDO",
		},
		Exit: 0,
	})

	Register(Scenario{
		ID:     "I2-dossie-de-processo-que-mente",
		Desc:   "o dossiê de um processo cujo argv se diz thread de kernel: as três identidades lado a lado",
		Images: []string{"debian:12"},
		Cmd:    "info",
		// O PID é descoberto no plantio e chega pelo shell, que é o mesmo
		// mecanismo dos cenários de preserve.
		Plant: `/helper argv0 "[kworker/0:9]" /helper sleep 300 &
			sleep 0.5
			echo $! > /tmp/pid`,
		Args: []string{"process", "$(cat /tmp/pid)"},
		ExpectOutput: []string{
			"IDENTIDADE",
			// As três: o que o kernel diz, e os dois que o processo escolhe.
			"executável",
			"argv[0]",
			"[kworker/0:9]",
			// E a leitura que o operador precisa: elas não batem.
			"divergência",
			"o exe é o que o kernel diz",
			// O passo seguinte já vem preenchido com o pid.
			"preserve --out",
		},
		Exit: 0,
	})
}
