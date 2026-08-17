package scenario

// A coleta de evidência (§19) — o único comando que ESCREVE.
//
// Os testes unitários provam a mecânica: hash dos dois lados, recusa de
// sobrescrever, nome de arquivo que não escapa do destino. O que só um contêiner
// prova é o /proc de verdade — que é justamente onde mora a razão de o comando
// existir:
//
//	V1  o binário foi APAGADO e o processo continua vivo. /proc/<pid>/exe ainda
//	    abre o arquivo, e um `kill` destrói a última cópia
//	V2  o binário NUNCA existiu em disco (memfd), e a região anônima gravável e
//	    executável ao lado dele não existe em lugar nenhum além daquela RAM
//	V3  sem privilégio: metade da coleta falha, e a falha precisa APARECER
//
// O contrato de saída aqui não é achado, é manifesto: por isso os cenários
// afirmam por ExpectOutput, e não por Expect.

func init() {
	Register(Scenario{
		ID:     "V1-preserva-exe-apagado",
		Desc:   "o binário foi apagado do disco e o processo continua vivo: a cópia em /proc é a última que existe",
		Images: []string{"debian:12", "alpine:3.20"},
		Cmd:    "preserve",
		// O mesmo plantio do cenário 11, que é o que o scan REPORTA. A diferença
		// é o que se faz depois de reportar: ali a ferramenta manda preservar,
		// aqui ela preserva.
		Plant: `cp /helper /tmp/.y
			/tmp/.y sleep 300 &
			echo $! > /tmp/pid
			sleep 0.4
			rm -f /tmp/.y
			mkdir -p /ir`,
		Args: []string{"--out", "/ir", "--pid", "$(cat /tmp/pid)"},
		ExpectOutput: []string{
			"PRESERVADO em /ir",
			// A nota é o que transforma um arquivo no diretório em evidência: ela
			// diz por que ESTA cópia é insubstituível.
			"foi APAGADO do disco",
			"morre junto com o processo",
			"sha256=",
			// A promessa que o comando faz ao operador, e que precisa estar
			// escrita na saída dele.
			"NADA foi executado",
		},
		// Nenhuma lacuna: tudo o que foi pedido foi guardado.
		ForbidOutput: []string{"NÃO PRESERVADO", "O ALVO MUDOU"},
		Exit:         0,
	})

	Register(Scenario{
		ID:     "V2-preserva-memfd-e-memoria-anonima",
		Desc:   "execução fileless e região anônima RWX: as duas coisas que só existem enquanto o processo viver",
		Images: []string{"debian:12"},
		Cmd:    "preserve",
		// SYS_PTRACE não é conveniência do rig: abrir /proc/<pid>/mem de outro
		// processo EXIGE privilégio de ptrace, e é exatamente isso que a mensagem
		// de falha do comando diz ao operador. O cenário V3 prova o outro lado.
		Caps: []string{"SYS_PTRACE"},
		Plant: `/helper memfd /helper sleep 300 &
			echo $! > /tmp/pid-memfd
			/helper rwx &
			echo $! > /tmp/pid-rwx
			sleep 0.5
			mkdir -p /ir`,
		Args: []string{
			"--out", "/ir",
			"--pid", "$(cat /tmp/pid-memfd)",
			"--pid", "$(cat /tmp/pid-rwx)",
			"--mem",
		},
		ExpectOutput: []string{
			// O memfd: não há caminho em disco para citar, e é essa a notícia.
			"execução fileless",
			"nunca houve arquivo em disco",
			// O dump de memória, e a região que justifica ele existir.
			"GRAVÁVEL E EXECUTÁVEL",
			"não existe em disco em lugar nenhum",
		},
		// A alternativa que esta implementação recusa é o gcore, que faz attach:
		// para o processo e escreve TracerPid. Um alvo parado no meio da coleta
		// muda o que se está medindo — e um implante que lê o próprio TracerPid
		// sabe que está sendo olhado.
		ForbidOutput: []string{"NÃO PRESERVADO"},
		Exit:         0,
	})

	Register(Scenario{
		ID:     "V3-coleta-parcial-declarada",
		Desc:   "sem privilégio, metade da coleta falha — e a metade que falhou aparece com o mesmo destaque da que deu certo",
		Images: []string{"debian:12", "alpine:3.20"},
		Cmd:    "preserve",
		User:   "1000",
		Plant:  `mkdir -p /tmp/ir`,
		// Um arquivo que se lê e um que não: é a situação real de um respondedor
		// que rodou sem sudo e não percebeu.
		Args: []string{"--out", "/tmp/ir", "--file", "/etc/hostname", "--file", "/etc/shadow"},
		ExpectOutput: []string{
			"NÃO PRESERVADO — isto é lacuna de evidência",
			"/etc/shadow",
			// O que deu certo continua saindo: coleta parcial é parcial, não
			// abortada. Perder /etc/hostname porque /etc/shadow falhou seria
			// jogar fora evidência boa.
			"file-etc_hostname.bin",
		},
		// Um exit 0 aqui seria a mentira central da ferramenta, na versão que
		// escreve: o operador guardaria o diretório achando que tem tudo.
		Exit: 1,
	})
}
