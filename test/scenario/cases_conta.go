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
		ExpectOutput: []string{"2 sinais no mesmo alvo"},
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
