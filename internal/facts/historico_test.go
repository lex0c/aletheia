package facts

import (
	"strings"
	"testing"
)

// As formas de desligar o histórico, e o que separa cada uma.
//
// As três primeiras deixam RASTRO NEGATIVO: o arquivo some, zera ou fica do
// tamanho errado, e quem procura acha a ausência. As duas últimas não deixam
// nada — o histórico continua ligado, do tamanho de sempre, e o que o invasor
// digitou simplesmente nunca entrou. São as que faltavam.
func TestDesligaHistoricoConheceAsFormas(t *testing.T) {
	desliga := []struct{ linha, contem string }{
		{"unset HISTFILE", "sem onde gravar"},
		{"export HISTFILE=/dev/null", "gravado no vazio"},
		{"HISTSIZE=0", "nenhuma linha"},
		{"set +o history", "desligado"},
		{"shopt -u histappend", "SOBRESCREVER"},
		{"export HISTIGNORE='*curl*:*wget*'", "SELETIVO"},
	}
	for _, c := range desliga {
		motivo, ok := DesligaHistorico(c.linha)
		if !ok {
			t.Errorf("%q devia ser reconhecida como desligamento", c.linha)
			continue
		}
		if !strings.Contains(motivo, c.contem) {
			t.Errorf("%q → %q, queria conter %q", c.linha, motivo, c.contem)
		}
	}
}

// E o que NÃO pode disparar: configuração normal de shell. Um HISTSIZE grande é
// o contrário de apagar rastro, e um HISTCONTROL só com erasedups é higiene de
// duplicata, não de evidência.
func TestDesligaHistoricoNaoPegaConfiguracaoNormal(t *testing.T) {
	for _, ln := range []string{
		"HISTSIZE=10000",
		"export HISTFILESIZE=20000",
		// HISTCONTROL inteiro fica de fora: `ignoreboth` é o estado de FÁBRICA do
		// Debian (via /etc/skel) e do CentOS (via /etc/profile). Ver historico.go.
		"HISTCONTROL=erasedups",
		"export HISTCONTROL=ignorespace",
		"HISTCONTROL=ignoreboth:erasedups",
		// Lista de comandos curtos é higiene de ruído, não apagamento: sem `*`
		// ela não casa por substring e não esconde nada.
		"HISTIGNORE='ls:cd:pwd:exit'",
		// As três formas que TÊM curinga e não escondem nada: o trecho da FAQ do
		// bash, o `ls *` com argumento, e o glob de linha começada por espaço.
		"HISTIGNORE='&:[ ]*:exit:ls:bg:fg:history:clear'",
		"HISTIGNORE='ls:ls *:cd *:pwd:exit'",
		"export HISTIGNORE=\"[ \t]*\"",
		"HISTTIMEFORMAT='%F %T '",
		"shopt -s histappend",
		"export HISTFILE=$HOME/.bash_history",
		"# unset HISTFILE",
		"HISTIGNORE=",
	} {
		if motivo, ok := DesligaHistorico(ln); ok {
			t.Errorf("%q não é desligamento de histórico, e saiu como %q", ln, motivo)
		}
	}
}
