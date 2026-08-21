package facts

import (
	"testing"
	"time"

	"github.com/lex0c/aletheia/internal/env"
)

// A varredura por sinal foi acrescentada para cobrir pid_max inteiro, e quase
// custou caro: `kill(2)` não passa pelo procfs, então sob hidepid=2 ele responde
// por TODO processo do host enquanto a listagem esconde os dos outros usuários.
// Cada um deles vira "existe e não está na listagem" — a definição literal de
// PID oculto, e 56 falsos positivos no cenário 31-hidepid-sem-root.
//
// Estes testes travam o guarda. O caso hidepid=1 está aqui por igual peso: é a
// configuração CIS mais comum que existe, ali a listagem CONTINUA completa, e
// desligar a varredura nela custaria a faixa inteira sem ganho nenhum.
func TestSinalEhTestemunha(t *testing.T) {
	casos := []struct {
		nome    string
		opcoes  string
		root    bool
		querUso bool
	}{
		{"sem hidepid, sem root: a listagem é completa", "rw,nosuid,nodev,noexec", false, true},
		{"hidepid=2 sem root: o kill vê o que o /proc esconde", "rw,hidepid=2", false, false},
		{"hidepid=invisible sem root: o mesmo, pelo nome", "rw,hidepid=invisible", false, false},
		{"hidepid=2 COM root: root vê tudo nas duas vias", "rw,hidepid=2", true, true},
		{"hidepid=1 sem root: esconde o conteúdo, não a entrada", "rw,hidepid=1", false, true},
		{"hidepid=0 sem root: explicitamente desligado", "rw,hidepid=0", false, true},
	}
	for _, c := range casos {
		f := &Facts{Mounts: []Montagem{
			{Ponto: "/", Tipo: "ext4"},
			{Ponto: "/proc", Tipo: "proc", Opcoes: c.opcoes},
		}}
		e := &env.Env{}
		if c.root {
			e.Caps |= env.CapRoot
		}
		if got := sinalEhTestemunha(f, e); got != c.querUso {
			t.Errorf("[%s] sinalEhTestemunha=%v, quer %v", c.nome, got, c.querUso)
		}
	}
}

// Sem /proc no retrato de montagens, a resposta é "pode": tratar ausência de
// informação como hidepid desligaria a varredura em todo dump que não trouxe
// mountinfo, e a ausência de prova de filtragem não é prova de filtragem.
func TestSinalEhTestemunhaSemMontagemDeProc(t *testing.T) {
	f := &Facts{Mounts: []Montagem{{Ponto: "/", Tipo: "ext4"}}}
	if !sinalEhTestemunha(f, &env.Env{}) {
		t.Error("sem /proc no mountinfo a varredura não devia ser desligada")
	}
}

// A varredura por sinal não pode comer o orçamento de quem tem orçamento.
//
// O `wtf` tem teto rígido de 2s (SPEC 6.1) para o host TODO. A sondagem sozinha
// custa ~0,4s ociosa, e as duas tentativas de encaixá-la ali falharam do mesmo
// jeito, medidas no 44-wtf-revshell: sem limite ela roubava seis lacunas de
// outros coletores, e limitada ao WalkDeadline ela consumia o prazo inteiro
// antes de eles começarem — 0 de 89 checks completos.
func TestSondaNaoRodaSobTetoDeTempo(t *testing.T) {
	if !sondaCabeNoComando(&env.Env{}) {
		t.Error("scan não tem teto de tempo: a sondagem tem que rodar")
	}
	if !sondaCabeNoComando(nil) {
		t.Error("sem Env a sondagem tem que rodar")
	}
	if sondaCabeNoComando(&env.Env{WalkDeadline: time.Now().Add(2 * time.Second)}) {
		t.Error("com teto de tempo a sondagem tem que ficar de fora: o orçamento " +
			"é compartilhado, e gastá-lo aqui cega os outros coletores")
	}
}
