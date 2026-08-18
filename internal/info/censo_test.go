package info

import (
	"strings"
	"testing"
	"time"

	"github.com/lex0c/aletheia/internal/facts"
)

// hostDoCaso reproduz o host que originou este comando.
//
// A saída era esta, e o operador levou quinze pipelines de `ps`, `awk`, `sort` e
// `uniq` para chegar até ela:
//
//	1014 processos · 5007 tarefas · teto 4096
//	406 node · 400 sh · 103 sendmail · 103 postdrop · 2 crond
//
// E o que explicava tudo — 400 cópias do mesmo cron, uma por minuto, nenhuma
// terminando — não saía de comando nenhum: saía da cabeça de quem olhou.
func hostDoCaso() *facts.Facts {
	f := &facts.Facts{
		Accounts: []facts.Account{{Name: "node", UID: 1001}, {Name: "root", UID: 0}},
	}
	base := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	pid := 1000

	// 400 cópias do mesmo job de cron, uma por minuto, nenhuma terminando —
	// cada uma com o `sh` e o `node` que ela gerou.
	for i := 0; i < 400; i++ {
		inicio := base.Add(time.Duration(i) * time.Minute).Format(time.RFC3339)
		pid++
		f.Processes = append(f.Processes, facts.Process{
			PID: pid, PPID: 2, UID: 1001, Comm: "sh", Exe: "/usr/bin/dash",
			Argv:    []string{"/bin/sh", "-c", "/home/node/check-pm2.sh"},
			Threads: 1, NProcMax: 4096, State: "S", StartUTC: inicio,
		})
		pai := pid
		pid++
		f.Processes = append(f.Processes, facts.Process{
			PID: pid, PPID: pai, UID: 1001, Comm: "node", Exe: "/usr/bin/node",
			Argv:    []string{"node", "/home/node/app/worker.js"},
			Threads: 11, NProcMax: 4096, State: "S", StartUTC: inicio,
		})
	}
	// O que o cron gera de sobra quando o job escreve em stdout.
	for i := 0; i < 103; i++ {
		pid++
		f.Processes = append(f.Processes, facts.Process{
			PID: pid, PPID: 2, UID: 1001, Comm: "sendmail", Exe: "/usr/sbin/sendmail",
			Argv:    []string{"sendmail", "-FCronDaemon", "-i", "node"},
			Threads: 1, NProcMax: 4096, State: "S",
		})
	}
	// E o crond, que é quem dispara.
	f.Processes = append(f.Processes, facts.Process{
		PID: 2, PPID: 1, UID: 0, Comm: "crond", Exe: "/usr/sbin/crond",
		Argv: []string{"/usr/sbin/crond", "-n"}, Threads: 1, NProcMax: -1, State: "S",
	})
	return f
}

// O número que nenhum comando isolado dá: tarefas contra o TETO. É ele que
// transforma "tem muito processo" em "por isso o su falha".
func TestCensoCompararComOTeto(t *testing.T) {
	c := Censo(hostDoCaso())
	if c.Processos != 904 {
		t.Errorf("processos = %d", c.Processos)
	}
	// 400 sh (1 thread) + 400 node (11) + 103 sendmail (1) + 1 crond = 4904
	if c.Tarefas != 4904 {
		t.Errorf("tarefas = %d — o RLIMIT_NPROC conta processos E threads", c.Tarefas)
	}

	u := c.Usuarios[0]
	if u.Nome != "node" {
		t.Fatalf("o primeiro da lista é %q: a ordem é a da URGÊNCIA, e quem está "+
			"perto do teto vem antes", u.Nome)
	}
	if u.Teto != 4096 || !u.TetoLido {
		t.Errorf("teto = %d (lido=%v)", u.Teto, u.TetoLido)
	}
	if !u.Estourou() {
		t.Errorf("4903 tarefas contra teto de 4096: precisa dizer que ESTOUROU — " +
			"é a explicação do EAGAIN em fork e em execve")
	}
}

// Agrupar pelo EXECUTÁVEL, e não pelo nome: `comm` e `argv[0]` são escolha do
// processo, e é exatamente por isso que um implante se dá um nome de kernel.
func TestCensoAgrupaPeloExecutavelReal(t *testing.T) {
	c := Censo(hostDoCaso())
	u := c.Usuarios[0]
	primeiro := u.PorExecutavel[0]
	if primeiro.Rotulo != "/usr/bin/dash" && primeiro.Rotulo != "/usr/bin/node" {
		t.Errorf("o topo por executável é %q", primeiro.Rotulo)
	}
	if primeiro.N != 400 {
		t.Errorf("N = %d, queria 400", primeiro.N)
	}
	var achouPai bool
	for _, p := range u.PorPai {
		if strings.Contains(p.Rotulo, "crond") && p.N == 503 {
			achouPai = true
		}
	}
	if !achouPai {
		t.Errorf("o pai comum precisa ser nomeado, com a contagem: %v", u.PorPai)
	}
}

// A parte que nenhum `ps` faz: dar NOME à repetição. Cópias do mesmo comando em
// intervalos REGULARES é um cron cujo job demora mais que o intervalo.
func TestCensoNomeiaOCronQueSeSobrepoe(t *testing.T) {
	c := Censo(hostDoCaso())
	var achou *Padrao
	for i := range c.Padroes {
		if strings.Contains(c.Padroes[i].Alvo, "check-pm2.sh") {
			achou = &c.Padroes[i]
		}
	}
	if achou == nil {
		t.Fatalf("o padrão não foi reconhecido: %+v", c.Padroes)
	}
	if achou.Tipo != "cron sobreposto" {
		t.Errorf("tipo = %q, queria 'cron sobreposto'", achou.Tipo)
	}
	if achou.N != 400 {
		t.Errorf("N = %d", achou.N)
	}
	if !strings.Contains(achou.Detalhe, "1m0s") {
		t.Errorf("o intervalo medido precisa aparecer: %q", achou.Detalhe)
	}
}

// E o outro lado: um pool que subiu TODO no mesmo instante não é cron
// sobreposto. Chamar de cron o que é pool mandaria o operador procurar um
// agendamento que não existe.
func TestPoolQueSubiuJuntoNaoEhCron(t *testing.T) {
	f := &facts.Facts{}
	inicio := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC).Format(time.RFC3339)
	for i := 0; i < 60; i++ {
		f.Processes = append(f.Processes, facts.Process{
			PID: 2000 + i, PPID: 900, UID: 33, Comm: "php-fpm",
			Exe: "/usr/sbin/php-fpm8.1", Argv: []string{"php-fpm: pool www"},
			Threads: 1, StartUTC: inicio,
		})
	}
	c := Censo(f)
	if len(c.Padroes) != 1 {
		t.Fatalf("padrões = %+v", c.Padroes)
	}
	if c.Padroes[0].Tipo == "cron sobreposto" {
		t.Errorf("sessenta processos que nasceram no MESMO segundo são um pool, " +
			"não um cron que se sobrepõe")
	}
}

// Repetição pequena não é padrão. Nomear forma onde não há é pior que calar,
// porque a frase sai com cara de conclusão.
func TestRepeticaoPequenaNaoViraPadrao(t *testing.T) {
	f := &facts.Facts{}
	for i := 0; i < 8; i++ {
		f.Processes = append(f.Processes, facts.Process{
			PID: 3000 + i, UID: 0, Comm: "worker", Exe: "/usr/bin/worker",
			Argv: []string{"worker"}, Threads: 1,
		})
	}
	if c := Censo(f); len(c.Padroes) != 0 {
		t.Errorf("oito cópias não são padrão: %+v", c.Padroes)
	}
}

// Teto não lido é diferente de teto ausente: a primeira é lacuna, a segunda é
// resposta. Confundir as duas faria a ferramenta afirmar que não há limite.
func TestTetoNaoLidoNaoViraSemLimite(t *testing.T) {
	f := &facts.Facts{Processes: []facts.Process{
		{PID: 10, UID: 500, Comm: "x", Threads: 1}, // NProcMax zero = não lido
	}}
	u := Censo(f).Usuarios[0]
	if u.TetoLido {
		t.Error("NProcMax zero significa NÃO LIDO")
	}
	if u.Estourou() || u.Perto() {
		t.Error("sem teto lido não dá para afirmar nada sobre estar perto dele")
	}
}

// O teto do uid é o MENOR entre os processos dele, não o maior: é o menor que
// decide onde o próximo fork falha.
//
// O caso real: o login tem 62675 e a unit de systemd que roda a aplicação tem
// `LimitNPROC=4096`. Reportar 62675 diria que há folga de sobra enquanto os
// processos que importam já estão no limite.
func TestTetoDoUsuarioEhOMenor(t *testing.T) {
	f := &facts.Facts{Processes: []facts.Process{
		{PID: 10, UID: 1001, Comm: "bash", Exe: "/bin/bash", Threads: 1, NProcMax: 62675},
		{PID: 11, UID: 1001, Comm: "node", Exe: "/usr/bin/node", Threads: 11, NProcMax: 4096},
		{PID: 12, UID: 1001, Comm: "node", Exe: "/usr/bin/node", Threads: 11, NProcMax: 4096},
	}}
	u := Censo(f).Usuarios[0]
	if u.Teto != 4096 {
		t.Errorf("teto = %d, queria 4096: o menor é quem decide onde o fork falha", u.Teto)
	}
}

// Início irregular NÃO é cron. Um laço de respawn cria cópias quando o processo
// morre — sem cadência —, e chamar isso de agendamento mandaria o operador
// procurar um crontab que não existe.
func TestIniciosIrregularesNaoViramCron(t *testing.T) {
	f := &facts.Facts{}
	base := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	// Intervalos de 3s, 400s, 12s, 900s… — a forma de um respawn, não a de um
	// disparo por relógio.
	saltos := []int{3, 403, 415, 1315, 1322, 2222, 2260, 3160, 3180, 4080,
		4090, 4990, 5000, 5900, 5910, 6810, 6820, 7720, 7730, 8630, 8640, 9540}
	for i, s := range saltos {
		f.Processes = append(f.Processes, facts.Process{
			PID: 4000 + i, PPID: 900, UID: 1002, Comm: "svc", Exe: "/opt/svc/run",
			Argv: []string{"/opt/svc/run", "--daemon"}, Threads: 1,
			StartUTC: base.Add(time.Duration(s) * time.Second).Format(time.RFC3339),
		})
	}
	c := Censo(f)
	if len(c.Padroes) != 1 {
		t.Fatalf("padrões = %+v", c.Padroes)
	}
	if c.Padroes[0].Tipo == "cron sobreposto" {
		t.Errorf("intervalos irregulares não são agendamento: dizer que são manda " +
			"o operador procurar um crontab que não existe")
	}
	if !strings.Contains(c.Padroes[0].Detalhe, "respawn") {
		t.Errorf("e a alternativa precisa ser nomeada: %q", c.Padroes[0].Detalhe)
	}
}
