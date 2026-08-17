package checks

import (
	"strings"
	"testing"
	"time"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

// Todo teste deste arquivo roda contra Facts sintéticos: sem root, sem /proc
// real, sem host comprometido. É a consequência prática de separar coleta de
// avaliação (SPEC 3, princípio 1) — e é o que permitirá rodar a suíte inteira
// contra fixtures de RHEL 6, Ubuntu e Alpine.
func testEnv() *env.Env {
	return &env.Env{
		Source:    env.SourceLive,
		Caps:      env.CapProcfs | env.CapFilesystem,
		CapReason: map[string]string{},
		Now:       time.Date(2026, 4, 30, 21, 44, 3, 0, time.UTC),
	}
}

func run(t *testing.T, c check.Check, procs ...facts.Process) check.Result {
	t.Helper()
	return c.Run(c, &facts.Facts{Processes: procs}, testEnv())
}

func sevOf(t *testing.T, r check.Result, i int) check.Severity {
	t.Helper()
	if len(r.Findings) <= i {
		t.Fatalf("esperava ao menos %d achados, veio %d", i+1, len(r.Findings))
	}
	return r.Findings[i].Sev
}

// --- proc.memfd_exec (runbook §3.16) ---

func TestMemfdExecDispara(t *testing.T) {
	r := run(t, memfdExec, facts.Process{
		PID: 8812, PPID: 1, UID: 1000, Comm: "node",
		Exe: "/memfd:libc.so (deleted)", ExeMemfd: true, ExeDeleted: true,
		Argv: []string{"node"},
	})
	if len(r.Findings) != 1 {
		t.Fatalf("achados = %d, quer 1", len(r.Findings))
	}
	f := r.Findings[0]
	if f.Sev != check.SevCritical {
		t.Errorf("severidade = %s, quer CRITICAL: fileless é a forma, não heurística", f.Sev)
	}
	if f.Subject != "pid=8812" {
		t.Errorf("Subject = %q — é o que preserva o caso individual na agregação", f.Subject)
	}
	// O passo irreversível precisa estar no achado, com o PID preenchido, e
	// precisa ser um comando que EXISTE. A regra nasceu do erro oposto: uma
	// versão prometia "aletheia preserve" quando o subcomando não existia, e o
	// operador recebia "comando desconhecido" — podendo seguir para matar o
	// processo e destruir a única cópia do binário.
	//
	// Hoje o subcomando existe, e quem prova que a linha impressa RODA é
	// TestInstrucaoDePreservacaoRodaNesteBuild, em cmd/aletheia: ele pega a
	// instrução como ela sai daqui e a entrega ao parser de verdade.
	if !f.Irreversible {
		t.Error("memfd precisa ser marcado Irreversible — é o campo que promove o passo a 1º")
	}
	var hasPreserve bool
	for _, ns := range f.NextSteps {
		if strings.Contains(ns, "preserve") && strings.Contains(ns, "--pid 8812") {
			hasPreserve = true
		}
	}
	if !hasPreserve {
		t.Errorf("NextSteps deve trazer o comando de preservação com o PID pronto: %v", f.NextSteps)
	}
}

func TestMemfdExecIgnoraSiMesmo(t *testing.T) {
	r := run(t, memfdExec, facts.Process{
		PID: 999, Exe: "/memfd:x", ExeMemfd: true, Self: true,
	})
	if len(r.Findings) != 0 {
		t.Error("a ferramenta não pode se reportar: um scanner que faz isso ninguém usa duas vezes")
	}
}

func TestMemfdExecNaoDisparaEmProcessoNormal(t *testing.T) {
	r := run(t, memfdExec,
		facts.Process{PID: 1, Exe: "/usr/lib/systemd/systemd", Argv: []string{"/sbin/init"}},
		facts.Process{PID: 2, Exe: "", Comm: "kthreadd"},
	)
	if len(r.Findings) != 0 {
		t.Errorf("achados = %d em host normal, quer 0", len(r.Findings))
	}
}

// --- proc.exe_deleted (runbook §3.14) ---

// WARN, não CRITICAL: apagar o binário com o serviço rodando é o que acontece
// em TODA atualização de pacote. O valor está na correlação, não no sinal
// isolado — e a severidade precisa refletir isso.
func TestExeDeletedEhWarnNaoCritical(t *testing.T) {
	r := run(t, exeDeleted, facts.Process{
		PID: 4211, Comm: "nginx", Exe: "/usr/sbin/nginx", ExeDeleted: true,
	})
	if got := sevOf(t, r, 0); got != check.SevWarn {
		t.Errorf("severidade = %s, quer WARN: upgrade de pacote produz isto o tempo todo", got)
	}
}

// memfd tem check próprio e severidade maior; contar duas vezes inflaria o
// relatório e a contagem do exit code.
func TestExeDeletedNaoDuplicaMemfd(t *testing.T) {
	r := run(t, exeDeleted, facts.Process{
		PID: 8812, Exe: "/memfd:x", ExeMemfd: true, ExeDeleted: true,
	})
	if len(r.Findings) != 0 {
		t.Error("memfd não pode aparecer também como exe_deleted")
	}
}

// --- proc.kthread_disguise (runbook §3.5) ---

func TestKthreadDisguiseArgv0EntreColchetes(t *testing.T) {
	r := run(t, kthreadDisguise, facts.Process{
		PID: 6574, PPID: 1, UID: 1000, Comm: "card0-crtc8",
		Exe:  "/home/node/.config/htop/defunct",
		Argv: []string{"[card0-crtc8]"},
	})
	if got := sevOf(t, r, 0); got != check.SevCritical {
		t.Errorf("severidade = %s, quer CRITICAL", got)
	}
	if !strings.Contains(strings.Join(r.Findings[0].Evidence, " "), "exec -a") {
		t.Errorf("a evidência deve nomear a técnica: %v", r.Findings[0].Evidence)
	}
}

func TestKthreadDisguiseCmdlineVazio(t *testing.T) {
	r := run(t, kthreadDisguise, facts.Process{
		PID: 7001, Exe: "/tmp/.x", CmdlineEmpty: true,
	})
	if len(r.Findings) != 1 {
		t.Fatalf("achados = %d, quer 1", len(r.Findings))
	}
}

// A distinção que sustenta o check: thread de kernel de verdade NÃO tem exe.
// Sem esta guarda, o relatório encheria de [kworker], [ksoftirqd] e afins.
func TestKthreadDisguiseIgnoraKthreadReal(t *testing.T) {
	r := run(t, kthreadDisguise,
		facts.Process{PID: 2, Comm: "kthreadd", Exe: "", CmdlineEmpty: true},
		facts.Process{PID: 12, Comm: "ksoftirqd/0", Exe: "", Argv: nil},
		facts.Process{PID: 44, Comm: "kworker/0:1", Exe: "", ExeErr: "não existe"},
	)
	if len(r.Findings) != 0 {
		t.Errorf("thread de kernel real não tem exe e não pode disparar: %d achados", len(r.Findings))
	}
}

func TestKthreadDisguiseIgnoraProcessoNormal(t *testing.T) {
	r := run(t, kthreadDisguise,
		facts.Process{PID: 1, Exe: "/usr/lib/systemd/systemd", Argv: []string{"/sbin/init"}},
		facts.Process{PID: 900, Exe: "/usr/sbin/nginx", Argv: []string{"nginx: master process"}},
	)
	if len(r.Findings) != 0 {
		t.Errorf("achados = %d em processo normal, quer 0", len(r.Findings))
	}
}

// --- invariantes do conjunto ---

// Todo check registrado precisa passar pelo cenário de host limpo sem produzir
// nada. Um check que dispara em host saudável é ruído que treina o operador a
// ignorar o relatório.
func TestNenhumCheckDisparaEmHostLimpo(t *testing.T) {
	limpo := []facts.Process{
		{PID: 1, PPID: 0, Comm: "systemd", Exe: "/usr/lib/systemd/systemd", Argv: []string{"/sbin/init"}},
		{PID: 2, PPID: 0, Comm: "kthreadd", Exe: ""},
		{PID: 12, PPID: 2, Comm: "ksoftirqd/0", Exe: ""},
		{PID: 900, PPID: 1, Comm: "nginx", Exe: "/usr/sbin/nginx", Argv: []string{"nginx: master process /usr/sbin/nginx"}},
		{PID: 901, PPID: 900, Comm: "nginx", UID: 33, Exe: "/usr/sbin/nginx", Argv: []string{"nginx: worker process"}},
		{PID: 1500, PPID: 1, Comm: "sshd", Exe: "/usr/sbin/sshd", Argv: []string{"sshd: /usr/sbin/sshd -D"}},
	}
	for _, c := range check.All() {
		if c.Mode == check.ModeManual {
			continue
		}
		res := c.Run(c, &facts.Facts{Processes: limpo}, testEnv())
		if len(res.Findings) != 0 {
			t.Errorf("%s disparou em host limpo (%d achados): %v",
				c.ID, len(res.Findings), res.Findings[0].Evidence)
		}
	}
}

// Todo achado precisa carregar os FalsePositives: é o que o operador lê ANTES
// de decidir se vale investigar.
func TestTodoAchadoCarregaFalsePositives(t *testing.T) {
	suspeito := []facts.Process{
		{PID: 8812, Exe: "/memfd:x", ExeMemfd: true},
		{PID: 4211, Exe: "/usr/sbin/nginx", ExeDeleted: true},
		{PID: 6574, Exe: "/tmp/.x", Argv: []string{"[kworker/0:1]"}},
	}
	for _, c := range check.All() {
		if c.Mode == check.ModeManual {
			continue
		}
		res := c.Run(c, &facts.Facts{Processes: suspeito}, testEnv())
		for _, f := range res.Findings {
			if len(f.FalsePositives) == 0 {
				t.Errorf("%s: achado %s sem FalsePositives", c.ID, f.Subject)
			}
			if f.Ref == "" {
				t.Errorf("%s: achado sem §ref — o relatório precisa apontar o runbook", c.ID)
			}
			if f.Subject == "" {
				t.Errorf("%s: achado sem Subject — a agregação de frota perde o caso individual", c.ID)
			}
		}
	}
}

// --- invariantes do CATÁLOGO REAL ---
//
// Estes moram aqui, e não em internal/check, porque só este pacote enxerga o
// registry populado: check não pode importar checks (ciclo). A versão anterior
// iterava um registry vazio e passava sem executar o corpo do laço.

func TestCatalogoNaoEstaVazio(t *testing.T) {
	if len(check.All()) == 0 {
		t.Fatal("registry vazio: os testes de invariante abaixo não estariam testando nada")
	}
}

func TestTodoCheckDeProcDeclaraCapRoot(t *testing.T) {
	// Sem root, exe/environ/fd de processo alheio são invisíveis. Um check que
	// lê /proc e não declara CapRoot seria contado como COMPLETO numa execução
	// em que não viu quase nada — a mentira central que a ferramenta existe
	// para não cometer.
	for _, c := range check.All() {
		if c.Mode == check.ModeManual || c.Requires&env.CapProcfs == 0 {
			continue
		}
		if (c.Requires|c.Optional)&env.CapRoot == 0 {
			t.Errorf("%s lê /proc mas não declara CapRoot em Requires nem Optional", c.ID)
		}
	}
}

func TestTodoCheckTemRefEIDEstavel(t *testing.T) {
	for _, c := range check.All() {
		if c.Ref == "" {
			t.Errorf("%s: sem §ref do runbook", c.ID)
		}
		if c.Sources == 0 {
			t.Errorf("%s: sem Sources", c.ID)
		}
		if !strings.Contains(c.ID, ".") {
			t.Errorf("%s: ID deve ser <grupo>.<nome> para agregação de frota estável", c.ID)
		}
		if c.Mode != check.ModeManual && len(c.FalsePositives) == 0 {
			t.Errorf("%s: check automático sem FalsePositives", c.ID)
		}
	}
}

// --- regressões da revisão ---

// Exe ilegível por PERMISSÃO não é thread de kernel. Confundir os dois fazia um
// `exec -a '[kworker/2:1]'` de root passar por kthread legítima num scan
// não-root — e o check ainda era contado como completo.
func TestExeIlegivelNaoEhKthreadLegitima(t *testing.T) {
	procs := []facts.Process{
		{PID: 2, Comm: "kthreadd", Exe: "", ExeErr: "não existe"},                    // kthread real
		{PID: 700, Comm: "sshd", Exe: "", ExeErr: "sem permissão", ExeDenied: true},  // root, ilegível
		{PID: 701, Comm: "nginx", Exe: "", ExeErr: "sem permissão", ExeDenied: true}, // root, ilegível
	}
	for _, c := range []check.Check{memfdExec, exeDeleted, kthreadDisguise} {
		res := c.Run(c, &facts.Facts{Processes: procs}, testEnv())
		if len(res.Partial) == 0 {
			t.Errorf("%s: 2 processos com exe ilegível precisam virar cobertura PARCIAL, não silêncio", c.ID)
		}
		if len(res.Findings) != 0 {
			t.Errorf("%s: não pode CONCLUIR nada sobre processo que não conseguiu ler", c.ID)
		}
	}
}

// Processo que morreu durante a coleta não pode virar achado: instruir a
// preservar um PID inexistente é pior que não reportar.
func TestProcessoQueMorreuNaoViraAchado(t *testing.T) {
	procs := []facts.Process{
		{PID: 9001, Exe: "/tmp/.x", CmdlineEmpty: true, Vanished: true},
		{PID: 9002, Exe: "/memfd:y", ExeMemfd: true, Vanished: true},
	}
	for _, c := range []check.Check{memfdExec, kthreadDisguise} {
		res := c.Run(c, &facts.Facts{Processes: procs}, testEnv())
		if len(res.Findings) != 0 {
			t.Errorf("%s reportou %d achados sobre processo que já morreu", c.ID, len(res.Findings))
		}
	}
}

// O PID 1 NÃO é isento. A versão anterior isentava toda a cadeia de ancestrais,
// e como a caminhada terminava em 1, o PID 1 ficava fora de todo check em todo
// host — junto com o sshd que costuma ser ancestral da sessão de IR.
func TestPID1NaoEhIsento(t *testing.T) {
	res := kthreadDisguise.Run(kthreadDisguise, &facts.Facts{Processes: []facts.Process{
		{PID: 1, Comm: "systemd", Exe: "/tmp/.init-backdoor", Argv: []string{"[kthreadd]"}},
	}}, testEnv())
	if len(res.Findings) != 1 {
		t.Error("um /sbin/init substituído precisa ser avaliado como qualquer outro processo")
	}
}

// O passo irreversível é marcado por CAMPO, não por casar o texto do comando:
// acoplar por string faz uma reescrita inocente silenciar o passo que não pode
// ser pulado, com todos os testes continuando verdes.
func TestAchadoIrreversivelEhTipado(t *testing.T) {
	res := memfdExec.Run(memfdExec, &facts.Facts{Processes: []facts.Process{
		{PID: 8812, Exe: "/memfd:x", ExeMemfd: true},
	}}, testEnv())
	if len(res.Findings) != 1 {
		t.Fatal("esperava 1 achado")
	}
	if !res.Findings[0].Irreversible {
		t.Error("memfd: perder o processo destrói a única cópia do binário — precisa ser Irreversible")
	}
}

// Credencial em linha de comando não pode chegar ao relatório nem ao JSONL.
func TestCredencialEmCmdlineEhRedigida(t *testing.T) {
	res := memfdExec.Run(memfdExec, &facts.Facts{Processes: []facts.Process{
		{PID: 8812, Exe: "/memfd:x", ExeMemfd: true,
			Argv: []string{"mysqldump", "-u", "root", "-pS3cr3tP4ss", "prod"}},
	}}, testEnv())
	ev := strings.Join(res.Findings[0].Evidence, " ")
	if strings.Contains(ev, "S3cr3tP4ss") {
		t.Errorf("a credencial vazou para a evidência do achado: %q", ev)
	}
	if !strings.Contains(ev, "mysqldump") {
		t.Error("a redação não pode apagar o que identifica o processo")
	}
}
