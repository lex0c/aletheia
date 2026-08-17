package checks

import (
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/facts"
)

const (
	capSysModule = 1 << 16
	capSysPtrace = 1 << 19
	capNetRaw    = 1 << 13
	capSysTime   = 1 << 25
)

func TestCapNamesOf(t *testing.T) {
	got := strings.Join(capNamesOf(capSysModule|capNetRaw), ",")
	if got != "net_raw,sys_module" {
		t.Errorf("capNamesOf = %q, quer \"net_raw,sys_module\"", got)
	}
	if len(capNamesOf(0)) != 0 {
		t.Error("máscara zero não tem capability nenhuma")
	}
	// 0x3fffffffff é o conjunto cheio: precisa decodificar sem estourar.
	if n := len(capNamesOf(1<<41 - 1)); n != len(capName) {
		t.Errorf("conjunto cheio decodificou %d de %d", n, len(capName))
	}
}

func TestCapsDisparaEmNaoRootComPoderDeRoot(t *testing.T) {
	f := &facts.Facts{Processes: []facts.Process{
		{PID: 900, UID: 1000, EUID: 1000, Comm: "agent", Exe: "/tmp/agent", CapEff: capSysModule},
	}}
	r := capsUnexpected.Run(capsUnexpected, f, testEnv())
	if len(r.Findings) != 1 {
		t.Fatalf("achados = %d, quer 1", len(r.Findings))
	}
	if ev := strings.Join(r.Findings[0].Evidence, " "); !strings.Contains(ev, "cap_sys_module") {
		t.Errorf("a capability precisa ser NOMEADA, não só a máscara: %s", ev)
	}
}

// O falso positivo que apareceu na primeira execução contra host real:
// fusermount3 tem `Uid: 1000 0 0 0`. O uid REAL é 1000, o EFETIVO é 0 — ele é
// root. Olhar só o real faz a ferramenta acusar de escalada todo setuid do
// sistema.
func TestCapsNaoDisparaEmSetuidRoot(t *testing.T) {
	f := &facts.Facts{Processes: []facts.Process{
		{PID: 1794, UID: 1000, EUID: 0, Comm: "fusermount3",
			Exe: "/usr/bin/fusermount3", CapEff: 1<<41 - 1},
	}}
	if r := capsUnexpected.Run(capsUnexpected, f, testEnv()); len(r.Findings) != 0 {
		t.Errorf("setuid-root É root: %v", r.Findings[0].Evidence)
	}
}

func TestCapsNaoDisparaEmRoot(t *testing.T) {
	f := &facts.Facts{Processes: []facts.Process{
		{PID: 1, UID: 0, EUID: 0, CapEff: 1<<41 - 1},
	}}
	if r := capsUnexpected.Run(capsUnexpected, f, testEnv()); len(r.Findings) != 0 {
		t.Error("capability em root não diz nada: root já pode tudo")
	}
}

// A lista de fora é tão deliberada quanto a de dentro: net_raw é o ping, e
// sys_time é o chrony. Incluí-las tornaria o check ruído em todo host.
func TestCapsIgnoraAsQueDistroDistribui(t *testing.T) {
	f := &facts.Facts{Processes: []facts.Process{
		{PID: 10, UID: 1000, EUID: 1000, Comm: "ping", Exe: "/usr/bin/ping", CapEff: capNetRaw},
		{PID: 11, UID: 992, EUID: 992, Comm: "chronyd", Exe: "/usr/sbin/chronyd", CapEff: capSysTime},
	}}
	if r := capsUnexpected.Run(capsUnexpected, f, testEnv()); len(r.Findings) != 0 {
		t.Errorf("disparou em capability que a distro concede de propósito: %v",
			r.Findings[0].Evidence)
	}
}

// Dentro de namespace de usuário o CapEff aparece cheio, e não vale nada fora
// dele. Podman rootless e sandbox de navegador caem aqui às dezenas.
func TestCapsDescartaNamespaceDeUsuarioProprio(t *testing.T) {
	f := &facts.Facts{Processes: []facts.Process{
		{PID: 1, UID: 0, EUID: 0, NS: map[string]string{"user": "user:[4026531837]"}},
		{PID: 50, UID: 1000, EUID: 1000, Comm: "podman", CapEff: 1<<41 - 1,
			NS: map[string]string{"user": "user:[4026532999]"}},
	}}
	if r := capsUnexpected.Run(capsUnexpected, f, testEnv()); len(r.Findings) != 0 {
		t.Errorf("capability em namespace próprio não vale no host: %v", r.Findings[0].Evidence)
	}
}

// --- proc.tracer ---

func TestTracerNomeiaQuemEstaTracando(t *testing.T) {
	f := &facts.Facts{Processes: []facts.Process{
		{PID: 100, Comm: "nginx", Exe: "/usr/sbin/nginx", TracerPID: 700},
		{PID: 700, Comm: "injector", Exe: "/tmp/.i", UID: 1000, EUID: 1000},
	}}
	r := tracer.Run(tracer, f, testEnv())
	if len(r.Findings) != 1 {
		t.Fatalf("achados = %d, quer 1", len(r.Findings))
	}
	ev := strings.Join(r.Findings[0].Evidence, " ")
	if !strings.Contains(ev, "/tmp/.i") {
		t.Errorf("saber QUEM traça é metade do achado: %s", ev)
	}
}

func TestTracerMarcaDepuradorELacunaDeTracer(t *testing.T) {
	f := &facts.Facts{Processes: []facts.Process{
		{PID: 100, Comm: "app", TracerPID: 700},
		{PID: 700, Comm: "gdb", Exe: "/usr/bin/gdb"},
		// tracer ausente da coleta: pior que tracer conhecido
		{PID: 200, Comm: "app2", TracerPID: 9999},
	}}
	r := tracer.Run(tracer, f, testEnv())
	if len(r.Findings) != 2 {
		t.Fatalf("achados = %d, quer 2", len(r.Findings))
	}
	var comGdb, semTracer bool
	for _, fd := range r.Findings {
		ev := strings.Join(fd.Evidence, " ")
		if strings.Contains(ev, "PARECE um depurador") {
			comGdb = true
		}
		if strings.Contains(ev, "NÃO está entre os processos coletados") {
			semTracer = true
		}
	}
	if !comGdb {
		t.Error("gdb precisa ser apontado como depurador: é o FP mais comum deste check")
	}
	if !semTracer {
		t.Error("tracer que não aparece na coleta precisa ser dito: pode estar oculto")
	}
}

func TestTracerNaoDisparaSemTracer(t *testing.T) {
	f := &facts.Facts{Processes: []facts.Process{{PID: 1, Comm: "init"}}}
	if r := tracer.Run(tracer, f, testEnv()); len(r.Findings) != 0 {
		t.Error("TracerPid 0 é o estado normal")
	}
}

func TestUidStrMostraSetuid(t *testing.T) {
	if got := uidStr(&facts.Process{UID: 1000, EUID: 0}); !strings.Contains(got, "setuid") {
		t.Errorf("uidStr = %q: a divergência entre real e efetivo É a informação", got)
	}
	if got := uidStr(&facts.Process{UID: 1000, EUID: 1000}); got != "uid=1000" {
		t.Errorf("uidStr = %q, quer \"uid=1000\"", got)
	}
}
