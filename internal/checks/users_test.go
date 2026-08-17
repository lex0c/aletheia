package checks

import (
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/facts"
)

// É o UID que define o poder, não o nome. Procurar por "root" acharia uma conta
// e perderia a outra — que é exatamente o ponto do disfarce.
func TestUidZeroNaoOlhaONome(t *testing.T) {
	f := &facts.Facts{Accounts: []facts.Account{
		{Name: "root", UID: 0, Shell: "/bin/bash"},
		{Name: "systemd-net", UID: 0, Shell: "/bin/bash", SemSenha: true},
		{Name: "app", UID: 1000, Shell: "/bin/bash"},
	}}
	r := uidZero.Run(uidZero, f, imgEnv())
	if len(r.Findings) != 1 || r.Findings[0].Subject != "systemd-net" {
		t.Fatalf("achados = %v", r.Findings)
	}
	if r.Findings[0].Sev != check.SevCritical {
		t.Error("conta com uid 0 É root para o kernel")
	}
	if !strings.Contains(strings.Join(r.Findings[0].Evidence, " "), "VAZIO") {
		t.Error("senha vazia junto de uid 0 precisa aparecer")
	}
}

// Campo de senha vazio não é senha fraca: é a ausência da pergunta. Com shell
// de login vira porta de entrada; sem, ainda vale para `su`.
func TestSemSenhaSeveridadePeloShell(t *testing.T) {
	f := &facts.Facts{Accounts: []facts.Account{
		{Name: "entrada", UID: 1001, Shell: "/bin/bash", SemSenha: true},
		{Name: "servico", UID: 120, Shell: "/usr/sbin/nologin", SemSenha: true},
		{Name: "normal", UID: 1002, Shell: "/bin/bash"},
	}}
	r := semSenha.Run(semSenha, f, imgEnv())
	sev := map[string]check.Severity{}
	for _, fd := range r.Findings {
		sev[fd.Subject] = fd.Sev
	}
	if len(r.Findings) != 2 {
		t.Fatalf("achados = %v", sev)
	}
	if sev["entrada"] != check.SevCritical || sev["servico"] != check.SevWarn {
		t.Errorf("severidades = %v", sev)
	}
}

// Sem root o /etc/shadow é ilegível, e "nenhuma conta sem senha" vira
// desconhecimento em vez de resposta.
func TestSemSenhaDeclaraShadowIlegivel(t *testing.T) {
	f := &facts.Facts{PersistDenied: map[string][]string{
		"users": {"/etc/shadow ilegível (precisa de root)"}}}
	if r := semSenha.Run(semSenha, f, imgEnv()); len(r.Partial) == 0 {
		t.Error("shadow ilegível precisa virar cobertura parcial")
	}
}

// O Alpine entrega `disk:x:6:root` de fábrica. Root num grupo equivalente a
// root não informa nada, e sem a exclusão todo contêiner vira achado.
func TestGrupoRootIgnoraORootComoMembro(t *testing.T) {
	f := &facts.Facts{Grupos: []facts.Grupo{
		{Name: "disk", GID: 6, Members: []string{"root"}},
		{Name: "docker", GID: 999, Members: []string{"app"}},
		{Name: "users", GID: 100, Members: []string{"app"}},
	}}
	r := grupoEquivalenteARoot.Run(grupoEquivalenteARoot, f, imgEnv())
	if len(r.Findings) != 1 || r.Findings[0].Subject != "docker" {
		t.Fatalf("achados = %v", r.Findings)
	}
	if !strings.Contains(strings.Join(r.Findings[0].Evidence, " "), "monta o filesystem") {
		t.Error("o achado precisa dizer POR QUE o grupo equivale a root")
	}
}

// postgres e git precisam de shell: sem a lista, todo host com PostgreSQL vira
// achado.
func TestContaDeServicoComShellPulaOsLegitimos(t *testing.T) {
	f := &facts.Facts{Accounts: []facts.Account{
		{Name: "postgres", UID: 105, Shell: "/bin/bash"},
		{Name: "app-svc", UID: 106, Shell: "/bin/bash"},
		{Name: "www-data", UID: 33, Shell: "/usr/sbin/nologin"},
	}}
	r := contaDeServicoComShell.Run(contaDeServicoComShell, f, imgEnv())
	if len(r.Findings) != 1 || r.Findings[0].Subject != "app-svc" {
		t.Fatalf("achados = %v", r.Findings)
	}
}

// --- integridade e redundância ---

func TestSemDonoSeveridadePeloDiretorio(t *testing.T) {
	f := &facts.Facts{
		Pkg: facts.PkgDB{Kind: "dpkg", Consultavel: true},
		Ownership: []facts.Ownership{
			{Path: "/usr/bin/curl", Owned: true, Onde: []string{"processo pid=1"}},
			{Path: "/usr/sbin/backdoor", Owned: false, Onde: []string{"unit x.service"}},
			{Path: "/usr/local/bin/tool", Owned: false, Onde: []string{"processo pid=2"}},
			// /tmp já tem check próprio: contar duas vezes infla a triagem
			{Path: "/tmp/.x", Owned: false, Onde: []string{"processo pid=3"}},
		},
	}
	r := semDonoDePacote.Run(semDonoDePacote, f, imgEnv())
	sev := map[string]check.Severity{}
	for _, fd := range r.Findings {
		sev[fd.Subject] = fd.Sev
	}
	if len(r.Findings) != 2 {
		t.Fatalf("achados = %v", sev)
	}
	if sev["/usr/sbin/backdoor"] != check.SevCritical {
		t.Error("diretório do gerenciador de pacotes: tudo ali deveria vir de um pacote")
	}
	if sev["/usr/local/bin/tool"] != check.SevWarn {
		t.Error("/usr/local existe PARA instalação manual")
	}
}

// A distribuição em transição do SysV entrega unit E init.d para o mesmo
// binário: o rsyslogd de qualquer Ubuntu 14.04 cai nessa forma.
func TestRedundanciaPulaAlvoComDonoDePacote(t *testing.T) {
	base := &facts.Facts{
		Pkg: facts.PkgDB{Kind: "dpkg", Consultavel: true},
		Units: []facts.Unit{{Name: "rsyslog.service",
			Exec: []facts.ExecLine{{Key: "ExecStart", Cmd: "/usr/sbin/rsyslogd -n"}}}},
		Triggers: []facts.Trigger{{File: "/etc/init.d/rsyslog", Kind: "initd",
			Lines: []facts.TriggerLine{{N: 1, Text: "/usr/sbin/rsyslogd -n"}}}},
		Ownership: []facts.Ownership{{Path: "/usr/sbin/rsyslogd", Owned: true}},
	}
	if r := persistRedundant.Run(persistRedundant, base, imgEnv()); len(r.Findings) != 0 {
		t.Errorf("pacote que entrega unit e init.d é a transição do SysV: %v",
			r.Findings[0].Evidence)
	}

	// Sem dono, a MESMA forma vira achado.
	base.Ownership[0].Owned = false
	if r := persistRedundant.Run(persistRedundant, base, imgEnv()); len(r.Findings) != 1 {
		t.Error("alvo sem dono de pacote persistido de dois jeitos precisa disparar")
	}
}

// Suprimir por IGNORÂNCIA seria pior que o ruído: onde a base não pode ser
// consultada, o achado sai dizendo isso.
func TestRedundanciaNaoSuprimeQuandoNaoSabe(t *testing.T) {
	f := &facts.Facts{
		Pkg: facts.PkgDB{Kind: "rpm", Consultavel: false, Motivo: "base binária"},
		Units: []facts.Unit{{Name: "x.service",
			Exec: []facts.ExecLine{{Key: "ExecStart", Cmd: "/usr/sbin/x"}}}},
		Cron: []facts.CronEntry{{File: "/etc/cron.d/x", Cmd: "/usr/sbin/x", Schedule: "@reboot"}},
	}
	r := persistRedundant.Run(persistRedundant, f, imgEnv())
	if len(r.Findings) != 1 {
		t.Fatalf("achados = %d", len(r.Findings))
	}
	if !strings.Contains(strings.Join(r.Findings[0].Evidence, " "), "não foi possível confirmar") {
		t.Error("o achado precisa DIZER que a propriedade não foi confirmada")
	}
}

// Atribuição comum guarda caminho de arquivo o tempo todo. Só variável cujo
// valor é EXECUTADO conta — o /etc/init.d/rsyslog de qualquer Ubuntu tem
// XCONSOLE=/dev/xconsole, que é dado.
func TestAtribuicaoSoContaSeAVariavelEhExecutada(t *testing.T) {
	casos := map[string]string{
		"XCONSOLE=/dev/xconsole": "XCONSOLE=/dev/xconsole",
		"PIDFILE=/var/run/x.pid": "PIDFILE=/var/run/x.pid",
		"BASH_ENV=/tmp/.x":       "/tmp/.x",
		"PROMPT_COMMAND=/tmp/.p": "/tmp/.p",
	}
	for ln, quer := range casos {
		if got := linhaExecutavel(ln); got != quer {
			t.Errorf("linhaExecutavel(%q) = %q, quer %q", ln, got, quer)
		}
	}
}
