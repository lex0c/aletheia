package check

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/facts"
)

// fatosDoAtor monta o host mínimo do cenário 71: um binário sem dono, o
// processo dele, e a unit que o executa.
func fatosDoAtor() *facts.Facts {
	f := &facts.Facts{
		Processes: []facts.Process{
			{PID: 17, Exe: "/usr/local/sbin/systemd-netlinkd"},
			{PID: 42, Exe: "/usr/bin/python3"},
			{PID: 43, Exe: "/usr/bin/python3"},
		},
		Units: []facts.Unit{{
			Name: "sshd.service",
			Exec: []facts.ExecLine{
				{Key: "ExecStartPre", Cmd: "-/usr/local/sbin/systemd-netlinkd --daemon"},
			},
		}},
	}
	f.Index()
	return f
}

func TestAtorLigaPidUnitECaminho(t *testing.T) {
	r := &Report{Findings: []Finding{
		{ID: "integrity.no_package_owner", Sev: SevWarn, Subject: "/usr/local/sbin/systemd-netlinkd"},
		{ID: "net.egress_unowned", Sev: SevWarn, Subject: "pid=17"},
		{ID: "persist.unit_dropin_exec", Sev: SevWarn, Subject: "sshd.service"},
	}}
	resolverAtores(r, fatosDoAtor())

	grupos, resto := r.Correlate()
	if len(grupos) != 1 {
		t.Fatalf("os três achados são um ator só, deu %d grupo(s)", len(grupos))
	}
	if grupos[0].Subject != "/usr/local/sbin/systemd-netlinkd" {
		t.Errorf("o grupo tem que se chamar pelo BINÁRIO, deu %q", grupos[0].Subject)
	}
	if len(grupos[0].Findings) != 3 {
		t.Errorf("esperava 3 sinais no grupo, deu %d", len(grupos[0].Findings))
	}
	if len(resto) != 0 {
		t.Errorf("nada deveria sobrar solto, sobrou %d", len(resto))
	}

	// O sujeito PRÓPRIO não pode sumir: é ele que o operador usa no passo
	// seguinte, e `pid=17` não se recupera do caminho do binário.
	var viuPid bool
	for _, fd := range grupos[0].Findings {
		if fd.Subject == "pid=17" {
			viuPid = true
		}
	}
	if !viuPid {
		t.Error("o achado de rede perdeu o próprio pid dentro do grupo")
	}
}

// O motivo de existir a guarda: metade dos processos de um host é python3, e
// agrupar por binário sem ela afirmaria parentesco onde há só interpretador
// compartilhado.
func TestAtorNaoFundeBinarioNaoAcusado(t *testing.T) {
	r := &Report{Findings: []Finding{
		{ID: "proc.shell_from_service", Sev: SevWarn, Subject: "pid=42"},
		{ID: "net.egress_unowned", Sev: SevWarn, Subject: "pid=43"},
	}}
	resolverAtores(r, fatosDoAtor())

	for _, fd := range r.Findings {
		if fd.Ator != "" {
			t.Fatalf("nenhum achado nomeia /usr/bin/python3: %s não podia ganhar ator %q",
				fd.Subject, fd.Ator)
		}
	}
	if grupos, _ := r.Correlate(); len(grupos) != 0 {
		t.Errorf("dois processos do mesmo interpretador não são um ator, deu %d grupo(s)", len(grupos))
	}
}

// Sujeito que JÁ é o caminho não ganha ator: seria ele mesmo, e encheria o
// JSONL de campo redundante.
func TestAtorNaoSeRepeteNoProprioCaminho(t *testing.T) {
	r := &Report{Findings: []Finding{
		{ID: "integrity.no_package_owner", Sev: SevWarn, Subject: "/usr/local/sbin/systemd-netlinkd"},
		{ID: "integrity.immutable_flag", Sev: SevWarn, Subject: "/usr/local/sbin/systemd-netlinkd"},
	}}
	resolverAtores(r, fatosDoAtor())
	for _, fd := range r.Findings {
		if fd.Ator != "" {
			t.Errorf("%s já é o caminho, não devia ganhar ator %q", fd.Subject, fd.Ator)
		}
	}
}

// Os prefixos de modificador do systemd grudam no caminho. Não tirá-los
// devolveria "-/usr/local/sbin/..." — que não casa com caminho nenhum — e a
// fusão sumiria em silêncio, que é o pior jeito de uma correlação falhar.
func TestPrimeiroBinarioTiraModificadorDoSystemd(t *testing.T) {
	for _, c := range []struct{ cmd, quer string }{
		{"/usr/bin/foo --x", "/usr/bin/foo"},
		{"-/usr/bin/foo", "/usr/bin/foo"},
		{"@/usr/bin/foo bar", "/usr/bin/foo"},
		{"+/usr/bin/foo", "/usr/bin/foo"},
		{"!!/usr/bin/foo", "/usr/bin/foo"},
		{"foo --x", ""}, // relativo: não é caminho que outro achado nomeie
		{"", ""},
	} {
		if got := primeiroBinario(c.cmd); got != c.quer {
			t.Errorf("primeiroBinario(%q) = %q, queria %q", c.cmd, got, c.quer)
		}
	}
}

// Exe apagado sai do /proc com sufixo, e ele não é parte do caminho.
func TestAtorIgnoraSufixoDeApagado(t *testing.T) {
	f := &facts.Facts{
		Processes: []facts.Process{{PID: 9, Exe: "/tmp/.x (deleted)"}},
	}
	f.Index()
	got := binariosDoSujeito("pid=9", f)
	if len(got) != 1 || got[0] != "/tmp/.x" {
		t.Errorf("queria [/tmp/.x], deu %q", got)
	}
}

// INFO não forma nem autoriza grupo — é a mesma regra da correlação por
// sujeito, e ela não pode mudar por causa do ator.
func TestAtorIgnoraInfo(t *testing.T) {
	r := &Report{Findings: []Finding{
		{ID: "a", Sev: SevInfo, Subject: "/usr/local/sbin/systemd-netlinkd"},
		{ID: "b", Sev: SevWarn, Subject: "pid=17"},
	}}
	resolverAtores(r, fatosDoAtor())
	if r.Findings[1].Ator != "" {
		t.Error("um INFO não pode autorizar fusão: só ele nomeia o caminho")
	}
}

func TestAtorSobreviveASemFatos(t *testing.T) {
	r := &Report{Findings: []Finding{{ID: "a", Sev: SevWarn, Subject: "pid=1"}}}
	resolverAtores(r, nil) // não pode entrar em pânico
	if r.Findings[0].Ator != "" {
		t.Error("sem fatos não há ator")
	}
}

// O campo vai para o JSONL, e a frota passa a poder agrupar por ator entre
// hosts. Se o nome mudar, isso quebra em silêncio do lado de fora.
func TestAtorNoJSON(t *testing.T) {
	b, err := json.Marshal(Finding{Ator: "/tmp/x"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"actor":"/tmp/x"`) {
		t.Errorf("o campo Ator tem que sair como `actor` no JSONL: %s", b)
	}
	// E ausente quando vazio, que é o caso da esmagadora maioria dos achados.
	if b, _ := json.Marshal(Finding{}); strings.Contains(string(b), "actor") {
		t.Errorf("ator vazio não pode aparecer no JSONL: %s", b)
	}
}

// O host REAL tem a unit de verdade ao lado do drop-in, e o contêiner do
// cenário não tinha. A primeira versão pegava um executável só e este teste
// falhava: /usr/sbin/sshd vinha antes, ninguém o acusa, e o drop-in do invasor
// voltava a ser um aviso solto — em silêncio, no único ambiente que importa.
func TestAtorComUnitDoPacotePresente(t *testing.T) {
	f := &facts.Facts{
		Processes: []facts.Process{{PID: 17, Exe: "/usr/local/sbin/systemd-netlinkd"}},
		Units: []facts.Unit{
			{Name: "sshd.service", Path: "/usr/lib/systemd/system/sshd.service",
				Vendor: true,
				Exec:   []facts.ExecLine{{Key: "ExecStart", Cmd: "/usr/sbin/sshd -D"}}},
			{Name: "sshd.service", DropInFor: "sshd.service",
				Path: "/etc/systemd/system/sshd.service.d/10-hardening.conf",
				Exec: []facts.ExecLine{{Key: "ExecStartPre", Cmd: "/usr/local/sbin/systemd-netlinkd sleep 1"}}},
		},
	}
	f.Index()
	r := &Report{Findings: []Finding{
		{ID: "integrity.no_package_owner", Sev: SevWarn, Subject: "/usr/local/sbin/systemd-netlinkd"},
		{ID: "net.egress_unowned", Sev: SevWarn, Subject: "pid=17"},
		{ID: "persist.unit_dropin_exec", Sev: SevWarn, Subject: "sshd.service"},
	}}
	resolverAtores(r, f)

	grupos, resto := r.Correlate()
	if len(grupos) != 1 || len(grupos[0].Findings) != 3 {
		t.Fatalf("o drop-in tinha que entrar no grupo do implante: %d grupo(s), %d solto(s)",
			len(grupos), len(resto))
	}
	if grupos[0].Subject != "/usr/local/sbin/systemd-netlinkd" {
		t.Errorf("o alvo é o implante, não o daemon do pacote: %q", grupos[0].Subject)
	}
}

// E o daemon do pacote NÃO pode ser puxado para dentro por tabela: se o achado
// for sobre a unit legítima e o implante não existir, não há ator nenhum.
func TestAtorNaoInventaQuandoNadaEstaAcusado(t *testing.T) {
	f := &facts.Facts{Units: []facts.Unit{
		{Name: "sshd.service", Exec: []facts.ExecLine{{Key: "ExecStart", Cmd: "/usr/sbin/sshd -D"}}},
	}}
	f.Index()
	r := &Report{Findings: []Finding{
		{ID: "persist.unit_dropin_exec", Sev: SevWarn, Subject: "sshd.service"},
		{ID: "cred.ssh_private_key", Sev: SevWarn, Subject: "/root/.ssh/id_rsa"},
	}}
	resolverAtores(r, f)
	if r.Findings[0].Ator != "" {
		t.Errorf("nenhum achado acusa /usr/sbin/sshd: ator %q saiu do nada", r.Findings[0].Ator)
	}
}

// Quando os DOIS executáveis da unit estão acusados — o daemon do pacote foi
// trocado e ainda há um drop-in com implante —, a prioridade decide qual
// história o achado do drop-in conta. Ele é sobre o que alguém ACRESCENTOU, e
// é ao acréscimo que ele tem que se juntar.
//
// Sem este teste a ordem das duas passadas podia ser invertida sem que nada
// reclamasse: com um só acusado, as duas ordens dão o mesmo resultado.
func TestAtorPrefereODropInQuandoOsDoisEstaoAcusados(t *testing.T) {
	f := &facts.Facts{Units: []facts.Unit{
		{Name: "sshd.service", Vendor: true, Path: "/usr/lib/systemd/system/sshd.service",
			Exec: []facts.ExecLine{{Key: "ExecStart", Cmd: "/usr/sbin/sshd -D"}}},
		{Name: "sshd.service", DropInFor: "sshd.service",
			Path: "/etc/systemd/system/sshd.service.d/10-hardening.conf",
			Exec: []facts.ExecLine{{Key: "ExecStartPre", Cmd: "/usr/local/sbin/systemd-netlinkd"}}},
	}}
	f.Index()
	r := &Report{Findings: []Finding{
		// o daemon do pacote, trocado
		{ID: "integrity.pkg_file_modified", Sev: SevCritical, Subject: "/usr/sbin/sshd"},
		// e o implante que o drop-in acrescentou
		{ID: "integrity.no_package_owner", Sev: SevWarn, Subject: "/usr/local/sbin/systemd-netlinkd"},
		{ID: "persist.unit_dropin_exec", Sev: SevWarn, Subject: "sshd.service"},
	}}
	resolverAtores(r, f)

	if got := r.Findings[2].Ator; got != "/usr/local/sbin/systemd-netlinkd" {
		t.Errorf("o drop-in é sobre o que foi ACRESCENTADO, e o ator saiu %q", got)
	}

	// E a ordem dos candidatos é o que carrega essa decisão.
	cs := binariosDoSujeito("sshd.service", f)
	if len(cs) != 2 || cs[0] != "/usr/local/sbin/systemd-netlinkd" {
		t.Errorf("o drop-in tem que vir primeiro na lista de candidatos: %v", cs)
	}
	// E o daemon do pacote não pode sumir da lista: ele é o candidato quando o
	// achado é sobre a unit em si.
	if len(cs) == 2 && cs[1] != "/usr/sbin/sshd" {
		t.Errorf("o executável da unit do pacote sumiu: %v", cs)
	}
}

// A unit ERRADA não pode emprestar o binário dela. Sem a guarda de nome, um
// achado sobre `sshd.service` adotaria o executável acusado de `cron.service` —
// e o relatório contaria uma história em que duas coisas independentes viram
// um ator só, que é exatamente o defeito que a correlação existe para não ter.
func TestAtorNaoPegaBinarioDeOutraUnit(t *testing.T) {
	f := &facts.Facts{Units: []facts.Unit{
		{Name: "cron.service", Exec: []facts.ExecLine{{Key: "ExecStart", Cmd: "/usr/local/bin/implante"}}},
		{Name: "sshd.service", Exec: []facts.ExecLine{{Key: "ExecStart", Cmd: "/usr/sbin/sshd -D"}}},
	}}
	f.Index()
	r := &Report{Findings: []Finding{
		{ID: "integrity.no_package_owner", Sev: SevWarn, Subject: "/usr/local/bin/implante"},
		{ID: "persist.unit_dropin_exec", Sev: SevWarn, Subject: "sshd.service"},
	}}
	resolverAtores(r, f)
	if got := r.Findings[1].Ator; got != "" {
		t.Errorf("o achado é sobre sshd.service e adotou %q, que é de outra unit", got)
	}
	if cs := binariosDoSujeito("sshd.service", f); len(cs) != 1 || cs[0] != "/usr/sbin/sshd" {
		t.Errorf("só o executável da própria unit é candidato: %v", cs)
	}
}
