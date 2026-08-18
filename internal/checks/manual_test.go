package checks

import (
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/facts"
)

// Os checks ModeManual não emitem achado que mexe no exit code — a severidade é
// MANUAL, um roteiro para o operador. Mas eles têm GUARDA condicional, e uma
// guarda sem teste é uma que regride calada: passa a emitir onde devia calar, ou
// o contrário. Estes testes existem para dar dentes às guardas.

// exfil_volume: emite quando há saída para endereço PÚBLICO estabelecido, e cala
// quando não há. Peer privado ou conexão não-ESTAB não conta — é a diferença
// entre "falou com fora" e "tem socket".
func TestExfilVolumeSoComSaidaPublica(t *testing.T) {
	pub := facts.Socket{Dir: facts.DirOut, PeerScope: facts.ScopePublic,
		State: "ESTAB", PeerIP: "203.0.113.10"}
	r := volumeDeSaida.Run(volumeDeSaida, &facts.Facts{Sockets: []facts.Socket{pub}}, testEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevManual {
		t.Fatalf("saída pública estabelecida tem de virar roteiro MANUAL: %v", r.Findings)
	}
	if !strings.Contains(strings.Join(r.Findings[0].Evidence, " "), "203.0.113.10") {
		t.Error("o destino precisa aparecer: é o que o operador vai consultar")
	}

	// privado, LISTEN e inbound: nenhum é exfiltração, e o check tem de calar.
	priv := facts.Socket{Dir: facts.DirOut, PeerScope: facts.ScopePrivate, State: "ESTAB", PeerIP: "10.0.0.5"}
	lst := facts.Socket{Dir: facts.DirOut, PeerScope: facts.ScopePublic, State: "LISTEN", PeerIP: "203.0.113.9"}
	if r := volumeDeSaida.Run(volumeDeSaida, &facts.Facts{Sockets: []facts.Socket{priv, lst}}, testEnv()); len(r.Findings) != 0 {
		t.Errorf("peer privado e socket em LISTEN não são saída pública: %v", r.Findings)
	}
}

// code_integrity: emite quando há repositório git sob árvore de aplicação, e o
// caminho vai ESCAPADO para os comandos sugeridos — um repo com espaço ou aspa
// no caminho não pode quebrar o `git -C`.
func TestCodeIntegritySoComRepoEComCaminhoEscapado(t *testing.T) {
	if r := integridadeDoCodigo.Run(integridadeDoCodigo, &facts.Facts{}, testEnv()); len(r.Findings) != 0 {
		t.Errorf("sem repo git não há o que sugerir: %v", r.Findings)
	}

	f := &facts.Facts{Repos: []string{"/srv/app minha api"}}
	r := integridadeDoCodigo.Run(integridadeDoCodigo, f, testEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevManual {
		t.Fatalf("repo git tem de virar roteiro MANUAL: %v", r.Findings)
	}
	passos := strings.Join(r.Findings[0].NextSteps, "\n")
	if strings.Contains(passos, "git -C /srv/app minha api ") {
		t.Error("o caminho com espaço saiu CRU no comando: um `git -C` assim quebra ou " +
			"aponta para outro diretório — tem de ir escapado")
	}
	if !strings.Contains(passos, "origin/HEAD") {
		t.Error("o passo autoritativo é comparar com o REMOTO, e ele precisa sair")
	}
}

// audit_query: três guardas. Cala se o auditd não está instalado, cala se está
// DESLIGADO (é achado de outro check, não deste), e cala se não há processo
// suspeito para amarrar. Emite só com auditd ativo E alvo.
func TestAuditQueryRespeitaAsTresGuardas(t *testing.T) {
	suspeito := facts.Process{PID: 812, Exe: "/tmp/.x", StartUTC: "2026-08-18T10:00:00Z"}
	ativo := facts.Auditoria{Instalada: true, Desligada: false}

	casos := []struct {
		nome  string
		f     facts.Facts
		emite bool
	}{
		{"nao instalado", facts.Facts{Processes: []facts.Process{suspeito}}, false},
		{"desligado", facts.Facts{Audit: facts.Auditoria{Instalada: true, Desligada: true}, Processes: []facts.Process{suspeito}}, false},
		{"ativo sem alvo", facts.Facts{Audit: ativo}, false},
		{"ativo com alvo", facts.Facts{Audit: ativo, Processes: []facts.Process{suspeito}}, true},
	}
	for _, c := range casos {
		f := c.f
		r := consultaAoAudit.Run(consultaAoAudit, &f, testEnv())
		if (len(r.Findings) > 0) != c.emite {
			t.Errorf("%s: emitiu=%v, queria %v (%v)", c.nome, len(r.Findings) > 0, c.emite, r.Findings)
		}
	}

	// no caso que emite, o pid alvo tem de estar no roteiro: é o que amarra o vetor.
	r := consultaAoAudit.Run(consultaAoAudit, &facts.Facts{Audit: ativo, Processes: []facts.Process{suspeito}}, testEnv())
	if !strings.Contains(strings.Join(r.Findings[0].NextSteps, " "), "812") {
		t.Error("o pid suspeito precisa aparecer na consulta sugerida")
	}
}

// cloud_audit: o provedor é lido das units, e cada um leva a um comando
// diferente — gcloud para GCP, cloudtrail para AWS. Sem unit de nuvem, cala.
func TestCloudAuditPeloProvedor(t *testing.T) {
	if r := logDaNuvem.Run(logDaNuvem, &facts.Facts{}, testEnv()); len(r.Findings) != 0 {
		t.Errorf("host sem marca de nuvem não deve sugerir log de provedor: %v", r.Findings)
	}

	casos := []struct {
		unit, comando string
	}{
		{"google-guest-agent.service", "gcloud logging"},
		{"amazon-ssm-agent.service", "aws cloudtrail"},
		{"aws-something.service", "aws cloudtrail"},
	}
	for _, c := range casos {
		f := &facts.Facts{
			Units: []facts.Unit{{Name: c.unit}},
			Host:  facts.Host{Hostname: "vm-1"},
		}
		r := logDaNuvem.Run(logDaNuvem, f, testEnv())
		if len(r.Findings) != 1 {
			t.Fatalf("%s: achados = %v", c.unit, r.Findings)
		}
		if !strings.Contains(strings.Join(r.Findings[0].NextSteps, "\n"), c.comando) {
			t.Errorf("%s: o roteiro precisa usar %q, veio %v", c.unit, c.comando, r.Findings[0].NextSteps)
		}
	}
}
