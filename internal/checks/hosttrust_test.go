package checks

import (
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/facts"
)

func fTrust(cs ...facts.ConfiancaDeHost) *facts.Facts {
	return &facts.Facts{ConfiancaDeHost: cs}
}

// O `+` curinga é o backdoor: confia em qualquer host e qualquer usuário. Tem
// de ser CRÍTICO.
func TestHostTrustCuringaEhCritico(t *testing.T) {
	f := fTrust(facts.ConfiancaDeHost{
		Path: "/etc/hosts.equiv", Escopo: "sistema", Curinga: true,
		Linhas: []string{"+"},
	})
	r := confiancaHostBased.Run(confiancaHostBased, f, testEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevCritical {
		t.Fatalf("`+` é login sem senha de qualquer lugar: %+v", r.Findings)
	}
	if !strings.Contains(strings.Join(r.Findings[0].Evidence, " "), "QUALQUER") {
		t.Errorf("a evidência precisa dizer que é irrestrito: %v", r.Findings[0].Evidence)
	}
}

// Host nomeado é raro em sistema moderno, mas não é acesso irrestrito: AVISO, e
// a pergunta é quem colocou.
func TestHostTrustNomeadoEhAviso(t *testing.T) {
	f := fTrust(facts.ConfiancaDeHost{
		Path: "/root/.rhosts", Escopo: "usuario", Conta: "root",
		Linhas: []string{"buildserver.interno"},
	})
	r := confiancaHostBased.Run(confiancaHostBased, f, testEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevWarn {
		t.Fatalf("host nomeado é AVISO: %+v", r.Findings)
	}
	if r.Findings[0].Subject == "" || !strings.Contains(r.Findings[0].Subject, "root") {
		t.Errorf("o sujeito precisa nomear a conta: %q", r.Findings[0].Subject)
	}
}

// Gravável por grupo/outros agrava, mas não muda a severidade sozinho.
func TestHostTrustGravavelApareceNaEvidencia(t *testing.T) {
	f := fTrust(facts.ConfiancaDeHost{
		Path: "/home/ana/.rhosts", Escopo: "usuario", Conta: "ana",
		Linhas: []string{"outrohost"}, Gravavel: true,
	})
	r := confiancaHostBased.Run(confiancaHostBased, f, testEnv())
	if len(r.Findings) != 1 {
		t.Fatalf("achados: %+v", r.Findings)
	}
	if !strings.Contains(strings.Join(r.Findings[0].Evidence, " "), "gravável") {
		t.Errorf("gravável tem de aparecer: %v", r.Findings[0].Evidence)
	}
}
