package checks

import (
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/facts"
)

func rodaAtributos(t *testing.T, f *facts.Facts) *check.Report {
	t.Helper()
	f.Index()
	return check.Run([]check.Check{arquivoImutavel}, f, testEnv())
}

// Num host RPM a base de pacotes é binária e o inventário de propriedade sai
// VAZIO INTEIRO. A ausência do caminho nesse inventário era lida como "tem
// dono": a ferramenta AFIRMAVA que o arquivo veio de pacote, citava o guia de
// endurecimento, e ainda deixava a severidade no piso — sobre um binário
// imutável em /usr/local/bin, que é a forma exata de implante que se defende.
func TestPropriedadeNaoConsultadaNaoViraTemDono(t *testing.T) {
	f := &facts.Facts{
		Atributos: []facts.AtributoInode{
			{Path: "/usr/local/bin/.sysupdate", Imutavel: true},
		},
		PersistDenied: map[string][]string{
			"pkg": {"base rpm é binária: não foi consultada"},
		},
	}
	r := rodaAtributos(t, f)
	if len(r.Findings) != 1 {
		t.Fatalf("achados = %+v", r.Findings)
	}
	for _, ev := range r.Findings[0].Evidence {
		if strings.Contains(ev, "tem dono de pacote") {
			t.Errorf("afirmou propriedade que nunca foi perguntada: %q", ev)
		}
	}
	if len(r.Coverage.Partial) == 0 {
		t.Error("e a pergunta que não foi feita precisa aparecer como lacuna: " +
			"é ela que separa endurecimento de implante")
	}
}

// Com o inventário respondendo, as duas pontas continuam valendo.
func TestAtributoComPropriedadeConhecidaPesaCerto(t *testing.T) {
	f := &facts.Facts{
		Atributos: []facts.AtributoInode{
			{Path: "/etc/shadow", Imutavel: true},
			{Path: "/usr/local/bin/.x", Imutavel: true},
		},
		Ownership: []facts.Ownership{
			{Path: "/etc/shadow", Owned: true, Pacote: "passwd"},
			{Path: "/usr/local/bin/.x", Owned: false},
		},
	}
	r := rodaAtributos(t, f)
	sev := map[string]check.Severity{}
	for _, fd := range r.Findings {
		sev[fd.Subject] = fd.Sev
	}
	if sev["/etc/shadow"] != check.SevWarn {
		t.Errorf("/etc/shadow imutável é endurecimento: %v", sev["/etc/shadow"])
	}
	if sev["/usr/local/bin/.x"] != check.SevCritical {
		t.Errorf("binário sem dono e imutável é implante que se defende: %v",
			sev["/usr/local/bin/.x"])
	}
	if len(r.Coverage.Partial) != 0 {
		t.Errorf("com a resposta em mãos não há lacuna: %v", r.Coverage.Partial)
	}
}
