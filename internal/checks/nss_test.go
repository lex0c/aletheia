package checks

import (
	"testing"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/facts"
)

// nss_module: o discriminador é o DONO, não o nome da fonte. Lib sem dono
// dispara CRÍTICO; a mesma lib COM dono (nss legítimo) não; fonte sem lib
// localizada também não.
func TestNSSModuleSemDono(t *testing.T) {
	casos := []struct {
		nome    string
		mod     facts.NSSModule
		owned   bool
		esperaN int
	}{
		{"lib sem dono dispara", facts.NSSModule{Fonte: "impl", Path: "/usr/lib/libnss_impl.so.2", Servicos: []string{"passwd"}}, false, 1},
		{"lib COM dono (nss legítimo) não dispara", facts.NSSModule{Fonte: "systemd", Path: "/usr/lib/libnss_systemd.so.2", Servicos: []string{"passwd"}}, true, 0},
		{"fonte sem lib localizada não dispara", facts.NSSModule{Fonte: "files", Path: ""}, false, 0},
	}
	for _, c := range casos {
		f := &facts.Facts{
			NSSModules: []facts.NSSModule{c.mod},
			Ownership:  []facts.Ownership{{Path: c.mod.Path, Owned: c.owned}},
			Pkg:        facts.PkgDB{Kind: "dpkg"},
		}
		r := nssModuleSemDono.Run(nssModuleSemDono, f, testEnv())
		if len(r.Findings) != c.esperaN {
			t.Errorf("[%s] achados=%d, quer %d: %+v", c.nome, len(r.Findings), c.esperaN, r.Findings)
		}
		if c.esperaN == 1 && len(r.Findings) == 1 && r.Findings[0].Sev != check.SevCritical {
			t.Errorf("[%s] severidade = %v, quer CRITICAL", c.nome, r.Findings[0].Sev)
		}
	}
}

// item 9: no musl o check NÃO acusa (o nsswitch é ignorado pela libc), e declara
// a inaplicabilidade em vez de silenciar.
func TestNSSModuleMuslNaoAcusa(t *testing.T) {
	f := &facts.Facts{
		NSSModules: []facts.NSSModule{{Fonte: "impl", Path: "/usr/lib/libnss_impl.so.2", Servicos: []string{"passwd"}}},
		Ownership:  []facts.Ownership{{Path: "/usr/lib/libnss_impl.so.2", Owned: false}},
		Pkg:        facts.PkgDB{Kind: "apk"},
	}
	f.Host.Libc = "musl"
	r := nssModuleSemDono.Run(nssModuleSemDono, f, testEnv())
	if len(r.Findings) != 0 {
		t.Fatalf("musl ignora nsswitch: não pode acusar execução NSS-glibc: %+v", r.Findings)
	}
	if len(r.Partial) == 0 {
		t.Error("inaplicabilidade no musl tem de ser declarada, não silenciada")
	}
}
