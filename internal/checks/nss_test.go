package checks

import (
	"strings"
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
		{"lib sem dono dispara", facts.NSSModule{Fonte: "impl", Paths: []string{"/usr/lib/libnss_impl.so.2"}, Servicos: []string{"passwd"}}, false, 1},
		{"lib COM dono (nss legítimo) não dispara", facts.NSSModule{Fonte: "systemd", Paths: []string{"/usr/lib/libnss_systemd.so.2"}, Servicos: []string{"passwd"}}, true, 0},
		{"fonte sem lib localizada não dispara", facts.NSSModule{Fonte: "files", Paths: nil}, false, 0},
	}
	for _, c := range casos {
		f := &facts.Facts{
			NSSModules: []facts.NSSModule{c.mod},
			Ownership:  ownershipDeMod(c.mod, c.owned),
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
//
// O QUE MUDOU, e por quê: a declaração saiu de `Partial` e virou achado INFO.
//
// A intenção do item 9 continua inteira — inaplicabilidade não pode virar
// silêncio —, o que estava errado era o canal. `Partial` significa "esta
// pergunta cabia aqui e eu não consegui responder", e como todo Alpine é musl,
// TODA varredura em Alpine saía INCOMPLETE com exit 1, inclusive a de um host
// limpo. Aqui a pergunta não cabe: não há libnss_ para carregar porque a libc
// não os carrega. Isso é ESCOPO, e escopo é contexto — o mesmo que o
// proc.container_boundary e o kernel.module_no_file já tinham aprendido.
func TestNSSModuleMuslNaoAcusa(t *testing.T) {
	f := &facts.Facts{
		NSSModules: []facts.NSSModule{{Fonte: "impl", Paths: []string{"/usr/lib/libnss_impl.so.2"}, Servicos: []string{"passwd"}}},
		Ownership:  []facts.Ownership{{Path: "/usr/lib/libnss_impl.so.2", Owned: false}},
		Pkg:        facts.PkgDB{Kind: "apk"},
	}
	f.Host.Libc = "musl"
	r := nssModuleSemDono.Run(nssModuleSemDono, f, testEnv())
	for _, fd := range r.Findings {
		if fd.Sev != check.SevInfo {
			t.Fatalf("musl ignora nsswitch: não pode ACUSAR execução NSS-glibc: %+v", fd)
		}
	}
	if len(r.Findings) == 0 {
		t.Error("inaplicabilidade no musl tem de ser declarada, não silenciada")
	}
	if len(r.Partial) != 0 {
		t.Errorf("inaplicabilidade não é lacuna de cobertura: todo Alpine é musl, e "+
			"isto faria toda varredura em Alpine sair INCOMPLETE — inclusive a de um "+
			"host limpo\npartial: %v", r.Partial)
	}
}

func ownershipDeMod(m facts.NSSModule, owned bool) []facts.Ownership {
	var out []facts.Ownership
	for _, p := range m.Paths {
		out = append(out, facts.Ownership{Path: p, Owned: owned})
	}
	return out
}

// item 7: shadowing — uma cópia COM dono e uma órfã para a mesma fonte. A órfã
// dispara (o loader pode carregá-la pelo ld.so.cache), com nota de ambiguidade.
func TestNSSModuleShadowingDispara(t *testing.T) {
	f := &facts.Facts{
		NSSModules: []facts.NSSModule{{Fonte: "sss", Paths: []string{
			"/usr/lib/libnss_sss.so.2", "/opt/.hidden/libnss_sss.so.2"}, Servicos: []string{"passwd"}}},
		Ownership: []facts.Ownership{
			{Path: "/usr/lib/libnss_sss.so.2", Owned: true},      // legítima
			{Path: "/opt/.hidden/libnss_sss.so.2", Owned: false}, // implante
		},
		Pkg: facts.PkgDB{Kind: "dpkg"},
	}
	r := nssModuleSemDono.Run(nssModuleSemDono, f, testEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevCritical {
		t.Fatalf("a cópia órfã em shadowing deve disparar CRÍTICO: %+v", r.Findings)
	}
	temNota := false
	for _, ev := range r.Findings[0].Evidence {
		if strings.Contains(ev, "ld.so.cache") {
			temNota = true
		}
	}
	if !temNota {
		t.Error("shadowing deve declarar a ambiguidade do ld.so.cache")
	}
}
