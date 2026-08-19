package checks

import (
	"testing"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/facts"
	"github.com/lex0c/aletheia/internal/kbpf"
)

// Um programa de cgroup sem dono visível e sem anexo nenhum só é ANOMALIA se a
// árvore de cgroup tiver sido percorrida por inteiro. Com qualquer buraco na
// cobertura — teto, prazo, EACCES — a mesma observação é CEGUEIRA, e a resposta
// certa é lacuna. Antes desta distinção, todo programa de cgroup caía sempre no
// segundo caso, e o trabalho de enumerar a árvore só servia para nomear o
// detentor quando ele aparecia.
func factsCgroup(cobertura bool, anexos []string) *facts.Facts {
	f := &facts.Facts{}
	f.BPF.Enumerado = true
	f.BPF.CoberturaAnexo.Cgroup = cobertura
	f.BPF.Programas = []facts.ProgramaBPF{{
		ID: 42, Tipo: "cgroup_skb", TipoNum: kbpf.ProgCgroupSkb,
		Nome: "x", Anexos: anexos,
	}}
	return f
}

func TestCgroupSemAnexoSoAcusaComCoberturaCompleta(t *testing.T) {
	// Cobertura completa, nenhum anexo: a ausência é AFIRMÁVEL.
	r := bpfSemDono.Run(bpfSemDono, factsCgroup(true, nil), testEnv())
	if len(r.Findings) != 1 {
		t.Fatalf("com a árvore inteira enumerada e nenhum anexo, é achado: %+v (partial=%v)",
			r.Findings, r.Partial)
	}

	// Cobertura incompleta: a MESMA observação vira lacuna, não achado.
	r = bpfSemDono.Run(bpfSemDono, factsCgroup(false, nil), testEnv())
	if len(r.Findings) != 0 {
		t.Errorf("sem cobertura completa não se afirma ausência: %+v", r.Findings)
	}
	if len(r.Partial) == 0 {
		t.Error("e o que não foi atribuído tem de virar lacuna DECLARADA")
	}

	// Com anexo encontrado, não há o que acusar em nenhum dos dois casos.
	for _, cob := range []bool{true, false} {
		r = bpfSemDono.Run(bpfSemDono, factsCgroup(cob, []string{"cgroup device em /"}), testEnv())
		if len(r.Findings) != 0 {
			t.Errorf("cobertura=%v: programa COM anexo não é órfão: %+v", cob, r.Findings)
		}
	}
}

// FixMapa continua sem cobertura: o conteúdo dos mapas não é lido, e struct_ops
// e sockmap seguem em lacuna declarada mesmo com cgroup e netlink completos.
func TestMapaContinuaSemCobertura(t *testing.T) {
	f := &facts.Facts{}
	f.BPF.CoberturaAnexo = facts.CoberturaDeAnexo{Netlink: true, Cgroup: true}
	if cobreFixacao(f, kbpf.FixMapa) {
		t.Error("o conteúdo dos mapas não é lido: FixMapa não pode ser dado como coberto")
	}
	if !cobreFixacao(f, kbpf.FixVisivel) || !cobreFixacao(f, kbpf.FixSocket) {
		t.Error("detentor legível e socket saem da própria enumeração: sempre cobertos")
	}
}

var _ = check.SevWarn
