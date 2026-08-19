package facts

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// árvoreCgroup monta uma hierarquia de cgroup falsa (só diretórios) para
// exercitar a travessia sem um /sys/fs/cgroup real.
func árvoreCgroup(t *testing.T, dirs ...string) string {
	raiz := t.TempDir()
	for _, d := range dirs {
		if err := os.MkdirAll(filepath.Join(raiz, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return raiz
}

// A árvore INTEIRA é percorrida — não só topo+slices —, porque limitar por
// caminho conhecido viraria regra de evasão. Os slices conhecidos só decidem a
// ORDEM, para o corte por orçamento cair nas folhas genéricas.
func TestPercorrerCgroupsVisitaTudoComPrioridade(t *testing.T) {
	raiz := árvoreCgroup(t,
		"aaa/leaf", "system.slice/sshd.service", "zzz", "user.slice",
		"kubepods-besteffort.slice/pod", ".hidden/attack",
	)
	// um ARQUIVO no meio da árvore: cgroup é diretório, e um arquivo não pode
	// virar cgroup nem ser aberto para BPF_PROG_QUERY.
	if err := os.WriteFile(filepath.Join(raiz, "cgroup.procs"), []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	paths, teto, fundo, _, _ := percorrerCgroups(raiz, 10_000, time.Now().Add(time.Minute), nil)
	if teto || fundo {
		t.Fatalf("árvore pequena não devia truncar: teto=%v fundo=%v", teto, fundo)
	}
	vistos := map[string]bool{}
	for _, p := range paths {
		vistos[p[len(raiz):]] = true
	}
	// tudo entra, inclusive o /.hidden/attack — o ponto do argumento.
	for _, q := range []string{"", "/aaa/leaf", "/system.slice/sshd.service",
		"/zzz", "/user.slice", "/kubepods-besteffort.slice/pod", "/.hidden/attack"} {
		if !vistos[q] {
			t.Errorf("cgroup %q não foi visitado — a árvore inteira tem de entrar", q)
		}
	}
	// o arquivo NÃO entra.
	if vistos["/cgroup.procs"] {
		t.Error("um arquivo não pode ser tratado como cgroup")
	}
	// ORDEM: os slices conhecidos vêm ANTES dos genéricos no mesmo nível — e o
	// casamento é por PREFIXO (kubepods-besteffort.slice casa "kubepods").
	idx := map[string]int{}
	for i, p := range paths {
		idx[p[len(raiz):]] = i
	}
	if idx["/system.slice"] > idx["/aaa"] || idx["/user.slice"] > idx["/zzz"] {
		t.Errorf("slice conhecido antes do genérico: %v", paths)
	}
	// contra "aaa", que ordena ANTES de "kubepods" alfabeticamente: só a
	// prioridade por PREFIXO coloca kubepods na frente.
	if idx["/kubepods-besteffort.slice"] > idx["/aaa"] {
		t.Errorf("kubepods-besteffort (prefixo kubepods) tem de vir antes de aaa: %v", paths)
	}
}

// O teto de quantidade corta a CAUDA e declara. Como os prioritários vêm
// primeiro, são as folhas genéricas que caem.
func TestPercorrerCgroupsCortaNoTeto(t *testing.T) {
	raiz := árvoreCgroup(t, "a", "b", "c", "d", "e")
	paths, teto, _, _, _ := percorrerCgroups(raiz, 3, time.Now().Add(time.Minute), nil)
	if !teto {
		t.Error("com 6 cgroups e teto 3, tem de truncar")
	}
	if len(paths) != 3 {
		t.Errorf("visitou %d, o teto é 3", len(paths))
	}
}
