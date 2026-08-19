package env

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Path é o ponto único onde --root é aplicado. Um caminho que escape daqui
// significa ler a VM forense em vez da imagem montada — e o resultado pareceria
// um host limpo.
func TestPathAplicaRoot(t *testing.T) {
	live := &Env{Root: ""}
	if got := live.Path("/etc/passwd"); got != "/etc/passwd" {
		t.Errorf("modo live não pode prefixar: %q", got)
	}

	img := &Env{Root: "/mnt/ir"}
	cases := map[string]string{
		"/etc/passwd":             "/mnt/ir/etc/passwd",
		"/etc/ld.so.preload":      "/mnt/ir/etc/ld.so.preload",
		"/usr/lib/systemd/system": "/mnt/ir/usr/lib/systemd/system",
	}
	for in, want := range cases {
		if got := img.Path(in); got != want {
			t.Errorf("Path(%q) = %q, quer %q", in, got, want)
		}
	}
}

// Path não pode permitir que um caminho vaze para fora do --root: ".." num
// caminho montado a partir de dado do alvo levaria a ferramenta a ler o host
// do analista.
func TestPathNaoEscapaDoRoot(t *testing.T) {
	img := &Env{Root: "/mnt/ir"}
	got := img.Path("/../../etc/shadow")
	if !strings.HasPrefix(got, "/mnt/ir") {
		t.Errorf("Path(%q) = %q escapou do root", "/../../etc/shadow", got)
	}
}

func TestHasEMissing(t *testing.T) {
	e := &Env{Caps: CapProcfs | CapFilesystem}

	if !e.Has(CapProcfs) {
		t.Error("Has(CapProcfs) deveria ser true")
	}
	if !e.Has(CapProcfs | CapFilesystem) {
		t.Error("Has com conjunto presente deveria ser true")
	}
	if e.Has(CapProcfs | CapRoot) {
		t.Error("Has exige TODAS as capacidades do conjunto")
	}
	if got := e.Missing(CapProcfs | CapRoot); got != CapRoot {
		t.Errorf("Missing = %v, quer apenas root", got.Names())
	}
	if got := e.Missing(CapProcfs); got != 0 {
		t.Errorf("Missing de capacidade presente deve ser 0, veio %v", got.Names())
	}
}

// Capacidade ausente sempre tem motivo escrito: é o que o rodapé imprime, e é
// a diferença entre "não achei" e "não olhei".
func TestReasonExplicaAusencia(t *testing.T) {
	e := &Env{CapReason: map[string]string{"debugfs": "debugfs não montado"}}
	if got := e.Reason(CapDebugfs); got != "debugfs não montado" {
		t.Errorf("Reason = %q", got)
	}
	if got := e.Reason(CapBPF); got == "" {
		t.Error("Reason nunca pode ser vazio: sem motivo, o rodapé mente por omissão")
	}
}

func TestCapNames(t *testing.T) {
	c := CapRoot | CapProcfs
	names := c.Names()
	if len(names) != 2 {
		t.Fatalf("Names = %v, quer 2", names)
	}
	if !strings.Contains(c.String(), "root") || !strings.Contains(c.String(), "procfs") {
		t.Errorf("String = %q", c.String())
	}
	if Cap(0).String() != "" {
		t.Error("conjunto vazio deve render string vazia")
	}
}

// --root implica modo image; sem ele, live. O modo decide quais checks se
// aplicam, então errar aqui silencia metade da ferramenta.
func TestProbeDefineSourcePeloRoot(t *testing.T) {
	dir := t.TempDir()

	live := Probe(Options{})
	if live.Source != SourceLive {
		t.Errorf("sem --root deve ser live, veio %s", live.Source)
	}

	img := Probe(Options{Root: dir})
	if img.Source != SourceImage {
		t.Errorf("com --root deve ser image, veio %s", img.Source)
	}
	// Numa imagem montada não há processo vivo: procfs precisa faltar, com
	// motivo, senão os checks de processo reportariam "nada encontrado".
	if img.Has(CapProcfs) {
		t.Error("modo image não pode ter CapProcfs")
	}
	if r := img.Reason(CapProcfs); !strings.Contains(r, "image") {
		t.Errorf("motivo deve citar o modo: %q", r)
	}
}

// O probe sonda caminho existente em vez de ramificar por nome de distro
// (SPEC 3, princípio 4).
func TestProbeSondaCaminhoNaoDistro(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "usr/lib/systemd/system"), 0o755); err != nil {
		t.Fatal(err)
	}
	e := Probe(Options{Root: dir})
	if !e.Has(CapSystemd) {
		t.Error("diretório de unit presente deve conceder CapSystemd, sem olhar /etc/os-release")
	}

	vazio := Probe(Options{Root: t.TempDir()})
	if vazio.Has(CapSystemd) {
		t.Error("sem diretório de unit, CapSystemd deve faltar")
	}
}

// Capacidade AUSENTE é declarada com motivo ESPECÍFICO. Fingir cobertura seria
// o oposto do propósito da ferramenta, e um motivo genérico não diz ao operador
// o que fazer: falta root, falta o mecanismo neste kernel, ou a ferramenta se
// recusou a perguntar?
//
// A versão anterior deste teste afirmava que CapBPF e CapNetlink nunca podiam
// ser concedidas, porque nenhuma das duas estava implementada quando ele foi
// escrito. As duas estão. O que sobrevive — e era o que importava — é a
// exigência do motivo, agora cobrando de TODAS.
func TestCapacidadeAusenteTemMotivoEspecifico(t *testing.T) {
	e := Probe(Options{})
	for _, c := range []Cap{
		CapRoot, CapProcfs, CapDebugfs, CapBPF,
		CapSystemd, CapPkgDB, CapNetlink, CapFilesystem,
	} {
		if e.Has(c) {
			continue
		}
		if r := e.Reason(c); r == "" || r == "indisponível" {
			t.Errorf("%v precisa de motivo específico, veio %q", c.Names(), r)
		}
	}
}

// O tempo é sempre UTC: a nuvem loga em UTC e misturar fuso arruína a
// correlação (runbook §9.1).
func TestProbeUsaUTC(t *testing.T) {
	e := Probe(Options{})
	if e.Now.Location() != nil && e.Now.Location().String() != "UTC" {
		t.Errorf("Now está em %s, quer UTC", e.Now.Location())
	}
}

// O binário se identifica: caminho e hash entram no relatório para o war log
// saber qual ferramenta produziu cada achado (runbook §39.3).
func TestProbeCalculaHashDoProprioBinario(t *testing.T) {
	e := Probe(Options{Version: "0.1.0-test"})
	if e.ToolPath == "" {
		t.Error("ToolPath vazio: o war log precisa do caminho")
	}
	if len(e.ToolSHA256) != 64 {
		t.Errorf("ToolSHA256 = %q, quer 64 hex", e.ToolSHA256)
	}
	if e.ToolVersion != "0.1.0-test" {
		t.Errorf("ToolVersion = %q", e.ToolVersion)
	}
}

func TestClockStateString(t *testing.T) {
	if ClockUnknown.String() != "desconhecido" {
		t.Errorf("relógio não determinado precisa dizer isso, não assumir sincronizado")
	}
	if ClockSynced.String() == ClockUnsynced.String() {
		t.Error("sincronizado e não sincronizado não podem imprimir igual")
	}
}

// A recusa que protege o host de nós mesmos.
//
// Consultar o sock_diag por netlink pode fazer o kernel carregar sozinho o
// módulo de diagnóstico — e para carregar módulo o kernel EXECUTA
// /proc/sys/kernel/modprobe, como root. Num host onde esse caminho foi trocado,
// a consulta desta ferramenta seria o gatilho do implante que ela mesma
// denuncia. Perder uma visão cruzada é preço menor.
func TestModprobeDeFabricaDecideSeAConsultaPodeSerFeita(t *testing.T) {
	casos := []struct {
		nome, valor string
		seguro      bool
	}{
		{"caminho da distribuição", "/sbin/modprobe", true},
		{"usrmerge", "/usr/sbin/modprobe", true},
		// Vazio significa que o kernel não executa NADA para carregar módulo:
		// não existe gatilho, e a consulta é segura.
		{"vazio", "", true},
		{"trocado por implante", "/tmp/.x", false},
		{"trocado por caminho de aparência boa", "/usr/local/sbin/modprobe", false},
	}
	for _, c := range casos {
		t.Run(c.nome, func(t *testing.T) {
			raiz := t.TempDir()
			if err := os.MkdirAll(filepath.Join(raiz, "proc/sys/kernel"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(raiz, "proc/sys/kernel/modprobe"),
				[]byte(c.valor+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			e := Probe(Options{Root: raiz})
			t.Cleanup(func() { e.Close() })
			if _, seguro := modprobeDeFabrica(e); seguro != c.seguro {
				t.Errorf("%q: seguro=%v, quer %v", c.valor, seguro, c.seguro)
			}
		})
	}
}

// Não poder VERIFICAR a precondição de uma ação com efeito colateral é motivo
// para não tomar a ação. O arquivo é legível por qualquer um em host normal;
// não estar lá é sinal por si só.
func TestModprobeIlegivelContaComoInseguro(t *testing.T) {
	e := Probe(Options{Root: t.TempDir()})
	t.Cleanup(func() { e.Close() })
	alvo, seguro := modprobeDeFabrica(e)
	if seguro {
		t.Error("sem poder ler o helper, a consulta não pode ser feita")
	}
	if !strings.Contains(alvo, "ilegível") {
		t.Errorf("o motivo precisa dizer que não deu para ler: %q", alvo)
	}
}
