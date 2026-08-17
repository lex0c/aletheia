package facts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/env"
)

// Regressão do vazamento mais perigoso encontrado na revisão: uma imagem cujos
// arquivos são symlinks ABSOLUTOS — situação NORMAL em rootfs real, sem atacante
// nenhum — fazia a ferramenta ler o host do ANALISTA e atribuir o valor à
// imagem. O operador via o próprio hostname e concluía coisas sobre a imagem a
// partir de dados que nunca estiveram nela.
//
// A primeira correção fechou só a metade léxica (".." no caminho). Symlink é a
// outra metade, e só o kernel resolve: os.Root usa openat2/RESOLVE_BENEATH.
func TestImagemNaoLeArquivoDeForaPorSymlink(t *testing.T) {
	img := t.TempDir()
	fora := t.TempDir()

	if err := os.WriteFile(filepath.Join(fora, "segredo"), []byte("HOST-DO-ANALISTA"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(img, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	// symlink absoluto para fora da imagem
	if err := os.Symlink(filepath.Join(fora, "segredo"), filepath.Join(img, "etc/hostname")); err != nil {
		t.Fatal(err)
	}

	e := env.Probe(env.Options{Root: img})
	defer e.Close()

	if b, err := e.ReadFile("/etc/hostname"); err == nil {
		t.Errorf("leu %q através de symlink que escapa da imagem", string(b))
	}

	f := Collect(e)
	if strings.Contains(f.Host.Hostname, "ANALISTA") {
		t.Errorf("Hostname = %q — dado de fora da imagem atribuído a ela", f.Host.Hostname)
	}
}

// E o caso mais sutil: os PROBES de capacidade compartilhavam a fuga. Um
// /var/lib/dpkg/status plantado como link faria os checks de integridade rodarem
// contra os arquivos do analista e reportarem a imagem como limpa.
func TestProbeNaoConcedeCapacidadePorSymlinkQueEscapa(t *testing.T) {
	img := t.TempDir()
	if err := os.MkdirAll(filepath.Join(img, "var/lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	// aponta para algo que EXISTE no host do analista
	if err := os.Symlink("/etc/passwd", filepath.Join(img, "var/lib/dpkg")); err != nil {
		t.Fatal(err)
	}

	e := env.Probe(env.Options{Root: img})
	defer e.Close()

	if e.Has(env.CapPkgDB) {
		t.Error("CapPkgDB concedida por link que escapa: checks de integridade rodariam " +
			"contra a base de pacotes do ANALISTA e diriam que a imagem está íntegra")
	}
}

// Em modo image, load/uptime/CPU são do host do analista e não pertencem ao
// relatório da imagem. Imprimir "load 0.00 (12 cpu)" atribui a ela um dado que
// não é dela.
func TestModoImageNaoAtribuiMetricasDoAnalista(t *testing.T) {
	img := t.TempDir()
	e := env.Probe(env.Options{Root: img})
	defer e.Close()

	f := Collect(e)
	if f.Host.NumCPU != 0 || f.Host.Load1 != 0 || f.Host.Uptime != "" {
		t.Errorf("modo image trouxe métrica do analista: cpu=%d load=%.2f uptime=%q",
			f.Host.NumCPU, f.Host.Load1, f.Host.Uptime)
	}
}

// Numa imagem montada não há processo vivo: a coleta precisa DIZER isso em vez
// de devolver zero processos como se o host estivesse vazio.
func TestModoImageDeclaraAusenciaDeProcessos(t *testing.T) {
	e := env.Probe(env.Options{Root: t.TempDir()})
	defer e.Close()

	f := Collect(e)
	if len(f.Processes) != 0 {
		t.Errorf("modo image não pode ter processos, veio %d", len(f.Processes))
	}
	if len(f.Partial["proc"]) == 0 {
		t.Error("a ausência de /proc precisa virar lacuna declarada, não silêncio")
	}
}
