package env

import (
	"os"
	"path/filepath"
	"testing"
)

// /sys/kernel/tracing e /sys/kernel/security existem em todo kernel com o
// Kconfig ligado, montados ou não. Um `IsDir` respondia sim nos dois casos, e
// o sim errado concedia capacidade sobre diretório VAZIO: a coleta parava de
// dizer que o ftrace não foi examinado exatamente onde ele não pôde ser.
func TestPontoDeMontagemVazioNaoEhFilesystemMontado(t *testing.T) {
	raiz := t.TempDir()
	// o ponto ocioso
	if err := os.MkdirAll(filepath.Join(raiz, "sys/kernel/tracing"), 0o755); err != nil {
		t.Fatal(err)
	}
	// o ponto com filesystem montado por baixo
	mont := filepath.Join(raiz, "sys/kernel/security")
	if err := os.MkdirAll(mont, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mont, "lockdown"), []byte("[none]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	e := Probe(Options{Root: raiz})
	t.Cleanup(e.Close)

	if got := e.EstadoDeMontagem("/sys/kernel/tracing"); got != MontagemVazia {
		t.Errorf("diretório vazio deu %v: um ponto de montagem ocioso não é um "+
			"filesystem montado", got)
	}
	if got := e.EstadoDeMontagem("/sys/kernel/security"); got != MontagemAtiva {
		t.Errorf("diretório com conteúdo deu %v", got)
	}
	if got := e.EstadoDeMontagem("/sys/kernel/nada"); got != MontagemAusente {
		t.Errorf("caminho inexistente deu %v", got)
	}
}

// E o outro lado, que é o que fez a primeira tentativa desta correção mentir
// no host onde ela foi escrita: tracefs MONTADO é 0700 de root. Sem privilégio
// o readdir falha, e chamar isso de "não montado" trocaria lacuna por resposta
// — o erro exato que esta função existe para não cometer.
func TestDiretorioIlegivelNaoViraNaoMontado(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root lista tudo")
	}
	raiz := t.TempDir()
	p := filepath.Join(raiz, "sys/kernel/tracing")
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p, "enabled_functions"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(p, 0o755) })

	e := Probe(Options{Root: raiz})
	t.Cleanup(e.Close)
	if got := e.EstadoDeMontagem("/sys/kernel/tracing"); got != MontagemIndeterminada {
		t.Errorf("diretório ilegível deu %v, queria MontagemIndeterminada", got)
	}
}
