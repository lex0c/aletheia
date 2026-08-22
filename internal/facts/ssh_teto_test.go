package facts

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/env"
)

// OS TRÊS TETOS DA LEITURA DE SSH, e por que eles precisam de teste próprio.
//
// Teto é a defesa contra config patológica — cadeia de Include em ciclo, glob
// que abre milhares de caminhos. O perigo dele é o modo de falha: cortar É
// correto, cortar CALADO não. Um corte silencioso faz "parei de olhar" sair
// como "não há mais nada", e o drift do lado seguinte afirma que o conjunto
// está exaustivo depois de tê-lo truncado.
//
// Os três casos abaixo cobrem as três formas, e cada um confere DUAS coisas: a
// lacuna para o operador e o FATO de completude que a família de drift lê. As
// duas erravam juntas — a expansão do cliente derrubava a flag do SERVIDOR, e
// os outros dois não derrubavam nenhuma.

func envDeRaiz(t *testing.T, raiz string) *env.Env {
	t.Helper()
	e := env.Probe(env.Options{Root: raiz, Version: "test"})
	t.Cleanup(func() { e.Close() })
	return e
}

func lacunaSSH(f *Facts, sub string) bool {
	for _, l := range f.PersistDenied["ssh"] {
		if strings.Contains(l, sub) {
			return true
		}
	}
	return false
}

// A expansão de Include do CLIENTE que estoura o teto de caminhos derruba a
// flag do CLIENTE — e não a do servidor, que foi o defeito.
func TestTetoDeExpansaoDoClienteDerrubaAFlagDoCliente(t *testing.T) {
	raiz := t.TempDir()
	perfis := filepath.Join(raiz, "home/u/.ssh/perfis")
	if err := os.MkdirAll(perfis, 0o755); err != nil {
		t.Fatal(err)
	}
	// Um único `*` abrindo mais caminhos que o teto.
	for i := 0; i < maxExpansaoInclude+5; i++ {
		d := filepath.Join(perfis, "p"+strconv.Itoa(i))
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(d, "c.conf"), []byte("ProxyCommand /bin/true\n"), 0o600)
	}
	os.MkdirAll(filepath.Join(raiz, "etc/ssh"), 0o755)
	os.WriteFile(filepath.Join(raiz, "etc/passwd"),
		[]byte("u:x:1000:1000::/home/u:/bin/sh\n"), 0o644)
	os.WriteFile(filepath.Join(raiz, "home/u/.ssh/config"),
		[]byte("Include ~/.ssh/perfis/*/c.conf\n"), 0o600)

	f := &Facts{SSHServerCompleto: true, SSHClienteCompleto: true}
	collectSSHClientConfig(f, envDeRaiz(t, raiz))

	if f.SSHClienteCompleto {
		t.Error("a expansão do CLIENTE foi truncada e SSHClienteCompleto continuou " +
			"verdadeiro: a família ssh.cliente_exec afirmaria conjunto exaustivo " +
			"logo depois de cortá-lo")
	}
	if !f.SSHServerCompleto {
		t.Error("SSHServerCompleto foi derrubado por um corte na config de CLIENTE: " +
			"a comparação do sshd é degradada sem nada ter acontecido com ela")
	}
	if !lacunaSSH(f, "expandiu para mais de") {
		t.Errorf("sem lacuna declarada: %v", f.PersistDenied["ssh"])
	}
}

// A cadeia de Include do cliente mais funda que o teto também degrada.
func TestTetoDeProfundidadeDoClienteDeclaraLacuna(t *testing.T) {
	raiz := t.TempDir()
	dir := filepath.Join(raiz, "home/u/.ssh")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(filepath.Join(raiz, "etc/ssh"), 0o755)
	os.WriteFile(filepath.Join(raiz, "etc/passwd"),
		[]byte("u:x:1000:1000::/home/u:/bin/sh\n"), 0o644)
	// config -> e1 -> e2 -> ... : cada elo inclui o próximo, e o último planta.
	n := maxArquivosSSH + 3
	os.WriteFile(filepath.Join(dir, "config"),
		[]byte("Include ~/.ssh/e1\n"), 0o600)
	for i := 1; i < n; i++ {
		os.WriteFile(filepath.Join(dir, "e"+strconv.Itoa(i)),
			[]byte("Include ~/.ssh/e"+strconv.Itoa(i+1)+"\n"), 0o600)
	}
	os.WriteFile(filepath.Join(dir, "e"+strconv.Itoa(n)),
		[]byte("ProxyCommand /tmp/.implante\n"), 0o600)

	f := &Facts{SSHServerCompleto: true, SSHClienteCompleto: true}
	collectSSHClientConfig(f, envDeRaiz(t, raiz))

	if f.SSHClienteCompleto {
		t.Error("a cadeia foi cortada na profundidade e SSHClienteCompleto " +
			"continuou verdadeiro")
	}
	if !lacunaSSH(f, "passou de") {
		t.Errorf("sem lacuna declarada: %v", f.PersistDenied["ssh"])
	}
}

// E o lado do SERVIDOR: mais arquivos de configuração que o teto do laço.
func TestTetoDeArquivosDoServidorDeclaraLacuna(t *testing.T) {
	raiz := t.TempDir()
	d := filepath.Join(raiz, "etc/ssh/sshd_config.d")
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(raiz, "etc/ssh/sshd_config"),
		[]byte("PermitRootLogin no\n"), 0o600)
	for i := 0; i < maxArquivosSSH+5; i++ {
		os.WriteFile(filepath.Join(d, strconv.Itoa(i)+".conf"),
			[]byte("# nada\n"), 0o600)
	}

	f := &Facts{SSHServerCompleto: true, SSHClienteCompleto: true}
	collectSSHConfig(f, envDeRaiz(t, raiz))

	if f.SSHServerCompleto {
		t.Error("a leitura do sshd parou no teto e SSHServerCompleto continuou " +
			"verdadeiro: uma diretiva além do corte sairia como inexistente")
	}
	if !lacunaSSH(f, "passou de") {
		t.Errorf("sem lacuna declarada: %v", f.PersistDenied["ssh"])
	}
	if f.SSHClienteCompleto != true {
		t.Error("um corte do lado do SERVIDOR não pode degradar a flag do cliente")
	}
}
