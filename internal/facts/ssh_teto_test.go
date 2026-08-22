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

// O GLOB DO INCLUDE VALE EM QUALQUER COMPONENTE, e o lado do SERVIDOR afirmava
// o contrário por escrito.
//
// O sshd_config(5) diz que cada pathname pode conter curinga de glob(7), e não
// restringe o curinga ao último componente. A versão anterior devolvia `nil` —
// calada, sem lacuna — para padrão com curinga no diretório, então um
// PermitRootLogin plantado um nível abaixo não existia para esta ferramenta.
func TestIncludeDoServidorExpandeGlobEmDiretorio(t *testing.T) {
	raiz := t.TempDir()
	for _, d := range []string{"etc/ssh/perfis/a", "etc/ssh/perfis/b"} {
		if err := os.MkdirAll(filepath.Join(raiz, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	os.WriteFile(filepath.Join(raiz, "etc/ssh/sshd_config"),
		[]byte("Include /etc/ssh/perfis/*/sshd.conf\n"), 0o600)
	os.WriteFile(filepath.Join(raiz, "etc/ssh/perfis/a/sshd.conf"),
		[]byte("PermitRootLogin yes\n"), 0o600)
	os.WriteFile(filepath.Join(raiz, "etc/ssh/perfis/b/sshd.conf"),
		[]byte("AuthorizedKeysCommand /tmp/.k\n"), 0o600)

	f := &Facts{SSHServerCompleto: true, SSHClienteCompleto: true}
	collectSSHConfig(f, envDeRaiz(t, raiz))

	if f.SSH.PermitRootLogin != "yes" {
		t.Errorf("o Include com curinga no DIRETÓRIO não foi expandido: "+
			"PermitRootLogin=%q, arquivos=%v", f.SSH.PermitRootLogin, f.SSH.Files)
	}
	if f.SSH.AuthorizedKeysCommand != "/tmp/.k" {
		t.Errorf("o segundo perfil também não entrou: %q", f.SSH.AuthorizedKeysCommand)
	}
}

// LISTAGEM QUE FALHA NÃO É DIRETÓRIO VAZIO.
//
// Os dois lados usavam ReadDirNames, que engole o erro por desenho — o
// comentário dele manda não usá-lo onde a diferença decide cobertura. Um
// diretório de perfis sem permissão dava zero matches e o conjunto continuava
// "completo": um ProxyCommand plantado ali saía como inexistente.
func TestGlobDeIncludeComDiretorioIlegivelDeclaraLacuna(t *testing.T) {
	raiz := t.TempDir()
	perfis := filepath.Join(raiz, "home/u/.ssh/perfis")
	if err := os.MkdirAll(perfis, 0o755); err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(filepath.Join(raiz, "etc/ssh"), 0o755)
	os.WriteFile(filepath.Join(raiz, "etc/passwd"),
		[]byte("u:x:1000:1000::/home/u:/bin/sh\n"), 0o644)
	os.WriteFile(filepath.Join(raiz, "home/u/.ssh/config"),
		[]byte("Include ~/.ssh/perfis/*.conf\n"), 0o600)
	if err := os.Chmod(perfis, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(perfis, 0o755) })

	f := &Facts{SSHServerCompleto: true, SSHClienteCompleto: true}
	collectSSHClientConfig(f, envDeRaiz(t, raiz))

	if f.SSHClienteCompleto {
		t.Error("o diretório do curinga não pôde ser LISTADO e SSHClienteCompleto " +
			"continuou verdadeiro: zero matches saiu como 'não há nada ali'")
	}
	if !lacunaSSH(f, "não pôde ser listado") {
		t.Errorf("sem lacuna declarada: %v", f.PersistDenied["ssh"])
	}
	if !f.SSHServerCompleto {
		t.Error("um diretório de config de CLIENTE não pode degradar o servidor")
	}
}
