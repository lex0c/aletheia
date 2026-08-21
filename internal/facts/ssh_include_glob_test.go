package facts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/env"
)

// O glob do Include vale em QUALQUER componente, e supor o contrário era um
// ponto cego silencioso.
//
// A versão anterior recusava curinga no diretório com o comentário "fora do que
// o ssh aceita". Medido contra o OpenSSH 9.2 em debian:12:
//
//	Include ~/.ssh/profiles/*/ops.conf  ->  ssh -G aplica o ProxyCommand de lá
//
// E o `return nil` saía sem lacuna, então o ProxyCommand plantado um nível
// abaixo não existia para esta ferramenta.
func TestIncludeClienteExpandeGlobEmDiretorio(t *testing.T) {
	raiz := t.TempDir()
	for _, d := range []string{"home/u/.ssh/profiles/ops", "home/u/.ssh/profiles/dev"} {
		if err := os.MkdirAll(filepath.Join(raiz, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	os.WriteFile(filepath.Join(raiz, "home/u/.ssh/profiles/ops/ops.conf"),
		[]byte("ProxyCommand /tmp/.implant\n"), 0o600)
	os.WriteFile(filepath.Join(raiz, "home/u/.ssh/profiles/dev/ops.conf"),
		[]byte("ProxyCommand /usr/bin/nc %h %p\n"), 0o600)

	e := env.Probe(env.Options{Root: raiz, Version: "test"})
	t.Cleanup(func() { e.Close() })
	f := &Facts{}

	incs := expandirIncludeCliente(f, e, "/home/u/.ssh", "/home/u",
		"~/.ssh/profiles/*/ops.conf")
	if len(incs) != 2 {
		t.Fatalf("expandiu para %d caminhos, queria 2: %v", len(incs), incs)
	}
	if !strings.Contains(strings.Join(incs, " "), "profiles/ops/ops.conf") {
		t.Errorf("o arquivo atrás do glob de diretório não entrou: %v", incs)
	}
}

// O caminho sem curinga nenhum não passa pela expansão e continua devolvendo
// ele mesmo — inclusive quando o arquivo não existe, porque quem decide isso é
// quem lê, não quem expande.
func TestIncludeClienteSemGlobEhOProprioCaminho(t *testing.T) {
	e := env.Probe(env.Options{Root: t.TempDir(), Version: "test"})
	t.Cleanup(func() { e.Close() })
	got := expandirIncludeCliente(&Facts{}, e, "/etc/ssh", "/root", "ssh_config.d/50-x.conf")
	if len(got) != 1 || got[0] != "/etc/ssh/ssh_config.d/50-x.conf" {
		t.Errorf("relativo sem glob = %v", got)
	}
}

// Expansão grande vira LACUNA declarada, não corte silencioso. O teto anterior
// era só de profundidade de Include, e um único curinga abre milhares de
// caminhos sem aumentar profundidade nenhuma.
func TestIncludeClienteDeclaraCorteDeExpansao(t *testing.T) {
	raiz := t.TempDir()
	base := filepath.Join(raiz, "home/u/.ssh/p")
	if err := os.MkdirAll(base, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxExpansaoInclude+10; i++ {
		os.WriteFile(filepath.Join(base, "c"+strings.Repeat("0", 3-len(itoaTeste(i)))+itoaTeste(i)), nil, 0o600)
	}
	e := env.Probe(env.Options{Root: raiz, Version: "test"})
	t.Cleanup(func() { e.Close() })
	f := &Facts{}

	got := expandirIncludeCliente(f, e, "/home/u/.ssh", "/home/u", "~/.ssh/p/*")
	if len(got) > maxExpansaoInclude {
		t.Errorf("expansão não foi cortada: %d", len(got))
	}
	if len(f.PersistDenied["ssh"]) == 0 {
		t.Error("corte de expansão precisa virar lacuna declarada, não silêncio")
	}
}

func itoaTeste(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
