package facts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/env"
)

// Decisões do COLETOR que nada fixava.
//
// A medição de mutação sobre `internal/facts` deu 46%, e o número bate com a
// cobertura (45%). É a camada que toca o mundo real, e foi ela que produziu
// todos os defeitos que apareceram lendo a saída em hosts de verdade — não os
// checks. O que estes testes fixam são as decisões cujo erro produz AFIRMAÇÃO
// FALSA, e não só dado ausente.

// Quem pode reescrever o que root executa (§36.4).
//
// São dois caminhos, e nenhum dos dois basta sozinho: o bit de "outros"
// escreve, ou o bit de GRUPO escreve E o grupo não é o root. Trocar a
// conjunção por disjunção faria todo diretório 0775 de root:root — que é
// comum — virar "gravável", e este check já rendeu mais de cem achados falsos
// numa versão anterior.
func TestDirGravavelExigeGrupoQueNaoSejaRoot(t *testing.T) {
	casos := []struct {
		nome string
		modo uint32
		gid  int
		quer bool
	}{
		{"outros escrevem", 0o777, 0, true},
		{"grupo escreve e o grupo é de usuário", 0o775, 1000, true},
		// O caso que a disjunção estragaria: grupo escreve, mas o grupo é o
		// root. Quem está nele já é root por outro caminho.
		{"grupo escreve e o grupo é root", 0o775, 0, false},
		{"ninguém além do dono escreve", 0o755, 1000, false},
	}
	for _, c := range casos {
		a := AlvoDeRoot{DirModo: c.modo, DirGID: c.gid}
		if got := a.DirGravavel(); got != c.quer {
			t.Errorf("%s (modo %o gid %d) = %v, queria %v", c.nome, c.modo, c.gid, got, c.quer)
		}
	}
}

// A primeira ocorrência VENCE no sshd. Sobrescrever com a última reportaria uma
// configuração que não é a efetiva — e é sobre ela que o check de
// PermitRootLogin conclui.
func TestSshdConfigPrimeiraOcorrenciaVence(t *testing.T) {
	f := imagem(t, map[string]string{
		"etc/ssh/sshd_config": "PermitRootLogin yes\n" +
			"PasswordAuthentication no\n" +
			"PermitRootLogin no\n", // ignorada: o sshd usa a primeira
	})
	if f.SSH.PermitRootLogin != "yes" {
		t.Errorf("PermitRootLogin = %q, queria yes: o sshd usa a PRIMEIRA "+
			"ocorrência, e relatar a última descreveria uma config que não vale",
			f.SSH.PermitRootLogin)
	}
	if f.SSH.PasswordAuthentication != "no" {
		t.Errorf("PasswordAuthentication = %q", f.SSH.PasswordAuthentication)
	}
}

// A raiz da varredura de SUID que é SYMLINK não entra.
//
// Com usrmerge, /bin, /sbin e /lib apontam para dentro de /usr. Entrar pelos
// dois faz cada arquivo ser visitado duas vezes com caminhos diferentes, e o
// mesmo binário sai como /bin/su E /usr/bin/su — dobrando os achados e
// confundindo a pergunta de propriedade.
func TestRaizQueEhSymlinkNaoEhVarridaDuasVezes(t *testing.T) {
	raiz := t.TempDir()
	if err := os.MkdirAll(filepath.Join(raiz, "usr/bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	x := filepath.Join(raiz, "usr/bin/su")
	if err := os.WriteFile(x, []byte("ELF"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(x, 0o755|os.ModeSetuid); err != nil {
		t.Fatal(err)
	}
	// A forma do usrmerge: /bin é link para usr/bin.
	if err := os.Symlink("usr/bin", filepath.Join(raiz, "bin")); err != nil {
		t.Fatal(err)
	}

	e := env.Probe(env.Options{Root: raiz})
	t.Cleanup(func() { e.Close() })
	f := Collect(e)

	var n int
	for _, s := range f.Suid {
		if strings.HasSuffix(s.Path, "/su") {
			n++
		}
	}
	if n != 1 {
		var ps []string
		for _, s := range f.Suid {
			ps = append(ps, s.Path)
		}
		t.Errorf("o mesmo binário apareceu %d vezes: %v", n, ps)
	}
}

// Região do maps que é gravável E executável é a assinatura de injeção. As
// duas, e não uma: quase toda região é gravável ou executável, e a disjunção
// faria todo processo do host virar achado.
func TestMapsRWXExigeAsDuasPermissoes(t *testing.T) {
	casos := []struct {
		linha string
		quer  bool
	}{
		{"7f0000000000-7f0000001000 rwxp 00000000 00:00 0 ", true},
		{"7f0000000000-7f0000001000 rw-p 00000000 00:00 0 ", false},
		{"7f0000000000-7f0000001000 r-xp 00000000 00:00 0 /usr/bin/x", false},
	}
	for _, c := range casos {
		perms, _, ok := splitMapLineBytes([]byte(c.linha))
		if !ok {
			t.Fatalf("linha não foi entendida: %q", c.linha)
		}
		rwx := indexOf(perms, 'w') >= 0 && indexOf(perms, 'x') >= 0
		if rwx != c.quer {
			t.Errorf("%q: rwx=%v, queria %v", c.linha, rwx, c.quer)
		}
	}
}

func indexOf(b []byte, c byte) int {
	for i := range b {
		if b[i] == c {
			return i
		}
	}
	return -1
}
