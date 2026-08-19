package facts

import (
	"fmt"
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
		_, perms, _, ok := splitMapLineBytes([]byte(c.linha))
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

// O cgroup é a PROVENIÊNCIA do processo: é ele que diz se aquilo veio de uma
// unit do systemd, de um contêiner, ou de nenhum dos dois. Errar aqui
// misatribui a origem de todo processo do host, e é sobre isso que
// proc.ns_divergent conclui "não é container nem unit".
func TestCgroupV1PegaALinhaDoSystemdENaoAPrimeira(t *testing.T) {
	// A forma real do v1: uma linha por controlador, em ordem arbitrária, e só
	// a de name=systemd carrega a unit. Pegar a primeira devolveria o caminho
	// do cpuset — que não diz nada sobre quem lançou o processo.
	// A primeira linha tem hierarquia "0" e controlador NÃO vazio: é v1, e
	// confundi-la com v2 devolveria o caminho do cpuset. Só as DUAS condições
	// juntas identificam a hierarquia unificada.
	v1 := `0:cpuset:/nao-eh-o-caminho-da-unit
11:net_cls,net_prio:/
1:name=systemd:/system.slice/nginx.service`
	if got := parseCgroup(v1); got != "/system.slice/nginx.service" {
		t.Errorf("v1 = %q, queria a linha de name=systemd", got)
	}

	// E o v2, que é "0::/caminho" — os dois primeiros campos VAZIOS.
	v2 := "0::/user.slice/user-1000.slice/session-2.scope"
	if got := parseCgroup(v2); got != "/user.slice/user-1000.slice/session-2.scope" {
		t.Errorf("v2 = %q", got)
	}

	// Sem systemd e sem v2, sobra a primeira linha como último recurso — e ela
	// é melhor que vazio, porque vazio se confunde com "não li".
	só := "5:memory:/docker/abc123"
	if got := parseCgroup(só); got != "/docker/abc123" {
		t.Errorf("fallback = %q", got)
	}
}

// Quem pode reescrever o que root executa: as cinco respostas são diferentes e
// mandam o operador para lugares diferentes. A do arquivo AUSENTE é a mais
// contraintuitiva — quem criar primeiro ganha a execução.
func TestQuemGravaDistingueOsCincoCasos(t *testing.T) {
	casos := []struct {
		nome string
		a    AlvoDeRoot
		quer string
	}{
		{"dono não é root", AlvoDeRoot{Existe: true, UID: 1000}, "não é root"},
		{"arquivo aberto a todos", AlvoDeRoot{Existe: true, Modo: 0o666}, "QUALQUER usuário"},
		{"grupo que não é o do root", AlvoDeRoot{Existe: true, Modo: 0o664, GID: 1000}, "grupo 1000"},
		// Grupo de usuário SEM o bit de escrita do grupo: as duas condições são
		// necessárias, e só a conjunção distingue este caso do de cima.
		{"grupo de usuário sem bit de escrita", AlvoDeRoot{Existe: true, Modo: 0o644, GID: 1000, DirModo: 0o755}, ""},
		{"não existe e o diretório aceita", AlvoDeRoot{DirModo: 0o777}, "quem criá-lo"},
		{"existe, protegido, diretório aceita", AlvoDeRoot{Existe: true, Modo: 0o644, DirModo: 0o777}, "diretório é gravável"},
	}
	for _, c := range casos {
		got := c.a.QuemGrava()
		if c.quer == "" {
			if got != "" {
				t.Errorf("%s: QuemGrava = %q, queria SILÊNCIO", c.nome, got)
			}
			continue
		}
		if !strings.Contains(got, c.quer) {
			t.Errorf("%s: QuemGrava = %q, queria conter %q", c.nome, got, c.quer)
		}
	}
	// E o caso em que ninguém além do root grava: silêncio.
	nada := AlvoDeRoot{Existe: true, Modo: 0o644, DirModo: 0o755}
	if got := nada.QuemGrava(); got != "" {
		t.Errorf("arquivo e diretório de root = %q, queria vazio", got)
	}
}

// A lacuna de módulos só existe se houver PERGUNTA. Um guest mínimo sem
// /lib/modules e sem módulo carregado nenhum não tem nada a responder, e
// degradar por nada gasta a mesma atenção que uma lacuna de verdade.
func TestLacunaDeModuloExigeModuloCarregado(t *testing.T) {
	// Sem árvore E sem módulo: não há pergunta, não há lacuna.
	f := &Facts{}
	declararLacunaDeModulos(f)
	if len(f.Partial["modulo"]) != 0 {
		t.Errorf("sem módulo carregado não há o que declarar: %v", f.Partial["modulo"])
	}

	// Sem árvore E COM módulo carregado: aí sim.
	f = &Facts{Carregados: []ModuloCarregado{{Nome: "x"}}}
	declararLacunaDeModulos(f)
	if len(f.Partial["modulo"]) == 0 {
		t.Error("módulo carregado sem árvore de módulos é pergunta sem resposta, " +
			"e precisa ser declarada")
	}

	// Em CONTÊINER não há pergunta a fazer daqui: a lista é a do host e a
	// árvore é a da imagem.
	f = &Facts{Carregados: []ModuloCarregado{{Nome: "x"}}}
	f.Host.EmContainer = true
	declararLacunaDeModulos(f)
	if len(f.Partial["modulo"]) != 0 {
		t.Errorf("em contêiner a comparação não se aplica: %v", f.Partial["modulo"])
	}
}

// Todo teto que corta precisa DIZER que cortou.
//
// A varredura por classe achou dois que não diziam, entre nove. O de
// bibliotecas mapeadas é o pior dos dois: o comentário do próprio código diz
// que aquela lista é a ÚNICA fonte que torna uma biblioteca candidata à
// pergunta de propriedade — ela não executa, então nada mais a traz. Descartar
// em silêncio apaga a pergunta junto, e é exatamente a forma do Ebury: a libssh
// trocada NO LUGAR dela, com o nome certo.
func TestTetoDeBibliotecasMapeadasDeclaraOCorte(t *testing.T) {
	p := &Process{PID: 1}
	// Uma linha de maps por biblioteca, além do teto.
	var b strings.Builder
	for i := 0; i < maxMapsLibs+5; i++ {
		fmt.Fprintf(&b, "7f00%04x000-7f00%04x000 r-xp 00000000 08:01 100 /opt/app/lib%d.so\n", i, i, i)
	}
	lerMaps(p, strings.NewReader(b.String()))

	if len(p.MapsLibs) != maxMapsLibs {
		t.Errorf("guardou %d bibliotecas, o teto é %d", len(p.MapsLibs), maxMapsLibs)
	}
	var disse bool
	for _, tr := range p.Truncated {
		if strings.Contains(tr, "pergunta de propriedade") {
			disse = true
		}
	}
	if !disse {
		t.Errorf("o corte não foi declarado: %v", p.Truncated)
	}
	// E declara UMA vez, não uma por biblioteca descartada.
	if n := len(p.Truncated); n != 1 {
		t.Errorf("declarou %d vezes: cinco descartes são um corte", n)
	}
}
