package env

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func raizDeInspecao(t *testing.T) (*Env, string) {
	t.Helper()
	raiz := t.TempDir()
	for _, d := range []string{"etc", "tmp", "dados"} {
		if err := os.MkdirAll(filepath.Join(raiz, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	escrever := func(p, s string, m os.FileMode) {
		if err := os.WriteFile(filepath.Join(raiz, p), []byte(s), m); err != nil {
			t.Fatal(err)
		}
	}
	escrever("etc/shadow", "root:$6$SEGREDO$hash:19000:0:99999:7:::\n", 0o640)
	escrever("dados/grande.bin", strings.Repeat("A", MaxLeituraDirecionada*2+7), 0o644)
	ligar := func(alvo, nome string) {
		if err := os.Symlink(alvo, filepath.Join(raiz, nome)); err != nil {
			t.Fatal(err)
		}
	}
	ligar("../etc/shadow", "tmp/atalho") // relativo: fica DENTRO da imagem
	ligar("../etc", "tmp/mau")
	ligar("/etc/shadow", "tmp/fuga") // absoluto: aponta para FORA dela
	if err := syscall.Mkfifo(filepath.Join(raiz, "tmp/cano"), 0o644); err != nil {
		t.Skipf("sem mkfifo: %v", err)
	}

	e := Probe(Options{Root: raiz, Version: "teste"})
	t.Cleanup(e.Close)
	return e, raiz
}

// EM MODO IMAGEM, O LINK QUE APONTA PARA FORA É RECUSADO.
//
// É a garantia que separa "analisar uma imagem montada" de "ler o filesystem de
// quem investiga": um `/tmp/fuga -> /etc/shadow` plantado dentro da imagem
// resolveria, sem a raiz travada, para o /etc/shadow do ANALISTA — e a resposta
// descreveria a estação forense como se fosse o alvo.
//
// A raiz travada do os.Root recusa, e recusa tanto com follow_symlinks quanto
// sem: o alvo absoluto sai da raiz nos dois casos.
func TestImagemRecusaLinkQueSaiDaRaiz(t *testing.T) {
	e, _ := raizDeInspecao(t)
	for _, seguir := range []bool{false, true} {
		_, _, err := e.AbrirParaInspecao("/tmp/fuga", seguir)
		if err == nil {
			t.Fatalf("follow=%v: um link para /etc/shadow ABSOLUTO dentro de uma "+
				"imagem foi seguido — isso lê o host de quem investiga", seguir)
		}
		if errors.Is(err, ErrEhLink) && seguir {
			t.Errorf("follow=true: a recusa devia ser da RAIZ, não do O_NOFOLLOW")
		}
	}
	// E a cadeia não inventa um caminho que ninguém pode abrir.
	cadeia, _, _ := e.CadeiaDeLinks("/tmp/fuga")
	if len(cadeia) == 0 {
		t.Error("a cadeia precisa dizer que há um link ali, mesmo recusado")
	}
}

// O_NOFOLLOW SÓ PROTEGE O ÚLTIMO COMPONENTE, e a cadeia é o que sobra.
//
// Medido, não suposto: com `/tmp/mau -> /etc`, abrir `/tmp/mau/shadow` com
// O_NOFOLLOW abre o /etc/shadow de verdade. openat2 com RESOLVE_NO_SYMLINKS
// resolveria e exige Linux 5.6, contra o piso de 3.2 que esta ferramenta
// declara sustentar.
//
// Fingir a trava seria pior que não tê-la: quem lê "follow_symlinks: false"
// concluiria que o caminho pedido é o caminho lido. A cadeia diz que não.
func TestNoFollowProtegeSoOFinalEACadeiaConta(t *testing.T) {
	e, _ := raizDeInspecao(t)

	// 1. O último componente é link: RECUSADO, e a recusa é resposta.
	if _, _, err := e.AbrirParaInspecao("/tmp/atalho", false); !errors.Is(err, ErrEhLink) {
		t.Errorf("symlink final sem follow: err=%v, queria ErrEhLink", err)
	}

	// 2. O componente do MEIO é link: abre, e abre OUTRO arquivo.
	fh, id, err := e.AbrirParaInspecao("/tmp/mau/shadow", false)
	if err != nil {
		t.Fatalf("o kernel abre isto e o teste precisa medir o que ele abriu: %v", err)
	}
	fh.Close()

	// 3. E a identidade prova QUAL arquivo foi aberto.
	_, idReal, err := e.AbrirParaInspecao("/etc/shadow", false)
	if err != nil {
		t.Fatal(err)
	}
	if id.Inode != idReal.Inode || id.Dev != idReal.Dev {
		t.Fatalf("a inspeção de /tmp/mau/shadow devia ter aberto o mesmo inode "+
			"de /etc/shadow: %d vs %d", id.Inode, idReal.Inode)
	}

	// 4. A CADEIA é o que transforma isso em evidência em vez de surpresa.
	cadeia, resolvido, _ := e.CadeiaDeLinks("/tmp/mau/shadow")
	if resolvido != "/etc/shadow" {
		t.Errorf("resolvido=%q, queria /etc/shadow", resolvido)
	}
	if len(cadeia) != 1 || !strings.Contains(cadeia[0], "/tmp/mau -> ../etc") {
		t.Errorf("a cadeia precisa NOMEAR o link atravessado: %v", cadeia)
	}
}

// O ciclo é detectado na REPETIÇÃO, e não esgotando os quarenta saltos.
func TestCicloDeSymlinkEhDitoUmaVez(t *testing.T) {
	e, raiz := raizDeInspecao(t)
	if err := os.Symlink("/tmp/b", filepath.Join(raiz, "tmp/a")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/tmp/a", filepath.Join(raiz, "tmp/b")); err != nil {
		t.Fatal(err)
	}
	cadeia, _, _ := e.CadeiaDeLinks("/tmp/a")
	if len(cadeia) > 4 {
		t.Errorf("o ciclo saiu em %d linhas: repetir o mesmo link quarenta "+
			"vezes obriga quem lê a chegar sozinho à conclusão\n%v",
			len(cadeia), cadeia)
	}
	if !strings.Contains(cadeia[len(cadeia)-1], "ciclo") {
		t.Errorf("a última linha precisa DIZER que é ciclo: %v", cadeia)
	}
}

// O QUE NÃO É ARQUIVO COMUM É RECUSADO NO DESCRITOR.
//
// O fifo é o caso que importa: `mkfifo /etc/ld.so.preload` é o truque que faz
// uma varredura ingênua bloquear para sempre. O O_NONBLOCK do abridor
// compartilhado impede o bloqueio, e o fstat no fd — e não no caminho — impede
// a troca entre a checagem e o uso.
func TestInspecaoRecusaOQueNaoEhArquivoComum(t *testing.T) {
	e, _ := raizDeInspecao(t)
	for _, c := range []struct{ p, tipo string }{
		{"/tmp/cano", "fifo"},
		{"/etc", "dir"},
	} {
		_, id, err := e.AbrirParaInspecao(c.p, false)
		if !errors.Is(err, ErrNaoEhArquivo) {
			t.Errorf("%s: err=%v, queria ErrNaoEhArquivo", c.p, err)
		}
		if id.Tipo != c.tipo {
			t.Errorf("%s: a recusa precisa DIZER o que era: tipo=%q", c.p, id.Tipo)
		}
	}
}

// A JANELA É LIMITADA, e o que sobrou é declarado.
func TestJanelaDeLeituraTemTetoEDeclaraOResto(t *testing.T) {
	e, _ := raizDeInspecao(t)
	fh, id, err := e.AbrirParaInspecao("/dados/grande.bin", false)
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()

	b, mais, err := LerJanela(fh, 0, 0) // 0 = o teto
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != MaxLeituraDirecionada {
		t.Errorf("leu %d bytes, o teto é %d", len(b), MaxLeituraDirecionada)
	}
	if !mais {
		t.Error("o arquivo tem o dobro do teto e a resposta disse que acabou")
	}

	// A última janela diz que acabou — e "acabou" precisa ser confiável, senão
	// quem lê pagina para sempre.
	fim := id.Tamanho - 10
	b, mais, err = LerJanela(fh, fim, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 10 || mais {
		t.Errorf("última janela: %d bytes, mais=%v", len(b), mais)
	}

	// Um pedido maior que o teto é REDUZIDO, e não recusado nem atendido.
	b, _, err = LerJanela(fh, 0, MaxLeituraDirecionada*8)
	if err != nil || len(b) != MaxLeituraDirecionada {
		t.Errorf("pedido acima do teto: %d bytes, err=%v", len(b), err)
	}
}

// Os xattr saem do DESCRITOR.
func TestXattrsSaemDoDescritor(t *testing.T) {
	e, raiz := raizDeInspecao(t)
	alvo := filepath.Join(raiz, "dados", "marcado")
	if err := os.WriteFile(alvo, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Setxattr(alvo, "user.aletheia", []byte("valor-do-host"), 0); err != nil {
		t.Skipf("filesystem sem xattr de usuário: %v", err)
	}

	fh, _, err := e.AbrirParaInspecao("/dados/marcado", false)
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()

	xs, err := XattrsDoFD(fh)
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range xs {
		if x.Nome != "user.aletheia" {
			continue
		}
		if string(x.Valor) != "valor-do-host" {
			t.Errorf("valor=%q", x.Valor)
		}
		return
	}
	t.Errorf("o atributo plantado não apareceu: %+v", xs)
}

// SEM RAIZ TRAVADA, A RECUSA É DO KERNEL.
//
// O caminho live não passa pelo os.Root, então O_NOFOLLOW vale de verdade e não
// há pré-checagem nem janela entre ela e o open. Os dois caminhos precisam
// responder a MESMA coisa a quem chama — é o contrato de follow_symlinks — e
// só um deles pode prometer a trava do kernel.
func TestSemRaizOKernelRecusaOLinkFinal(t *testing.T) {
	dir := t.TempDir()
	alvo := filepath.Join(dir, "alvo.txt")
	if err := os.WriteFile(alvo, []byte("conteudo"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "atalho")
	if err := os.Symlink(alvo, link); err != nil {
		t.Fatal(err)
	}

	e := &Env{Source: SourceLive, Caps: CapFilesystem, CapReason: map[string]string{}}

	if _, _, err := e.AbrirParaInspecao(link, false); !errors.Is(err, ErrEhLink) {
		t.Errorf("sem follow: err=%v, queria ErrEhLink", err)
	}
	fh, id, err := e.AbrirParaInspecao(link, true)
	if err != nil {
		t.Fatalf("com follow tinha de abrir: %v", err)
	}
	defer fh.Close()
	if id.Tipo != "regular" || id.Tamanho != 8 {
		t.Errorf("a identidade é do ALVO aberto, não do link: %+v", id)
	}
}
