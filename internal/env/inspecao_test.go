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

// SEM SEGUIR LINK, NENHUM COMPONENTE É ATRAVESSADO — nem o do meio.
//
// A versão anterior deste teste media o contrário, e estava certa sobre o
// kernel: O_NOFOLLOW protege só o componente FINAL, e `/tmp/mau/segredos.env`
// com `/tmp/mau -> ../etc` abria o arquivo real. A defesa era CONTAR — devolver
// a cadeia e o inode.
//
// Contar tinha um furo: a cadeia saía de uma série de Lstat e o arquivo saía de
// um open SEPARADO, duas resoluções independentes do mesmo caminho. Entre elas
// cabia a troca de um link, e a resposta afirmaria uma cadeia que pertencia a
// outra resolução — justamente no host comprometido, que é o threat model.
//
// Agora o caminho é percorrido componente a componente por DESCRITOR, e nenhum
// link é atravessado em posição nenhuma. É o que openat2(RESOLVE_NO_SYMLINKS)
// faria, sem exigir Linux 5.6.
func TestSemSeguirLinkNenhumComponenteEhAtravessado(t *testing.T) {
	e, _ := raizDeInspecao(t)

	// 1. O último componente é link: recusado, como antes.
	if _, _, err := e.AbrirParaInspecao("/tmp/atalho", false); !errors.Is(err, ErrEhLink) {
		t.Errorf("symlink final: err=%v, queria ErrEhLink", err)
	}

	// 2. O componente do MEIO também. O kernel abriria; este percurso não.
	if _, _, err := e.AbrirParaInspecao("/tmp/mau/shadow", false); !errors.Is(err, ErrEhLink) {
		t.Fatalf("o link do MEIO foi atravessado: err=%v.\n"+
			"Com follow_symlinks:false o arquivo aberto tem de estar exatamente "+
			"no caminho pedido — senão a resposta descreve outro arquivo.", err)
	}

	// 3. E o caminho sem link nenhum continua abrindo.
	fh, id, err := e.AbrirParaInspecao("/etc/shadow", false)
	if err != nil {
		t.Fatalf("caminho sem link: %v", err)
	}
	fh.Close()
	if id.Inode == 0 {
		t.Error("a identidade não veio")
	}
}

// COM follow_symlinks:true a travessia acontece, e a cadeia a descreve.
//
// Aqui a cadeia é observação, e não garantia — quem chamou pediu para seguir. O
// que continua sendo FATO é dev e inode: a identidade do descritor que foi
// realmente aberto.
func TestSeguindoLinkAIdentidadeEhDoAlvo(t *testing.T) {
	e, _ := raizDeInspecao(t)

	fh, id, err := e.AbrirParaInspecao("/tmp/mau/shadow", true)
	if err != nil {
		t.Fatalf("com follow tinha de abrir: %v", err)
	}
	fh.Close()

	fh2, idReal, err := e.AbrirParaInspecao("/etc/shadow", false)
	if err != nil {
		t.Fatal(err)
	}
	fh2.Close()
	if id.Inode != idReal.Inode || id.Dev != idReal.Dev {
		t.Fatalf("seguindo o link, a identidade tem de ser a do ALVO: %d vs %d",
			id.Inode, idReal.Inode)
	}

	cadeia, resolvido, err := e.CadeiaDeLinks("/tmp/mau/shadow")
	if err != nil {
		t.Fatal(err)
	}
	if resolvido != "/etc/shadow" {
		t.Errorf("resolvido=%q", resolvido)
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

// O_PATH FAZ O QUE ESTE CÓDIGO ACHA QUE FAZ.
//
// A constante não é exportada pelo syscall do Go e está escrita à mão aqui —
// 010000000, o valor do asm-generic. Um número de kernel escrito à mão merece
// prova, e a propriedade que importa não é o número: é que o descritor
// resultante NÃO seja legível, porque é isso que garante que o open() do driver
// não foi chamado.
func TestOPathAbreSemPermitirLeitura(t *testing.T) {
	// O alvo é um ARQUIVO COMUM, e não um diretório: ler um diretório falha de
	// qualquer jeito, e um teste sobre "/" passaria mesmo com oPath = 0. A
	// primeira versão deste teste fazia exatamente isso, e a mutação que zerava
	// a constante passou limpa.
	alvo := filepath.Join(t.TempDir(), "comum.txt")
	if err := os.WriteFile(alvo, []byte("conteudo"), 0o644); err != nil {
		t.Fatal(err)
	}
	fd, err := syscall.Open(alvo, syscall.O_RDONLY|oPath|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("O_PATH não abriu um arquivo comum: a constante 0x%x não é "+
			"O_PATH neste kernel/arquitetura (%v)", oPath, err)
	}
	defer syscall.Close(fd)

	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		t.Fatalf("fstat num descritor O_PATH tem de funcionar: %v", err)
	}
	b := make([]byte, 1)
	if n, err := syscall.Read(fd, b); err == nil {
		t.Fatalf("o descritor de um arquivo comum é LEGÍVEL (%d byte): isto não "+
			"é O_PATH, e o open do driver de um device node estaria sendo "+
			"chamado antes da recusa", n)
	}
}

// O DEVICE NODE É RECUSADO SEM QUE O DRIVER SEJA ACORDADO.
//
// A recusa acontecia depois do open: para fifo o O_NONBLOCK resolvia, mas para
// um device node o callback de open do driver já tinha rodado. Num host
// comprometido com root — o threat model desta entrega — um caminho de
// aparência banal pode ser um /dev/qualquer-coisa que faz algo ao ser aberto.
//
// A recusa continua carregando a identidade: "isto é um chardev, dev tal, inode
// tal" é exatamente o que quem investiga queria saber.
func TestDeviceNodeEhRecusadoComIdentidade(t *testing.T) {
	e := &Env{Source: SourceLive, Caps: CapFilesystem, CapReason: map[string]string{}}

	for _, c := range []struct{ p, tipo string }{
		{"/dev/zero", "chardev"},
		{"/dev/null", "chardev"},
	} {
		if _, err := os.Stat(c.p); err != nil {
			continue
		}
		_, id, err := e.AbrirParaInspecao(c.p, false)
		if !errors.Is(err, ErrNaoEhArquivo) {
			t.Errorf("%s: err=%v, queria ErrNaoEhArquivo", c.p, err)
			continue
		}
		if id.Tipo != c.tipo {
			t.Errorf("%s: a recusa precisa DIZER o que era: tipo=%q", c.p, id.Tipo)
		}
		if id.Inode == 0 {
			t.Errorf("%s: a recusa jogou fora a identidade", c.p)
		}
	}
}
