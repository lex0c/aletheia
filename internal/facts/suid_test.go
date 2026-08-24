package facts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lex0c/aletheia/internal/env"
)

// Diretório que não abre precisa aparecer na cobertura.
//
// O código dizia "sem permissão neste galho: o resto da árvore continua" e
// seguia em silêncio. /home é 0700 por usuário na maioria das distribuições, e
// um `chmod u+s` num binário dentro de um home é retenção de privilégio que
// sobrevive à faxina — a varredura sem root pulava exatamente esse lugar e
// dizia "nenhum SUID fora do padrão".
func TestGalhoIlegivelNaVarreduraDeSuidViraLacuna(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root abre tudo")
	}
	raiz := t.TempDir()
	fundo := filepath.Join(raiz, "home/alvo/.cache")
	if err := os.MkdirAll(fundo, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fundo, "x"), []byte("bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(raiz, "home/alvo"), 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(filepath.Join(raiz, "home/alvo"), 0o755) })

	e := env.Probe(env.Options{Root: raiz})
	t.Cleanup(func() { e.Close() })
	f := Collect(e)

	var citou bool
	for _, m := range f.PersistDenied["suid"] {
		if strings.Contains(m, "/home/alvo") {
			citou = true
		}
	}
	if !citou {
		t.Errorf("o galho negado não foi declarado: %v", f.PersistDenied["suid"])
	}
}

// "Está em diretório gravável por qualquer usuário" era dito por PREFIXO: tudo
// abaixo de /tmp recebia a frase. Ela é evidência num achado CRITICAL, e é
// falsa para todo subdiretório 0700 dentro de /tmp — que é o que
// systemd-private, /tmp/ssh-* e qualquer `mktemp -d` criam. A ferramenta
// afirmava uma permissão que não conferiu.
func TestGravavelPorTodosEhMedidoENaoDeduzidoDoPrefixo(t *testing.T) {
	raiz := t.TempDir()
	// Duas árvores sob /tmp: uma realmente 1777, outra 0755.
	aberto := filepath.Join(raiz, "tmp/aberto")
	fechado := filepath.Join(raiz, "tmp/privado")
	for _, d := range []string{aberto, fechado} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		x := filepath.Join(d, "x")
		if err := os.WriteFile(x, []byte("ELF"), 0o755); err != nil {
			t.Fatal(err)
		}
		// os.ModeSetuid, e NÃO o octal 0o4755: num fs.FileMode do Go o bit de
		// setuid é 1<<23, e o 0o4000 do octal de C é descartado em silêncio. A
		// primeira versão deste teste plantava arquivos comuns e passava por
		// não encontrar SUID nenhum.
		if err := os.Chmod(x, 0o755|os.ModeSetuid); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(aberto, 0o777|os.ModeSticky); err != nil {
		t.Fatal(err)
	}

	e := env.Probe(env.Options{Root: raiz})
	t.Cleanup(func() { e.Close() })
	f := Collect(e)

	if len(f.Suid) != 2 {
		t.Fatalf("plantei dois SUID e a varredura achou %d: sem eles o resto do "+
			"teste passa por não testar nada", len(f.Suid))
	}
	visto := map[string]bool{}
	for _, s := range f.Suid {
		if !s.DirLido {
			t.Errorf("%s: o modo do diretório não foi medido", s.Path)
		}
		visto[s.Path] = s.DirGravavelPorTodos()
	}
	if !visto["/tmp/aberto/x"] {
		t.Error("/tmp/aberto é 1777: ali qualquer usuário escreve mesmo")
	}
	if visto["/tmp/privado/x"] {
		t.Error("/tmp/privado é 0755, e dizer que é gravável por todos é afirmar " +
			"uma permissão que ninguém conferiu — dentro de um achado CRITICAL")
	}
}

// Sem a medida — dump antigo, ou imagem onde a permissão vem achatada — vale a
// aproximação léxica de antes. Ela continua certa para arquivo solto em /tmp,
// que é o caso comum.
func TestSemMedidaValeOPrefixo(t *testing.T) {
	if !(SuidFile{Path: "/tmp/x"}).DirGravavelPorTodos() {
		t.Error("sem modo medido, /tmp/x cai na aproximação e ela diz sim")
	}
	if (SuidFile{Path: "/usr/bin/x"}).DirGravavelPorTodos() {
		t.Error("/usr/bin não é árvore gravável nem por aproximação")
	}
}

// Camada de imagem de contêiner NÃO é este host.
//
// Cada camada traz o conjunto setuid inteiro de uma distribuição — su, mount,
// passwd, sudo —, nenhum é reivindicado pelo gerenciador do host (correto: não
// foi ele que os entregou), e o ctime é o da extração enquanto o mtime é o da
// construção do pacote meses antes. Os três sinais disparam juntos em cada
// binário de cada camada.
//
// Num desktop com containerd isso deu 310 CRÍTICOS. Um relatório com 310
// críticos falsos não é ruim: é um relatório que ninguém lê. docker, podman e
// lxc já estavam na lista de exclusão; containerd — que é o armazenamento do
// Docker moderno e de todo Kubernetes — faltava.
func TestCamadaDeImagemDeContainerNaoEhVarrida(t *testing.T) {
	raiz := t.TempDir()
	// A forma real do containerd, e um SUID de verdade fora dela como controle.
	camada := filepath.Join(raiz,
		"var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/50165/fs/usr/bin")
	fora := filepath.Join(raiz, "usr/local/sbin")
	for _, d := range []string{camada, fora} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		x := filepath.Join(d, "su")
		if err := os.WriteFile(x, []byte("ELF"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(x, 0o755|os.ModeSetuid); err != nil {
			t.Fatal(err)
		}
	}

	e := env.Probe(env.Options{Root: raiz})
	t.Cleanup(func() { e.Close() })
	f := Collect(e)

	for _, s := range f.Suid {
		if strings.Contains(s.Path, "containerd") {
			t.Errorf("camada de imagem entrou na varredura: %s", s.Path)
		}
	}
	// E o controle: fora da camada, o SUID continua sendo achado. Sem esta
	// asserção o teste passaria com a varredura inteira quebrada.
	var achouControle bool
	for _, s := range f.Suid {
		if s.Path == "/usr/local/sbin/su" {
			achouControle = true
		}
	}
	if !achouControle {
		t.Fatalf("o SUID FORA da camada precisa continuar aparecendo: %+v", f.Suid)
	}

	// E pular é decisão, que se DECLARA: voltar em silêncio faria a varredura
	// estreitar o próprio escopo sem dizer.
	var citou bool
	for _, m := range f.PersistDenied["suid"] {
		if strings.Contains(m, "containerd") && strings.Contains(m, "--root") {
			citou = true
		}
	}
	if !citou {
		t.Errorf("a árvore pulada não foi declarada, nem o caminho para varrê-la: %v",
			f.PersistDenied["suid"])
	}
}

// Panic num trabalhador NÃO pode pendurar a pool.
//
// O `rodar` chamava `v.visitar(t)` e `v.terminou()` como duas instruções
// soltas. Um panic dentro do visitar matava o trabalhador ENTRE as duas: o
// guardaGoroutine recuperava e o wg.Done liberava, mas `v.ativos` — que o
// proxima tinha incrementado — nunca voltava. Os outros trabalhadores ficavam
// presos no laço do proxima, que só devolve false com fila vazia E ativos == 0,
// girando em Gosched+1ms para sempre. Sem WalkDeadline (o padrão do collect e
// do scan sem --fs-budget) não havia saída nenhuma.
//
// O desfecho era pior que uma queda, e o comentário do guardaGoroutine já dizia
// isso com todas as letras: "a ferramenta PENDURARIA, sem saída e sem
// relatório". O invariante do defer tinha sido aplicado aos mutexes e esquecido
// no contador, que é uma trava de terminação com outro nome.
//
// O panic é forçado com `donos` nil: o visitar termina em `v.donos.juntar(...)`
// sempre que acha dono de arquivo, e receiver nil ali desreferencia. O teste
// EXIGE ver a lacuna do panic — sem isso ele viraria um no-op silencioso no dia
// em que alguém puser uma guarda de nil no caminho, passando sem testar nada.
func TestPanicEmTrabalhadorDeSuidNaoPenduraAVarredura(t *testing.T) {
	raiz := t.TempDir()
	for _, d := range []string{"a", "b", "c", "d"} {
		dir := filepath.Join(raiz, d)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "x"), []byte("bin"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	e := env.Probe(env.Options{Root: raiz})
	t.Cleanup(func() { e.Close() })

	f := &Facts{}
	v := &varredura{
		e: e, f: f,
		limite: 1000,
		donos:  nil, // o gatilho do panic
	}
	// Caminho VIRTUAL, como suidRaizes: quem traduz para o disco é o env.
	for _, d := range []string{"/a", "/b", "/c", "/d"} {
		v.fila = append(v.fila, tarefaDir{dir: d, teto: 4})
	}

	feito := make(chan struct{})
	go func() {
		defer close(feito)
		v.rodar(4)
	}()

	select {
	case <-feito:
	case <-time.After(10 * time.Second):
		v.mu.Lock()
		ativos, fila := v.ativos, len(v.fila)
		v.mu.Unlock()
		t.Fatalf("rodar() não voltou em 10s (ativos=%d fila=%d): o contador de "+
			"ativos vazou num panic e os trabalhadores restantes giram para "+
			"sempre — a ferramenta pendura sem saída e sem relatório", ativos, fila)
	}

	if v.ativos != 0 {
		t.Errorf("ativos=%d depois de rodar() voltar: o contador vazou", v.ativos)
	}
	var viuPanic bool
	for _, m := range f.Partial["suid"] {
		if strings.Contains(m, "panic") {
			viuPanic = true
		}
	}
	if !viuPanic {
		t.Fatalf("nenhum panic foi provocado, então este teste não testou o que "+
			"diz testar — o gatilho (donos nil) deixou de valer. Lacunas vistas: %v",
			f.Partial["suid"])
	}
}
