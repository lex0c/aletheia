package preserve

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// O maps de um processo real, reduzido ao que decide a escolha.
const mapsExemplo = `55d4a0000000-55d4a0021000 r-xp 00000000 fd:00 1049 /usr/bin/sshd
55d4a0021000-55d4a0022000 rw-p 00021000 fd:00 1049 /usr/bin/sshd
55d4a1000000-55d4a1021000 rw-p 00000000 00:00 0 [heap]
7f3c1a000000-7f3c1a002000 rwxp 00000000 00:00 0
7f3c1b000000-7f3c1b010000 rw-p 00000000 00:00 0
7f3c1c000000-7f3c1c001000 ---p 00000000 00:00 0
7f3c1d000000-7f3c1d002000 r--s 00000000 00:05 42 /memfd:x (deleted)
7ffd0a000000-7ffd0a021000 rw-p 00000000 00:00 0 [stack]
7ffd0aaa0000-7ffd0aaa2000 r--p 00000000 00:00 0 [vvar]
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0 [vsyscall]
`

// A escolha das regiões É a metade do valor do dump: pegar tudo enche o disco
// com o que já está em /usr/bin, e pegar de menos perde o código injetado.
func TestRegioesAnonimasEscolheOQueNaoExisteEmDisco(t *testing.T) {
	rs := regioesAnonimas(mapsExemplo)
	quer := []string{
		"55d4a1000000-55d4a1021000", // [heap]
		"7f3c1a000000-7f3c1a002000", // anônima rwx: o alvo
		"7f3c1b000000-7f3c1b010000", // anônima rw
		"7ffd0a000000-7ffd0a021000", // [stack]
	}
	if len(rs) != len(quer) {
		t.Fatalf("escolheu %d regiões, queria %d: %+v", len(rs), len(quer), rs)
	}
	for i, r := range rs {
		if r.rotulo() != quer[i] {
			t.Errorf("região %d = %s, queria %s", i, r.rotulo(), quer[i])
		}
	}
}

// Cada exclusão tem um motivo diferente, e trocar um por outro seria perder
// evidência ou coletar lixo.
func TestRegioesAnonimasExcluiPorMotivo(t *testing.T) {
	casos := []struct {
		linha, porque string
	}{
		{"55d4a0000000-55d4a0021000 r-xp 00000000 fd:00 1049 /usr/bin/sshd",
			"tem arquivo por trás: está no disco, e --file copia melhor"},
		{"7f3c1c000000-7f3c1c001000 ---p 00000000 00:00 0 ",
			"sem permissão de leitura não há o que ler"},
		{"7ffd0aaa0000-7ffd0aaa2000 r--p 00000000 00:00 0 [vvar]",
			"mapeamento do kernel, idêntico em todo processo"},
		{"ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0 [vsyscall]",
			"idem, e nem legível é"},
		{"7f3c1d000000-7f3c1d002000 r--s 00000000 00:05 42 /memfd:x (deleted)",
			"tem arquivo por trás — o memfd se preserva pelo exe/fd, não aqui"},
		{"lixo que não é linha de maps", "não parseia"},
		{"55d4a1021000-55d4a1000000 rw-p 00000000 00:00 0 ", "faixa invertida"},
	}
	for _, c := range casos {
		if rs := regioesAnonimas(c.linha + "\n"); len(rs) != 0 {
			t.Errorf("%q entrou no dump, mas %s", c.linha, c.porque)
		}
	}
}

// A ordem decide o que sobrevive quando o orçamento corta: uma arena de 400 MB
// não pode enterrar as quatro páginas rwx que vêm depois dela.
func TestPorInteresseColocaRWXNaFrente(t *testing.T) {
	rs := porInteresse(regioesAnonimas(mapsExemplo))
	if !rs[0].rwx() {
		t.Fatalf("a primeira região é %s (%s), queria a rwx", rs[0].rotulo(), rs[0].perms)
	}
	if rs[1].rotuloFS == "" || rs[2].rotuloFS == "" {
		t.Errorf("[heap] e [stack] deveriam vir logo depois: %s %s",
			rs[1].rotulo(), rs[2].rotulo())
	}
	// Dentro da mesma classe, a ordem de endereço se mantém — é o que faz o
	// manifesto ser comparável entre duas coletas do mesmo processo.
	if rs[1].rotulo() != "55d4a1000000-55d4a1021000" {
		t.Errorf("a ordem dentro da classe mudou: %s", rs[1].rotulo())
	}
}

func TestRWXSoOlhaGravavelEExecutavel(t *testing.T) {
	casos := map[string]bool{
		"rwxp": true, "rwxs": true,
		"rw-p": false, "r-xp": false, "r--p": false, "---p": false, "rw": false,
	}
	for perms, quer := range casos {
		if got := (regiao{perms: perms}).rwx(); got != quer {
			t.Errorf("rwx(%q) = %v, queria %v", perms, got, quer)
		}
	}
}

// escreverFaixa é o caminho do dump: não pode materializar a faixa inteira em
// RAM, e o que ele escreve tem que bater byte a byte com a origem.
func TestEscreverFaixaCopiaSoAFaixa(t *testing.T) {
	c, dir := coletor(t)
	origem := bytes.Repeat([]byte("AB"), 4096) // 8 KiB
	copy(origem[100:], []byte("PAYLOAD"))

	it, err := c.escreverFaixa("mem-1-64-6b.bin", bytes.NewReader(origem), 100, 7, "teste")
	if err != nil {
		t.Fatalf("escreverFaixa: %v", err)
	}
	if it.Bytes != 7 || it.Tipo != "mem" {
		t.Fatalf("item = %+v", it)
	}
	b, err := os.ReadFile(filepath.Join(dir, it.Destino))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "PAYLOAD" {
		t.Errorf("dump = %q, queria só a faixa pedida", b)
	}
	if it.HashOrigem != it.HashCopia {
		t.Errorf("hash da origem e da cópia divergem: %+v", it)
	}
}

// Uma leitura que não rende nada não pode deixar arquivo vazio no diretório de
// evidência: ali um arquivo de 0 byte se lê como "região dumpada e vazia", que
// é uma afirmação diferente de "não consegui ler".
func TestEscreverFaixaNaoDeixaArquivoVazio(t *testing.T) {
	c, dir := coletor(t)
	_, err := c.escreverFaixa("mem-vazio.bin", errReaderAt{}, 0, 4096, "teste")
	if err == nil {
		t.Fatal("leitura que falha deveria retornar erro")
	}
	if _, err := os.Stat(filepath.Join(dir, "mem-vazio.bin")); !os.IsNotExist(err) {
		t.Errorf("sobrou arquivo no diretório de evidência: %v", err)
	}
}

type errReaderAt struct{}

func (errReaderAt) ReadAt([]byte, int64) (int, error) { return 0, os.ErrPermission }

// donoEDatas é o que a interface padrão do Go não expõe — e é onde o i686
// quebra se a conversão de tipo sumir.
func TestDonoEDatasTrazCtime(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	uid, _, ctime, ok := donoEDatas(fi)
	if !ok {
		t.Fatal("donoEDatas falhou num arquivo comum")
	}
	if uid != os.Getuid() {
		t.Errorf("uid = %d, queria %d", uid, os.Getuid())
	}
	if !strings.HasSuffix(ctime, "Z") {
		t.Errorf("ctime = %q, queria UTC — a ferramenta inteira é UTC", ctime)
	}
}

// O mapeamento de arquivo APAGADO e executável é o mais irrecuperável: o arquivo
// sumiu do disco, e esta faixa é a única cópia. O regioesAnonimas o ignora (tem
// nome); o regioesApagadas o pega.
func TestRegioesApagadasPegaCodigoDeArquivoRemovido(t *testing.T) {
	const maps = `7f00a0000000-7f00a0002000 r-xp 00000000 08:01 123 /tmp/.x.so (deleted)
7f00a0002000-7f00a0003000 rw-p 00002000 08:01 123 /tmp/.x.so (deleted)
7f00b0000000-7f00b0002000 r-xp 00000000 08:01 456 /usr/lib/libc.so.6 (deleted)
7f00c0000000-7f00c0002000 r-xp 00000000 fd:00 999 /usr/bin/sshd
7f00d0000000-7f00d0002000 r-xp 00000000 00:05 7 /memfd:payload (deleted)
7f00e0000000-7f00e0002000 r-xp 00000000 08:01 789 /tmp/my lib.so
7f00f0000000-7f00f0002000 r-xp 00000000 00:00 0 [vdso] (deleted)
`
	rs := regioesApagadas(maps)
	var got []string
	for _, r := range rs {
		if !r.apagado {
			t.Errorf("%s devia estar marcado apagado", r.rotulo())
		}
		got = append(got, r.rotuloFS)
	}
	// só os EXECUTÁVEIS apagados: o rw-p apagado NÃO entra (é dado), nem o sshd
	// (arquivo VIVO), nem o "/tmp/my lib.so" VIVO com espaço no path — que só o
	// requisito de "(deleted)" filtra —, nem o [vdso] com sufixo apagado, que só
	// o requisito de caminho absoluto de verdade filtra. memfd apagado é código
	// só em memória: entra.
	quer := map[string]bool{
		"/tmp/.x.so":         true,
		"/usr/lib/libc.so.6": true,
		"/memfd:payload":     true,
	}
	if len(got) != len(quer) {
		t.Fatalf("regiões = %v, quer as 3 executáveis apagadas", got)
	}
	for _, g := range got {
		if !quer[g] {
			t.Errorf("região inesperada: %s", g)
		}
	}
}

// No corte por orçamento, o apagado tem de vir ANTES de tudo: é o único cuja
// perda é definitiva. Se o orçamento acabar, a última coisa a cair é ele.
func TestApagadoTemPrioridadeMaximaNoCorte(t *testing.T) {
	const maps = `7f00a0000000-7f00a0002000 rwxp 00000000 00:00 0
7f00b0000000-7f00b0002000 r-xp 00000000 08:01 123 /tmp/.x.so (deleted)
`
	ord := porInteresse(append(regioesApagadas(maps), regioesAnonimas(maps)...))
	if len(ord) < 2 || !ord[0].apagado {
		t.Fatalf("o apagado tem de ser o primeiro: %+v", ord)
	}
}
