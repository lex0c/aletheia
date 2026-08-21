package facts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lex0c/aletheia/internal/env"
)

// Os três backends de hash são o que separa "binário do sistema alterado" de
// "binário do sistema". Um defeito ali sai como acusação falsa ou como
// modificação perdida, e os dois são caros.
//
// Estavam sem teste unitário, e a COLISÃO DE USRMERGE já apareceu três vezes
// nesta base — inclusive nos três backends de uma vez, com 274 arquivos de um
// host real saindo como "não pude comparar". É o defeito que estes testes
// existem para travar.

// rootfs monta uma árvore de mentira e devolve o env que a lê.
func rootfs(t *testing.T, arquivos map[string]string) *env.Env {
	t.Helper()
	raiz := t.TempDir()
	for p, corpo := range arquivos {
		full := filepath.Join(raiz, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if corpo == "<link:usr/bin>" {
			if err := os.Symlink("usr/bin", full); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.WriteFile(full, []byte(corpo), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	e := env.Probe(env.Options{Root: raiz})
	t.Cleanup(func() { e.Close() })
	return e
}

func TestHashesDpkg(t *testing.T) {
	e := rootfs(t, map[string]string{
		"usr/bin/dash": "#!/bin/sh\n",
		"var/lib/dpkg/info/dash:amd64.md5sums": "" +
			"d41d8cd98f00b204e9800998ecf8427e  usr/bin/dash\n" +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  usr/share/doc/dash/copyright\n",
	})
	got := hashesDpkg(&Facts{}, e, map[string][]string{"dash:amd64": {"/usr/bin/dash"}})

	h, ok := got["/usr/bin/dash"]
	if !ok {
		t.Fatalf("o hash do binário perguntado não veio: %v", got)
	}
	if h.hash != "d41d8cd98f00b204e9800998ecf8427e" || h.algo != "md5" {
		t.Errorf("hash=%q algo=%q", h.hash, h.algo)
	}
	// O que NÃO foi perguntado não pode entrar: o md5sums de um pacote grande
	// tem milhares de linhas, e guardá-las todas é memória à toa.
	if _, tem := got["/usr/share/doc/dash/copyright"]; tem {
		t.Error("entrou hash de arquivo que ninguém perguntou")
	}
}

// A COLISÃO DE USRMERGE, travada. /bin é link para usr/bin, o dpkg lista
// `usr/bin/dash`, e o processo roda `/bin/dash`. As duas grafias são o mesmo
// arquivo, e as DUAS precisam receber o hash — guardar uma só fazia a outra
// sair como "não pude comparar".
func TestHashesDpkgSobUsrMerge(t *testing.T) {
	e := rootfs(t, map[string]string{
		"usr/bin/dash":                   "#!/bin/sh\n",
		"bin":                            "<link:usr/bin>",
		"var/lib/dpkg/info/dash.md5sums": "d41d8cd98f00b204e9800998ecf8427e  usr/bin/dash\n",
	})
	got := hashesDpkg(&Facts{}, e, map[string][]string{"dash": {"/bin/dash", "/usr/bin/dash"}})

	for _, forma := range []string{"/bin/dash", "/usr/bin/dash"} {
		if h, ok := got[forma]; !ok || h.hash == "" {
			t.Errorf("%s ficou sem hash: as duas grafias são o MESMO arquivo (got=%v)", forma, got)
		}
	}
}

func TestHashesApk(t *testing.T) {
	// Formato do apk: F: diretório, R: arquivo, Z: hash em "Q1"+base64(sha1).
	// O valor abaixo é o sha1 REAL de "#!/bin/sh\n" — a primeira versão deste
	// teste tinha um base64 inventado, e o backend o rejeitou com razão.
	e := rootfs(t, map[string]string{
		"usr/bin/busybox": "#!/bin/sh\n",
		"lib/apk/db/installed": "" +
			"P:busybox\n" +
			"F:usr/bin\n" +
			"R:busybox\n" +
			"Z:Q1vZcb7IgUmVZFihD8nF7LPrmd1FI=\n",
	})
	got := hashesApk(&Facts{}, e, map[string][]string{"busybox": {"/usr/bin/busybox"}})

	h, ok := got["/usr/bin/busybox"]
	if !ok {
		t.Fatalf("o hash não veio: %v", got)
	}
	if h.algo != "sha1" {
		t.Errorf("o apk guarda sha1 e o algo saiu %q", h.algo)
	}
	if h.hash != "bd971bec88149956458a10fc9c5ecb3eb99dd452" {
		t.Errorf("o base64 tem que virar hex: %q", h.hash)
	}
}

// Linha Z sem o prefixo Q1 é outro algoritmo, e o apk já usou outros. Adivinhar
// produziria comparação errada — que é pior que não comparar.
func TestHashesApkIgnoraAlgoritmoDesconhecido(t *testing.T) {
	e := rootfs(t, map[string]string{
		"usr/bin/busybox":      "x",
		"lib/apk/db/installed": "P:busybox\nF:usr/bin\nR:busybox\nZ:Q2abcdef==\n",
	})
	got := hashesApk(&Facts{}, e, map[string][]string{"busybox": {"/usr/bin/busybox"}})
	if len(got) != 0 {
		t.Errorf("prefixo desconhecido não pode virar hash: %v", got)
	}
}

// Base de pacotes AUSENTE devolve vazio, e o silêncio aqui não é "tudo bate":
// é o chamador que precisa saber que não houve comparação.
func TestHashesSemBaseDePacote(t *testing.T) {
	e := rootfs(t, map[string]string{"usr/bin/x": "x"})
	if got := hashesDpkg(&Facts{}, e, map[string][]string{"p": {"/usr/bin/x"}}); len(got) != 0 {
		t.Errorf("sem md5sums não há hash: %v", got)
	}
	if got := hashesApk(&Facts{}, e, map[string][]string{"p": {"/usr/bin/x"}}); len(got) != 0 {
		t.Errorf("sem base do apk não há hash: %v", got)
	}
}

// TIMESTOMP: o arquivo DIZ ser de meses atrás e os metadados foram tocados
// agora. A condição é reproduzível — `Chtimes` mexe no mtime e deixa o ctime no
// presente, que é exatamente o que `touch -d` do invasor faz.
func TestColetarTimestomp(t *testing.T) {
	raiz := t.TempDir()
	criar := func(nome string, mtimeAtras time.Duration) string {
		p := filepath.Join(raiz, nome)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o755); err != nil {
			t.Fatal(err)
		}
		quando := time.Now().Add(-mtimeAtras)
		if err := os.Chtimes(p, quando, quando); err != nil {
			t.Fatal(err)
		}
		return "/" + nome
	}
	antigo := criar("usr/local/bin/implante", 90*24*time.Hour) // 3 meses
	recente := criar("usr/local/bin/normal", 1*time.Hour)      // dentro da folga
	comDono := criar("usr/bin/legitimo", 90*24*time.Hour)

	e := env.Probe(env.Options{Root: raiz})
	t.Cleanup(func() { e.Close() })

	f := &Facts{Ownership: []Ownership{
		{Path: antigo, Owned: false},
		{Path: recente, Owned: false},
		// COM dono de pacote sai da pergunta: a data de um arquivo entregue
		// pela distribuição é o que a distribuição quis, e o gerenciador de
		// pacotes reescreve mtime na instalação o tempo todo.
		{Path: comDono, Owned: true, Pacote: "coreutils"},
	}}
	coletarTimestomp(f, e)

	if len(f.Timestomps) != 1 {
		t.Fatalf("só o antigo E sem dono é timestomp, e vieram %d: %+v", len(f.Timestomps), f.Timestomps)
	}
	ts := f.Timestomps[0]
	if ts.Path != antigo {
		t.Errorf("acusou o arquivo errado: %s", ts.Path)
	}
	// A folga existe porque instalação e build produzem minutos de diferença
	// legitimamente. Três meses não são minutos.
	if ts.DeltaH < 48 {
		t.Errorf("delta de %dh está abaixo da folga e não devia ter entrado", ts.DeltaH)
	}
	if ts.ModUTC == "" || ts.MetaUTC == "" {
		t.Error("as duas datas são a evidência: sem elas o operador não vê a contradição")
	}
}

// Conffiles: o dpkg guarda o md5 dos arquivos de CONFIGURAÇÃO no status, e não
// no .md5sums. Sem ler daqui, todo /etc entregue por pacote sairia como "não
// pude comparar".
func TestConffilesDpkg(t *testing.T) {
	e := rootfs(t, map[string]string{
		"var/lib/dpkg/status": "" +
			"Package: openssh-server\n" +
			"Status: install ok installed\n" +
			"Conffiles:\n" +
			" /etc/ssh/sshd_config 1111111111111111111111111111111a\n" +
			" /etc/init.d/ssh 2222222222222222222222222222222b obsolete\n" +
			"Description: secure shell server\n" +
			"\n" +
			"Package: cron\n" +
			"Conffiles:\n" +
			" /etc/crontab 3333333333333333333333333333333c\n",
	})
	donos := map[string]string{
		"/etc/ssh/sshd_config": "openssh-server",
		"/etc/init.d/ssh":      "openssh-server",
		"/etc/crontab":         "cron",
	}
	out := map[string]hashRef{}
	conffilesDpkg(&Facts{}, e, out, donos)

	for caminho, quer := range map[string]string{
		"/etc/ssh/sshd_config": "1111111111111111111111111111111a",
		"/etc/crontab":         "3333333333333333333333333333333c",
	} {
		h, ok := out[caminho]
		if !ok {
			t.Errorf("%s ficou sem hash: %v", caminho, out)
			continue
		}
		if h.hash != quer {
			t.Errorf("%s hash=%q, queria %q", caminho, h.hash, quer)
		}
		// conf=true é o que dá PESO diferente: editar config é o trabalho
		// normal do administrador, e a divergência ali não vale o mesmo que a
		// de um binário.
		if !h.conf {
			t.Errorf("%s tinha que estar marcado como configuração", caminho)
		}
	}

	// O terceiro campo marca o conffile como OBSOLETO, e o hash continua
	// valendo: descartar a linha perderia a comparação de um arquivo que ainda
	// está no disco.
	if h, ok := out["/etc/init.d/ssh"]; !ok || h.hash != "2222222222222222222222222222222b" {
		t.Errorf("conffile obsoleto perdeu o hash: %v", out["/etc/init.d/ssh"])
	}

	// E o que ninguém perguntou não entra: o status de um host real tem
	// milhares de linhas de Conffiles.
	e2 := rootfs(t, map[string]string{
		"var/lib/dpkg/status": "Package: x\nConffiles:\n /etc/x.conf abc\n",
	})
	out2 := map[string]hashRef{}
	conffilesDpkg(&Facts{}, e2, out2, map[string]string{})
	if len(out2) != 0 {
		t.Errorf("entrou conffile que ninguém perguntou: %v", out2)
	}
}

// A CADEIA DE LINKS DO update-alternatives, que é o mecanismo PADRÃO do Debian
// e do RHEL para escolher entre implementações:
//
//	/usr/bin/java -> /etc/alternatives/java -> /usr/lib/jvm/…/bin/java
//
// O dpkg reivindica o alvo final e NUNCA os dois links — eles nascem no
// postinst, não são empacotados. Sem seguir a cadeia, /usr/bin/java saía como
// "nenhum pacote reivindica", e em /usr/bin isso é CRÍTICO.
//
// Medido num servidor de CI montado por outra pessoa: 101 alternatives na
// imagem. Todo host com java, python ou editor tem essa forma.
func TestAlvoFinalSegueACadeia(t *testing.T) {
	raiz := t.TempDir()
	mk := func(p string) string {
		full := filepath.Join(raiz, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		return full
	}
	if err := os.WriteFile(mk("usr/lib/jvm/java-17/bin/java"), []byte("ELF"), 0o755); err != nil {
		t.Fatal(err)
	}
	// dois saltos, como o update-alternatives faz
	if err := os.Symlink("/usr/lib/jvm/java-17/bin/java", mk("etc/alternatives/java")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/alternatives/java", mk("usr/bin/java")); err != nil {
		t.Fatal(err)
	}
	// link RELATIVO, que resolve contra o diretório do PRÓPRIO link
	if err := os.Symlink("java", mk("usr/bin/java-runtime")); err != nil {
		t.Fatal(err)
	}
	// e um arquivo comum, que não é link
	if err := os.WriteFile(mk("usr/bin/normal"), []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}

	e := env.Probe(env.Options{Root: raiz})
	t.Cleanup(func() { e.Close() })

	if got := alvoFinal(e, "/usr/bin/java"); got != "/usr/lib/jvm/java-17/bin/java" {
		t.Errorf("cadeia de dois saltos: %q", got)
	}
	if got := alvoFinal(e, "/usr/bin/java-runtime"); got != "/usr/lib/jvm/java-17/bin/java" {
		t.Errorf("link relativo resolve contra o diretório do link: %q", got)
	}
	if got := alvoFinal(e, "/usr/bin/normal"); got != "" {
		t.Errorf("arquivo comum não é link, e devolveu %q", got)
	}
	if got := alvoFinal(e, "/nao/existe"); got != "" {
		t.Errorf("caminho inexistente: %q", got)
	}
}

// Ciclo de links não pode travar a coleta. O teto existe para isso.
func TestAlvoFinalNaoTravaEmCiclo(t *testing.T) {
	raiz := t.TempDir()
	if err := os.MkdirAll(filepath.Join(raiz, "usr/bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/usr/bin/b", filepath.Join(raiz, "usr/bin/a")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/usr/bin/a", filepath.Join(raiz, "usr/bin/b")); err != nil {
		t.Fatal(err)
	}
	e := env.Probe(env.Options{Root: raiz})
	t.Cleanup(func() { e.Close() })

	feito := make(chan string, 1)
	go func() { feito <- alvoFinal(e, "/usr/bin/a") }()
	select {
	case <-feito: // qualquer resposta serve; o que importa é TERMINAR
	case <-time.After(5 * time.Second):
		t.Fatal("ciclo de links travou a resolução")
	}
}

// bufio.Scanner para em SILÊNCIO numa linha maior que o buffer, e o laço acaba
// como se o arquivo tivesse terminado. Numa base de referência de hash isso é
// evasão: quem consegue escrever uma linha comprida no começo do arquivo
// derruba a verificação de tudo que vem depois, e o relatório sai dizendo que
// nada divergiu.
func TestLinhaCompridaNaBaseDeHashViraLacunaENaoFimDeArquivo(t *testing.T) {
	// 128 KiB numa linha só: acima do buffer de 64 KiB do leitor de .md5sums.
	entulho := strings.Repeat("A", 128*1024)
	raiz := t.TempDir()
	dir := filepath.Join(raiz, "var/lib/dpkg/info")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	corpo := entulho + "\n" +
		"d41d8cd98f00b204e9800998ecf8427e  usr/bin/dash\n"
	if err := os.WriteFile(filepath.Join(dir, "dash.md5sums"), []byte(corpo), 0o644); err != nil {
		t.Fatal(err)
	}
	e := env.Probe(env.Options{Root: raiz})
	t.Cleanup(func() { e.Close() })

	f := &Facts{}
	got := hashesDpkg(f, e, map[string][]string{"dash": {"/usr/bin/dash"}})
	if len(got) != 0 {
		t.Fatalf("a linha depois do entulho não podia ter sido lida: %v", got)
	}
	if len(f.PersistDenied["hash"]) == 0 {
		t.Error("o corte silencioso da base de referência não foi declarado: " +
			"sem hash esperado, o arquivo sai como não verificado, e não " +
			"verificado com cara de íntegro é o pior resultado possível")
	}
}

// O cluster de ctime é MEDIDO aqui e pesado no check.
//
// A versão anterior descartava o candidato nesta camada, e isso criou a evasão
// mais barata do catálogo: o ctime é truncado a segundos, então `touch -d` em
// quatro arquivos no mesmo segundo apagava a evidência inteira antes de
// qualquer check olhar — sem lacuna, sem rastro. Medir e deixar o peso para
// quem tem os outros sinais é o que devolve a decisão a quem pode tomá-la.
func TestMarcaClustersDeCtime(t *testing.T) {
	// 4 arquivos com o MESMO ctime (o instante da extração da imagem) + 1
	// isolado (o backdoor tocado depois).
	cand := []Timestomp{
		{Path: "/etc/apt/apt.conf.d/docker-clean", MetaUTC: "2026-08-19T17:00:03Z"},
		{Path: "/etc/apt/apt.conf.d/docker-gzip", MetaUTC: "2026-08-19T17:00:03Z"},
		{Path: "/etc/apt/apt.conf.d/docker-no-lang", MetaUTC: "2026-08-19T17:00:03Z"},
		{Path: "/etc/apt/apt.conf.d/docker-autoremove", MetaUTC: "2026-08-19T17:00:03Z"},
		{Path: "/usr/local/sbin/.backdoor", MetaUTC: "2026-08-19T17:05:41Z"},
	}
	got := marcaClustersDeCtime(cand)
	if len(got) != 5 {
		t.Fatalf("nenhum candidato pode ser descartado nesta camada: %+v", got)
	}
	for _, c := range got {
		quer := 4
		if c.Path == "/usr/local/sbin/.backdoor" {
			quer = 1
		}
		if c.Cluster != quer {
			t.Errorf("%s: Cluster=%d, queria %d", c.Path, c.Cluster, quer)
		}
	}
}

// O A4 planta DOIS timestomps (ctime da hora do plant): um cluster de 2 fica
// ABAIXO do limite do check e continua valendo integralmente.
func TestA4TemClusterPequeno(t *testing.T) {
	cand := marcaClustersDeCtime([]Timestomp{
		{Path: "/usr/local/sbin/dbus-broker-helper", MetaUTC: "2026-08-19T17:05:41Z"},
		{Path: "/etc/systemd/system/dbus-broker-helper.service", MetaUTC: "2026-08-19T17:05:41Z"},
	})
	for _, c := range cand {
		if c.Cluster != 2 {
			t.Errorf("%s: Cluster=%d, queria 2", c.Path, c.Cluster)
		}
	}
}
