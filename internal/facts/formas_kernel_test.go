package facts

import "testing"

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
