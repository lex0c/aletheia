package facts

import "testing"

// Os casos abaixo vêm de uma rodada de revisão. Cada um reproduz um defeito que
// a suíte anterior não pegava porque as fixtures já vinham na forma FÁCIL — a
// linha de ftrace sempre com `tramp:`, o crontab sempre separado por espaço.
// O formato real do kernel é condicional, e é nas formas condicionais que o
// parser posicional errava.

// O separador de um atalho @ é qualquer branco, e quem o escolhe é quem escreve
// o crontab. Com TAB, a linha inteira sumia da coleta.
func TestCutScheduleAceitaTab(t *testing.T) {
	casos := []struct{ ln, sched, rest string }{
		{"@reboot\t/tmp/.x.sh", "@reboot", "/tmp/.x.sh"},
		{"@reboot /tmp/.x.sh", "@reboot", "/tmp/.x.sh"},
		{"@daily \t /usr/bin/backup", "@daily", "/usr/bin/backup"},
		{"@hourly\t\tcmd arg", "@hourly", "cmd arg"},
	}
	for _, c := range casos {
		sched, rest, ok := cutSchedule(c.ln)
		if !ok || sched != c.sched || rest != c.rest {
			t.Errorf("cutSchedule(%q) = %q,%q,%v — quer %q,%q,true",
				c.ln, sched, rest, ok, c.sched, c.rest)
		}
	}
}

// enabled_functions só traz `tramp: X (Y)` com FTRACE_FL_TRAMP_EN; sem ele o
// kernel escreve " ->%pS", sem parênteses, e o `%pS` do endereço interceptado
// acrescenta " [mod]" que DESLOCA os campos.
func TestLerFtraceFormasCondicionais(t *testing.T) {
	casos := []struct {
		nome, texto, sim, cb, mod string
		cont                      int
	}{
		{"com_tramp", "vfs_read (1) R   I   \ttramp: ftrace_regs_caller+0x0/0x60 (kprobe_ftrace_handler+0x0/0x120)",
			"vfs_read", "kprobe_ftrace_handler+0x0/0x120", "", 1},
		{"sem_tramp", "packet_rcv (2) R  I  D   ->ftrace_caller+0x5b/0x90",
			"packet_rcv", "ftrace_caller+0x5b/0x90", "", 2},
		{"funcao_de_modulo", "tpacket_rcv [af_packet] (2) R  I     \ttramp: x+0x0/0x10 (nf_hook+0x0/0x50 [nf_tables])",
			"tpacket_rcv", "nf_hook+0x0/0x50 [nf_tables]", "nf_tables", 2},
		{"direct_de_bpf", "__x64_sys_openat (1)    D  \n\tdirect-->bpf_trampoline_6442509+0x4c/0x1000",
			"__x64_sys_openat", "bpf_trampoline_6442509+0x4c/0x1000", "", 1},
		{"tramp_error", "do_exit (1) R\ttramp: ERROR!", "do_exit", "", "", 1},
	}
	for _, c := range casos {
		t.Run(c.nome, func(t *testing.T) {
			f := &Facts{}
			lerFtrace(f, c.texto)
			if len(f.Ftrace) != 1 {
				t.Fatalf("esperava 1 hook, veio %d: %+v", len(f.Ftrace), f.Ftrace)
			}
			h := f.Ftrace[0]
			if h.Simbolo != c.sim || h.Callback != c.cb || h.Modulo != c.mod || h.Contagem != c.cont {
				t.Errorf("sim=%q cb=%q mod=%q cont=%d\nquer sim=%q cb=%q mod=%q cont=%d",
					h.Simbolo, h.Callback, h.Modulo, h.Contagem, c.sim, c.cb, c.mod, c.cont)
			}
		})
	}
}

// module_flags põe '+' (COMING) ou '-' (GOING) DENTRO dos parênteses. Rejeitar
// a linha por causa desse byte tirava o módulo do inventário — e se ele fosse o
// único a admitir O/E, essas marcas passavam a figurar como taint SEM DONO.
func TestModulosComTaintAceitaEstadoTransitorio(t *testing.T) {
	for _, letras := range []string{"(OE)", "(OE+)", "(OE-)"} {
		out := modulosComTaint("nvidia 76546048 41 nvidia_modeset, Live 0x0 " + letras)
		if len(out) != 1 || out[0].Letras != "OE" {
			t.Errorf("%s → %+v; quer um módulo com letras OE", letras, out)
		}
	}
}

// O tipo 'B' do binfmt_misc nunca escreve "interpreter ": o registro inteiro
// era descartado dentro do coletor, com o kernel roteando execução agora.
func TestParseBinfmtReconheceBPF(t *testing.T) {
	corpo := "enabled\nbpf meu_ops\nbpf-interpreter alvo /usr/bin/qemu-x\nflags: F\n"
	r := parseBinfmtRegistro("teste", "/proc/sys/fs/binfmt_misc/teste", corpo)
	if r.BPFOps != "meu_ops" {
		t.Errorf("BPFOps = %q", r.BPFOps)
	}
	if len(r.BPFInterpretadores) != 1 || r.BPFInterpretadores[0] != "/usr/bin/qemu-x" {
		t.Errorf("BPFInterpretadores = %v", r.BPFInterpretadores)
	}
	if !r.TemInterpretador() {
		t.Error("um registro 'B' ligado a um interpretador TEM interpretador")
	}
}

// O git aceita a variável na mesma linha do cabeçalho, e o parser posicional
// engolia o core.fsmonitor — que o git EXECUTA a cada `git status` — junto com
// todas as chaves seguintes da seção.
func TestParseConfigGitChaveNaLinhaDoCabecalho(t *testing.T) {
	opts := ParseConfigGit("[core] fsmonitor = /tmp/.x\npager = less\n")
	var achou bool
	for _, o := range opts {
		if o.Chave == "core.fsmonitor" && o.Valor == "/tmp/.x" {
			achou = true
		}
		if o.Chave == "core] fsmonitor" || o.Valor == "" && o.Chave == "" {
			t.Errorf("chave corrompida: %+v", o)
		}
	}
	if !achou {
		t.Fatalf("core.fsmonitor não foi lido: %+v", opts)
	}
}
