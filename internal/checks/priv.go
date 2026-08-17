package checks

import (
	"strconv"
	"strings"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

func init() {
	check.Register(capsUnexpected)
	check.Register(tracer)
}

// capName decodifica a máscara de CapEff sem depender do capsh — que é
// binário do host, e o host é justamente o que não se pode assumir íntegro
// (SPEC 4). Índice = número da capability no kernel.
var capName = [...]string{
	"chown", "dac_override", "dac_read_search", "fowner", "fsetid",
	"kill", "setgid", "setuid", "setpcap", "linux_immutable",
	"net_bind_service", "net_broadcast", "net_admin", "net_raw", "ipc_lock",
	"ipc_owner", "sys_module", "sys_rawio", "sys_chroot", "sys_ptrace",
	"sys_pacct", "sys_admin", "sys_boot", "sys_nice", "sys_resource",
	"sys_time", "sys_tty_config", "mknod", "lease", "audit_write",
	"audit_control", "setfcap", "mac_override", "mac_admin", "syslog",
	"wake_alarm", "block_suspend", "audit_read", "perfmon", "bpf",
	"checkpoint_restore",
}

// escalating são as capabilities que, num processo NÃO-root, valem por root.
// O critério não é "é poderosa": é "com ela, o UID deixa de significar
// qualquer coisa".
//
// O que ficou DE FORA é tão deliberado quanto o que ficou dentro. net_raw
// (ping, dumpcap), net_bind_service (serviço em porta baixa), sys_time
// (chrony), setpcap (unit de systemd), ipc_lock (ssh-agent, gpg-agent) e
// chown/fowner/fsetid (gerenciador de pacote) são distribuídas por distro a
// processo legítimo. Incluí-las transformaria o check em ruído — e ruído é
// como um relatório inteiro passa a ser ignorado.
var escalating = map[string]string{
	"setuid":          "vira root diretamente",
	"setgid":          "assume qualquer grupo",
	"dac_override":    "ignora permissão de arquivo: lê e escreve qualquer coisa",
	"dac_read_search": "lê qualquer arquivo do sistema, inclusive /etc/shadow",
	"sys_admin":       "quase root: mount, namespace, e mais",
	"sys_ptrace":      "injeta código em qualquer processo (runbook §3.16)",
	"sys_module":      "carrega módulo de kernel: é a porta do rootkit (runbook §35.3)",
	"sys_rawio":       "acesso direto a /dev/mem e a portas de E/S",
	"bpf":             "carrega programa eBPF: rootkit sem módulo e sem arquivo (runbook §35.4)",
	"perfmon":         "instrumenta o kernel inteiro",
	"net_admin":       "reconfigura rede e firewall: derruba a própria contenção (runbook §18)",
	"audit_control":   "desliga o auditd — anti-forense (runbook §21)",
	"linux_immutable": "remove chattr +i: desprotege o que foi travado (runbook §21)",
	"mac_admin":       "reconfigura SELinux/AppArmor",
	"mac_override":    "ignora SELinux/AppArmor",
	"syslog":          "lê o log do kernel, que entrega endereços para derrotar o KASLR",
}

// capsUnexpected — runbook §3.7.
//
// Capability substitui o SUID e passa despercebida em auditoria por UID: `ps`
// mostra um processo de usuário comum, e ele tem poder de root. O check não
// pergunta "tem capability?" — todo serviço tem alguma. Pergunta se tem alguma
// que torne o UID irrelevante.
var capsUnexpected = check.Check{
	ID:       "proc.caps_unexpected",
	Ref:      "3.7",
	Title:    "processo não-root com capability que vale por root",
	Group:    "proc",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive,
	Requires: env.CapProcfs,
	Optional: env.CapRoot,
	Wtf:      true,
	FalsePositives: []string{
		"agente de segurança e observabilidade roda sem privilégio COM capability " +
			"de propósito — sys_ptrace e bpf são exatamente o que ele precisa. " +
			"São poucos e você os conhece pelo nome",
		"container: o processo pode ter capability do bounding set da imagem sem " +
			"que ninguém a tenha concedido de propósito",
		"quem JÁ É root não entra aqui — e o teste é pelo uid EFETIVO: um binário " +
			"setuid como fusermount3 tem uid real 1000 e efetivo 0. Olhar só o real " +
			"faria a ferramenta acusar de escalada todo setuid legítimo do sistema",
		"processo em namespace de USUÁRIO (Podman rootless, Flatpak, sandbox de " +
			"navegador) exibe CapEff cheio, e essas capabilities só valem dentro do " +
			"namespace. São descartadas quando o namespace do PID 1 é legível",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		// Capability dentro de namespace de usuário não vale nada fora dele. Sem
		// a linha de base do PID 1 não dá para separar, e aí o achado vale mais
		// que o silêncio: o texto avisa.
		var initUserNS string
		if init1 := f.ProcessByPID(1); init1 != nil {
			initUserNS = init1.NS["user"]
		}

		for i := range f.Processes {
			p := &f.Processes[i]
			if p.Self || p.Vanished {
				continue
			}
			// O uid que decide é o EFETIVO: setuid-root é root.
			if p.UID == 0 || p.EUID == 0 {
				continue
			}
			if ns := p.NS["user"]; ns != "" && initUserNS != "" && ns != initUserNS {
				continue
			}
			var hits []string
			for _, name := range capNamesOf(p.CapEff) {
				if why, ok := escalating[name]; ok {
					hits = append(hits, "cap_"+name+" ("+why+")")
				}
			}
			if len(hits) == 0 {
				continue
			}

			ev := []string{
				"uid=" + strconv.Itoa(p.UID) + " euid=" + strconv.Itoa(p.EUID) +
					" — não é root nem por herança nem por setuid, e mesmo assim:",
			}
			ev = append(ev, hits...)
			ev = append(ev,
				"CapEff=0x"+strconv.FormatUint(p.CapEff, 16),
				"exe="+nz(p.Exe, "?")+" comm="+p.Comm)
			if p.Cgroup != "" {
				// A unit responde QUEM concedeu: AmbientCapabilities no arquivo
				// da unit, ou setcap no binário.
				ev = append(ev, "cgroup="+p.Cgroup)
			}

			fd := self.F(check.SevWarn, "pid="+strconv.Itoa(p.PID), "", ev...)
			fd.NextSteps = []string{
				"descubra QUEM concedeu: `getcap` no binário, ou AmbientCapabilities/" +
					"CapabilityBoundingSet na unit (runbook §7.2)",
				"se ninguém concedeu de propósito, trate como escalada de privilégio " +
					"e reveja a §7.9 (usuários e sudo)",
			}
			r.Findings = append(r.Findings, fd)
		}
		return r
	},
}

// tracer — runbook §3.7 e §3.16.
//
// TracerPid != 0 significa que outro processo tem controle sobre este: lê e
// escreve a memória dele à vontade. É a forma de injeção que não deixa arquivo
// nenhum — e, do outro lado, é também o que todo depurador faz.
var tracer = check.Check{
	ID:       "proc.tracer",
	Ref:      "3.7",
	Title:    "processo sob ptrace: alguém controla a memória dele",
	Group:    "proc",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive,
	Requires: env.CapProcfs,
	Optional: env.CapRoot,
	Wtf:      true,
	FalsePositives: []string{
		"depurador e profiler usam ptrace — é a função deles. gdb, strace, ltrace, " +
			"lldb, dlv e perf aparecem aqui e estão fazendo o trabalho normal",
		"o próprio `gcore` que o runbook manda rodar na §6 aparece aqui enquanto " +
			"o dump está em andamento: pode ser a SUA coleta",
		"CRIU e alguns supervisores fazem ptrace em operação legítima",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		for i := range f.Processes {
			p := &f.Processes[i]
			if p.Self || p.Vanished || p.TracerPID == 0 {
				continue
			}
			ev := []string{
				"traçado por pid=" + strconv.Itoa(p.TracerPID),
				"alvo: exe=" + nz(p.Exe, "?") + " comm=" + p.Comm + " " + uidStr(p),
			}
			sev := check.SevWarn
			if t := f.ProcessByPID(p.TracerPID); t != nil {
				ev = append(ev, "tracer: exe="+nz(t.Exe, "?")+" comm="+t.Comm+" "+uidStr(t))
				if isDebugger(t) {
					// Continua valendo o achado — o operador precisa saber que
					// existe uma sessão de depuração ativa —, mas o texto diz
					// qual é a leitura mais provável.
					ev = append(ev, "o tracer PARECE um depurador: pode ser trabalho legítimo, "+
						"ou um depurador usado como ferramenta de injeção")
				}
			} else {
				// Tracer fora da lista é pior que tracer conhecido: ou morreu,
				// ou está escondido de nós.
				ev = append(ev, "o tracer NÃO está entre os processos coletados: "+
					"morreu, está em outro namespace de PID, ou está oculto")
			}

			fd := self.F(sev, "pid="+strconv.Itoa(p.PID), "", ev...)
			fd.NextSteps = []string{
				"a memória do alvo pode ter sido reescrita: o binário em disco não " +
					"prova mais nada sobre o que está rodando (runbook §3.16)",
				"`kernel.yama.ptrace_scope=1` impede ptrace fora da relação pai/filho " +
					"(runbook §34)",
			}
			r.Findings = append(r.Findings, fd)
		}
		return r
	},
}

// capNamesOf devolve os nomes dos bits ligados na máscara.
func capNamesOf(mask uint64) []string {
	var out []string
	for i := 0; i < len(capName); i++ {
		if mask&(1<<uint(i)) != 0 {
			out = append(out, capName[i])
		}
	}
	return out
}

var debuggers = map[string]bool{
	"gdb": true, "gdbserver": true, "lldb": true, "lldb-server": true,
	"strace": true, "ltrace": true, "dlv": true, "perf": true,
	"gcore": true, "criu": true, "rr": true, "valgrind": true,
}

// uidStr mostra o uid efetivo junto quando ele diverge do real: a divergência
// É a informação (runbook §3.7).
func uidStr(p *facts.Process) string {
	if p.EUID != p.UID {
		return "uid=" + strconv.Itoa(p.UID) + " euid=" + strconv.Itoa(p.EUID) + " (setuid)"
	}
	return "uid=" + strconv.Itoa(p.UID)
}

func isDebugger(p *facts.Process) bool {
	if debuggers[p.Comm] {
		return true
	}
	if p.Exe == "" {
		return false
	}
	return debuggers[p.Exe[strings.LastIndexByte(p.Exe, '/')+1:]]
}
