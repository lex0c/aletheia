// Package checks contém os checks concretos, um arquivo por seção do runbook.
// Cada arquivo se registra no init: acrescentar um check é criar um arquivo,
// sem fiação manual.
package checks

import (
	"strconv"
	"strings"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
	"github.com/lex0c/aletheia/internal/redact"
)

func init() {
	check.Register(memfdExec)
	check.Register(exeDeleted)
	check.Register(kthreadDisguise)
}

// memfdExec — runbook §3.16.
//
// Um binário executado via memfd_create NUNCA esteve em disco: não há o que o
// find encontre (§8), o que o sha256sum calcule (§5.4) nem o que o rpm -Va
// compare (§24). Matar o processo destrói a única cópia existente.
var memfdExec = check.Check{
	ID:       "proc.memfd_exec",
	Ref:      "3.16",
	Title:    "execução fileless: exe aponta para memória anônima",
	Group:    "proc",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive,
	Requires: env.CapProcfs,
	// Sem root, readlink(/proc/<pid>/exe) falha para todo processo alheio: um
	// implante memfd de root fica estruturalmente invisível. Declarar como
	// Optional faz o motor reportar cobertura DEGRADADA em vez de completa.
	Optional: env.CapRoot,
	Wtf:      true,
	FalsePositives: []string{
		"runtime que usa memfd_create para JIT ou para empacotar o próprio binário",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		// Idem: chave emitida pelo coletor e nunca lida. Ver o comentário do
		// primeiro check que a consome.
		r.Partial = append(r.Partial, f.Partial["proc"]...)
		var unreadable int
		for i := range f.Processes {
			p := &f.Processes[i]
			if p.ExeDenied {
				unreadable++
			}
			if p.Self || p.Vanished || !p.ExeMemfd {
				continue
			}
			fd := self.F(check.SevCritical, "pid="+strconv.Itoa(p.PID), "",
				"exe="+p.Exe,
				"comm="+p.Comm+" uid="+strconv.Itoa(p.UID)+" ppid="+strconv.Itoa(p.PPID),
				// A credencial passada em linha de comando é redigida ANTES de
				// entrar no achado: daqui ela iria para o relatório, para o
				// JSONL da frota e para o ticket (SPEC 5.4).
				"cmdline="+strings.Join(redact.Cmdline(p.Argv), " "),
			)
			fd.Quando, fd.QuandoFonte = p.StartUTC, "início do processo"
			if p.StartUTC != "" {
				fd.Evidence = append(fd.Evidence, "início="+p.StartUTC)
			}
			fd.Irreversible = true
			fd.NextSteps = []string{
				"NÃO mate antes de preservar: o binário só existe neste processo",
				preservarPID(e, p.PID),
			}
			r.Findings = append(r.Findings, fd)
		}
		r.Partial = append(r.Partial, partialForUnreadable(unreadable)...)
		return r
	},
}

// partialForUnreadable transforma exe ilegível em cobertura degradada. Sem
// isto, uma execução que não conseguiu ler 248 de 303 processos reportaria
// cobertura completa.
func partialForUnreadable(n int) []string {
	if n == 0 {
		return nil
	}
	return []string{strconv.Itoa(n) + " processos com /proc/<pid>/exe ilegível não foram avaliados"}
}

// exeDeleted — runbook §3.14.
//
// WARN, e não CRITICAL, de propósito: apagar o binário com o processo em
// execução é o que acontece em TODA atualização de pacote com o serviço no ar.
// O valor está na correlação (runbook §17), não neste sinal isolado.
var exeDeleted = check.Check{
	ID:       "proc.exe_deleted",
	Ref:      "3.14",
	Title:    "executável apagado do disco, processo ainda rodando",
	Group:    "proc",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive,
	Requires: env.CapProcfs,
	Optional: env.CapRoot,
	Wtf:      true,
	FalsePositives: []string{
		"atualização de pacote com o serviço em execução — MUITO comum, é o caso majoritário",
		"build ou deploy que substituiu o binário sem reiniciar o serviço",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		var unreadable int
		for i := range f.Processes {
			p := &f.Processes[i]
			if p.ExeDenied {
				unreadable++
			}
			if p.Self || p.Vanished || !p.ExeDeleted || p.ExeMemfd {
				continue // memfd tem check próprio, com severidade maior
			}
			fd := self.F(check.SevWarn, "pid="+strconv.Itoa(p.PID), "",
				"exe="+p.Exe+" (deleted)",
				"comm="+p.Comm+" uid="+strconv.Itoa(p.UID)+" ppid="+strconv.Itoa(p.PPID),
			)
			fd.Quando, fd.QuandoFonte = p.StartUTC, "início do processo"
			if p.StartUTC != "" {
				fd.Evidence = append(fd.Evidence, "início="+p.StartUTC)
			}
			fd.Irreversible = true
			fd.NextSteps = []string{
				"o binário continua íntegro em /proc/" + strconv.Itoa(p.PID) + "/exe",
				preservarPID(e, p.PID),
			}
			r.Findings = append(r.Findings, fd)
		}
		r.Partial = append(r.Partial, partialForUnreadable(unreadable)...)
		return r
	},
}

// kthreadDisguise — runbook §3.5.
//
// Thread de kernel NÃO tem /proc/<pid>/exe. Um processo de userspace com exe
// resolvido e cmdline vazio — ou argv0 entre colchetes — está se disfarçando
// de uma.
var kthreadDisguise = check.Check{
	ID:       "proc.kthread_disguise",
	Ref:      "3.5",
	Title:    "processo de userspace disfarçado de thread de kernel",
	Group:    "proc",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive,
	Requires: env.CapProcfs,
	Optional: env.CapRoot,
	Wtf:      true,
	FalsePositives: []string{
		"processo em meio a exec lê cmdline vazio: o coletor reconfirma numa " +
			"segunda passada e descarta quem morreu na janela",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		var unreadable int
		for i := range f.Processes {
			p := &f.Processes[i]
			if p.Self || p.Vanished {
				continue
			}
			if p.Exe == "" {
				// Exe vazio tem DUAS causas, e confundi-las é o pior tipo de
				// erro aqui: thread de kernel legítima (não tem exe) e falta de
				// permissão. Sem root, um `exec -a '[kworker/2:1]' /tmp/.x` de
				// root cai no segundo caso — e a versão anterior o classificava
				// como kthread legítima e o pulava.
				if p.ExeDenied {
					unreadable++
				}
				continue
			}

			var why string
			switch {
			case p.CmdlineEmpty:
				why = "cmdline vazio com exe resolvido"
			case len(p.Argv) > 0 && strings.HasPrefix(p.Argv[0], "[") && strings.HasSuffix(p.Argv[0], "]"):
				why = "argv0 entre colchetes: padrão de exec -a"
			default:
				continue
			}

			fd := self.F(check.SevCritical, "pid="+strconv.Itoa(p.PID), "",
				why,
				"exe="+p.Exe,
				"comm="+p.Comm+" uid="+strconv.Itoa(p.UID)+" ppid="+strconv.Itoa(p.PPID),
			)
			fd.Quando, fd.QuandoFonte = p.StartUTC, "início do processo"
			if len(p.Argv) > 0 {
				fd.Evidence = append(fd.Evidence, "argv0="+p.Argv[0])
			}
			fd.Irreversible = true
			fd.NextSteps = []string{
				"o nome mente, o exe não",
				preservarPID(e, p.PID),
			}
			r.Findings = append(r.Findings, fd)
		}
		r.Partial = append(r.Partial, partialForUnreadable(unreadable)...)
		return r
	},
}
