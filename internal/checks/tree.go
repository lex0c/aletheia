package checks

import (
	"strconv"
	"strings"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

func init() {
	check.Register(shellDeServico)
	check.Register(ptyDeServico)
}

// Árvore de processos (runbook §3.2).
//
// O processo isolado quase nunca é o sinal. `curl` sozinho é rotina; `curl`
// filho de `sh` filho de `nginx` é pós-exploração de servidor web, e a
// diferença está inteira na LINHAGEM.
//
// A regra que os dois checks abaixo compartilham: um daemon de rede não abre
// shell. Ele responde requisição. Quando abre, alguém está do outro lado.

// daemonsDeRede são os processos que atendem a rede e NUNCA deveriam gerar um
// shell no curso normal da vida.
//
// A lista é de PAPEL, não de nome de produto: qualquer coisa que aceite entrada
// de fora e gere shell é a mesma história.
var daemonsDeRede = map[string]string{
	"nginx": "servidor web", "httpd": "servidor web", "apache2": "servidor web",
	"caddy": "servidor web", "lighttpd": "servidor web",
	"node": "aplicação", "python": "aplicação", "python3": "aplicação",
	"java": "aplicação", "ruby": "aplicação", "php": "aplicação",
	"php-fpm": "aplicação", "gunicorn": "aplicação", "uwsgi": "aplicação",
	"postgres": "banco de dados", "mysqld": "banco de dados",
	"mariadbd": "banco de dados", "mongod": "banco de dados",
	"redis-server": "banco de dados", "memcached": "banco de dados",
	"tomcat": "aplicação", "jboss": "aplicação",
	"smbd": "compartilhamento", "vsftpd": "transferência", "proftpd": "transferência",
}

var shells = map[string]bool{
	"sh": true, "bash": true, "dash": true, "zsh": true, "ksh": true,
	"ash": true, "busybox": true, "csh": true, "tcsh": true, "fish": true,
}

// shellDeServico — runbook §3.2.
//
// A cadeia clássica de pós-exploração de aplicação web:
//
//	nginx → sh → curl
//
// Nenhum dos três é suspeito sozinho. A LINHAGEM é.
var shellDeServico = check.Check{
	ID:       "proc.shell_from_service",
	Ref:      "3.2",
	Title:    "daemon de rede gerou um shell",
	Group:    "proc",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive,
	Requires: env.CapProcfs,
	Optional: env.CapRoot,
	Wtf:      true,
	FalsePositives: []string{
		"aplicação que executa comando de sistema por design dispara aqui o " +
			"tempo todo: script de deploy chamado pelo app, health check que roda " +
			"shell, worker que invoca ferramenta externa. Em servidor bem " +
			"comportado é raro; em aplicação legada é rotina",
		"console administrativo embutido — Rails console, Django shell, " +
			"`docker exec` num container de app — produz exatamente esta forma",
		"entrypoint de container costuma ser um shell, e aí TODO processo do " +
			"container é filho de shell: o check olha a direção oposta, daemon " +
			"gerando shell, mas init de container confunde a linhagem",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		var semExe int

		for i := range f.Processes {
			p := &f.Processes[i]
			if p.Self || p.Vanished || !shells[baseDe(p.Exe)] && !shells[p.Comm] {
				continue
			}
			pai := f.ProcessByPID(p.PPID)
			if pai == nil {
				continue
			}
			if pai.ExeDenied {
				semExe++
				continue
			}
			papel, ok := daemonsDeRede[baseDe(pai.Exe)]
			if !ok {
				papel, ok = daemonsDeRede[pai.Comm]
			}
			if !ok {
				continue
			}

			ev := []string{
				pai.Comm + " (" + papel + ", pid=" + strconv.Itoa(pai.PID) + ") → " +
					p.Comm + " (pid=" + strconv.Itoa(p.PID) + ")",
				"um daemon de rede não abre shell no curso normal: ele responde " +
					"requisição",
				"pai: exe=" + nz(pai.Exe, "?") + " " + uidStr(pai),
				"shell: exe=" + nz(p.Exe, "?") + " " + uidStr(p),
			}
			if len(p.Argv) > 0 {
				ev = append(ev, "argv="+strings.Join(p.Argv, " "))
			}
			// Os filhos do shell contam a história inteira — é onde o `curl`
			// aparece.
			if filhos := filhosDe(f, p.PID); len(filhos) > 0 {
				ev = append(ev, "e o shell gerou: "+strings.Join(filhos, " · "))
			}
			if hasPTY(p) {
				ev = append(ev, "com PTY: há um humano digitando do outro lado (runbook §13)")
			}

			fd := self.F(check.SevCritical, "pid="+strconv.Itoa(p.PID), "", ev...)
			fd.Quando, fd.QuandoFonte = p.StartUTC, "início do processo"
			fd.Irreversible = true
			fd.NextSteps = []string{
				"a linhagem é a evidência: preserve a árvore inteira antes de matar " +
					"qualquer um (runbook §6)",
				"sudo cp /proc/" + strconv.Itoa(p.PID) + "/exe \"$IR/pid-" +
					strconv.Itoa(p.PID) + ".bin\"",
				"o PAI é o vetor de entrada: a §16 começa por ele, não pelo shell",
			}
			r.Findings = append(r.Findings, fd)
		}
		r.Partial = partialForUnreadable(semExe)
		return r
	},
}

// ptyDeServico — runbook §3.2, §13.
//
// Um PTY não é malicioso: é o normal de toda sessão SSH. O sinal é QUEM o tem.
// Conta de serviço não faz login interativo — ela roda um daemon. PTY numa
// conta dessas significa que alguém entrou com a identidade dela.
var ptyDeServico = check.Check{
	ID:       "proc.service_account_pty",
	Ref:      "3.2",
	Title:    "conta de serviço com terminal interativo",
	Group:    "proc",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive,
	Requires: env.CapProcfs,
	Optional: env.CapRoot,
	Wtf:      true,
	FalsePositives: []string{
		"manutenção legítima usa `su - postgres` e `sudo -u www-data` o tempo " +
			"todo, e produz exatamente esta forma. O que separa é a hora e quem " +
			"estava trabalhando — pergunta para o time, não para a ferramenta",
		"`docker exec -it` num container cujo app roda como conta de serviço " +
			"também cai aqui",
		"a fronteira de uid entre conta de serviço e conta de pessoa varia por " +
			"distribuição",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		for i := range f.Processes {
			p := &f.Processes[i]
			// Conta de SISTEMA: uid abaixo do primeiro uid de pessoa, e não root
			// — root com PTY é o administrador, que é o caso normal.
			if p.Self || p.Vanished || p.UID == 0 || p.UID >= 1000 || !hasPTY(p) {
				continue
			}
			if !shells[baseDe(p.Exe)] && !shells[p.Comm] {
				continue
			}
			ev := []string{
				p.Comm + " roda como uid " + strconv.Itoa(p.UID) + " e tem terminal",
				"conta de serviço não faz login interativo: ela roda um daemon",
				"exe=" + nz(p.Exe, "?") + " " + uidStr(p),
			}
			if pai := f.ProcessByPID(p.PPID); pai != nil {
				// O pai diz COMO se chegou aqui: sshd é login direto, su/sudo é
				// troca de identidade, daemon é pós-exploração.
				ev = append(ev, "pai: "+pai.Comm+" (pid="+strconv.Itoa(pai.PID)+
					") — é ele que diz COMO se chegou a este shell")
			}
			if p.StartUTC != "" {
				ev = append(ev, "início="+p.StartUTC+" — confira contra o horário de "+
					"trabalho e o wtmp (runbook §13)")
			}

			fd := self.F(check.SevWarn, "pid="+strconv.Itoa(p.PID), "", ev...)
			fd.Quando, fd.QuandoFonte = p.StartUTC, "início do processo"
			fd.NextSteps = []string{
				"pergunte ao time se alguém estava trabalhando como este usuário " +
					"nesse horário",
				"o histórico dessa sessão está no home da conta (runbook §13)",
			}
			r.Findings = append(r.Findings, fd)
		}
		return r
	},
}

// filhosDe devolve os filhos diretos, que é onde a cadeia continua.
func filhosDe(f *facts.Facts, pid int) []string {
	var out []string
	for i := range f.Processes {
		c := &f.Processes[i]
		if c.PPID != pid || c.Self {
			continue
		}
		out = append(out, c.Comm+" (pid="+strconv.Itoa(c.PID)+")")
		if len(out) >= 5 {
			break
		}
	}
	return out
}
