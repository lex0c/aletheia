package checks

import (
	"strconv"
	"strings"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

func init() {
	check.Register(shellStartup)
	check.Register(bashEnv)
	check.Register(triggerExec)
	check.Register(pamExec)
	check.Register(udevRun)
}

// shellStartup — runbook §7.6.
//
// O favorito da persistência de usuário, e por um motivo prático: não precisa
// de root, não precisa de systemd, e o `.bashrc` de distribuição tem dezenas de
// linhas que ninguém rola até o fim.
//
// Duas informações que a §7.6 dá de graça e que entram na evidência:
//
//	o diff contra /etc/skel   o esqueleto é a versão que a distribuição copiou
//	                          para cada home. O que sobra foi ACRESCENTADO
//	a posição no arquivo      acrescentar no fim, depois de linhas em branco,
//	                          é o padrão do `echo >>`
var shellStartup = check.Check{
	ID:       "persist.shell_startup",
	Ref:      "7.6",
	Title:    "arquivo de inicialização de shell executa algo suspeito",
	Group:    "persist",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Wtf:      true,
	FalsePositives: []string{
		"gerenciador de versão (nvm, rbenv, pyenv, conda) e instalador de SDK " +
			"acrescentam linhas no fim do .bashrc por design, e o fazem com " +
			"`curl` na instalação. Em estação de desenvolvimento é rotina",
		"o diff contra /etc/skel só existe se a distribuição tiver esqueleto: " +
			"onde não tem, toda linha aparece como acrescentada e a informação " +
			"perde valor",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		for i := range f.Triggers {
			t := &f.Triggers[i]
			if t.Kind != "shell" {
				continue
			}
			for _, ln := range t.Lines {
				motivo, sev, ok := execSuspect(linhaExecutavel(ln.Text))
				if !ok {
					continue
				}
				ev := []string{
					ln.Text,
					motivo,
					"arquivo: " + t.File + ":" + strconv.Itoa(ln.N),
					"QUANDO roda: " + t.When,
				}
				if ln.Added {
					// O baseline de graça: esta linha não está no esqueleto que
					// a distribuição copiou.
					ev = append(ev, "esta linha NÃO existe em /etc/skel: foi acrescentada depois")
				}
				if ln.Tail {
					ev = append(ev, "está no FIM do arquivo — onde ninguém rola, "+
						"e onde o `echo >>` deixa a linha")
				}
				ev = append(ev, contextoDoTrigger(t)...)

				fd := self.F(sev, alvoDoTrigger(t), "", ev...)
				fd.NextSteps = []string{
					"`tail -20` em cada arquivo de inicialização vale mais que grep: " +
						"o acréscimo fica no fim (runbook §7.6)",
					"o diff contra /etc/skel mostra tudo que foi acrescentado desde a " +
						"instalação, sem precisar de baseline",
				}
				r.Findings = append(r.Findings, fd)
			}
		}
		r.Partial = append(r.Partial, f.PersistDenied["startup"]...)
		return r
	},
}

// bashEnv — runbook §7.6.
//
// O caminho que quase ninguém confere. `BASH_ENV` é lido por shell NÃO
// interativo: script, cron, scp, comando remoto de ssh. Não aparece em login
// nenhum, e é por isso que ele sobrevive à limpeza dos arquivos que todo mundo
// olha.
var bashEnv = check.Check{
	ID:       "persist.bash_env",
	Ref:      "7.6",
	Title:    "BASH_ENV definido: executa em shell NÃO interativo",
	Group:    "persist",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Wtf:      true,
	FalsePositives: []string{
		"BASH_ENV tem uso legítimo raro — ambiente de build que precisa de setup " +
			"em shell não interativo. Fora disso, quase nunca aparece, e é " +
			"justamente essa raridade que dá valor ao sinal",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		for i := range f.Triggers {
			t := &f.Triggers[i]
			for _, ln := range t.Lines {
				if !defineBashEnv(ln.Text) {
					continue
				}
				ev := []string{
					ln.Text,
					"BASH_ENV é lido por shell NÃO interativo: script, cron, scp e " +
						"comando remoto de ssh — nenhum deles passa pelo .bashrc",
					"arquivo: " + t.File + ":" + strconv.Itoa(ln.N),
					"QUANDO roda: " + t.When,
				}
				if ln.Added {
					ev = append(ev, "esta linha NÃO existe em /etc/skel: foi acrescentada depois")
				}
				ev = append(ev, contextoDoTrigger(t)...)

				fd := self.F(check.SevCritical, alvoDoTrigger(t), "", ev...)
				fd.NextSteps = []string{
					"leia o arquivo apontado: ele roda em toda execução não interativa",
					"procure o mesmo padrão em /etc/environment e em drop-in de unit " +
						"(runbook §7.8, §7.2)",
				}
				r.Findings = append(r.Findings, fd)
			}
		}
		r.Partial = append(r.Partial, f.PersistDenied["startup"]...)
		return r
	},
}

// triggerExec — runbook §7.7 e §7.12.
//
// A mesma pergunta dos outros gatilhos, sobre os que sobraram: rc.local,
// init.d, MOTD, sshrc, hook de pacote e generator. O que muda entre eles é o
// EVENTO, e é isso que o achado precisa dizer — um MOTD roda a cada login, um
// generator roda antes de qualquer unit.
//
// Por que rc.local continua valendo: é legado do SysV, mas as distribuições
// mantêm um `rc-local.service` que o executa no boot SE o arquivo existir e
// tiver bit de execução. É persistência de root num arquivo que a maioria dos
// times nunca abre, porque "ninguém usa mais isso".
var triggerExec = check.Check{
	ID:       "persist.trigger_exec",
	Ref:      "7.7",
	Title:    "gatilho de boot, login ou pacote executa algo suspeito",
	Group:    "persist",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Wtf:      true,
	FalsePositives: []string{
		"init.d e MOTD legítimos existem e chamam script de /usr/lib — o que os " +
			"separa é o caminho do que executam e o dono do pacote",
		"hook de gerenciador de pacote é usado por ferramenta de configuração " +
			"(needrestart, unattended-upgrades) de forma legítima",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		for i := range f.Triggers {
			t := &f.Triggers[i]
			switch t.Kind {
			case "rc", "initd", "motd", "ssh_rc", "pkg_hook", "generator":
			default:
				continue
			}
			for _, ln := range t.Lines {
				motivo, sev, ok := execSuspect(linhaExecutavel(ln.Text))
				if !ok {
					continue
				}
				ev := []string{
					ln.Text,
					motivo,
					"arquivo: " + t.File + ":" + strconv.Itoa(ln.N),
					"QUANDO roda: " + t.When,
				}
				if t.Kind == "rc" && !t.Exec {
					// Detalhe que decide: rc.local sem bit de execução é INERTE.
					ev = append(ev, "sem bit de execução ("+t.Modo+"): o arquivo é "+
						"INERTE hoje — mas um chmod +x o ativa, e o ctime data isso")
					sev = check.SevWarn
				}
				ev = append(ev, contextoDoTrigger(t)...)

				fd := self.F(sev, alvoDoTrigger(t), "", ev...)
				fd.NextSteps = []string{
					"o ctime do arquivo data a ativação, mesmo que o conteúdo pareça " +
						"antigo (runbook §5.2, §9)",
					"script em /etc/init.d ainda vira unit pelo systemd-sysv-generator " +
						"e NÃO aparece em /etc/systemd/system (runbook §7.7)",
				}
				r.Findings = append(r.Findings, fd)
			}
		}
		r.Partial = append(r.Partial, f.PersistDenied["startup"]...)
		return r
	},
}

// pamExec — runbook §7.12.
//
// Backdoor de AUTENTICAÇÃO. `pam_exec.so` roda um programa a cada autenticação
// — com a senha em mãos, se o módulo pedir. E um módulo carregado de fora dos
// diretórios de segurança é código injetado no caminho de login.
var pamExec = check.Check{
	ID:       "persist.pam_exec",
	Ref:      "7.12",
	Title:    "PAM executa programa ou carrega módulo de fora do lugar padrão",
	Group:    "persist",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Wtf:      true,
	FalsePositives: []string{
		"pam_exec tem uso legítimo: notificação de login, provisionamento de " +
			"home, integração com MFA. O programa apontado tem nome reconhecível " +
			"e mora em diretório de sistema",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		for i := range f.Triggers {
			t := &f.Triggers[i]
			if t.Kind != "pam" {
				continue
			}
			for _, ln := range t.Lines {
				modulo, args, ok := moduloPAM(ln.Text)
				if !ok {
					continue
				}
				var ev []string
				sev := check.SevWarn

				switch {
				case strings.HasPrefix(modulo, "/") && !moduloPAMPadrao(modulo):
					ev = append(ev, "módulo carregado de "+modulo+
						", fora dos diretórios de segurança do PAM")
					sev = check.SevCritical
				case baseDe(modulo) == "pam_exec.so":
					ev = append(ev, "pam_exec.so executa um programa a CADA autenticação: "+
						nz(args, "(sem argumento)"))
					if m, s, susp := execSuspect(args); susp {
						ev = append(ev, m)
						sev = s
					}
				default:
					continue
				}

				ev = append(ev,
					"arquivo: "+t.File+":"+strconv.Itoa(ln.N),
					"QUANDO roda: "+t.When,
					ln.Text)
				ev = append(ev, contextoDoTrigger(t)...)

				fd := self.F(sev, alvoDoTrigger(t), "", ev...)
				fd.NextSteps = []string{
					"o caminho de autenticação vê a senha: trate como comprometimento " +
						"de credencial até provar o contrário (runbook §23)",
					"compare os módulos com os do pacote antes de concluir (runbook §24)",
				}
				r.Findings = append(r.Findings, fd)
			}
		}
		r.Partial = append(r.Partial, f.PersistDenied["startup"]...)
		return r
	},
}

// udevRun — runbook §7.12.
//
// Regra de udev executa em EVENTO DE DISPOSITIVO — e um dispositivo pode ser
// criado por software. É gatilho sem horário e sem login, o que o deixa fora de
// toda correlação temporal.
var udevRun = check.Check{
	ID:       "persist.udev_run",
	Ref:      "7.12",
	Title:    "regra de udev executa programa em evento de dispositivo",
	Group:    "persist",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Wtf:      true,
	FalsePositives: []string{
		"RUN e PROGRAM são o mecanismo NORMAL do udev, e as regras de " +
			"distribuição os usam o tempo todo. O check só olha as regras de " +
			"/etc/udev/rules.d — que é onde o administrador escreve — e só " +
			"reporta quando o programa está fora de diretório de sistema",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		for i := range f.Triggers {
			t := &f.Triggers[i]
			if t.Kind != "udev" {
				continue
			}
			for _, ln := range t.Lines {
				prog, ok := programaUdev(ln.Text)
				if !ok {
					continue
				}
				motivo, sev, susp := execSuspect(prog)
				if !susp {
					continue
				}
				ev := []string{
					prog,
					motivo,
					"arquivo: " + t.File + ":" + strconv.Itoa(ln.N),
					"QUANDO roda: " + t.When + " — sem horário e sem login, " +
						"fora de toda correlação temporal",
					ln.Text,
				}
				ev = append(ev, contextoDoTrigger(t)...)

				fd := self.F(sev, alvoDoTrigger(t), "", ev...)
				fd.NextSteps = []string{
					"um dispositivo pode ser criado por software: o gatilho não " +
						"depende de hardware novo",
				}
				r.Findings = append(r.Findings, fd)
			}
		}
		r.Partial = append(r.Partial, f.PersistDenied["startup"]...)
		return r
	},
}

// linhaExecutavel tira as formas que envolvem o comando sem serem ele, para o
// classificador ver o caminho de verdade.
func linhaExecutavel(s string) string {
	s = strings.TrimSpace(s)
	for _, p := range []string{"source ", ". ", "eval ", "exec "} {
		if r, ok := strings.CutPrefix(s, p); ok {
			return strings.TrimSpace(r)
		}
	}
	// `export X=/tmp/y` e `VAR=/tmp/y cmd` escondem o caminho depois do "=".
	if k, v, ok := strings.Cut(s, "="); ok && !strings.ContainsAny(k, " \t/") {
		return strings.Trim(strings.TrimSpace(v), `"'`)
	}
	return s
}

func defineBashEnv(s string) bool {
	t := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(s), "export "))
	return strings.HasPrefix(t, "BASH_ENV=") || strings.HasPrefix(t, "ENV=")
}

// moduloPAM devolve o módulo e os argumentos de uma linha do pam.d.
// Formato: <tipo> <controle> <módulo> [args]. O controle pode vir entre
// colchetes com espaços dentro — `[success=1 default=ignore]` —, e cortar por
// espaço ali faria o módulo virar um pedaço do controle.
func moduloPAM(ln string) (modulo, args string, ok bool) {
	campos := strings.Fields(ln)
	if len(campos) < 3 {
		return "", "", false
	}
	i := 1
	if strings.HasPrefix(campos[i], "[") {
		for i < len(campos) && !strings.HasSuffix(campos[i], "]") {
			i++
		}
		i++
	} else {
		i++
	}
	if i >= len(campos) {
		return "", "", false
	}
	return campos[i], strings.Join(campos[i+1:], " "), true
}

// moduloPAMPadrao reconhece os diretórios onde módulo de PAM legitimamente mora.
func moduloPAMPadrao(p string) bool {
	for _, d := range []string{"/lib/security/", "/lib64/security/",
		"/usr/lib/security/", "/usr/lib64/security/", "/usr/lib/"} {
		if strings.HasPrefix(p, d) {
			return true
		}
	}
	return false
}

// programaUdev extrai o comando de RUN{...}+= ou PROGRAM=.
func programaUdev(ln string) (string, bool) {
	for _, chave := range []string{"RUN", "PROGRAM"} {
		i := strings.Index(ln, chave)
		if i < 0 {
			continue
		}
		j := strings.Index(ln[i:], "=")
		if j < 0 {
			continue
		}
		v := strings.TrimSpace(strings.TrimPrefix(ln[i+j:], "="))
		v = strings.TrimPrefix(v, "+")
		v = strings.TrimPrefix(strings.TrimSpace(v), "=")
		v = strings.TrimSpace(v)
		if len(v) > 1 && (v[0] == '"' || v[0] == '\'') {
			fim := strings.IndexByte(v[1:], v[0])
			if fim >= 0 {
				return v[1 : 1+fim], true
			}
		}
	}
	return "", false
}

func contextoDoTrigger(t *facts.Trigger) []string {
	var ev []string
	if t.User != "" {
		ev = append(ev, "usuário: "+t.User)
	}
	if t.ModUTC != "" {
		ev = append(ev, "arquivo modificado em "+t.ModUTC)
	}
	return ev
}

func alvoDoTrigger(t *facts.Trigger) string {
	if t.User != "" {
		return t.User + ":" + baseDe(t.File)
	}
	return t.File
}
