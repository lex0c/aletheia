package checks

import (
	"strconv"
	"strings"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

func init() {
	check.Register(webPrepend)
	check.Register(shellStartup)
	check.Register(bashEnv)
	check.Register(shellEnv)
	check.Register(triggerExec)
	check.Register(pamExec)
	check.Register(udevRun)
}

// webPrepend — runbook §7.12.
//
// `auto_prepend_file` faz o PHP executar um arquivo ANTES de cada requisição,
// em qualquer rota. O docroot fica limpo, o grep de webshell da §16 não acha
// nada, e o backdoor roda em 100% dos acessos.
//
// Aqui o sinal é a DIRETIVA, não o comando: diferente dos outros gatilhos, o
// caminho apontado pode parecer perfeitamente normal — o que importa é que
// alguém pôs código no caminho de toda requisição.
var webPrepend = check.Check{
	ID:       "persist.web_prepend",
	Ref:      "7.12",
	Title:    "PHP executa arquivo antes de cada requisição",
	Group:    "app",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Wtf:      true,
	FalsePositives: []string{
		"auto_prepend_file tem uso legítimo: APM, profiler e framework que " +
			"precisa de bootstrap global usam exatamente isto. O arquivo apontado " +
			"tem nome reconhecível e vem junto do pacote da ferramenta",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		for i := range f.Triggers {
			t := &f.Triggers[i]
			if t.Kind != "php" {
				continue
			}
			for _, ln := range t.Lines {
				k, v, ok := strings.Cut(ln.Text, "=")
				k = strings.TrimSpace(k)
				v = strings.Trim(strings.TrimSpace(v), `"'`)
				if !ok || v == "" || v == "none" ||
					(k != "auto_prepend_file" && k != "auto_append_file") {
					continue
				}
				ev := []string{
					k + " = " + v,
					"o PHP executa este arquivo em TODA requisição, em qualquer rota",
					"o docroot fica limpo: a busca por webshell da §16 não acha nada",
					"arquivo: " + t.File + ":" + strconv.Itoa(ln.N),
				}
				sev := check.SevWarn
				if m, s, susp := execSuspect(v); susp {
					ev = append(ev, m)
					sev = s
				}
				ev = append(ev, contextoDoTrigger(t)...)

				fd := self.F(sev, v, "", ev...)
				fd.NextSteps = []string{
					"leia o arquivo apontado como se fosse malware (runbook §5)",
					"um módulo carregado no nginx ou no apache tem o mesmo efeito um " +
						"nível abaixo (runbook §7.12)",
				}
				r.Findings = append(r.Findings, fd)
			}
		}
		r.Partial = append(r.Partial, f.PersistDenied["startup"]...)
		return r
	},
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
		// Montado UMA vez. Construí-lo dentro do laço de linhas custava uma
		// passada sobre toda a propriedade por LINHA de arquivo de shell.
		semDono := caminhosSemDono(f)

		for i := range f.Triggers {
			t := &f.Triggers[i]
			if t.Kind != "shell" {
				continue
			}
			// Gatilho ENTREGUE PELA DISTRIBUIÇÃO não é achado.
			//
			// /etc/cron.daily/apt e /etc/cron.daily/dpkg fazem coisas que
			// parecem suspeitas em qualquer heurística de conteúdo — no Ubuntu
			// 14.04 renderam quinze acusações. O que os separa de um script
			// acrescentado é a mesma pergunta de sempre: veio de um pacote?
			//
			// E a isenção exige PROVA de que o arquivo está intacto, não só que
			// ele tenha dono. Um invasor que acrescenta uma linha ao
			// /etc/cron.daily/apt mantém o dono de pacote — o que muda é o
			// conteúdo, e a fase 7 compara isso com o hash que o próprio
			// gerenciador guarda. Sem hash disponível não há isenção.
			donoDoGatilho := entregueIntactoPeloPacote(f, t.File)

			for _, ln := range t.Lines {
				motivo, sev, ok := execSuspect(linhaExecutavel(ln.Text))
				if ok && donoDoGatilho {
					ok = false
				}
				if !ok {
					// O PADRÃO DE CONTEÚDO NÃO É A ÚNICA ENTRADA.
					//
					// O Outlaw põe o binário em ~/.configrc e o chama do
					// crontab e do shell de login. A linha não baixa nada e não
					// tem pipe para shell — só executa um caminho — e o
					// `execSuspect` passa batido, com razão.
					//
					// O que denuncia é a pergunta sobre o ALVO: nenhum pacote
					// entregou aquilo que a linha de inicialização executa.
					motivo, sev, ok = alvoSemDono(f, semDono, ln.Text)
					if !ok {
						continue
					}
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
				fd.Quando, fd.QuandoFonte = t.ModUTC, "mtime do arquivo de gatilho"
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
				fd.Quando, fd.QuandoFonte = t.ModUTC, "mtime do arquivo de gatilho"
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

// shellEnv — runbook §7.6.
//
// ENV é o BASH_ENV do mundo POSIX, e as duas variáveis são OPOSTAS no evento
// que disparam:
//
//	BASH_ENV   bash NÃO interativo: script, cron, scp, comando remoto de ssh
//	ENV        shell POSIX INTERATIVO: dash, ksh, e bash invocado como `sh`
//
// A diferença decide a severidade. BASH_ENV quase não tem uso legítimo, e é
// essa raridade que faz dele um sinal forte. ENV é o contrário: é o mecanismo
// documentado de arquivo de inicialização do shell POSIX, `ENV=$HOME/.shrc` em
// /etc/profile é configuração de fábrica em vários sistemas, e ele roda numa
// sessão INTERATIVA — onde alguém está olhando, e onde o .bashrc já é auditado.
//
// Aqui o achado é AVISO e diz por quê: o valor aponta para um arquivo que roda
// a cada shell interativo, e a pergunta é quem o entregou.
var shellEnv = check.Check{
	ID:       "persist.shell_env",
	Ref:      "7.6",
	Title:    "ENV definido: arquivo lido a cada shell POSIX interativo",
	Group:    "persist",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Wtf:      true,
	FalsePositives: []string{
		"ENV é o mecanismo DOCUMENTADO de arquivo de inicialização do shell " +
			"POSIX: `ENV=$HOME/.shrc` em /etc/profile é configuração de fábrica " +
			"em vários sistemas, e sozinho não é sinal de nada. O que vale é o " +
			"ALVO — quem entregou o arquivo que ele aponta",
		"não confunda com BASH_ENV (persist.bash_env), que é o oposto: aquele " +
			"roda em shell NÃO interativo, não tem uso legítimo comum, e por isso " +
			"sai como crítico",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		semDono := caminhosSemDono(f)
		for i := range f.Triggers {
			t := &f.Triggers[i]
			for _, ln := range t.Lines {
				if !defineShellEnv(ln.Text) {
					continue
				}
				// semExport primeiro: com o `export ` na frente, o lado esquerdo do
				// `=` vira "export ENV", que não está em varExecutada — e o alvo sairia
				// sendo a linha inteira em vez do caminho.
				alvo := linhaExecutavel(semExport(ln.Text))

				// ENV SOZINHO não é sinal, e o FalsePositives deste check diz
				// isso com todas as letras. `ENV=$HOME/.shrc` em /etc/profile é
				// configuração de fábrica em vários sistemas, e emitir aviso
				// para ela trocava um falso CRÍTICO por ruído permanente — que
				// gasta a atenção do operador do mesmo jeito, só mais devagar.
				//
				// O que faz o achado é o REFORÇO: o alvo em diretório gravável,
				// o alvo que nenhum pacote reivindica, ou a linha que não existe
				// no /etc/skel. Sem nenhum dos três, a linha é config e o
				// silêncio é a resposta certa.
				motivo, gravavel := suspectDir(alvo)
				semPacote := alvo != "" && semDono[alvo]
				if !gravavel && !semPacote && !ln.Added {
					continue
				}

				sev := check.SevWarn
				ev := []string{
					ln.Text,
					"ENV é lido por shell POSIX INTERATIVO (dash, ksh, bash como `sh`): " +
						"o arquivo apontado roda a cada sessão daquela conta",
					"arquivo: " + t.File + ":" + strconv.Itoa(ln.N),
					"QUANDO roda: " + t.When,
				}
				// O que decide não é a variável, é o ALVO dela.
				if gravavel {
					sev = check.SevCritical
					ev = append(ev, "e o arquivo apontado está "+motivo)
				} else if semPacote {
					ev = append(ev, "e nenhum pacote reivindica "+alvo)
				}
				if ln.Added {
					ev = append(ev, "esta linha NÃO existe em /etc/skel: foi acrescentada depois")
				}
				ev = append(ev, contextoDoTrigger(t)...)

				fd := self.F(sev, alvoDoTrigger(t), "", ev...)
				fd.Quando, fd.QuandoFonte = t.ModUTC, "mtime do arquivo de gatilho"
				fd.NextSteps = []string{
					"leia o arquivo que ele aponta: é ele que roda, não esta linha",
					"pergunte quem o entregou — `dpkg -S` / `rpm -qf` no alvo",
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
		"hook de git legítimo existe: lint, teste e deploy. O que separa é o " +
			"caminho do que ele executa — e um hook fora do .sample num servidor " +
			"que atualiza por `git pull` roda a cada deploy",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		// Montado UMA vez. Construí-lo dentro do laço de linhas custava uma
		// passada sobre toda a propriedade por LINHA de gatilho.
		semDono := caminhosSemDono(f)

		for i := range f.Triggers {
			t := &f.Triggers[i]
			switch t.Kind {
			case "rc", "initd", "motd", "ssh_rc", "pkg_hook", "generator",
				"git_hook", "mail", "supervisor", "cron_script":
			default:
				continue
			}
			// Gatilho ENTREGUE PELA DISTRIBUIÇÃO não é achado.
			//
			// /etc/cron.daily/apt e /etc/cron.daily/dpkg fazem coisas que
			// parecem suspeitas em qualquer heurística de conteúdo — no Ubuntu
			// 14.04 renderam quinze acusações. O que os separa de um script
			// acrescentado é a mesma pergunta de sempre: veio de um pacote?
			//
			// E a isenção exige PROVA de que o arquivo está intacto, não só que
			// ele tenha dono. Um invasor que acrescenta uma linha ao
			// /etc/cron.daily/apt mantém o dono de pacote — o que muda é o
			// conteúdo, e a fase 7 compara isso com o hash que o próprio
			// gerenciador guarda. Sem hash disponível não há isenção.
			donoDoGatilho := entregueIntactoPeloPacote(f, t.File)

			for _, ln := range t.Lines {
				motivo, sev, ok := execSuspect(linhaExecutavel(ln.Text))
				if ok && donoDoGatilho {
					ok = false
				}
				if !ok {
					// O PADRÃO DE CONTEÚDO NÃO É A ÚNICA ENTRADA.
					//
					// XorDDoS põe `/lib/libudev.so` num script de cron.hourly e
					// num init.d; HiddenWasp põe `/lib/libselinux.so` no
					// rc.local. Nenhum baixa nada, nenhum tem pipe para shell, e
					// os dois caminhos parecem de sistema — `execSuspect` passa
					// batido nos dois, com razão.
					//
					// O que denuncia é a pergunta sobre o ALVO, e ela é a mesma
					// que este check já citava nos falsos positivos sem usar.
					motivo, sev, ok = alvoSemDono(f, semDono, ln.Text)
					if !ok {
						continue
					}
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
				fd.Quando, fd.QuandoFonte = t.ModUTC, "mtime do arquivo de gatilho"
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
		r.Partial = append(r.Partial, f.PersistDenied["githook"]...)
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
				fd.Quando, fd.QuandoFonte = t.ModUTC, "mtime do arquivo de gatilho"
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
				fd.Quando, fd.QuandoFonte = t.ModUTC, "mtime do arquivo de gatilho"
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
	// Compara o primeiro TOKEN, não um prefixo com espaço literal: `source ` só
	// casa com espaço, e `source\t/tmp/.x` é linha de rc perfeitamente válida
	// que passava inteira adiante como se fosse o nome de um programa.
	if i := strings.IndexAny(s, " \t"); i > 0 {
		switch s[:i] {
		case "source", ".", "eval", "exec":
			return strings.TrimSpace(s[i+1:])
		}
	}
	// Alias e .forward: uma linha |"/caminho/comando" faz o MTA executar aquilo
	// a cada e-mail recebido. Sem extrair, o classificador vê o nome do alias.
	if i := strings.IndexByte(s, '|'); i >= 0 {
		cmd := strings.TrimSpace(s[i+1:])
		if len(cmd) > 1 && (cmd[0] == '"' || cmd[0] == '\'') {
			if fim := strings.IndexByte(cmd[1:], cmd[0]); fim >= 0 {
				return cmd[1 : 1+fim]
			}
		}
		if strings.HasPrefix(cmd, "/") {
			return cmd
		}
	}
	// Atribuição só conta quando a variável é EXECUTADA.
	//
	// Antes isto valia para qualquer `X=/caminho`, e o valor virava "caminho de
	// programa": o `/etc/init.d/rsyslog` de qualquer Ubuntu tem
	// `XCONSOLE=/dev/xconsole`, que é DADO, e virava achado. Variável comum
	// guarda caminho de arquivo o tempo todo.
	if k, v, ok := strings.Cut(s, "="); ok && varExecutada[strings.TrimSpace(k)] {
		return strings.Trim(strings.TrimSpace(v), `"'`)
	}
	return s
}

// varExecutada são as variáveis cujo VALOR o shell executa. Fora desta lista,
// atribuição é dado.
var varExecutada = map[string]bool{
	"BASH_ENV": true, "ENV": true,
	// roda antes de CADA prompt — é gatilho, não configuração
	"PROMPT_COMMAND": true,
}

// defineBashEnv casa SÓ BASH_ENV.
//
// BASH_ENV e ENV são variáveis OPOSTAS, e por muito tempo esta função tratou as
// duas como a mesma coisa: o achado saía com o título "BASH_ENV definido:
// executa em shell NÃO interativo" e severidade CRÍTICA para uma linha
// `ENV=$HOME/.shrc`, que é configuração documentada e faz o contrário.
//
//	BASH_ENV   bash NÃO interativo — script, cron, scp, comando remoto de ssh.
//	           Nenhum deles passa pelo .bashrc, e é isso que dá valor ao sinal.
//	ENV        shell POSIX INTERATIVO (dash, ksh, e bash invocado como sh ou em
//	           modo POSIX). É o .bashrc do mundo POSIX, e existe em host de
//	           fábrica.
func defineBashEnv(s string) bool {
	return strings.HasPrefix(semExport(s), "BASH_ENV=")
}

// defineShellEnv casa ENV, a variável de startup do shell POSIX.
func defineShellEnv(s string) bool {
	return strings.HasPrefix(semExport(s), "ENV=")
}

func semExport(s string) string {
	return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(s), "export "))
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

// alvoSemDono responde a pergunta de propriedade sobre o programa que a linha
// executa. É a entrada estrutural do gatilho: não olha o conteúdo do comando,
// olha de onde veio o binário.
func alvoSemDono(f *facts.Facts, semDono map[string]bool, linha string) (string, check.Severity, bool) {
	alvo := facts.PrimeiroCaminhoAbsoluto(linha)
	// /etc fora: é o território da configuração local, e ali "sem dono de
	// pacote" é a norma e não sinal.
	if alvo == "" || strings.HasPrefix(alvo, "/etc/") {
		return "", 0, false
	}
	if !semDono[alvo] {
		return "", 0, false
	}

	sev, nota := pesoDoCaminho(alvo)
	motivo := "executa " + alvo + ", e nenhum pacote reivindica esse arquivo " +
		"(base: " + f.Pkg.Kind + ") — " + nota
	// Executar uma BIBLIOTECA é anomalia por si só: `.so` é carregado pelo
	// ligador, não executado por gatilho. É a forma do XorDDoS.
	if strings.HasSuffix(alvo, ".so") || strings.Contains(alvo, ".so.") {
		sev = check.SevCritical
		motivo += " · e o alvo tem nome de BIBLIOTECA: `.so` é carregado pelo " +
			"ligador, não executado por gatilho de boot"
	}
	return motivo, sev, true
}

// temDonoDePacote responde se o pacote reivindica o arquivo. Falso quando a
// base não pôde ser consultada — e aí o ramo de conteúdo continua valendo, que
// é o comportamento seguro.
// entregueIntactoPeloPacote é a única condição que autoriza CALAR sobre um
// arquivo — e ela exige PROVA, não só procedência.
//
// A versão anterior perguntava apenas "tem dono de pacote?", e isso silenciou um
// backdoor de manual: `curl | sh` acrescentado ao /etc/bash.bashrc, que é
// entregue pelo base-files. O dono continua certo depois da edição; é o
// CONTEÚDO que muda, e era exatamente esse o limite escrito ali — "isto não vê
// modificação de arquivo empacotado".
//
// Com a fase 7 a prova existe. Quando ela não existir — base ilegível, arquivo
// sem hash declarado —, a resposta é NÃO suprimir: a ausência de prova não é
// prova de integridade, e o comportamento seguro é o de antes desta exceção.
func entregueIntactoPeloPacote(f *facts.Facts, p string) bool {
	var temDono bool
	for i := range f.Ownership {
		if f.Ownership[i].Path == p {
			temDono = f.Ownership[i].Owned
			break
		}
	}
	if !temDono {
		return false
	}
	for _, ok := range f.HashOK {
		if ok == p {
			return true
		}
	}
	return false
}
