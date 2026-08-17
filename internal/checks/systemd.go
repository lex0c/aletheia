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
		r.Partial = f.PersistDenied["unit"]
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
	// o campo de tempo é o último; hh:mm[:ss]
	hhmm := fields[len(fields)-1]
	parts := strings.Split(hhmm, ":")
	// unidade de cada posição, do fim para o começo: seg, min, hora
	unit := []int{1, 60, 3600}
	for i := len(parts) - 1; i >= 0; i-- {
		u := 1
		if k := len(parts) - 1 - i; k < len(unit) {
			u = unit[k]
		}
		if n, ok := strings.CutPrefix(parts[i], "*/"); ok {
			if v, err := strconv.Atoi(n); err == nil && v > 0 {
				return v * u, cal, true
			}
		}
	}
	return 0, "", false
}

// execSuspect classifica um comando de unit. Devolve o motivo em português
// porque ele vai direto para a evidência: o operador precisa saber POR QUE,
// não só que disparou.
func execSuspect(cmd string) (string, check.Severity, bool) {
	low := strings.ToLower(cmd)

	// Interpretador consumindo código de fora: o payload não está aqui.
	for _, pat := range []string{"curl ", "wget ", "base64 -d", "base64 --decode"} {
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
	bin := strings.TrimLeft(firstToken(cmd), "-@+!:")
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

// pareceCaminho recusa o que não pode ser caminho de executável. Metacaractere
// de shell é a marca de que aquele token é sintaxe, não programa.
func pareceCaminho(s string) bool {
	if s == "" || !strings.HasPrefix(s, "/") {
		return false
	}
	return !strings.ContainsAny(s, "*?[]()|;&$\"'`<>")
}

func pipesToShell(low string) bool {
	if !strings.Contains(low, "|") {
		return false
	}
	for _, sh := range []string{"sh", "bash", "zsh", "dash", "python", "perl", "ruby"} {
		if strings.Contains(low, "|"+sh) || strings.Contains(low, "| "+sh) {
			return true
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
	for _, p := range []string{
		"b64decode", "base64.b64", "atob(", "codecs.decode", "unhexlify",
		"decode('hex", "fromcharcode", "pack(\"h", "eval(", "exec(",
		"base64 -d", "base64 --decode", "openssl enc -d", "|xxd -r", "| xxd -r",
	} {
		if strings.Contains(low, p) {
			return true
		}
	}
	return false
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
