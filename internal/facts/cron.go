package facts

import (
	"strconv"
	"strings"
	"time"

	"github.com/lex0c/aletheia/internal/env"
)

// Cron e at (runbook §7.1 e §7.4).
//
// Lido de ARQUIVO, nunca de `crontab -l`: o binário do host responde o que o
// atacante quiser, e a §7.1 existe porque a linha no spool é a verdade. De
// quebra, funciona sobre imagem montada.
//
// A diferença entre os dois vale ser dita, porque muda o que se procura:
//
//	cron  recorrente. Aparece em qualquer varredura de "o que roda periodicamente"
//	at    dispara UMA vez, no FUTURO. Não é recorrente, então não aparece em
//	      varredura nenhuma — e é assim que um atacante sobrevive à limpeza:
//	      agenda para daqui a seis horas, você limpa, valida, e ele volta de
//	      madrugada (runbook §7.4)

// CronEntry é uma linha de agendamento já separada em gatilho e comando.
type CronEntry struct {
	File string `json:"file"`
	Line int    `json:"line,omitempty"`

	// Kind separa as origens porque elas têm FORMATO diferente: as de sistema
	// têm um campo de usuário a mais, e as de diretório não têm gatilho nenhum.
	Kind string `json:"kind"` // system | user | dropin | dir | at

	User     string `json:"user,omitempty"`
	Schedule string `json:"schedule,omitempty"`
	Cmd      string `json:"cmd"`

	// IntervalSec é o menor intervalo que o gatilho produz; 0 = não periódico
	// ou não determinado. É o que responde à §2.7 — a cadência do beacon.
	IntervalSec int  `json:"interval_sec,omitempty"`
	Reboot      bool `json:"reboot,omitempty"`

	// Env é o ambiente capturado junto do job. Só `at` guarda isso, e é um
	// achado por si: SSH_CONNECTION ali dentro entrega o IP de quem agendou.
	Env []EnvSetting `json:"env,omitempty"`

	ModUTC string `json:"mod_utc,omitempty"`
}

// cronSpoolDirs cobre as duas convenções: Debian põe em crontabs/, RHEL põe
// direto. Sondar as duas evita depender de detecção de distribuição.
var cronSpoolDirs = []string{"/var/spool/cron/crontabs", "/var/spool/cron"}

var cronRunParts = []string{
	"/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly",
}

var atSpoolDirs = []string{"/var/spool/cron/atjobs", "/var/spool/at"}

func collectCron(f *Facts, e *env.Env) {
	// /etc/crontab e /etc/cron.d/*: formato de SISTEMA, com campo de usuário.
	f.Cron = append(f.Cron, parseCronFile(e, "/etc/crontab", "system", "")...)
	for _, n := range e.ReadDirNames("/etc/cron.d") {
		f.Cron = append(f.Cron, parseCronFile(e, "/etc/cron.d/"+n, "dropin", "")...)
	}

	// Spool por usuário: sem campo de usuário, o dono é o NOME do arquivo.
	for _, dir := range cronSpoolDirs {
		for _, n := range e.ReadDirNames(dir) {
			p := dir + "/" + n
			if e.IsDir(p) {
				continue // /var/spool/cron/crontabs dentro de /var/spool/cron
			}
			f.Cron = append(f.Cron, parseCronFile(e, p, "user", n)...)
		}
	}

	// cron.hourly e amigos: script solto, sem gatilho na própria linha.
	for _, dir := range cronRunParts {
		for _, n := range e.ReadDirNames(dir) {
			p := dir + "/" + n
			f.Cron = append(f.Cron, CronEntry{
				File: p, Kind: "dir", Cmd: p,
				Schedule:    strings.TrimPrefix(dir, "/etc/cron."),
				IntervalSec: runPartsInterval(dir),
				ModUTC:      modUTC(e, p),
			})
		}
	}

	collectAt(f, e)
}

// collectAt lê o spool do at. O arquivo do job é um script de shell que carrega
// o AMBIENTE INTEIRO de quem o criou — daí o parsing de export.
func collectAt(f *Facts, e *env.Env) {
	for _, dir := range atSpoolDirs {
		for _, n := range e.ReadDirNames(dir) {
			p := dir + "/" + n
			if e.IsDir(p) {
				continue
			}
			b, err := e.ReadFile(p)
			if err != nil {
				continue
			}
			ent := CronEntry{File: p, Kind: "at", ModUTC: modUTC(e, p)}
			var corpo []string
			for _, ln := range strings.Split(string(b), "\n") {
				t := strings.TrimSpace(ln)
				switch {
				case t == "" || strings.HasPrefix(t, "#"):
				case strings.HasPrefix(t, "export "):
					if k, v, ok := strings.Cut(strings.TrimPrefix(t, "export "), "="); ok {
						ent.Env = append(ent.Env, EnvSetting{
							File: p, Key: k, Value: strings.Trim(v, `"'`),
						})
					}
				case strings.HasPrefix(t, "${SHELL:-"), strings.HasPrefix(t, "cd "),
					strings.HasPrefix(t, "umask "):
					// preâmbulo que o próprio at escreve
				default:
					corpo = append(corpo, t)
				}
			}
			ent.Cmd = strings.Join(corpo, "; ")
			f.Cron = append(f.Cron, ent)
		}
	}
}

// parseCronFile entende os dois formatos. O de sistema tem um campo a mais:
//
//	usuário   min hora dia mês dow  USUÁRIO  comando
//	sistema   min hora dia mês dow           comando
//
// Confundir os dois faz o nome do usuário virar o começo do comando, e o
// comando de verdade some do relatório.
func parseCronFile(e *env.Env, path, kind, user string) []CronEntry {
	b, err := e.ReadFile(path)
	if err != nil {
		return nil
	}
	mod := modUTC(e, path)
	comUsuario := kind == "system" || kind == "dropin"

	var out []CronEntry
	for i, raw := range strings.Split(string(b), "\n") {
		ln := strings.TrimSpace(raw)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		// MAILTO=, PATH=, SHELL=: atribuição, não agendamento. Mas PATH
		// reescrito é persistência por si (runbook §7.6), então vira entrada
		// com gatilho vazio em vez de ser descartada.
		if k, v, ok := strings.Cut(ln, "="); ok && !strings.ContainsAny(k, " \t") {
			out = append(out, CronEntry{
				File: path, Line: i + 1, Kind: kind, User: user,
				Schedule: "(atribuição)", Cmd: k + "=" + v, ModUTC: mod,
			})
			continue
		}

		sched, rest, ok := cutSchedule(ln)
		if !ok {
			continue
		}
		ent := CronEntry{
			File: path, Line: i + 1, Kind: kind, User: user,
			Schedule: sched, ModUTC: mod,
		}
		ent.Reboot = strings.HasPrefix(sched, "@reboot")
		ent.IntervalSec = cronInterval(sched)

		if comUsuario {
			// O separador é QUALQUER branco, e a distinção não é teórica: o
			// /etc/crontab que o pacote `cron` instala no Debian usa TAB entre
			// o usuário e o comando.
			//
			//	17 *  * * *  root<TAB>cd / && run-parts --report /etc/cron.hourly
			//
			// Cortando só em espaço, o usuário virava "root\tcd" e o comando
			// virava "/ && run-parts …" — cujo primeiro token é `/`. O diretório
			// raiz entrava na pergunta de propriedade, nenhum pacote reivindica
			// `/`, e todo servidor Debian de fábrica com cron instalado saía com
			// um aviso e exit code 1.
			//
			// O comentário desta função já dizia que confundir os dois faz o
			// nome do usuário virar o começo do comando. Era exatamente isso, e
			// nenhum contêiner da matriz tem cron instalado para mostrar.
			r := strings.TrimSpace(rest)
			i := strings.IndexAny(r, " \t")
			if i < 0 {
				continue
			}
			ent.User, ent.Cmd = r[:i], strings.TrimSpace(r[i+1:])
		} else {
			ent.Cmd = strings.TrimSpace(rest)
		}
		if ent.Cmd == "" {
			continue
		}
		out = append(out, ent)
	}
	return out
}

// cutSchedule separa o gatilho do resto. Trata as duas formas: os cinco campos
// e os atalhos com @.
func cutSchedule(ln string) (sched, rest string, ok bool) {
	if strings.HasPrefix(ln, "@") {
		s, r, found := strings.Cut(ln, " ")
		return s, r, found
	}
	campos := 0
	i := 0
	for campos < 5 {
		for i < len(ln) && (ln[i] == ' ' || ln[i] == '\t') {
			i++
		}
		ini := i
		for i < len(ln) && ln[i] != ' ' && ln[i] != '\t' {
			i++
		}
		if ini == i {
			return "", "", false
		}
		campos++
	}
	return strings.Join(strings.Fields(ln[:i]), " "), ln[i:], true
}

// CronIntervalParaTeste expõe a extração de intervalo. É função pura e o
// comportamento dela decide um check inteiro; testá-la pelo coletor exigiria
// montar spool em disco para responder uma pergunta de string.
func CronIntervalParaTeste(sched string) int { return cronInterval(sched) }

// cronInterval devolve o MENOR intervalo que o gatilho produz.
//
// Não é um avaliador de expressão cron: é a resposta para "isto roda com que
// frequência?", que é o que a §2.7 precisa para correlacionar com a rede.
// Implementar o formato inteiro para responder isso trocaria um sinal por um
// gerador de falso positivo.
func cronInterval(sched string) int {
	switch {
	case strings.HasPrefix(sched, "@reboot"):
		return 0 // dispara no boot, não periodicamente
	case strings.HasPrefix(sched, "@hourly"):
		return 3600
	case strings.HasPrefix(sched, "@daily"), strings.HasPrefix(sched, "@midnight"):
		return 86400
	case strings.HasPrefix(sched, "@weekly"):
		return 604800
	case strings.HasPrefix(sched, "@monthly"), strings.HasPrefix(sched, "@yearly"),
		strings.HasPrefix(sched, "@annually"):
		return 2592000
	}

	campos := strings.Fields(sched)
	if len(campos) < 5 {
		return 0
	}
	// unidade de cada campo: minuto, hora, dia, mês, dia-da-semana
	unidade := []int{60, 3600, 86400}
	for i := 0; i < 3 && i < len(campos); i++ {
		c := campos[i]
		switch {
		case c == "*":
			// "*" no campo de minuto = a cada minuto. Nos demais, só significa
			// "todo", e a frequência é decidida pelo campo menor.
			if i == 0 {
				return 60
			}
		case strings.HasPrefix(c, "*/"):
			if n, err := strconv.Atoi(c[2:]); err == nil && n > 0 {
				return n * unidade[i]
			}
		case strings.Contains(c, ","):
			// lista: N execuções dentro daquela unidade
			if n := strings.Count(c, ",") + 1; n > 1 {
				return unidade[i] * intervalDeUnidade(i) / n
			}
		}
	}
	return 0
}

// intervalDeUnidade é quantas vezes a unidade cabe no período seguinte, para
// converter lista em intervalo médio.
func intervalDeUnidade(i int) int {
	switch i {
	case 0:
		return 60 // minutos numa hora
	case 1:
		return 24 // horas num dia
	default:
		return 1
	}
}

func runPartsInterval(dir string) int {
	switch dir {
	case "/etc/cron.hourly":
		return 3600
	case "/etc/cron.daily":
		return 86400
	case "/etc/cron.weekly":
		return 604800
	default:
		return 2592000
	}
}

func modUTC(e *env.Env, p string) string {
	fi, err := e.Lstat(p)
	if err != nil {
		return ""
	}
	return fi.ModTime().UTC().Format(time.RFC3339)
}
