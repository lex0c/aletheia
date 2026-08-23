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
	Cmd      string `json:"cmd" redact:"linha"`

	// IntervalSec é o menor intervalo que o gatilho produz; 0 = não periódico
	// ou não determinado. É o que responde à §2.7 — a cadência do beacon.
	IntervalSec int  `json:"interval_sec,omitempty"`
	Reboot      bool `json:"reboot,omitempty"`

	// Env é o ambiente capturado junto do job. Só `at` guarda isso, e é um
	// achado por si: SSH_CONNECTION ali dentro entrega o IP de quem agendou.
	Env []EnvSetting `json:"env,omitempty" redact:"valor"`

	ModUTC string `json:"mod_utc,omitempty"`
}

// cronSpoolDirs cobre as três convenções: Debian põe em crontabs/, RHEL põe
// direto, e o busybox crond do Alpine põe em /etc/crontabs — que não é spool
// nenhum, é /etc. Sondar as três evita depender de detecção de distribuição.
//
// O Alpine importa mais do que a fatia dele de servidores sugere: é a base da
// maioria das imagens de contêiner, então um agendamento plantado ali é
// exatamente o que se procura numa imagem sob suspeita.
var cronSpoolDirs = []string{
	"/var/spool/cron/crontabs", "/var/spool/cron", "/etc/crontabs",
}

// cronRunParts são os diretórios de script solto. A segunda metade é do
// busybox: o Alpine não tem /etc/cron.daily, tem /etc/periodic/daily — e sem
// esses quatro caminhos a varredura de um contêiner Alpine devolvia zero
// agendamentos com ar de resposta.
var cronRunParts = []string{
	"/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly",
	"/etc/periodic/15min", "/etc/periodic/hourly", "/etc/periodic/daily",
	"/etc/periodic/weekly", "/etc/periodic/monthly",
}

var atSpoolDirs = []string{"/var/spool/cron/atjobs", "/var/spool/at"}

func collectCron(f *Facts, e *env.Env) {
	// /etc/crontab e /etc/cron.d/*: formato de SISTEMA, com campo de usuário.
	f.Cron = append(f.Cron, parseCronFile(f, e, "/etc/crontab", "system", "")...)
	for _, n := range f.listarNegando(e, "cron", "/etc/cron.d") {
		f.Cron = append(f.Cron, parseCronFile(f, e, "/etc/cron.d/"+n, "dropin", "")...)
	}

	// Spool por usuário: sem campo de usuário, o dono é o NOME do arquivo.
	//
	// É AQUI que a varredura sem root cega: o spool do Debian é 1730
	// root:crontab, e listá-lo falha com EACCES. Sem declarar essa negativa, a
	// ferramenta relatava zero crontab de usuário — a mesma saída de um host
	// que realmente não tem nenhum.
	for _, dir := range cronSpoolDirs {
		for _, n := range f.listarNegando(e, "cron", dir) {
			p := dir + "/" + n
			if e.IsDir(p) {
				continue // /var/spool/cron/crontabs dentro de /var/spool/cron
			}
			f.Cron = append(f.Cron, parseCronFile(f, e, p, "user", n)...)
		}
	}

	// cron.hourly e amigos: script solto, sem gatilho na própria linha.
	for _, dir := range cronRunParts {
		for _, n := range f.listarNegando(e, "cron", dir) {
			p := dir + "/" + n
			f.Cron = append(f.Cron, CronEntry{
				File: p, Kind: "dir", Cmd: p,
				Schedule:    periodo(dir),
				IntervalSec: runPartsInterval(dir),
				ModUTC:      modUTC(e, p),
			})
		}
	}

	// E os diretórios que uma LINHA DE CRON manda o run-parts executar.
	//
	// A lista fixa acima cobre os da distribuição. Ela não cobre
	// `run-parts /etc/cron.backup`, e essa linha agenda tudo que estiver lá
	// dentro com a mesma força — medido: um script de `curl | sh` a cada minuto
	// saía com RESULT OK, porque a linha era isentada por parecer plumbing e o
	// diretório nunca era lido.
	seguirRunParts(f, e)

	collectAt(f, e)
}

// seguirRunParts coleta os diretórios que as próprias linhas de cron mandam
// executar. Sem isto, quem escolhe o nome do diretório escolhe se ele é olhado.
func seguirRunParts(f *Facts, e *env.Env) {
	visto := map[string]bool{}
	for _, d := range cronRunParts {
		visto[d] = true
	}
	// Cópia: o laço acrescenta a f.Cron, e iterar sobre o que se modifica é
	// como um diretório vira dois.
	linhas := append([]CronEntry(nil), f.Cron...)
	for _, c := range linhas {
		dir, ok := DiretorioDoRunParts(c.Cmd)
		if !ok || visto[dir] {
			continue
		}
		visto[dir] = true
		for _, n := range f.listarNegando(e, "cron", dir) {
			p := dir + "/" + n
			if e.IsDir(p) {
				continue
			}
			f.Cron = append(f.Cron, CronEntry{
				File: p, Kind: "dir", Cmd: p, User: c.User,
				Schedule:    c.Schedule,
				IntervalSec: c.IntervalSec,
				ModUTC:      modUTC(e, p),
			})
		}
	}
}

// DiretorioDoRunParts extrai o diretório que um `run-parts` executa, se a linha
// for isso. Exportado porque o check de frequência precisa da MESMA leitura
// para decidir se a linha é plumbing da distribuição — e a resposta não pode
// divergir entre os dois.
func DiretorioDoRunParts(cmd string) (string, bool) {
	// O run-parts não precisa ser o PRIMEIRO token. A linha de fábrica do
	// /etc/crontab do Debian é `cd / && run-parts --report /etc/cron.hourly`, e
	// a diária vem embrulhada em `test -x /usr/sbin/anacron || ( ... )`. Exigir
	// a primeira posição fazia a isenção não reconhecer o agendador da própria
	// distribuição — hoje sem efeito visível porque o horário passa do teto de
	// beacon antes de chegar aqui, mas é falso positivo esperando o teto mudar.
	//
	// Alargar não dá escolha ao adversário: quem decide a isenção é
	// RunPartsDaDistro sobre o DIRETÓRIO, e o conteúdo desses diretórios é
	// inventariado como entrada própria.
	campos := strings.Fields(cmd)
	for i, c := range campos {
		if baseNome(strings.TrimLeft(c, "(")) != "run-parts" {
			continue
		}
		for _, a := range campos[i+1:] {
			if strings.HasPrefix(a, "-") {
				continue // --report e afins
			}
			return strings.TrimRight(strings.TrimRight(a, ")"), "/"), true
		}
	}
	return "", false
}

// RunPartsDaDistro diz se o diretório é um dos que a distribuição usa. A lista
// é a MESMA que o coletor percorre: isentar um diretório que não se inventaria
// é dar a escolha ao adversário.
func RunPartsDaDistro(dir string) bool {
	for _, d := range cronRunParts {
		if d == dir {
			return true
		}
	}
	return false
}

// collectAt lê o spool do at. O arquivo do job é um script de shell que carrega
// o AMBIENTE INTEIRO de quem o criou — daí o parsing de export.
func collectAt(f *Facts, e *env.Env) {
	for _, dir := range atSpoolDirs {
		for _, n := range f.listarNegando(e, "cron", dir) {
			p := dir + "/" + n
			if e.IsDir(p) {
				continue
			}
			b, ok := f.lerNegando(e, "cron", p)
			if !ok {
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
func parseCronFile(f *Facts, e *env.Env, path, kind, user string) []CronEntry {
	b, ok := f.lerNegando(e, "cron", path)
	if !ok {
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
		// Qualquer branco separa, não só o espaço: o cronie/Vixie pula brancos
		// com get_string, e `@reboot\t/tmp/.x.sh` é crontab válido. Cortar só
		// no espaço fazia a linha inteira ser descartada pelo chamador — a
		// persistência de boot mais barata que existe ficava invisível, e quem
		// escolhe o byte separador é quem escreve o crontab.
		i := strings.IndexAny(ln, " \t")
		if i < 0 {
			return ln, "", false
		}
		return ln[:i], strings.TrimLeft(ln[i:], " \t"), true
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

// periodo é o nome da cadência dentro do caminho. As duas convenções o põem no
// último elemento, uma depois de ponto e a outra depois de barra:
//
//	/etc/cron.daily      →  daily
//	/etc/periodic/daily  →  daily
func periodo(dir string) string {
	nome := dir[strings.LastIndexByte(dir, '/')+1:]
	if i := strings.IndexByte(nome, '.'); i >= 0 {
		nome = nome[i+1:]
	}
	return nome
}

// runPartsInterval traduz a cadência para segundos. Ele responde à §2.7 — a
// frequência com que aquilo dispara —, e o `default` aqui é perigoso: qualquer
// diretório fora da lista virava "mensal", o que faria um job de 15 em 15
// minutos aparecer como o mais lento do host em vez do mais rápido.
func runPartsInterval(dir string) int {
	switch periodo(dir) {
	case "15min":
		return 900
	case "hourly":
		return 3600
	case "daily":
		return 86400
	case "weekly":
		return 604800
	case "monthly":
		return 2592000
	default:
		return 0 // não sei a cadência: 0 é "não determinado", e não "mensal"
	}
}

func modUTC(e *env.Env, p string) string {
	fi, err := e.Lstat(p)
	if err != nil {
		return ""
	}
	return fi.ModTime().UTC().Format(time.RFC3339)
}
