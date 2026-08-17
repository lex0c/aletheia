package checks

import (
	"strconv"
	"strings"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

func init() {
	check.Register(cronSuspect)
	check.Register(cronFrequent)
	check.Register(atJob)
}

// cronSuspect — runbook §7.1.
//
// O que a linha EXECUTA. É a mesma pergunta do `unit_exec_suspect`, feita sobre
// o outro gatilho — e o cron é o mais usado dos dois em invasão real, porque
// não precisa de systemd, não precisa de root para o próprio usuário, e uma
// linha a mais num arquivo de texto não chama atenção.
//
// Por que os padrões, na letra da §7.1: o atacante quer o payload FORA do disco
// (baixado a cada execução, então ele muda quando quiser, e o que fica na sua
// máquina é uma linha inocente) e ILEGÍVEL (base64 derrota o grep do defensor).
var cronSuspect = check.Check{
	ID:       "persist.cron_suspect",
	Ref:      "7.1",
	Title:    "agendamento executa de lugar suspeito, ou baixa o que executa",
	Group:    "persist",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Wtf:      true,
	FalsePositives: []string{
		"provisionamento e instalação legítimos usam curl e sh — cloud-init, " +
			"agentes de nuvem e scripts de deploy aparecem aqui. O que os separa " +
			"é ter dono conhecido e vir junto do pacote",
		"backup e sincronização rodam de /home e de /opt legitimamente em host " +
			"de desenvolvimento; em servidor de produção, quase nunca",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		for i := range f.Cron {
			c := &f.Cron[i]
			motivo, sev, ok := execSuspect(c.Cmd)
			if !ok {
				continue
			}
			ev := []string{
				c.Cmd,
				motivo,
				"arquivo: " + c.File + linhaDe(c.Line),
			}
			ev = append(ev, cronContexto(c)...)

			fd := self.F(sev, cronSubject(c), "", ev...)
			fd.NextSteps = []string{
				"remova a persistência ANTES de matar o processo: o cron o recria " +
					"na próxima execução (runbook §19)",
				"depois de limpar, `atq` é obrigatório — o `at` dispara UMA vez no " +
					"futuro e não aparece em varredura de periodicidade (runbook §7.4)",
			}
			r.Findings = append(r.Findings, fd)
		}
		r.Partial = append(r.Partial, f.PersistDenied["cron"]...)
		return r
	},
}

// cronFrequent — runbook §7.1 e §2.7.
//
// A cadência do beacon. `*/7 * * * *` é o favorito justamente porque sete
// minutos não casa com nenhuma janela redonda de amostragem.
var cronFrequent = check.Check{
	ID:       "persist.cron_frequent",
	Ref:      "7.1",
	Title:    "agendamento com intervalo curto: a cadência de um beacon",
	Group:    "persist",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Wtf:      true,
	FalsePositives: []string{
		"monitoração, coleta de métrica e renovação de certificado rodam em " +
			"intervalo curto por projeto. São poucas, vêm de pacote e você as " +
			"conhece pelo nome",
		"o intervalo sozinho não acusa nada: ele diz ONDE procurar na §2.7, " +
			"correlacionando com conexão no mesmo período",
		"o agendador da própria distribuição é pulado: `run-parts` sobre " +
			"/etc/periodic ou /etc/cron.* é plumbing, e o Alpine entrega " +
			"`*/15 run-parts /etc/periodic/15min` de fábrica. O que esses " +
			"diretórios contêm é coletado como entrada própria e continua avaliado",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		for i := range f.Cron {
			c := &f.Cron[i]
			// `>` e não `>=`, e a diferença tem nome: o Outlaw agenda `*/15`.
			//
			// A versão anterior usava `>=` argumentando que quinze minutos é
			// cadência redonda e cadência redonda é manutenção legítima. O
			// argumento é bom e a conclusão era errada — malware de verdade usa
			// cadência redonda o tempo todo, e o exemplo estava publicado.
			//
			// Quem isenta o agendador da distribuição é a checagem de COMANDO
			// logo abaixo, que é precisa. O limiar não deve fazer esse trabalho:
			// fazendo, ele cega a ferramenta para todo agendamento de 15 minutos.
			if c.IntervalSec == 0 || c.IntervalSec > maxBeaconSeg {
				continue
			}
			// O próprio agendador da distribuição não é anomalia: o Alpine
			// entrega `*/15 run-parts /etc/periodic/15min` de fábrica, e o que
			// esses diretórios contêm já é coletado como entrada própria.
			if agendadorDaDistro(c.Cmd) {
				continue
			}
			ev := []string{
				"dispara a cada " + duracao(c.IntervalSec) + " — " + c.Schedule,
				c.Cmd,
				"arquivo: " + c.File + linhaDe(c.Line),
			}
			ev = append(ev, cronContexto(c)...)
			ev = append(ev, "correlacione com conexão nesse mesmo intervalo (runbook §2.7): "+
				"o beacon só é visível na janela estendida, não no retrato")

			fd := self.F(check.SevWarn, cronSubject(c), "", ev...)
			fd.NextSteps = []string{
				"amostre a rede pelo intervalo do agendamento, não por instantes (runbook §2.7)",
			}
			r.Findings = append(r.Findings, fd)
		}
		r.Partial = append(r.Partial, f.PersistDenied["cron"]...)
		return r
	},
}

// atJob — runbook §7.4.
//
// É o gatilho que mais escapa, e por um motivo específico: dispara UMA vez, no
// FUTURO. Não é recorrente, então não aparece em nenhuma varredura de "o que
// roda periodicamente" — e é exatamente assim que um atacante sobrevive à
// limpeza. Agenda para daqui a seis horas, você limpa tudo, valida, e ele volta
// de madrugada.
//
// Por isso a existência do job já é o achado: em servidor, `at` é raro.
var atJob = check.Check{
	ID:       "persist.at_job",
	Ref:      "7.4",
	Title:    "job do at agendado: dispara uma vez, no futuro",
	Group:    "persist",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Wtf:      true,
	FalsePositives: []string{
		"`at` tem uso legítimo — manutenção agendada, reinício programado, " +
			"`shutdown` com horário. Em servidor de produção é raro, e cada job " +
			"tem dono e motivo que alguém sabe dizer",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		for i := range f.Cron {
			c := &f.Cron[i]
			if c.Kind != "at" {
				continue
			}
			ev := []string{
				"comando: " + nz(c.Cmd, "(vazio)"),
				"arquivo: " + c.File,
				"dispara UMA vez, no futuro: não aparece em varredura de periodicidade",
			}
			if c.ModUTC != "" {
				ev = append(ev, "agendado em "+c.ModUTC)
			}
			// O job guarda o ambiente INTEIRO de quem o criou, e ali dentro
			// SSH_CONNECTION entrega o IP de origem de quem agendou (§3.6).
			for _, s := range c.Env {
				switch s.Key {
				case "SSH_CONNECTION", "SSH_CLIENT":
					ev = append(ev, "quem agendou veio de: "+s.Value+
						" ("+s.Key+" capturado no ambiente do job)")
				case "USER", "LOGNAME":
					ev = append(ev, "criado por: "+s.Value)
				}
			}

			sev := check.SevWarn
			if _, s, susp := execSuspect(c.Cmd); susp && s == check.SevCritical {
				sev = check.SevCritical
			}
			fd := self.F(sev, "at:"+baseDe(c.File), "", ev...)
			fd.NextSteps = []string{
				"leia o job inteiro: ele carrega o ambiente de quem o criou (runbook §7.4)",
				"depois de qualquer limpeza, `atq` de novo: é o gatilho que sobrevive " +
					"à validação da §22",
			}
			r.Findings = append(r.Findings, fd)
		}
		r.Partial = append(r.Partial, f.PersistDenied["cron"]...)
		return r
	},
}

// agendadorDaDistro reconhece o cron que existe só para chamar os diretórios
// periódicos da distribuição. A isenção é do MECANISMO no lugar certo: um
// run-parts apontando para /tmp não é plumbing de distribuição.
func agendadorDaDistro(cmd string) bool {
	campos := strings.Fields(cmd)
	if len(campos) < 2 || baseDe(campos[0]) != "run-parts" {
		return false
	}
	for _, a := range campos[1:] {
		if strings.HasPrefix(a, "-") {
			continue // --report e afins
		}
		return strings.HasPrefix(a, "/etc/periodic/") || strings.HasPrefix(a, "/etc/cron.")
	}
	return false
}

// cronContexto acrescenta o que decide se a linha importa.
func cronContexto(c *facts.CronEntry) []string {
	var ev []string
	if c.User != "" {
		ev = append(ev, "roda como: "+c.User)
	}
	if c.Reboot {
		ev = append(ev, "@reboot: sobrevive a restart, e não tem periodicidade "+
			"para a §2.7 correlacionar")
	}
	if c.ModUTC != "" {
		ev = append(ev, "arquivo modificado em "+c.ModUTC)
	}
	return ev
}

func cronSubject(c *facts.CronEntry) string {
	if c.User != "" {
		return c.User + "@" + baseDe(c.File)
	}
	return baseDe(c.File)
}

func linhaDe(n int) string {
	if n == 0 {
		return ""
	}
	return ":" + strconv.Itoa(n)
}

func baseDe(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

// duracao formata segundos de um jeito que o operador lê sem contar.
func duracao(s int) string {
	switch {
	case s < 60:
		return strconv.Itoa(s) + "s"
	case s < 3600:
		return strconv.Itoa(s/60) + "min"
	default:
		return strconv.Itoa(s/3600) + "h"
	}
}
