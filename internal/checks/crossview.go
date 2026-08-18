package checks

import (
	"strconv"
	"strings"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

func init() {
	check.Register(pidOculto)
	check.Register(threadOculta)
	check.Register(moduloDivergente)
}

// pidOculto — runbook §32, §35.
//
// A pergunta que este check faz é diferente de todos os outros do catálogo. Os
// demais perguntam "isto que estou vendo é suspeito?". Este pergunta "o que
// estou vendo é TUDO que existe?".
//
// Um rootkit de userland reescreve `readdir()` e some com o processo da
// listagem de /proc — mas o `stat()` num caminho direto passa por outro caminho
// de código, e esconder dos dois de forma consistente é mais difícil.
//
// Duas formas de achar, e a primeira é a mais precisa:
//
//	ppid       um processo VISÍVEL declara um pai que não aparece na lista. Um
//	           stat resolve sem corrida: se o pai existe, a LISTAGEM mentiu
//	sondagem   PID que responde a stat sem estar na listagem
var pidOculto = check.Check{
	ID:       "cross.hidden_pid",
	Ref:      "35",
	Title:    "processo responde direto mas não aparece na listagem de /proc",
	Group:    "kernel",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive,
	Requires: env.CapProcfs,
	Optional: env.CapRoot,
	Wtf:      true,
	FalsePositives: []string{
		"corrida de nascimento NÃO produz mais este achado: o coletor relista " +
			"/proc depois da sondagem, e quem nasceu no intervalo aparece na " +
			"segunda listagem e é descartado. Foi o que fazia um guest de kernel " +
			"3.18 acusar as threads de kernel nascidas durante o boot",
		"hidepid não causa isto: sob hidepid o processo some das DUAS vias, e o " +
			"que degrada é a cobertura, não a comparação",
		"LIMITE que vale mais que o check: se o KERNEL estiver comprometido, as " +
			"duas fontes mentem juntas. Ausência de divergência não prova nada — " +
			"presença prova muito",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		for _, h := range f.Cross.Hidden {
			viaPPID := strings.HasPrefix(h.Como, "ppid")
			sev := check.SevWarn
			ev := []string{
				"pid=" + strconv.Itoa(h.PID) + " comm=" + nz(h.Comm, "?"),
				h.Como,
			}
			if viaPPID {
				// Esta via não tem corrida: o filho existe AGORA e declara o pai.
				sev = check.SevCritical
				ev = append(ev, "um processo visível declara este PID como pai, e ele "+
					"responde a stat: a LISTAGEM de /proc é que o omitiu")
			} else {
				ev = append(ev, "pode ser processo nascido entre a listagem e a "+
					"sondagem — o que dá sinal é a quantidade, não o caso isolado")
			}
			ev = append(ev, "sondagem foi até pid "+strconv.Itoa(f.Cross.ProbeAte)+
				" (pid_max="+strconv.Itoa(f.Cross.PidMax)+")")

			fd := self.F(sev, "pid="+strconv.Itoa(h.PID), "", ev...)
			fd.Irreversible = true
			fd.NextSteps = []string{
				"leia direto, sem passar por listagem: " +
					"sudo cat /proc/" + strconv.Itoa(h.PID) + "/status /proc/" +
					strconv.Itoa(h.PID) + "/cmdline",
				preservarPID(e, h.PID),
				"ocultação de processo é a assinatura do rootkit: a partir daqui, " +
					"analise a imagem DE FORA (runbook §35.6)",
			}
			r.Findings = append(r.Findings, fd)
		}
		// ModFtraceDiff NÃO é processado aqui: módulo escondido é achado de
		// `moduloDivergente` (cross.module_view), não de PID oculto. Havia um
		// loop duplicado nesta função que fazia um módulo virar cross.hidden_pid
		// — semanticamente errado, e com efeito colateral grave: cross.hidden_pid
		// é kernelBreaker, e o relatório passava a acusar "um PID responde a
		// /proc" sem PID oculto nenhum ter existido. O teste exercitava
		// moduloDivergente direto e não via a duplicação global.
		r.Partial = append(r.Partial, f.Partial["cross"]...)
		return r
	},
}

// threadOculta — runbook §35.
//
// O status DECLARA quantas threads o processo tem; o diretório de tarefas
// MOSTRA quantas existem. São caminhos diferentes no kernel, e esconder uma
// thread exige mentir nos dois.
var threadOculta = check.Check{
	ID:       "cross.thread_count",
	Ref:      "35",
	Title:    "contagem de threads diverge entre o status e o diretório de tarefas",
	Group:    "kernel",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive,
	Requires: env.CapProcfs,
	Optional: env.CapRoot,
	Wtf:      true,
	FalsePositives: []string{
		"thread que MORRE entre as duas leituras produz exatamente esta forma, " +
			"e runtime com pool (Go, JVM, Node) faz isso o tempo todo. Por isso " +
			"o coletor relê e só reporta o que PERSISTE — mas um processo em " +
			"encolhimento rápido e contínuo ainda pode escapar",
		"a direção oposta — diretório com mais entradas que o status declara — " +
			"não é reportada: é só a ordem de leitura, com uma thread nascendo " +
			"no intervalo",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		for _, d := range f.Cross.Threads {
			// O coletor já filtrou direção e confirmou por releitura; aqui só
			// resta o que sobreviveu às duas.
			p := f.ProcessByPID(d.PID)
			nome := "?"
			if p != nil {
				nome = p.Comm
			}
			fd := self.F(check.SevWarn, "pid="+strconv.Itoa(d.PID), "", []string{
				"status declara " + strconv.Itoa(d.Status) + " threads, o diretório " +
					"de tarefas mostra " + strconv.Itoa(d.Task),
				"comm=" + nome,
				"são caminhos diferentes no kernel: esconder uma thread exige " +
					"mentir nos dois",
			}...)
			fd.NextSteps = []string{
				"sudo ls /proc/" + strconv.Itoa(d.PID) + "/task && " +
					"grep Threads /proc/" + strconv.Itoa(d.PID) + "/status",
			}
			r.Findings = append(r.Findings, fd)
		}
		return r
	},
}

// moduloDivergente — runbook §7.12, §35.3.
//
// O kernel expõe a lista de módulos por duas interfaces. Um LKM que se remove
// da lista encadeada para sumir do /proc/modules costuma esquecer do sysfs — e
// o contrário também acontece.
//
// Duas comparações alimentam este check. A primeira é /proc/modules × sysfs,
// só na direção "carregado no /proc e ausente do sysfs" — a oposta é ruído,
// porque módulo embutido no kernel aparece no sysfs e nunca no /proc/modules.
//
// A segunda cobre o ponto cego da primeira: um LKM que faz list_del some do
// /proc/modules mas fica no sysfs, e ali é indistinguível de um builtin. O
// ftrace desfaz o empate — a função rastreável do módulo continua anotada com o
// nome dele mesmo depois do list_del, e builtin não leva anotação de módulo.
var moduloDivergente = check.Check{
	ID:       "cross.module_view",
	Ref:      "35.3",
	Title:    "módulo aparece numa interface do kernel e não na outra",
	Group:    "kernel",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive,
	Requires: env.CapProcfs,
	Optional: env.CapRoot,
	Wtf:      true,
	FalsePositives: []string{
		"nome com hífen e com sublinhado é o MESMO módulo, e a normalização já " +
			"cuida disso. Divergência real aqui é rara",
		"a direção oposta — presente no sysfs e ausente do /proc/modules — é " +
			"módulo EMBUTIDO no kernel, e não é reportada",
		"a comparação com o ftrace só reporta tag presente no ftrace e ausente " +
			"do /proc/modules; o contrário — módulo sem função rastreável, que " +
			"não aparece no ftrace — é normal e não é achado",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		for _, d := range f.Cross.ModDiff {
			fd := self.F(check.SevCritical, d, "", []string{
				d,
				"as duas interfaces expõem a MESMA informação: divergir significa " +
					"que uma delas foi manipulada",
				"é a forma do LKM que se desencadeia da lista para sumir (runbook §35.3)",
			}...)
			fd.NextSteps = []string{
				"compare com um kernel do mesmo pacote em host limpo",
				"a partir daqui, resultado vindo deste host não vale como prova: " +
					"analise a imagem DE FORA (runbook §35.6)",
			}
			r.Findings = append(r.Findings, fd)
		}
		for _, d := range f.Cross.ModFtraceDiff {
			fd := self.F(check.SevCritical, d, "", []string{
				d,
				"o ftrace registra a função rastreável de um módulo no " +
					"CARREGAMENTO e só a libera no descarregamento real: um módulo " +
					"que se desencadeia da lista para sumir do /proc/modules não " +
					"limpa esse registro",
				"e é a interface que o crossview de sysfs não alcança — ali o " +
					"módulo escondido é indistinguível de um embutido no kernel " +
					"(runbook §35.3)",
			}...)
			fd.NextSteps = []string{
				"`grep \"[<nome>]\" /sys/kernel/tracing/available_filter_functions` " +
					"lista as funções que o módulo escondido ainda expõe",
				"a partir daqui, resultado vindo deste host não vale como prova: " +
					"analise a imagem DE FORA (runbook §35.6)",
			}
			r.Findings = append(r.Findings, fd)
		}
		r.Partial = append(r.Partial, f.Partial["cross"]...)
		return r
	},
}
