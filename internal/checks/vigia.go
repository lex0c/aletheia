package checks

import (
	"strconv"
	"strings"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

func init() { check.Register(vigiaDeArquivo) }

// vigiaDeArquivo — runbook §7.12, §19.
//
// A frase que este check existe para explicar: **"removi o backdoor e ele
// voltou"**.
//
// Quem recria um arquivo apagado precisa SABER que ele sumiu, e o jeito de
// saber é um watch de inotify no arquivo — ou no diretório dele, que é o que
// sobrevive ao `rm`. O vigia não abre porta, não tem cron, não tem unit, e
// reage em milissegundos. A §19 manda remover persistência ANTES de matar
// processo exatamente por isso, e obedecer exige saber que o vigia existe.
//
// # O que separa sinal de ruído
//
// Vigiar arquivo é comum: systemd, portais de desktop, indexadores, IDEs e
// agentes de configuração fazem isso o tempo todo. Acusar o ESTADO encheria o
// relatório em todo host com interface gráfica.
//
// O que é objetivo é a combinação:
//
//	o vigia não veio de pacote    ninguém empacotou este observador
//	e observa PERSISTÊNCIA        cron, unit, authorized_keys, ld.so.preload —
//	                              o que executa, ou o que decide quem entra
//
// Cada metade sozinha é rotina. Juntas, descrevem um programa sem procedência
// esperando o momento de reescrever o que garante a volta dele.
var vigiaDeArquivo = check.Check{
	ID:       "persist.file_watch",
	Ref:      "7.12",
	Title:    "processo sem dono de pacote vigiando arquivo de persistência",
	Group:    "persist",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive,
	Requires: env.CapProcfs,
	Optional: env.CapRoot,
	Wtf:      true,
	FalsePositives: []string{
		"VIGIAR ARQUIVO É COMUM e legítimo: systemd (path units e userdbd), " +
			"portais de desktop, gvfs, indexadores, IDEs e agentes de " +
			"configuração (puppet, chef, salt) observam /etc e o home o tempo " +
			"todo. Por isso o achado exige as DUAS metades — sem dono de pacote " +
			"E sobre caminho de persistência",
		"ferramenta de automação existe para isto: `incron`, `entr` e " +
			"`watchexec` são vigias por desenho, e num host de desenvolvimento " +
			"aparecem legitimamente. O que muda é quem instalou, e onde o binário " +
			"mora",
		"fanotify é usado por antivírus e por auditoria de arquivo, ambos " +
			"legítimos e ambos exigindo CAP_SYS_ADMIN. A lista é curta e o time " +
			"reconhece cada um pelo nome",
		"LIMITE do formato: o fdinfo dá a identidade do arquivo, não o caminho. " +
			"O casamento é feito contra os caminhos que a varredura já conhece, " +
			"e o que ficar de fora sai contado como NÃO nomeado — nunca atribuído " +
			"a um palpite",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		semDono := caminhosSemDono(f)

		for i := range f.Vigias {
			v := &f.Vigias[i]
			var persistidos []string
			for _, a := range v.Alvos {
				if a.Persistencia {
					persistidos = append(persistidos, a.Caminho)
				}
			}
			if len(persistidos) == 0 {
				continue
			}
			// A outra metade: o observador precisa ser um binário que ninguém
			// empacotou. Sem isso, todo systemd do mundo entra aqui.
			if v.Exe == "" || !semDono[v.Exe] {
				continue
			}

			sev := check.SevCritical
			ev := []string{
				comoSeChama(v) + " observa " + strconv.Itoa(len(persistidos)) +
					" caminho(s) de persistência: " + strings.Join(corta(persistidos, 6), " · "),
				"nenhum pacote reivindica " + v.Exe,
				"quem observa um arquivo sabe no instante em que ele é apagado, e " +
					"pode recriá-lo antes de a próxima linha do roteiro rodar",
			}
			if v.Tipo == "fanotify" {
				ev = append(ev, "é fanotify, e não inotify: exige CAP_SYS_ADMIN, "+
					"e sabe vigiar montagem inteira")
			}
			if v.Bloqueia {
				ev = append(ev, "e o grupo tem classe de PERMISSÃO: ele não só "+
					"observa, ele DECIDE se a operação acontece — remover o arquivo "+
					"pode simplesmente falhar")
			}
			if v.MontagemInteira {
				ev = append(ev, "um dos watches cobre a MONTAGEM inteira: não é um "+
					"arquivo, é tudo que estiver montado ali")
			}
			if v.SemNome > 0 {
				ev = append(ev, strconv.Itoa(v.SemNome)+" outro(s) alvo(s) deste "+
					"mesmo descritor NÃO puderam ser nomeados: o fdinfo dá a "+
					"identidade do arquivo, não o caminho")
			}

			fd := self.F(sev, "pid="+strconv.Itoa(v.PID), "", ev...)
			fd.Ator = v.Exe
			fd.NextSteps = []string{
				"a ORDEM importa: remova a persistência e este " +
					"observador ANTES de apagar o que ele vigia, ou o arquivo volta",
				"sudo cp " + check.Arg(v.Exe) + " \"$IR/\"   # a amostra, antes de qualquer coisa",
				"`sudo ls -l /proc/" + strconv.Itoa(v.PID) + "/fd` e o fdinfo de cada " +
					"descritor mostram TODOS os alvos, inclusive os que não puderam ser nomeados",
			}
			r.Findings = append(r.Findings, fd)
		}

		r.Partial = append(r.Partial, f.PersistDenied["pkg"]...)
		return r
	},
}

func comoSeChama(v *facts.Vigia) string {
	if v.Comm != "" {
		return v.Comm + " (pid=" + strconv.Itoa(v.PID) + ")"
	}
	return "pid=" + strconv.Itoa(v.PID)
}
