package checks

import (
	"sort"
	"strconv"
	"strings"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

func init() { check.Register(hookDeEnumeracao) }

// hookDeEnumeracao — runbook §35.3.
//
// Os checks de visão cruzada dizem que o kernel PODE estar mentindo: comparam
// duas fontes e denunciam a divergência. Este diz COMO — e é a peça que
// faltava, porque saber que há ocultação sem saber de quê não orienta resposta
// nenhuma.
//
// O ftrace é a infraestrutura de tracing do próprio kernel, e o rootkit moderno
// a usa em vez de reescrever a tabela de syscalls: é estável entre versões,
// sobrevive a atualização e não dispara verificação de integridade de texto.
//
// O que este check NÃO faz é listar todo hook. Um host com bpftrace, perf ou
// patch ao vivo tem dezenas, todos legítimos, e reportá-los seria descrever a
// ferramenta de observação do próprio time.
//
// O que ele olha é o ALVO. Interceptar uma função de ENUMERAÇÃO tem um
// propósito só, e ele não é observar:
//
//	getdents      esconder arquivo de quem lista diretório
//	tcp4_seq_show esconder conexão de quem lê /proc/net/tcp
//	kill          receber comando por sinal, sem abrir porta nenhuma
var hookDeEnumeracao = check.Check{
	ID:       "kernel.ftrace_hook",
	Ref:      "35.3",
	Title:    "função de enumeração do kernel interceptada: algo está sendo escondido",
	Group:    "kernel",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive,
	Requires: env.CapProcfs,
	Optional: env.CapRoot,
	Wtf:      true,
	FalsePositives: []string{
		"FERRAMENTA DE OBSERVAÇÃO usa exatamente isto: bpftrace, perf, SystemTap e " +
			"agente de segurança comercial interceptam as mesmas funções, e um " +
			"host onde o time está diagnosticando produz este achado com razão. " +
			"O callback diz qual é o caso — trampolim de eBPF é programa " +
			"carregado por ferramenta, módulo nomeado é outra coisa",
		"patch ao vivo (kpatch, kgraft, livepatch) intercepta função de kernel por " +
			"desenho, e é assim que correção de segurança entra sem reiniciar",
		"LIMITE que vale mais que o check: se o kernel já estiver comprometido, " +
			"este arquivo é produzido por ele. Ausência de hook não prova nada; " +
			"presença prova muito",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result

		// Agrupado por PROPÓSITO: cinco hooks para esconder arquivo são um
		// fato, não cinco.
		porMotivo := map[string][]facts.HookFtrace{}
		for i := range f.Ftrace {
			h := &f.Ftrace[i]
			if motivo, ok := funcaoDeEnumeracao(h.Simbolo); ok {
				porMotivo[motivo] = append(porMotivo[motivo], *h)
			}
		}

		motivos := make([]string, 0, len(porMotivo))
		for m := range porMotivo {
			motivos = append(motivos, m)
		}
		sort.Strings(motivos)

		for _, motivo := range motivos {
			hs := porMotivo[motivo]
			var simbolos, donos []string
			vistoDono := map[string]bool{}
			porBPF := true
			var multiplos bool
			for _, h := range hs {
				rot := h.Simbolo
				if h.Contagem > 1 {
					// Mais de um interceptador na MESMA função: ou há duas
					// ferramentas observando, ou alguém se pendurou depois.
					rot += "(" + strconv.Itoa(h.Contagem) + "×)"
					multiplos = true
				}
				simbolos = append(simbolos, rot)
				dono := h.Modulo
				if dono == "" {
					dono = h.Callback
				}
				if dono != "" && !vistoDono[dono] {
					vistoDono[dono] = true
					donos = append(donos, dono)
				}
				if !pareceEBPF(h.Callback) || h.Modulo != "" {
					porBPF = false
				}
			}
			if len(simbolos) > 8 {
				simbolos = append(simbolos[:8:8], "…")
			}

			ev := []string{
				strconv.Itoa(len(hs)) + " função(ões) interceptada(s): " +
					strings.Join(simbolos, " "),
				motivo,
				"quem intercepta: " + strings.Join(donos, " · "),
			}

			// O CALLBACK é o discriminador. Trampolim de eBPF é programa
			// carregado por ferramenta de observação — bpftrace, agente
			// comercial —, e é a forma legítima mais comum. Módulo nomeado
			// interceptando enumeração é outra conversa.
			sev := check.SevCritical
			if porBPF {
				sev = check.SevWarn
				ev = append(ev, "o callback é um trampolim de eBPF: é a forma de "+
					"ferramenta de observação (bpftrace, perf, agente), e também a "+
					"de um implante em eBPF — o que separa é alguém do time "+
					"reconhecer o programa")
			} else {
				ev = append(ev, "o callback NÃO é trampolim de eBPF: interceptação de "+
					"enumeração vinda de módulo é a forma do rootkit")
			}

			if multiplos {
				ev = append(ev, "e há função com MAIS DE UM interceptador: ou são "+
					"duas ferramentas observando, ou alguém se pendurou depois da "+
					"primeira")
			}

			fd := self.F(sev, motivo, "", ev...)
			fd.Irreversible = true
			fd.NextSteps = []string{
				"`cat /sys/kernel/tracing/enabled_functions` guardado agora é a prova: " +
					"ela some no reboot",
				"pergunte ao time se alguém está diagnosticando este host com " +
					"bpftrace, perf ou agente que use eBPF",
				"a partir daqui, NADA que dependa da função interceptada vale como " +
					"prova vindo deste host: analise a imagem DE FORA (runbook §35.6)",
			}
			r.Findings = append(r.Findings, fd)
		}
		r.Partial = append(r.Partial, f.PersistDenied["ftrace"]...)
		return r
	},
}

// funcoesDeEnumeracao são as que servem para ESCONDER, com o motivo junto. A
// lista é de PROPÓSITO, não de nome: o sufixo de arquitetura (`__x64_sys_`,
// `__arm64_sys_`) é removido antes da comparação.
var funcoesDeEnumeracao = map[string]string{
	"getdents":    "listagem de diretório: interceptar isto esconde ARQUIVO de quem lista",
	"getdents64":  "listagem de diretório: interceptar isto esconde ARQUIVO de quem lista",
	"filldir":     "listagem de diretório: interceptar isto esconde ARQUIVO de quem lista",
	"filldir64":   "listagem de diretório: interceptar isto esconde ARQUIVO de quem lista",
	"iterate_dir": "listagem de diretório: interceptar isto esconde ARQUIVO de quem lista",

	"tcp4_seq_show": "tabela de conexões: interceptar isto esconde CONEXÃO de quem lê /proc/net",
	"tcp6_seq_show": "tabela de conexões: interceptar isto esconde CONEXÃO de quem lê /proc/net",
	"udp4_seq_show": "tabela de conexões: interceptar isto esconde CONEXÃO de quem lê /proc/net",
	"udp6_seq_show": "tabela de conexões: interceptar isto esconde CONEXÃO de quem lê /proc/net",
	"packet_rcv":    "captura de pacote: interceptar isto esconde TRÁFEGO de quem escuta",
	"tpacket_rcv":   "captura de pacote: interceptar isto esconde TRÁFEGO de quem escuta",

	"kill":                "envio de sinal: é o canal de comando de rootkit que não abre porta (runbook §35.3)",
	"kill_something_info": "envio de sinal: é o canal de comando de rootkit que não abre porta",

	"proc_readdir":   "listagem de /proc: interceptar isto esconde PROCESSO",
	"pid_revalidate": "resolução de PID: interceptar isto esconde PROCESSO",

	"module_free": "gestão de módulo: interceptar isto esconde o próprio MÓDULO carregado",
	"find_module": "gestão de módulo: interceptar isto esconde o próprio MÓDULO carregado",

	"audit_log_start": "registro de auditoria: interceptar isto apaga RASTRO na origem",
	"do_syslog":       "registro do kernel: interceptar isto apaga RASTRO na origem",
}

// funcaoDeEnumeracao resolve o símbolo, tirando os prefixos que o kernel
// acrescenta por arquitetura. Sem isso, `__x64_sys_getdents64` — que é como o
// símbolo aparece de verdade — não casaria com nada.
func funcaoDeEnumeracao(sim string) (string, bool) {
	s := sim
	for _, p := range []string{
		"__x64_sys_", "__arm64_sys_", "__ia32_sys_", "__se_sys_", "__do_sys_", "sys_",
	} {
		if t, ok := strings.CutPrefix(s, p); ok {
			s = t
			break
		}
	}
	m, ok := funcoesDeEnumeracao[s]
	return m, ok
}

// pareceEBPF reconhece o trampolim que o kernel cria para um programa eBPF. É a
// forma da ferramenta de observação, e a do implante em eBPF também — mas a
// primeira é comum e a segunda é rara, e por isso ela pesa menos.
func pareceEBPF(callback string) bool {
	return strings.Contains(callback, "bpf_trampoline") ||
		strings.Contains(callback, "bpf_dispatcher") ||
		strings.Contains(callback, "call_direct_funcs")
}
