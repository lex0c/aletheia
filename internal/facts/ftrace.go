package facts

import (
	"os"
	"strings"

	"github.com/lex0c/aletheia/internal/env"
)

// Hooks de ftrace (runbook §35.3).
//
// Os checks de visão cruzada dizem que o kernel PODE estar mentindo — comparam
// duas fontes e denunciam a divergência. Esta fonte diz outra coisa, e é a que
// falta: COMO ele estaria mentindo.
//
// O ftrace é a infraestrutura de tracing do próprio kernel, e um rootkit
// moderno a usa em vez de reescrever a tabela de syscalls: é estável entre
// versões, sobrevive a atualização e não dispara verificação de integridade de
// texto. O arquivo `enabled_functions` lista toda função interceptada agora,
// com o endereço de quem a intercepta.
//
// O formato:
//
//	nome_da_funcao (2) R  D  tramp: ftrace_regs_caller+0x0/0x65 (callback+0x0/0x20)
//		direct-->bpf_trampoline_6442516084+0x0/0xee
//
// A linha continuada — a que começa com tabulação — pertence à anterior.
//
// LIMITE de acesso: o arquivo exige privilégio, e o diretório pode estar em
// /sys/kernel/tracing ou no /sys/kernel/debug/tracing dos kernels antigos.

// HookFtrace é uma função do kernel interceptada agora.
type HookFtrace struct {
	Simbolo  string `json:"symbol"`
	Contagem int    `json:"count"`

	// Callback é quem atende a interceptação, cru, como o kernel escreveu. É a
	// evidência que separa um programa eBPF de um módulo carregado.
	Callback string `json:"callback,omitempty"`
	// Modulo é o dono do callback, quando o kernel o nomeia entre colchetes.
	Modulo string `json:"module,omitempty"`
}

func collectFtrace(f *Facts, e *env.Env) {
	// AUSENTE e ILEGÍVEL não são a mesma coisa, e a diferença decide se isto
	// vira lacuna de cobertura.
	//
	//	existe e não abre    o host TEM a interface e falta privilégio. É
	//	                     lacuna, e a ação é rodar como root
	//	não existe           não há interface de tracing NESTE namespace. Um
	//	                     contêiner não tem kernel próprio, e o runtime
	//	                     mascara /sys/kernel de propósito — não há o que
	//	                     examinar aqui, do mesmo jeito que não há unit para
	//	                     examinar num host sem systemd
	//
	// Tratar as duas igual deixaria TODA varredura em contêiner permanentemente
	// degradada — e com isso morreria a única forma que a suíte tem de afirmar
	// "contêiner limpo sai OK", que é como ela pega falso positivo.
	//
	// O risco que sobra — kernel do host interceptado, varredura de dentro do
	// contêiner cega — é o mesmo que os checks de visão cruzada já declaram:
	// se o kernel mente, todas as fontes que dependem dele mentem juntas.
	var negado bool
	for _, p := range []string{
		"/sys/kernel/tracing/enabled_functions",
		"/sys/kernel/debug/tracing/enabled_functions",
	} {
		b, err := e.ReadFile(p)
		if err == nil {
			lerFtrace(f, string(b))
			return
		}
		if !os.IsNotExist(err) {
			negado = true
		}
	}
	if negado {
		f.denyPersist("ftrace", "enabled_functions existe e não pôde ser lido "+
			"(exige privilégio): as funções do kernel interceptadas AGORA não "+
			"foram examinadas — rode como root para respondê-lo")
	}
}

func lerFtrace(f *Facts, texto string) {
	for _, ln := range strings.Split(texto, "\n") {
		// Linha continuada pertence à anterior: `direct-->` detalha o destino
		// do hook que veio acima, e tratá-la como registro próprio inventaria
		// um símbolo chamado "direct-->alguma_coisa".
		if ln == "" || ln[0] == '\t' || ln[0] == ' ' {
			continue
		}
		campos := strings.Fields(ln)
		if len(campos) < 2 {
			continue
		}
		h := HookFtrace{Simbolo: campos[0], Contagem: 1}
		if c := strings.Trim(campos[1], "()"); c != campos[1] {
			if n := atoiSeguro(c); n > 0 {
				h.Contagem = n
			}
		}
		// O callback vem entre parênteses no fim, e o módulo dono entre
		// colchetes quando existe.
		if i := strings.LastIndex(ln, "("); i > 0 {
			h.Callback = strings.Trim(ln[i:], "()")
		}
		if i := strings.Index(ln, "["); i > 0 {
			if j := strings.Index(ln[i:], "]"); j > 0 {
				h.Modulo = ln[i+1 : i+j]
			}
		}
		f.Ftrace = append(f.Ftrace, h)
	}
}

func atoiSeguro(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0
		}
		n = n*10 + int(s[i]-'0')
	}
	return n
}
