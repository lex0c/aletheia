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

// lerFtrace decodifica enabled_functions no formato que t_show escreve
// (kernel/trace/ftrace.c). A linha é
//
//	<simbolo>[ [mod]] (<n>)<flags>[\ttramp: <tramp> (<func>)][\tops: <ops> (<func>)]
//
// com uma continuação opcional "\n\tdirect-->%pS" logo abaixo. Quase todo campo
// é condicional, e é aí que o parser posicional errava: sem FTRACE_FL_TRAMP_EN
// o kernel não escreve `tramp:` nenhum — escreve " ->%pS", sem parênteses.
func lerFtrace(f *Facts, texto string) {
	for _, ln := range strings.Split(texto, "\n") {
		if ln == "" {
			continue
		}
		// Linha continuada pertence à anterior. Tratá-la como registro próprio
		// inventava um símbolo "direct-->alguma_coisa"; descartá-la calada
		// perdia a ÚNICA menção a bpf_trampoline_* num hook DIRECT — que é
		// exatamente o que pareceEBPF procura para não acusar um fentry de eBPF
		// de ser rootkit.
		if ln[0] == '\t' || ln[0] == ' ' {
			if n := len(f.Ftrace); n > 0 {
				if _, alvo, ok := strings.Cut(ln, "-->"); ok {
					h := &f.Ftrace[n-1]
					alvo = strings.TrimSpace(alvo)
					h.Callback = alvo
					h.Modulo = moduloDeSimbolo(alvo)
				}
			}
			continue
		}
		campos := strings.Fields(ln)
		if len(campos) < 2 {
			continue
		}
		h := HookFtrace{Simbolo: campos[0], Contagem: 1}

		// %pS acrescenta " [mod]" quando o símbolo pertence a um módulo
		// (kallsyms.c). Aqui esse módulo é o dono da função INTERCEPTADA, não
		// do interceptador — e ele DESLOCA os campos, empurrando a contagem
		// para campos[2]. Ler campos[1] cegamente perdia a contagem e gravava
		// o módulo errado em h.Modulo, atribuindo o rootkit a um módulo
		// inocente sempre que a função interceptada morava num (packet_rcv em
		// af_packet, por exemplo).
		resto := campos[1:]
		if len(resto) > 0 && strings.HasPrefix(resto[0], "[") {
			resto = resto[1:]
		}
		if len(resto) > 0 {
			if c := strings.Trim(resto[0], "()"); c != resto[0] {
				if n := atoiSeguro(c); n > 0 {
					h.Contagem = n
				}
			}
		}

		if cb, ok := callbackDeFtrace(ln); ok {
			h.Callback = cb
			h.Modulo = moduloDeSimbolo(cb)
		} else if _, alvo, ok := strings.Cut(ln, " ->"); ok {
			// add_trampoline_func sem ops: o trampolim genérico da arquitetura.
			// Não nomeia um handler específico, mas é melhor que a contagem.
			alvo = strings.TrimSpace(alvo)
			h.Callback = alvo
			h.Modulo = moduloDeSimbolo(alvo)
		}
		f.Ftrace = append(f.Ftrace, h)
	}
}

// callbackDeFtrace extrai quem ATENDE a interceptação. O kernel escreve o
// handler como o SEGUNDO %pS de "tramp: <trampolim> (<func>)" ou de
// "ops: <ops> (<func>)" — o primeiro é o endereço do trampolim, que não
// identifica ninguém. As duas formas são condicionais (TRAMP_EN e CALL_OPS_EN),
// e quando nenhuma sai, um LastIndex("(") acabava capturando o "(2)" da
// contagem: o callback virava "2) R  I  D …", pareceEBPF falhava, e o check
// subia de WARN para CRITICAL com a contagem no lugar de quem intercepta.
func callbackDeFtrace(ln string) (string, bool) {
	for _, marca := range []string{"tramp: ", "ops: "} {
		i := strings.Index(ln, marca)
		if i < 0 {
			continue
		}
		j := strings.Index(ln[i:], "(")
		if j < 0 {
			continue // "tramp: ERROR!" e afins: não há handler nomeado
		}
		k := strings.Index(ln[i+j:], ")")
		if k < 2 {
			continue
		}
		return ln[i+j+1 : i+j+k], true
	}
	return "", false
}

// moduloDeSimbolo devolve o módulo que %pS anexa entre colchetes ao símbolo.
func moduloDeSimbolo(s string) string {
	i := strings.Index(s, "[")
	if i < 0 {
		return ""
	}
	j := strings.Index(s[i:], "]")
	if j < 2 {
		return ""
	}
	return s[i+1 : i+j]
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
