package report

import "github.com/lex0c/aletheia/internal/check"

// Tema é o realce PROGRESSIVO: o significado vive no texto ASCII (a etiqueta de
// severidade, o id local), e a cor é só reforço. Num terminal sem cor, sem
// Unicode ou antigo, o relatório continua legível — nada essencial depende de
// escape ANSI.
//
// A cor NUNCA sai por padrão: o teste de injeção exige zero ESC no buffer, e a
// coleta só liga cor quando a saída é um TTY de verdade (ver o CLI). Assim
// evidência controlada pelo alvo não pode carregar realce, e ticket em texto
// puro não vem sujo de escape.
type Tema struct {
	cor bool
}

func temaPara(cor bool) Tema { return Tema{cor: cor} }

// etiqueta é a marca ASCII de severidade — o sinal primário, que funciona em
// qualquer terminal. Largura fixa de 4 para alinhar as colunas.
func (t Tema) etiqueta(s check.Severity) string {
	switch s {
	case check.SevCritical:
		return "CRIT"
	case check.SevWarn:
		return "WARN"
	case check.SevManual:
		return "MANL"
	case check.SevInfo:
		return "INFO"
	default:
		return "????"
	}
}

// pinta a etiqueta de severidade: crítico vermelho-negrito, aviso amarelo,
// manual/info esmaecidos. Sem cor, devolve o texto cru.
func (t Tema) pintaSev(s check.Severity, txt string) string {
	if !t.cor {
		return txt
	}
	switch s {
	case check.SevCritical:
		return "\x1b[1;31m" + txt + "\x1b[0m" // negrito vermelho
	case check.SevWarn:
		return "\x1b[33m" + txt + "\x1b[0m" // amarelo
	default:
		return "\x1b[2m" + txt + "\x1b[0m" // esmaecido
	}
}

func (t Tema) verde(s string) string {
	if !t.cor {
		return s
	}
	return "\x1b[1;32m" + s + "\x1b[0m"
}

func (t Tema) negrito(s string) string {
	if !t.cor {
		return s
	}
	return "\x1b[1m" + s + "\x1b[0m"
}

func (t Tema) fraco(s string) string {
	if !t.cor {
		return s
	}
	return "\x1b[2m" + s + "\x1b[0m"
}

// regua é a linha separadora — ASCII puro, para não virar lixo em console antigo.
func (t Tema) regua() string {
	return "------------------------------------------------------------"
}
