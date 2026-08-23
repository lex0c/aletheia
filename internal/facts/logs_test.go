package facts

import "testing"

// `dateext` é o padrão de fábrica da família RHEL, e o parser só entendia
// contador.
//
// O /etc/logrotate.conf do RHEL, Rocky, Alma, CentOS e Fedora traz `dateext`, e
// com ele o rotacionado é `wtmp-20260801`. O LastIndex(".") não achava nada,
// então aquele arquivo virava BASE PRÓPRIA com geração 0 — e a guarda do
// antiforense.wtmp_cleared, que procura um wtmp rotacionado ao lado antes de
// acusar, nunca casava.
//
// O resultado era um CRITICAL irreversível dizendo que o operador limpou o
// histórico de login, em qualquer jump host RHEL com wtmp > 1 MB (a rotação
// mensal dispara) e uma sessão longa atravessando a rotação — tmux, screen,
// conta de serviço. O wtmp é 0664 root:utmp no RHEL, então reproduz sem root.
func TestSufixoDeDataDoLogrotateEhRotacaoENaoBaseNova(t *testing.T) {
	casos := []struct {
		nome        string
		querBase    string
		querGeracao int
		querDatada  bool
	}{
		{"wtmp-20260801", "wtmp", 1, true},
		{"secure-20260815.gz", "secure", 1, true},
		// A forma Debian continua valendo, e continua NÃO sendo datada.
		{"auth.log.1", "auth.log", 1, false},
		{"auth.log.3.gz", "auth.log", 3, false},
		{"auth.log", "auth.log", 0, false},
		// Estreito de propósito: número atrás de traço não é data.
		{"app-20250", "app-20250", 0, false},
		{"backup-99999999", "backup-99999999", 0, false},
		{"relatorio-20261301", "relatorio-20261301", 0, false}, // mês 13
		{"conf-abcdefgh", "conf-abcdefgh", 0, false},
	}
	for _, c := range casos {
		base, ger, datada := separaRotacao(c.nome)
		if base != c.querBase || ger != c.querGeracao || datada != c.querDatada {
			t.Errorf("separaRotacao(%q) = (%q, %d, %v), queria (%q, %d, %v)",
				c.nome, base, ger, datada, c.querBase, c.querGeracao, c.querDatada)
		}
	}
}

// A série datada fica FORA do cálculo de buraco, e a ausência dela é DECLARADA.
//
// Buraco de rotação pergunta "falta a geração N no meio?", e data não tem
// sucessor definido: entre secure-20260801 e secure-20260815 pode faltar uma
// semana apagada, ou o logrotate pode simplesmente não ter rodado (é o que
// `minsize` faz, e é o padrão do wtmp no RHEL). Derivar buraco de aritmética de
// datas trocaria o falso limpo por um falso positivo.
//
// O que não pode continuar é o silêncio: sem declarar, a família RHEL inteira
// saía com cobertura completa sobre um método que não roda ali.
func TestSerieDatadaNaoViraBuracoEEhDeclarada(t *testing.T) {
	f := &Facts{Logs: []ArquivoDeLog{
		{Path: "/var/log/secure", Base: "/var/log/secure", Geracao: 0},
		{Path: "/var/log/secure-20260801", Base: "/var/log/secure", Geracao: 1, Datada: true},
		{Path: "/var/log/secure-20260815", Base: "/var/log/secure", Geracao: 1, Datada: true},
	}}
	if b := f.BuracosNaRotacao(); len(b) > 0 {
		t.Errorf("série datada produziu buraco inventado: %v", b)
	}
	d := f.SeriesDatadas()
	if len(d) != 1 || d[0] != "/var/log/secure" {
		t.Errorf("SeriesDatadas() = %v, queria a base declarada para virar lacuna", d)
	}

	// A forma com contador continua sendo avaliada: o conserto não pode cegar
	// o método onde ele funciona.
	g := &Facts{Logs: []ArquivoDeLog{
		{Path: "/var/log/auth.log", Base: "/var/log/auth.log", Geracao: 0},
		{Path: "/var/log/auth.log.1", Base: "/var/log/auth.log", Geracao: 1},
		{Path: "/var/log/auth.log.3.gz", Base: "/var/log/auth.log", Geracao: 3},
	}}
	b := g.BuracosNaRotacao()
	if len(b["/var/log/auth.log"]) != 1 || b["/var/log/auth.log"][0] != 2 {
		t.Errorf("buraco no contador deixou de ser visto: %v", b)
	}
	if len(g.SeriesDatadas()) != 0 {
		t.Errorf("série com contador marcada como datada: %v", g.SeriesDatadas())
	}
}
