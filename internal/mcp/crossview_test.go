package mcp

import (
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/facts"
)

// A catraca central desta tool: SILÊNCIO DA SEGUNDA TESTEMUNHA NUNCA VIRA
// "CONCORDAM".
//
// É o defeito que a tool inteira existe para não cometer. "Nenhum socket
// oculto" com o netlink indisponível é a MESMA frase de "nenhum socket oculto"
// com as duas visões batendo, e as duas conclusões são opostas: a primeira não
// afirma nada, a segunda afirma bastante. Um estado binário — divergiu / não
// divergiu — apaga essa diferença, e quem lê a resposta não tem como recuperá-la.
//
// Cada caso abaixo é um jeito de a segunda testemunha faltar. Todos precisam
// chegar em not_compared, nenhum em agree.
func TestTestemunhaAusenteNaoViraConcordancia(t *testing.T) {
	casos := []struct {
		nome  string
		cross facts.CrossView
		eixo  func(*facts.CrossView) map[string]any
	}{
		{"netlink não respondeu",
			facts.CrossView{SocketProc: 12, SocketDiagLido: false}, eixoDeSockets},
		{"netlink respondeu CORTADO",
			facts.CrossView{SocketProc: 12, SocketDiag: 12,
				SocketDiagLido: true, SocketDiagCortado: true}, eixoDeSockets},
		{"nenhuma sondagem de pid rodou",
			facts.CrossView{}, porCrossView(eixoDeProcessos)},
		{"nenhuma interface de módulo foi lida",
			facts.CrossView{}, eixoDeModulos},
		{"ftrace ilegível, com /proc/modules cheio",
			facts.CrossView{ModProc: []string{"a", "b"}}, eixoDeFtrace},
	}
	for _, c := range casos {
		got := c.eixo(&c.cross)["state"]
		if got != "not_compared" {
			t.Errorf("%s: state=%v, queria not_compared.\n"+
				"Sem segunda testemunha não houve comparação, e responder %q "+
				"transforma 'ninguém olhou' em 'está limpo' — que é exatamente a "+
				"confusão que esta tool desfaz.", c.nome, got, got)
		}
	}
}

// O par /proc×/sys concordar NÃO pode arrastar o ftrace junto.
//
// Este é o caso REAL da máquina onde isto foi escrito: /proc/modules e
// /sys/module lidos e batendo, available_filter_functions ilegível porque exige
// root. Enquanto as duas comparações dividiam um estado só, a resposta era
// "modules: agree" — e carregava, de graça, a afirmação de que nada se
// escondeu do ftrace. Essa afirmação nunca foi feita, e é justamente a que pega
// o LKM que se desencadeia da lista.
func TestFtraceIlegivelNaoHerdaAConcordanciaDosOutros(t *testing.T) {
	c := facts.CrossView{
		ModProc: []string{"nf_tables", "overlay"},
		ModSys:  []string{"nf_tables", "overlay", "ext4"},
	}
	if s := eixoDeModulos(&c)["state"]; s != "agree" {
		t.Fatalf("o par /proc×/sys foi lido e bate; state=%v", s)
	}
	if s := eixoDeFtrace(&c)["state"]; s != "not_compared" {
		t.Errorf("ftrace não lido devolveu %v: a concordância de OUTRA "+
			"comparação virou afirmação sobre esta", s)
	}
}

// Contagens diferentes sob "agree" precisam de explicação NA RESPOSTA.
//
// /sys/module lista também o que foi compilado dentro do kernel: 248 contra 353
// no host de desenvolvimento. Publicar os dois números e dizer "concordam" sem
// mais nada é uma contradição na cara de quem lê — e o leitor sensato conclui
// que a ferramenta está errada, não que a comparação é unidirecional.
func TestDivergenciaLegitimaDeContagemEhExplicada(t *testing.T) {
	c := facts.CrossView{ModProc: []string{"a"}, ModSys: []string{"a", "b", "c"}}
	e := eixoDeModulos(&c)
	nota, _ := e["note"].(string)
	if !strings.Contains(nota, "DENTRO do kernel") {
		t.Errorf("as contagens divergem por construção e a resposta não diz "+
			"por quê. note=%q", nota)
	}
	if !strings.Contains(nota, "não foi verificado") {
		t.Errorf("a comparação corre num sentido só e a resposta não declara "+
			"o sentido que ficou de fora. note=%q", nota)
	}
}

// Divergência é divergência mesmo quando a segunda testemunha falhou depois.
//
// Um socket oculto já encontrado não vira "não comparado" porque a leitura foi
// cortada em seguida: o ACHADO sobrevive à lacuna. Só a AUSÊNCIA é que não.
func TestAchadoSobreviveALacuna(t *testing.T) {
	c := facts.CrossView{
		SocketProc: 3, SocketDiag: 4, SocketDiagLido: true,
		SocketDiagCortado: true,
		SocketOcultos:     []facts.SocketOculto{{}},
	}
	e := eixoDeSockets(&c)
	if e["state"] != "disagree" {
		t.Errorf("socket oculto encontrado e state=%v: a truncagem apagou um "+
			"achado que já existia", e["state"])
	}
	if len(e["divergences"].([]map[string]any)) != 1 {
		t.Error("a divergência não foi devolvida")
	}
}

// O alcance faz parte da afirmação.
//
// "Nenhum processo oculto até 4.194.304" e "até 65.536" são frases diferentes,
// e a segunda quase não é frase. Quando a sondagem parou antes do pid_max do
// host, a resposta tem de DIZER onde parou — senão o leitor completa sozinho, e
// completa para o lado errado.
func TestAlcanceParcialApareceNaFrase(t *testing.T) {
	f := &facts.Facts{Cross: facts.CrossView{
		ProbeAte: 65536, ProbeProcfsAte: 65536, PidMax: 4194304}}
	m, _ := eixoDeProcessos(f)["meaning"].(string)
	if !strings.Contains(m, "65536") || !strings.Contains(m, "4194304") {
		t.Errorf("a sondagem parou em 65536 num host com pid_max 4194304 e a "+
			"resposta não diz isso: %q", m)
	}
}

// declared_gaps e observability.collector_gaps precisam ser A MESMA COISA.
//
// A tool publica, dentro de `data`, o recorte das lacunas do coletor `cross` —
// porque quem lê "not_compared" quer o motivo DESTE eixo, e collector_gaps
// mistura bpf, logs, net e o resto da execução. Um recorte é barato e honesto;
// uma segunda contagem seria o defeito que este projeto já pagou uma vez, com
// dois agrupamentos de achado que divergiam calados.
//
// A diferença entre as duas coisas não está na intenção de quem escreve, e sim
// em haver ou não um teste que force a identidade. Este é o teste.
func TestLacunaDeclaradaEhAMesmaDoEnvelope(t *testing.T) {
	f := &facts.Facts{Partial: map[string][]string{
		"cross": {"available_filter_functions ilegível", "pid_max não pôde ser lido"},
		"bpf":   {"sem CAP_BPF"},
	}}
	o := ObservabilidadeDeFatos(f)

	noEnvelope := map[string]bool{}
	for _, g := range o.LacunasDeColeta {
		noEnvelope[g] = true
	}
	for _, g := range f.Partial["cross"] {
		if !noEnvelope["cross: "+g] {
			t.Errorf("declared_gaps publica %q e o envelope não tem "+
				"\"cross: %s\" em collector_gaps.\nAs duas listas saem do mesmo "+
				"facts.Partial; divergirem significa que uma delas passou a ser "+
				"recalculada, e recalcular é como duas contabilidades nascem.", g, g)
		}
	}
	if len(o.LacunasDeColeta) < 3 {
		t.Errorf("o envelope publicou %d lacuna(s) e o Facts tinha 3: o recorte "+
			"virou filtro no lugar errado", len(o.LacunasDeColeta))
	}
}

// porCrossView adapta um eixo que precisa do Facts inteiro para a tabela, que
// escreve só o CrossView. O eixo de processos precisa da LISTAGEM, que mora
// fora do CrossView — e a tabela continua legível.
func porCrossView(fn func(*facts.Facts) map[string]any) func(*facts.CrossView) map[string]any {
	return func(c *facts.CrossView) map[string]any {
		return fn(&facts.Facts{Cross: *c})
	}
}
