// Package activity responde uma pergunta que os checks não respondem: o que
// aconteceu neste host recentemente?
//
// O `scan` pergunta "existe implante AGORA?" e o `drift` pergunta "o que mudou
// entre dois retratos?". Nenhum dos dois monta o quadro do uso: quantas
// entradas, de quantas origens, quantas recusas, quem está logado agora. É
// nesse quadro que vive o abuso de credencial e o living-off-the-land, onde não
// há arquivo para achar — só uma sequência operacional feita com ssh, sudo e
// contas válidas.
//
// # A regra que governa tudo aqui
//
//	ATIVIDADE conta e declara COBERTURA. Ela nunca conclui.
//
// Quem conclui é check: ele tem §ref, falsos positivos, cenário e severidade.
// Uma segunda derivação do mesmo evento, com outro limiar, produziria duas
// verdades sobre um fato só — é a mesma recusa que AgregadoDeLog documenta.
// `auth.bruteforce_success` já cruza falha e sucesso, e já aparece no `wtf`;
// este pacote dá o DENOMINADOR que torna aquele achado legível.
//
// # Derivação, e não fato
//
// Nada daqui é serializado em Facts, pela razão que AgregadoDeLog já escreveu:
// agregado guardado ao lado dos eventos vira uma segunda fonte de verdade que
// precisa ficar eternamente consistente com a primeira.
package activity

import (
	"sort"
	"time"

	"github.com/lex0c/aletheia/internal/facts"
)

// carimbo é o formato de Login.QuandoU. Ele é de largura fixa e em UTC, então a
// comparação lexicográfica de duas strings é a comparação cronológica dos dois
// instantes — é o mesmo atalho que AgregarLog usa.
const carimbo = "2006-01-02T15:04:05Z"

// Fonte é uma testemunha da atividade, com o ALCANCE dela.
//
// É o coração do pacote, e não um detalhe de rodapé. A leitura de login é da
// CAUDA, com teto por arquivo: num host que recebe 400 tentativas de SSH por
// hora, o btmp alcança uma tarde e não uma semana. Imprimir "24h · 183 falhas"
// ali seria afirmar sobre 24 horas um número medido em cinco — a mentira exata
// que esta ferramenta existe para não cometer.
//
// Por FONTE, e nunca um número global: wtmp (pouco volume, legível por todos) e
// btmp (root, muito volume) têm horizontes que diferem em ordens de grandeza, e
// um número só mentiria para um dos dois lados. É o mesmo desenho de
// CoberturaLog(família).
type Fonte struct {
	Papel  string `json:"role"`
	Path   string `json:"path"`
	Estado string `json:"state"`

	// Desde e Ate são o intervalo DATADO que esta fonte entregou — o registro
	// mais antigo e o mais recente que entraram, não o começo do arquivo.
	Desde string `json:"since,omitempty"`
	Ate   string `json:"until,omitempty"`

	Lidos    int  `json:"records_read,omitempty"`
	Total    int  `json:"records_total,omitempty"`
	SemData  int  `json:"records_undated,omitempty"`
	Truncada bool `json:"truncated,omitempty"`

	// TamRegistro é o layout escolhido para decodificar (384 ou 400). Viaja
	// até aqui porque é a decisão que, errada, produz inventário de login lido
	// do byte errado SEM lacuna nenhuma — e é depois do incidente, com a VM já
	// destruída, que alguém precisa poder conferir qual foi.
	TamRegistro int `json:"record_size,omitempty"`

	// RelogioAlterado marca que há registro de MUDANÇA DE RELÓGIO entre os que
	// esta fonte entregou.
	//
	// Ele destrói a comparabilidade das datas dos dois lados do salto — e é o
	// próprio utmp que registra o par OLD_TIME/NEW_TIME, então a informação
	// está ali. Sem consultá-la, o alcance era calculado como min(timestamp), e
	// um relógio que voltou três dias fazia um arquivo de poucas horas afirmar
	// `wtmp ≥24h`. Não precisa de atacante: `date -s`, salto de NTP, restore de
	// snapshot de VM e relógio de hardware quebrado produzem a mesma forma.
	RelogioAlterado bool `json:"clock_changed,omitempty"`

	// GeracoesNaoLidas conta os arquivos ROTACIONADOS desta série que existem
	// ao lado e que a coleta de login não abre.
	//
	// Sem ele, a cobertura confundia "meu teto de 2000 registros não mordeu"
	// com "o histórico inteiro está aqui" — e o logrotate roda no wtmp e no
	// btmp por padrão em toda distribuição. No dia 2 do mês, um wtmp de duas
	// horas com wtmp.1 fechado ao lado saía como `≥24h`: o falso "limpo" que
	// esta feature existe para não cometer, produzido pelo campo que existe
	// para impedi-lo.
	GeracoesNaoLidas int `json:"unread_generations,omitempty"`

	// NaoInterpretados conta os registros que a coleta leu e que este pacote
	// não traduz em evento — tipos de utmp que não são login, saída, boot nem
	// mudança de runlevel. Eles não somem em silêncio: a cobertura os declara.
	NaoInterpretados int `json:"records_unmapped,omitempty"`

	// CobreJanela responde diretamente "os números abaixo valem para a janela
	// que eu pedi?". Sem ele, quem lê tem de comparar duas datas de cabeça.
	CobreJanela bool `json:"covers_window"`

	Motivo string `json:"reason,omitempty"`
}

// Existe diz que o arquivo existe neste host. Ausente é ESCOPO — um contêiner
// sem btmp não tem tentativas recusadas a esconder —, e escopo não é lacuna.
func (s Fonte) Existe() bool { return s.Estado != facts.FonteLoginAusente }

// Lida diz que o arquivo foi aberto E decodificado. Só com ela um número de
// contagem significa alguma coisa.
func (s Fonte) Lida() bool { return s.Estado == facts.FonteLoginLida }

// Sessao é alguém logado NESTE INSTANTE.
type Sessao struct {
	User   string `json:"user"`
	Origem string `json:"remote_ip,omitempty"`
	Linha  string `json:"line,omitempty"`
	Desde  string `json:"since,omitempty"`
}

// Contagem é um par chave/quantidade para os topos.
type Contagem struct {
	Chave string `json:"key"`
	N     int    `json:"count"`
}

// Resumo é o quadro do uso recente. Nenhum campo dele é severidade.
type Resumo struct {
	// JanelaSolicitada é o que foi PEDIDO. A janela observada está em Fontes, e
	// as duas são campos diferentes porque quase nunca são o mesmo intervalo.
	JanelaSolicitada string  `json:"window_requested"`
	Desde            string  `json:"window_since"`
	Fontes           []Fonte `json:"sources"`

	Aceitos   int `json:"accepted"`
	Recusados int `json:"refused"`
	Usuarios  int `json:"users"`
	Origens   int `json:"origins"`

	// OrigensNaoObservadasAntes conta as origens da janela que não aparecem no
	// histórico retido ANTES dela.
	//
	// Nunca "novas": "nova" afirma que o host nunca as viu, e o que se sabe é
	// só que elas não estão nos registros que sobraram. O bit ao lado diz se a
	// pergunta sequer pôde ser feita — quando a retenção começa DENTRO da
	// janela não há "antes" para comparar, e responder 0 ali seria inventar uma
	// negativa.
	OrigensNaoObservadasAntes     int  `json:"origins_not_seen_before"`
	OrigensNaoObservadasAntesCalc bool `json:"origins_not_seen_before_computable"`

	Sessoes          []Sessao   `json:"open_sessions,omitempty"`
	TopOrigensRecusa []Contagem `json:"top_refused_origins,omitempty"`
}

// Coletado diz se a coleta de login chegou a rodar. Falso num retrato volátil
// (o amostrador do `watch`), e o chamador precisa CALAR o bloco em vez de
// imprimir zeros — zero de uma coleta que não aconteceu é a leitura
// tranquilizadora que este pacote inteiro existe para não produzir.
func (r Resumo) Coletado() bool { return len(r.Fontes) > 0 }

// Fonte devolve a testemunha de um papel.
func (r Resumo) Fonte(papel string) (Fonte, bool) {
	for _, s := range r.Fontes {
		if s.Papel == papel {
			return s, true
		}
	}
	return Fonte{}, false
}

// maxTopOrigens limita o topo impresso. Numa triagem o que decide é a ordem de
// grandeza e quem lidera, não a lista inteira.
const maxTopOrigens = 5

// Resumir monta o quadro. `agora` entra como parâmetro para o teste não
// depender do relógio da máquina, como em ParseJanela.
func Resumir(f *facts.Facts, agora time.Time, janela time.Duration) Resumo {
	r := Resumo{
		JanelaSolicitada: dur(janela),
		Desde:            agora.Add(-janela).UTC().Format(carimbo),
	}
	if f == nil {
		return r
	}
	r.Fontes = Cobertura(f, r.Desde)

	usuarios := map[string]bool{}
	origens := map[string]bool{}
	// origensAntes é o histórico ANTERIOR à janela, e é ele que dá sentido a
	// "não observada antes".
	origensAntes := map[string]bool{}
	// origensSemData são as que apareceram em registro que não pôde ser datado.
	// Elas NÃO podem ser chamadas de não-observadas-antes: elas FORAM
	// observadas, e o que falta é saber se foi antes ou dentro da janela. A
	// incerteza já está contada em Fonte.SemData; aqui ela precisa ser
	// respeitada em vez de virar uma afirmação temporal que o registro impede.
	origensSemData := map[string]bool{}
	recusasPorOrigem := map[string]int{}

	for i := range f.Logins {
		l := &f.Logins[i]
		// O marcador de boot nunca é entrada: o campo de origem dele carrega a
		// VERSÃO DO KERNEL, e contá-lo poria texto de kernel na lista de
		// endereços de onde alguém entrou.
		if l.Tipo == facts.TipoBoot {
			continue
		}
		if l.Agora {
			if l.Tipo == facts.TipoLoginUsuario {
				r.Sessoes = append(r.Sessoes, Sessao{
					User: l.User, Origem: l.Origem, Linha: l.Linha, Desde: l.QuandoU,
				})
			}
			continue
		}
		// Sem data, o registro não pode ser posto dentro nem fora da janela. Ele
		// não some: está contado em Fonte.SemData, que é onde a ausência fica
		// declarada em vez de virar silêncio.
		if l.QuandoU == "" {
			if facts.OrigemDeRede(l.Origem) {
				origensSemData[l.Origem] = true
			}
			continue
		}
		naJanela := l.QuandoU >= r.Desde

		if l.Falhou {
			// A CONTAGEM não filtra por origem de rede, e o topo filtra.
			//
			// São perguntas diferentes: "quantas tentativas foram recusadas" é
			// sobre o btmp inteiro, e login(1) e gerenciador de display
			// escrevem ali com ut_host VAZIO. Filtrar a contagem fazia 40
			// falhas de console saírem como `recusadas nenhuma` uma linha
			// abaixo de `btmp … 40 registro(s), lido inteiro` — e ainda
			// divergia do `activity --summary`, que contava todas. Duas
			// respostas para um fato só.
			if naJanela {
				r.Recusados++
				if facts.OrigemDeRede(l.Origem) {
					recusasPorOrigem[l.Origem]++
				}
			}
			continue
		}
		if l.Tipo != facts.TipoLoginUsuario {
			continue
		}
		if !naJanela {
			if facts.OrigemDeRede(l.Origem) {
				origensAntes[l.Origem] = true
			}
			continue
		}
		r.Aceitos++
		if l.User != "" {
			usuarios[l.User] = true
		}
		if facts.OrigemDeRede(l.Origem) {
			origens[l.Origem] = true
		}
	}

	r.Usuarios = len(usuarios)
	r.Origens = len(origens)

	// A pergunta "esta origem já apareceu antes?" só existe se houver ANTES: a
	// retenção precisa alcançar além do começo da janela. Quando ela começa
	// dentro, não há passado com que comparar, e o número sai não-computável em
	// vez de zero.
	if h, ok := r.Fonte(facts.PapelHistorico); ok && h.Lida() && h.Desde != "" && h.Desde < r.Desde {
		r.OrigensNaoObservadasAntesCalc = true
		for o := range origens {
			if !origensAntes[o] && !origensSemData[o] {
				r.OrigensNaoObservadasAntes++
			}
		}
	}

	r.TopOrigensRecusa = topN(recusasPorOrigem, maxTopOrigens)
	// Ordem TOTAL, e não parcial: o `wtf` imprime só as três primeiras, e com
	// duas sessões do mesmo usuário no mesmo segundo — que é o que um pool de
	// terminais produz — `sort.Slice` (instável) escolhia sessões diferentes
	// entre execuções sobre o MESMO retrato.
	sort.Slice(r.Sessoes, func(i, j int) bool {
		a, b := r.Sessoes[i], r.Sessoes[j]
		if a.Desde != b.Desde {
			return a.Desde > b.Desde
		}
		if a.User != b.User {
			return a.User < b.User
		}
		if a.Linha != b.Linha {
			return a.Linha < b.Linha
		}
		return a.Origem < b.Origem
	})
	return r
}

// Cobertura traduz as fontes da coleta para o alcance OBSERVADO de cada uma,
// cruzando o que o coletor mediu (FonteDeLogin) com as datas dos registros que
// entraram (f.Logins).
//
// `desde` é o começo da janela; vazio dispensa a pergunta de cobertura.
func Cobertura(f *facts.Facts, desde string) []Fonte {
	if f == nil || len(f.FontesDeLogin) == 0 {
		return nil
	}
	// O papel de cada Login sai dos dois bits que o coletor já grava: o arquivo
	// de onde ele veio é o que diz se aquilo foi entrada, tentativa recusada ou
	// sessão aberta.
	extremos := map[string][2]string{}
	saltou := map[string]bool{}
	for i := range f.Logins {
		l := &f.Logins[i]
		p := papelDoLogin(l)
		if l.Tipo == facts.TipoTempoAntigo || l.Tipo == facts.TipoTempoNovo {
			saltou[p] = true
		}
		if l.QuandoU == "" {
			continue
		}
		e, ok := extremos[p]
		if !ok {
			extremos[p] = [2]string{l.QuandoU, l.QuandoU}
			continue
		}
		if l.QuandoU < e[0] {
			e[0] = l.QuandoU
		}
		if l.QuandoU > e[1] {
			e[1] = l.QuandoU
		}
		extremos[p] = e
	}

	out := make([]Fonte, 0, len(f.FontesDeLogin))
	for i := range f.FontesDeLogin {
		s := &f.FontesDeLogin[i]
		fo := Fonte{
			Papel: s.Papel, Path: s.Path, Estado: s.Estado,
			Lidos: s.Lidos, Total: s.Registros, TamRegistro: s.TamRegistro,
			SemData: s.SemData, Truncada: s.Truncada, Motivo: s.Motivo,
			GeracoesNaoLidas: geracoesAoLado(f, s.Path),
		}
		if e, ok := extremos[s.Papel]; ok {
			fo.Desde, fo.Ate = e[0], e[1]
		}
		fo.RelogioAlterado = saltou[s.Papel]
		// As sessões abertas são o AGORA por construção: a pergunta de janela
		// não se aplica a elas.
		// A ÚNICA prova positiva de alcance é uma ÂNCORA OBSERVADA anterior ao
		// começo da janela.
		//
		// "Li o arquivo vivo inteiro e não há rotacionado ao lado AGORA" não
		// prova nada sobre trinta dias atrás: a retenção do logrotate é
		// finita, e uma semana depois o wtmp.1 que tinha o passado já expirou.
		// Ausência de geração antiga é ausência de geração antiga.
		//
		// E arquivo VAZIO não cobre janela nenhuma. `: > /var/log/wtmp`
		// produz exatamente a forma de um wtmp legitimamente novo, e é o
		// estado que o atacante que apagou o rastro e saiu deixa para trás —
		// tanto que existe um check inteiro sobre ele
		// (antiforense.wtmp_cleared). Um arquivo vazio prova que a fonte foi
		// lida e não entregou registro; nunca que não houve registro.
		//
		// Truncada e GeracoesNaoLidas continuam sendo metadado útil no rodapé,
		// mas "não truncado" não é prova positiva de idade.
		switch {
		case s.Papel == facts.PapelSessoes:
			// As sessões abertas são o AGORA por construção: a pergunta de
			// janela não se aplica a elas.
			fo.CobreJanela = fo.Lida()
		case !fo.Lida() || desde == "" || fo.Desde == "":
			fo.CobreJanela = false
		case fo.RelogioAlterado:
			// O RELÓGIO SALTOU dentro do que esta fonte entregou, e com ele o
			// mínimo dos timestamps deixou de significar alcance: os registros
			// dos dois lados do salto foram carimbados por relógios diferentes,
			// e compará-los com o começo da janela é somar duas réguas.
			//
			// A recusa é do bloco inteiro, e não de um segmento: decidir QUAL
			// lado do salto ainda vale exigiria confiar nos mesmos carimbos que
			// o salto tornou incomparáveis. O evento fica na linha do tempo
			// (sistema.clock_changed) dizendo por que a resposta é essa.
			fo.CobreJanela = false
		default:
			fo.CobreJanela = fo.Desde <= desde
		}
		out = append(out, fo)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return ordemDoPapel(out[i].Papel) < ordemDoPapel(out[j].Papel)
	})
	return out
}

// geracoesAoLado conta os rotacionados da MESMA série que a coleta de login não
// abre. Ela lê apenas a geração viva de cada arquivo; o inventário de /var/log
// (collectLogs) é quem sabe o que existe ao lado.
func geracoesAoLado(f *facts.Facts, path string) int {
	// `ArquivoDeLog.Base` é o caminho COMPLETO do arquivo vivo da série
	// (`/var/log/wtmp`), e não o nome nu. A primeira versão disto recortava o
	// diretório do lado esquerdo e comparava "wtmp" com "/var/log/wtmp": nunca
	// casava, a contagem saía sempre zero, e a cobertura voltava a afirmar
	// `wtmp ≥24h` sobre duas horas de dados com o wtmp.1 fechado ao lado.
	//
	// O teste não pegou porque montava a fixture à mão, com `Base: "wtmp"` —
	// uma representação que collectLogs não produz. Ele provava que o código
	// lia o que o teste escrevia.
	n := 0
	for i := range f.Logs {
		a := &f.Logs[i]
		// Geração 0 é o arquivo vivo, que é justamente o que foi lido.
		if a.Base == path && a.Path != path && (a.Geracao > 0 || a.Datada) {
			n++
		}
	}
	return n
}

func papelDoLogin(l *facts.Login) string {
	switch {
	case l.Agora:
		return facts.PapelSessoes
	case l.Falhou:
		return facts.PapelRecusadas
	}
	return facts.PapelHistorico
}

// ordemDoPapel põe as fontes na ordem em que a pergunta se faz: quem entrou,
// quem tentou, quem está aqui agora.
func ordemDoPapel(p string) int {
	switch p {
	case facts.PapelHistorico:
		return 0
	case facts.PapelRecusadas:
		return 1
	case facts.PapelSessoes:
		return 2
	}
	return 3
}

func topN(m map[string]int, n int) []Contagem {
	if len(m) == 0 {
		return nil
	}
	out := make([]Contagem, 0, len(m))
	for k, v := range m {
		out = append(out, Contagem{Chave: k, N: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].N != out[j].N {
			return out[i].N > out[j].N
		}
		return out[i].Chave < out[j].Chave
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// Duracao é dur exportado, para a camada de saída falar da mesma forma.
func Duracao(d time.Duration) string { return dur(d) }

// dur escreve uma duração como quem fala dela numa investigação: `32h`, `7d`,
// `3h12m`. O `dur` do pacote report resolve outra coisa — quanto a varredura
// demorou, em ms e s —, e as duas escalas não se misturam.
func dur(d time.Duration) string {
	if d < 0 {
		d = -d
	}
	switch {
	case d < time.Minute:
		return itoa(int(d/time.Second)) + "s"
	case d < time.Hour:
		return itoa(int(d/time.Minute)) + "m"
	// O corte para DIAS é 48h, e não 24h: quem pergunta por um plantão diz "24h"
	// e "32h", nunca "1d" e "1d8h". A partir de dois dias a unidade vira dia,
	// que é como se fala de retenção.
	case d < 48*time.Hour:
		h := int(d / time.Hour)
		if m := int(d/time.Minute) % 60; m > 0 {
			return itoa(h) + "h" + itoa(m) + "m"
		}
		return itoa(h) + "h"
	}
	dias := int(d / (24 * time.Hour))
	if h := int(d/time.Hour) % 24; h > 0 {
		return itoa(dias) + "d" + itoa(h) + "h"
	}
	return itoa(dias) + "d"
}

// Alcance mede o quanto do passado esta fonte entregou, a partir de `agora`.
// Vazio quando ela não trouxe nenhum registro datado — e vazio ali não é zero,
// é "esta fonte não sustenta afirmação temporal nenhuma".
func (s Fonte) Alcance(agora time.Time) string {
	if s.Desde == "" {
		return ""
	}
	t, err := time.Parse(carimbo, s.Desde)
	if err != nil {
		return ""
	}
	return dur(agora.Sub(t))
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var d [20]byte
	i := len(d)
	for n > 0 {
		i--
		d[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		d[i] = '-'
	}
	return string(d[i:])
}
