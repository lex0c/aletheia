package activity

import (
	"math"
	"sort"
	"strings"
	"time"

	"github.com/lex0c/aletheia/internal/facts"
)

// A linha do tempo, e o problema que ela resolve de verdade: a MESMA entrada
// tem duas testemunhas.
//
// Um login por SSH deixa um registro binário no wtmp e uma linha de texto no
// auth.log. As duas descrevem o mesmo evento e nenhuma delas sabe o que a outra
// sabe: o wtmp tem o instante exato em epoch e a tty; o log tem o método, o
// fingerprint da chave e o pid do sshd. Juntá-las é o produto deste arquivo.
//
// E juntá-las DEMAIS destrói evidência, que é o erro mais caro aqui. Por isso a
// fusão tem força declarada, e a força fraca não funde — ela RELACIONA.

// Kind é o tipo de um evento na linha do tempo. O namespace é pontuado e o
// filtro casa por PREFIXO: `auth` alcança tudo abaixo de `auth.`, sem precisar
// listar os filhos.
//
// É namespace DERIVADO. `EventoDeLog.Kind` é fato serializado e não muda; este
// unifica aquele com os registros binários, que não têm kind nenhum — só um
// inteiro de tipo de registro utmp.
type Kind string

const (
	KindLoginAceito   Kind = "auth.login.accepted"
	KindLoginRecusado Kind = "auth.login.refused"
	KindSessaoAberta  Kind = "auth.session.open"
	KindSessaoFechada Kind = "auth.session.close"
	KindBoot          Kind = "auth.boot"
	// KindDesligamento é o RUN_LVL que o `shutdown` escreve. O intervalo entre
	// ele e o boot seguinte é o tempo em que o host não observou nada — e era
	// justamente o que sumia da linha do tempo.
	KindDesligamento Kind = "auth.shutdown"
	// KindRelogioAlterado é o par NEW_TIME/OLD_TIME. É o instante a partir do
	// qual toda data dos dois lados deixa de ser comparável.
	KindRelogioAlterado Kind = "sistema.clock_changed"

	KindSudo Kind = "privilege.sudo"
	KindSu   Kind = "privilege.su"

	KindContaCriada     Kind = "account.created"
	KindContaModificada Kind = "account.modified"

	KindExecAudit Kind = "exec.audit"
	KindExecCron  Kind = "exec.cron"
)

// deLogKind traduz o kind do fato para o desta linha do tempo.
//
// O que NÃO estiver aqui passa com o nome de origem, e isso é decisão: um kind
// novo em logparse.go apareceria na linha do tempo sem ninguém precisar lembrar
// de atualizar esta tabela. Sumir de uma reconstrução histórica por causa de um
// mapa desatualizado é pior que aparecer com o nome errado.
var deLogKind = map[string]Kind{
	"auth.accepted":     KindLoginAceito,
	"auth.failed":       KindLoginRecusado,
	"auth.invalid_user": KindLoginRecusado,
	"auth.sudo":         KindSudo,
	"auth.su":           KindSu,
	"account.created":   KindContaCriada,
	"account.modified":  KindContaModificada,
	"audit.exec":        KindExecAudit,
	"cron.exec":         KindExecCron,
}

// ForcaDaFusao ordena a EVIDÊNCIA da ligação entre duas testemunhas.
//
// "Mesmo pid" e "mesmo usuário e origem em ±90s" não são a mesma coisa, e
// colapsá-las numa marca só perderia a distinção justamente onde ela importa —
// quando alguém for decidir, a partir desta linha do tempo, que houve uma
// sessão.
type ForcaDaFusao uint8

const (
	FusaoNenhuma ForcaDaFusao = iota
	// FusaoRelacionada é ligação FRACA. Ela nunca funde: marca os dois eventos
	// como possivelmente ligados e deixa os dois na linha do tempo.
	FusaoRelacionada
	// FusaoTemporal é mesmo usuário e mesma origem numa vizinhança de segundos.
	FusaoTemporal
	// FusaoIdentidade é o mesmo PID dentro de uma janela temporal compatível. O
	// ut_pid do wtmp É o pid do sshd da sessão, e o envelope do syslog carrega o
	// mesmo número: a ligação é por identificador, não por proximidade.
	FusaoIdentidade
)

func (f ForcaDaFusao) String() string {
	switch f {
	case FusaoIdentidade:
		return "pid"
	case FusaoTemporal:
		return "user+origem±90s"
	case FusaoRelacionada:
		return "user+origem no mesmo dia"
	}
	return ""
}

const (
	// guardaDePID é a janela em que dois registros com o mesmo pid podem ser o
	// mesmo processo.
	//
	// PID é identidade DENTRO de uma janela, nunca globalmente: num host com
	// uptime grande e muitos sshd o número recicla, e sem esta guarda um login
	// de terça funde com um sudo de quinta que herdou o pid.
	guardaDePID = 5 * time.Minute

	// guardaTemporal é a vizinhança em que mesmo usuário e mesma origem são
	// tomados pelo mesmo evento. Um login gera as duas linhas em milissegundos;
	// noventa segundos é folga para relógio e para buffer de syslog.
	guardaTemporal = 90 * time.Second

	// guardaSemFuso é a guarda de pid quando o /etc/localtime do ALVO não pôde
	// ser lido: a data do log foi suposta em UTC, e o erro real pode chegar a
	// catorze horas (a faixa de offsets em uso vai de −12 a +14). A ligação por
	// pid sobrevive porque a igualdade do número não depende do relógio; o que
	// se alarga é só a guarda contra reciclagem.
	guardaSemFuso = 14 * time.Hour
)

// Confiança da data de um evento.
const (
	DataExata         = "exato"
	DataAnoInferido   = "ano_inferido"
	DataFusoInferido  = "fuso_inferido"
	DataAmbosInferido = "ano_e_fuso_inferidos"
	DataAusente       = "sem_data"
)

// Estados de Divergente.
const (
	// DivergenteAusente é a testemunha que TINHA como registrar e não registrou.
	// É a forma da manipulação de log.
	DivergenteAusente = "ausente"
	// DivergenteNaoConfirmado é a ausência que não sustenta afirmação: o parser
	// não estava entendendo aquele arquivo, ou aquela fonte nunca produziu
	// evento daquele tipo — e aí a configuração é que não registra.
	DivergenteNaoConfirmado = "nao_confirmado"
)

// Evento é um instante na história do host, com as testemunhas que o
// sustentam.
type Evento struct {
	At          string `json:"at,omitempty"`
	AtConfianca string `json:"at_confidence"`

	Kind Kind `json:"kind"`

	User        string   `json:"user,omitempty"`
	Origem      string   `json:"remote_ip,omitempty"`
	Linha       string   `json:"line,omitempty"`
	PID         int      `json:"pid,omitempty"`
	Metodo      string   `json:"method,omitempty"`
	Fingerprint string   `json:"fingerprint,omitempty"`
	Alvos       []string `json:"targets,omitempty"`

	// Testemunhas são as fontes que registraram este evento. Plural porque a
	// fusão é o produto: um login por SSH observado de verdade tem duas.
	Testemunhas []string `json:"witnesses"`
	// Fusao é a FORÇA da ligação entre elas. Vazia quando há uma testemunha só.
	Fusao ForcaDaFusao `json:"correlation_strength,omitempty"`
	// FusaoNota registra a ressalva quando a guarda teve de ser afrouxada.
	FusaoNota string `json:"correlation_note,omitempty"`

	// Relacionados são eventos LIGADOS e não fundidos: é onde a ligação fraca
	// vive sem virar afirmação de identidade.
	Relacionados []string `json:"related,omitempty"`

	// Divergente é a ausência da outra testemunha, quando ela pôde ser avaliada.
	Divergente string `json:"divergent,omitempty"`

	Trecho string `json:"snippet,omitempty"`

	// ordem desempata eventos do mesmo instante, preservando a ordem de leitura.
	ordem int
}

// id é a referência estável usada em Relacionados.
//
// A testemunha entra na chave porque `ordem` é o índice DENTRO da lista de
// origem: um registro binário e um evento de log podem ter o mesmo índice, o
// mesmo tipo e o mesmo instante, e aí as duas referências colidiriam — fazendo
// um evento apontar para si mesmo como relacionado.
func (e Evento) id() string {
	fonte := "?"
	if len(e.Testemunhas) > 0 {
		fonte = e.Testemunhas[0]
	}
	return fonte + ":" + string(e.Kind) + "@" + nzs(e.At, "sem-data") + "#" + itoa(e.ordem)
}

// Filtro recorta a linha do tempo. Campo vazio não filtra.
type Filtro struct {
	Desde string // carimbo UTC inclusivo
	Ate   string
	User  string
	IP    string
	// Kind casa por PREFIXO: "auth" alcança auth.login.accepted.
	Kind string
}

func (fl Filtro) casa(e *Evento) bool {
	if fl.User != "" && e.User != fl.User {
		return false
	}
	if fl.IP != "" && e.Origem != fl.IP {
		return false
	}
	if fl.Kind != "" && !casaKind(e.Kind, fl.Kind) {
		return false
	}
	// Evento SEM DATA nunca é recortado pela janela: descartá-lo seria esconder
	// por ignorância, e não por escolha de quem pediu o recorte. É a mesma
	// decisão que check.Janela toma para o achado sem data.
	if e.At == "" {
		return true
	}
	if fl.Desde != "" && e.At < fl.Desde {
		return false
	}
	if fl.Ate != "" && e.At > fl.Ate {
		return false
	}
	return true
}

// PrefixoValido diz se algum tipo conhecido cai sob este prefixo.
//
// Existe porque `--group-by porta` era recusado e `--kind porta` não: o segundo
// devolvia a mensagem tranquilizadora de linha do tempo vazia, que é a resposta
// mais perigosa que este comando pode dar a um erro de digitação.
func PrefixoValido(prefixo string) bool {
	for _, k := range TodosOsKinds {
		if casaKind(k, prefixo) {
			return true
		}
	}
	return false
}

// TodosOsKinds é o namespace publicado. Kind que o parser produza e que não
// esteja aqui continua aparecendo na linha do tempo — ver deLogKind —, mas não
// é oferecido como filtro.
var TodosOsKinds = []Kind{
	KindLoginAceito, KindLoginRecusado, KindSessaoAberta, KindSessaoFechada,
	KindBoot, KindDesligamento, KindRelogioAlterado,
	KindSudo, KindSu, KindContaCriada, KindContaModificada,
	KindExecAudit, KindExecCron,
}

func casaKind(k Kind, prefixo string) bool {
	s := string(k)
	return s == prefixo || strings.HasPrefix(s, prefixo+".")
}

// Linha monta a linha do tempo. Devolve também as fontes, porque uma lista de
// eventos sem o alcance de quem os viu não sustenta afirmação nenhuma.
func Linha(f *facts.Facts, fl Filtro) ([]Evento, []Fonte) {
	if f == nil {
		return nil, nil
	}
	fontes := Cobertura(f, fl.Desde)

	binarios, naoMapeados := deRegistros(f)
	// O que a adaptação não traduziu volta para a COBERTURA. Sem isto, o rodapé
	// dizia "59 registros, lido inteiro" enquanto a linha do tempo mostrava 45,
	// e a diferença — 13 desligamentos, neste host — era invisível.
	for i := range fontes {
		fontes[i].NaoInterpretados = naoMapeados[fontes[i].Papel]
	}

	texto := deLogs(f)
	eventos := fundir(f, binarios, texto)
	marcarDivergencia(f, eventos, fontes)

	out := eventos[:0]
	for i := range eventos {
		if fl.casa(&eventos[i]) {
			out = append(out, eventos[i])
		}
	}
	ordenar(out)
	return out, fontes
}

// deRegistros converte wtmp/btmp/utmp. A data deles é epoch: exata por
// construção, e é por isso que ela vence na fusão.
func deRegistros(f *facts.Facts) ([]Evento, map[string]int) {
	out := make([]Evento, 0, len(f.Logins))
	naoMapeados := map[string]int{}
	for i := range f.Logins {
		l := &f.Logins[i]
		e := Evento{
			At: l.QuandoU, User: l.User, Origem: l.Origem, Linha: l.Linha,
			PID: l.PID, ordem: i,
			Testemunhas: []string{nomeDoArquivo(papelDoLogin(l))},
			AtConfianca: DataExata,
		}
		if l.QuandoU == "" {
			e.AtConfianca = DataAusente
		}
		switch {
		case l.Tipo == facts.TipoBoot, l.Tipo == facts.TipoRunLevel:
			e.Kind = KindBoot
			if l.Tipo == facts.TipoRunLevel {
				e.Kind = KindDesligamento
			}
			// O campo de origem destes registros carrega a VERSÃO DO KERNEL, e
			// não um endereço. Deixá-lo em Origem faria um filtro por IP casar
			// com texto de kernel, e a coluna de origem imprimir uma versão. O
			// ut_line deles é o literal `~`, que não é tty nenhuma.
			e.Trecho, e.Origem, e.Linha = l.Origem, "", ""
		case l.Tipo == facts.TipoTempoNovo, l.Tipo == facts.TipoTempoAntigo:
			e.Kind = KindRelogioAlterado
			e.Origem, e.Linha = "", ""
		case l.Falhou:
			e.Kind = KindLoginRecusado
		// O TIPO decide ANTES de o arquivo decidir. `Agora` diz de qual arquivo
		// o registro veio, e não o que ele é: o /run/utmp guarda LOGIN_PROCESS
		// (um getty ocioso, ut_user="LOGIN"), INIT_PROCESS e slots DEAD_PROCESS
		// que retêm o usuário anterior. Com o teste do arquivo primeiro, um
		// servidor com getty@tty1..6 anunciava seis sessões abertas de um
		// usuário chamado LOGIN — enquanto o bloco do `wtf`, que exige o tipo,
		// dizia nenhuma. Duas verdades sobre um fato só.
		case l.Tipo == facts.TipoLoginUsuario && l.Agora:
			e.Kind = KindSessaoAberta
		case l.Tipo == facts.TipoSaida:
			e.Kind = KindSessaoFechada
		case l.Tipo == facts.TipoLoginUsuario:
			e.Kind = KindLoginAceito
		default:
			// NÃO some em silêncio. INIT_PROCESS, LOGIN_PROCESS e ACCOUNTING
			// são contabilidade de daemon e não são evento; o que não pode
			// acontecer é o rodapé dizer "59 registros, lido inteiro" enquanto
			// a linha do tempo mostra 45. A contagem sobe para a cobertura.
			naoMapeados[papelDoLogin(l)]++
			continue
		}
		out = append(out, e)
	}
	return dedupBinario(out), naoMapeados
}

// dedupBinario junta o MESMO registro presente em dois arquivos.
//
// O /run/utmp guarda o boot corrente e as sessões abertas, e os dois também
// estão no /var/log/wtmp: sem isto, todo host imprime o próprio boot duas vezes
// numa reconstrução que promete uma linha por evento. A chave é a identidade
// completa do registro — tipo, instante, conta, tty e pid —, porque é isso que
// dois arquivos com o mesmo registro compartilham.
//
// Ela NÃO junta o par (login aceito, sessão aberta) do mesmo instante: aqueles
// são Kinds diferentes, e são dois fatos — "entrou" e "ainda está aqui".
func dedupBinario(ev []Evento) []Evento {
	type ident struct {
		kind        Kind
		at, user, l string
		pid         int
	}
	visto := map[ident][]int{}
	out := ev[:0]
	for i := range ev {
		e := ev[i]
		// Sem data não há identidade: dois registros sem instante podem ser dois
		// eventos, e juntá-los apagaria um.
		if e.At == "" {
			out = append(out, e)
			continue
		}
		k := ident{e.Kind, e.At, e.User, e.Linha, e.PID}
		// A JUNÇÃO SÓ ATRAVESSA ARQUIVOS. Dois registros idênticos no MESMO
		// arquivo são dois eventos, e a diferença é a mais cara possível: seis
		// senhas erradas dentro de uma conexão SSH (MaxAuthTries) escrevem seis
		// registros de btmp com o mesmo pid, o mesmo usuário, o mesmo
		// `ssh:notty` e o mesmo segundo. Colapsá-los fazia `lastb` mostrar 6 e
		// esta ferramenta mostrar 1 — apagando a rajada de força bruta, que é o
		// caso que ela mais existe para mostrar.
		if j := semEstaTestemunha(out, visto[k], e); j >= 0 {
			out[j].Testemunhas = append(out[j].Testemunhas, e.Testemunhas...)
			continue
		}
		visto[k] = append(visto[k], len(out))
		out = append(out, e)
	}
	return out
}

// semEstaTestemunha acha, entre os candidatos, um que ainda não tenha a
// testemunha deste registro. É o que separa "o mesmo registro em dois arquivos"
// de "dois registros no mesmo arquivo".
func semEstaTestemunha(out []Evento, cand []int, e Evento) int {
	if len(e.Testemunhas) == 0 {
		return -1
	}
	for _, j := range cand {
		jaTem := false
		for _, w := range out[j].Testemunhas {
			if w == e.Testemunhas[0] {
				jaTem = true
				break
			}
		}
		if !jaTem {
			return j
		}
	}
	return -1
}

// deLogs converte o conteúdo dos logs. A data deles pode ter ano ou fuso
// inferidos, e as duas incertezas viajam separadas porque erram em escalas
// diferentes — meses e horas.
func deLogs(f *facts.Facts) []Evento {
	out := make([]Evento, 0, len(f.EventosDeLog))
	for i := range f.EventosDeLog {
		ev := &f.EventosDeLog[i]
		k, ok := deLogKind[ev.Kind]
		if !ok {
			k = Kind(ev.Kind)
		}
		out = append(out, Evento{
			At: ev.At, AtConfianca: confiancaDaData(ev), Kind: k,
			User: ev.User, Origem: ev.RemoteIP, PID: ev.PID,
			Metodo: ev.Metodo, Fingerprint: ev.Fingerprint, Alvos: ev.Alvos,
			Trecho: ev.Trecho, ordem: i,
			Testemunhas: []string{"log:" + ev.File},
		})
	}
	return out
}

func confiancaDaData(ev *facts.EventoDeLog) string {
	switch {
	case ev.At == "" || !ev.AtKnown:
		return DataAusente
	case ev.AtAnoInferido && ev.AtFusoInferido:
		return DataAmbosInferido
	case ev.AtAnoInferido:
		return DataAnoInferido
	case ev.AtFusoInferido:
		return DataFusoInferido
	}
	return DataExata
}

// fundir junta as duas testemunhas do mesmo evento, pela hierarquia declarada
// em ForcaDaFusao.
//
// Em DOIS passos, e a ordem é o ponto. As fusões FORTES rodam primeiro e
// consomem; só depois a ligação fraca trabalha sobre o que sobrou dos dois
// lados. Numa passada só, um evento de texto podia ser relacionado fracamente a
// um registro e depois consumido por outro — e aí a referência cruzada do
// primeiro apontava para um id que não existe mais na saída.
func fundir(f *facts.Facts, bin, txt []Evento) []Evento {
	// O fuso do ALVO decide o que a proximidade temporal vale. Sem ele a data do
	// log foi suposta em UTC, e o erro pode chegar a horas: dois logins
	// legítimos do mesmo usuário e da mesma origem, um de manhã e outro à noite,
	// colapsariam num evento só. Então a fusão por tempo é REBAIXADA a ligação.
	fusoLido := f.FusoDoAlvoLido
	guardaPID := guardaDePID
	nota := ""
	if !fusoLido {
		guardaPID = guardaSemFuso
		nota = "guarda temporal ampliada — o fuso do alvo não foi lido"
	}

	porPID := map[chavePID][]int{}
	porFraca := map[chaveFraca][]int{}
	for i := range txt {
		t := &txt[i]
		if !fundivel(t.Kind) {
			continue
		}
		if t.PID > 0 {
			k := chavePID{t.Kind, t.PID}
			porPID[k] = append(porPID[k], i)
		}
		k := chaveFraca{t.Kind, t.User, t.Origem}
		porFraca[k] = append(porFraca[k], i)
	}

	// consumido sai da saída (foi fundido); ligado FICA na saída e não pode ser
	// reusado. Dois estados, porque ligação fraca não é fusão.
	consumido := make([]bool, len(txt))
	ligado := make([]bool, len(txt))
	fundido := make([]*Evento, len(bin))

	// PASSO 1 — as fusões FORTES.
	for i := range bin {
		b := &bin[i]
		if !fundivel(b.Kind) {
			continue
		}
		if b.PID > 0 {
			if j := melhor(txt, consumido, porPID[chavePID{b.Kind, b.PID}], b, guardaPID); j >= 0 {
				consumido[j] = true
				e := juntar(*b, txt[j], FusaoIdentidade, nota)
				fundido[i] = &e
				continue
			}
		}
		// Só com o fuso do alvo lido — ver acima.
		if !fusoLido {
			continue
		}
		if j := melhor(txt, consumido, porFraca[chaveFraca{b.Kind, b.User, b.Origem}], b, guardaTemporal); j >= 0 {
			consumido[j] = true
			e := juntar(*b, txt[j], FusaoTemporal, "")
			fundido[i] = &e
		}
	}

	// PASSO 2 — a ligação FRACA, e ela é 1:1 como as outras.
	//
	// Sem consumir, uma única linha de log sobrevivente "explicava" quantos
	// registros binários quisesse — e como marcarDivergencia pula quem tem
	// relacionado, quem apagasse 49 de 50 linhas do próprio login saía com zero
	// divergência, cada órfão decorado com `⇄user+origem no mesmo dia`, que se
	// lê como corroboração.
	for i := range bin {
		if fundido[i] != nil || !fundivel(bin[i].Kind) {
			continue
		}
		b := &bin[i]
		cand := porFraca[chaveFraca{b.Kind, b.User, b.Origem}]
		j := noMesmoDia(txt, consumido, ligado, cand, b.At)
		if j < 0 {
			continue
		}
		ligado[j] = true
		b.Relacionados = append(b.Relacionados, txt[j].id())
		txt[j].Relacionados = append(txt[j].Relacionados, b.id())
		b.Fusao, txt[j].Fusao = FusaoRelacionada, FusaoRelacionada
		if nota != "" {
			b.FusaoNota, txt[j].FusaoNota = nota, nota
		}
	}

	out := make([]Evento, 0, len(bin)+len(txt))
	for i := range bin {
		if fundido[i] != nil {
			out = append(out, *fundido[i])
			continue
		}
		out = append(out, bin[i])
	}
	for i := range txt {
		if !consumido[i] {
			out = append(out, txt[i])
		}
	}
	return out
}

type chavePID struct {
	kind Kind
	pid  int
}

type chaveFraca struct {
	kind         Kind
	user, origem string
}

// fundivel diz quais tipos têm DUAS testemunhas possíveis. Um sudo só existe no
// log e uma sessão aberta só existe no utmp: procurá-los na outra fonte
// produziria divergência sobre uma pergunta que nunca coube.
func fundivel(k Kind) bool {
	return k == KindLoginAceito || k == KindLoginRecusado
}

// melhor escolhe, entre os candidatos livres, o mais próximo no tempo dentro da
// guarda. Sem data dos dois lados não há como avaliar a guarda, e a ligação cai
// para a força de baixo.
func melhor(txt []Evento, usado []bool, cand []int, b *Evento, guarda time.Duration) int {
	if b.At == "" || len(cand) == 0 {
		return -1
	}
	t0, ok := instante(b.At)
	if !ok {
		return -1
	}
	escolhido, menor := -1, time.Duration(1<<62)
	for _, j := range cand {
		if usado[j] || txt[j].At == "" {
			continue
		}
		// A chave por PID não exige acordo sobre a origem, e sem esta recusa
		// dois eventos com endereços DIFERENTES podiam virar um só por
		// reciclagem de pid — apagando um dos dois endereços da investigação.
		if b.Origem != "" && txt[j].Origem != "" && b.Origem != txt[j].Origem {
			continue
		}
		d := diferenca(t0, txt[j].At)
		if d < 0 {
			continue
		}
		if d <= guarda && d < menor {
			escolhido, menor = j, d
		}
	}
	return escolhido
}

// diferenca é |t0 - at|, e devolve -1 quando não dá para medir.
//
// O `if d < 0 { d = -d }` ingênuo tinha um caso que passava por todos os
// guardas: com instantes saturados, Sub satura em MinInt64, cuja negação é ele
// mesmo — negativo, portanto menor que qualquer guarda e que qualquer mínimo, o
// que forçava uma FusaoIdentidade falsa.
func diferenca(t0 time.Time, at string) time.Duration {
	t1, ok := instante(at)
	if !ok {
		return -1
	}
	d := t0.Sub(t1)
	if d == math.MinInt64 {
		return -1
	}
	if d < 0 {
		d = -d
	}
	return d
}

func noMesmoDia(txt []Evento, consumido, ligado []bool, cand []int, at string) int {
	if len(at) < 10 {
		return -1
	}
	for _, j := range cand {
		if consumido[j] || ligado[j] || len(txt[j].At) < 10 {
			continue
		}
		if txt[j].At[:10] == at[:10] {
			return j
		}
	}
	return -1
}

// juntar constrói o evento fundido. O registro BINÁRIO manda no tempo — o epoch
// do utmp não infere ano nem fuso —, e o log entrega o que só ele tem: método,
// fingerprint e o pid do serviço.
func juntar(b, t Evento, forca ForcaDaFusao, nota string) Evento {
	b.Testemunhas = append(b.Testemunhas, t.Testemunhas...)
	b.Fusao = forca
	b.FusaoNota = nota
	if b.Metodo == "" {
		b.Metodo = t.Metodo
	}
	if b.Fingerprint == "" {
		b.Fingerprint = t.Fingerprint
	}
	if b.PID == 0 {
		b.PID = t.PID
	}
	// A ORIGEM também é "o que só o log tem" quando o registro binário não a
	// traz — e num caso de abuso de credencial ela é o campo que mais importa.
	// Sem isto, uma fusão por pid publicava `remote_ip` vazio como se fosse a
	// única observação, e `activity --ip <endereço>` não casava nada num host
	// cujo auth.log mostra aquele endereço entrando.
	if b.Origem == "" {
		b.Origem = t.Origem
	}
	if b.User == "" {
		b.User = t.User
	}
	if b.Linha == "" {
		b.Linha = t.Linha
	}
	if len(b.Alvos) == 0 {
		b.Alvos = t.Alvos
	}
	if b.Trecho == "" {
		b.Trecho = t.Trecho
	}
	if b.At == "" {
		b.At, b.AtConfianca = t.At, t.AtConfianca
	}
	b.Relacionados = append(b.Relacionados, t.Relacionados...)
	return b
}

func ordenar(ev []Evento) {
	sort.SliceStable(ev, func(i, j int) bool {
		// Sem data vai para o FIM, num bloco próprio. Interpolá-lo numa posição
		// fabricada seria inventar quando aquilo aconteceu.
		if (ev[i].At == "") != (ev[j].At == "") {
			return ev[j].At == ""
		}
		if ev[i].At != ev[j].At {
			return ev[i].At < ev[j].At
		}
		return ev[i].ordem < ev[j].ordem
	})
}

func instante(s string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}

func nomeDoArquivo(papel string) string {
	switch papel {
	case facts.PapelHistorico:
		return "wtmp"
	case facts.PapelRecusadas:
		return "btmp"
	case facts.PapelSessoes:
		return "utmp"
	}
	return papel
}

func nzs(s, padrao string) string {
	if s == "" {
		return padrao
	}
	return s
}

// marcarDivergencia é a parte que faz afirmação — e por isso é a mais cuidadosa
// do arquivo.
//
// "O wtmp viu o login e o auth.log não" tem a forma da manipulação de log. Só
// que ela tem, IDÊNTICA, a forma de várias coisas inocentes, e a primeira
// versão disto acusava todas elas. O que a revisão mediu:
//
//	recusa            btmp e auth.log NÃO são 1:1. Uma conexão de bot escreve
//	                  N linhas de log (auth.failed, auth.invalid_user) contra
//	                  um registro de btmp, e num host exposto isso vira MILHARES
//	                  de acusações de adulteração por hora
//	console           login(1), gdm e lightdm escrevem wtmp e NÃO escrevem
//	                  "Accepted " — o parser só produz auth.accepted daquele
//	                  prefixo, então toda entrada por tty era acusada
//	ssh não-interativo scp, rsync, git e ansible produzem "Accepted publickey"
//	                  sem sessão e portanto sem registro de wtmp. É rotina em
//	                  qualquer host com backup
//
// O que sobrou é estreito de propósito, e a estreiteza é a entrega:
//
//	tipo        SÓ login ACEITO. Recusa não tem correspondência 1:1
//	direção     SÓ binário -> texto. A direção oposta tem causa benigna comum
//	            (ssh não-interativo) que os fatos coletados não descartam
//	forma       a fonte ausente precisa ter produzido evento do mesmo tipo E
//	            com a mesma forma de origem: um auth.log que só registra login
//	            de REDE não diz nada sobre a falta de um login de CONSOLE
//	cobertura   o instante dentro do intervalo contínuo da fonte ausente
//	parser      a fonte sem lacuna declarada pela camada de fatos
//
// Falhando forma, cobertura ou parser DENTRO da cobertura: `nao_confirmado`.
// Fora da cobertura: NADA — ali não há pergunta, e marcar poria uma ressalva em
// cada evento de um host cujo wtmp guarda mais passado que o auth.log, que é
// todo host.
func marcarDivergencia(f *facts.Facts, ev []Evento, fontes []Fonte) {
	cob := f.CoberturaLog("auth")
	parserOK := parserConfiavel(f, "auth")

	// A chave inclui a FORMA da origem, e não só o tipo. Sem ela, um auth.log
	// cheio de login de rede "provava" que ele registraria o login de console
	// que falta — que é a acusação errada mais fácil de produzir.
	type forma struct {
		kind   Kind
		emRede bool
	}
	vistoNoLog := map[forma]bool{}
	for i := range ev {
		for _, w := range ev[i].Testemunhas {
			if strings.HasPrefix(w, "log:") {
				vistoNoLog[forma{ev[i].Kind, facts.OrigemDeRede(ev[i].Origem)}] = true
			}
		}
	}

	for i := range ev {
		e := &ev[i]
		if e.Kind != KindLoginAceito || e.At == "" {
			continue
		}
		// Uma testemunha só, e ela é a BINÁRIA: é a única direção afirmável.
		if len(e.Testemunhas) != 1 || strings.HasPrefix(e.Testemunhas[0], "log:") {
			continue
		}
		// A ligação fraca já disse que há um candidato do outro lado; chamar
		// isso de ausência contradiria a linha de cima.
		if len(e.Relacionados) > 0 {
			continue
		}
		if !cob.Existe || !cob.Lida || !dentro(e.At, cob.ContinuoDesde, cob.ContinuoAte) {
			continue
		}
		if parserOK && vistoNoLog[forma{e.Kind, facts.OrigemDeRede(e.Origem)}] {
			e.Divergente = DivergenteAusente
		} else {
			e.Divergente = DivergenteNaoConfirmado
		}
	}
}

// parserConfiavel pergunta à camada de FATOS se ela declarou lacuna nos
// arquivos desta família.
//
// A primeira versão media `reconhecidas/candidatas` aqui mesmo, com um limiar
// próprio de 50% e sem piso de amostra — e a mesma pergunta já estava
// respondida em facts.declaraCapacidadeDoParser, com 20% e piso de 50
// candidatas, calibrados contra hosts reais. Dois números para um fato só é
// exatamente o que AgregadoDeLog documenta ter recusado, e aqui o número não
// calibrado decidia a afirmação mais forte que este arquivo faz.
//
// Qualquer lacuna na fonte desqualifica, e não só a de capacidade do parser:
// se a camada de fatos disse que aquele arquivo não entregou o que promete, a
// acusação de adulteração não pode se apoiar nele.
func parserConfiavel(f *facts.Facts, familia string) bool {
	viu := false
	for i := range f.FontesDeLog {
		s := &f.FontesDeLog[i]
		if !temFamilia(s, familia) {
			continue
		}
		if s.Lacuna != "" {
			return false
		}
		viu = true
	}
	return viu
}

func temFamilia(s *facts.FonteDeLog, familia string) bool {
	for _, fam := range s.Familias {
		if fam == familia {
			return true
		}
	}
	return false
}

func dentro(at, desde, ate string) bool {
	return desde != "" && ate != "" && at >= desde && at <= ate
}
