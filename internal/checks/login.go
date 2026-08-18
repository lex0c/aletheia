package checks

import (
	"sort"
	"strconv"
	"strings"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

func init() {
	check.Register(inventarioDeLogin)
	check.Register(forcaBrutaComSucesso)
}

// minFalhasParaForcaBruta é onde tentativa vira campanha.
//
// Um humano erra a senha três, quatro vezes. Dez falhas da MESMA origem não é
// dedo trocado — e o número exato importa menos que a ordem de grandeza,
// porque quem faz força bruta tenta milhares.
const minFalhasParaForcaBruta = 10

// minOrigensPorConta é o segundo eixo, e ele existe porque o primeiro é
// contado POR ORIGEM.
//
// Nove falhas de cada um de cem endereços somam novecentas tentativas e não
// cruzam o limiar em origem nenhuma. Essa não é a forma exótica: é a comum,
// justamente porque todo mundo limita por IP, e quem escreve a ferramenta de
// ataque sabe disso.
//
// O eixo transposto não tem esse problema. Um usuário legítimo erra a senha do
// celular, do laptop e da VPN — três origens, e olhe lá. Cinco endereços
// DIFERENTES falhando contra a MESMA conta não é gente digitando errado, e o
// limiar por origem nunca precisou ser cruzado para isso ser verdade.
const minOrigensPorConta = 5

// inventarioDeLogin — runbook §13.
//
// Esta ferramenta cita o wtmp em dezenas de evidências: "confira contra o
// wtmp", "compare com o horário de trabalho". Mandar o operador a uma fonte é
// útil; ir até ela é melhor, e o formato nunca justificou a omissão — é
// registro binário de tamanho fixo.
//
// É MANUAL porque a ferramenta não tem como saber quais entradas são
// esperadas: quem trabalha de madrugada, de qual endereço, com qual conta. Ela
// entrega o quadro; quem reconhece é o time.
var inventarioDeLogin = check.Check{
	ID:       "auth.login_inventory",
	Ref:      "12",
	Title:    "inventário de entradas registradas no host",
	Group:    "priv",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Wtf:      false, // é contexto para investigar, não indicador de incêndio
	FalsePositives: []string{
		"não é achado: é o quadro que a §13 manda montar. A ferramenta não sabe " +
			"quem deveria ter entrado, de onde, nem a que horas — só o time sabe",
		"o wtmp é ROTACIONADO: o que estiver em wtmp.1 e nos comprimidos não " +
			"aparece aqui, e um invasor que apaga rastro apaga justamente este " +
			"arquivo. Ausência de registro NÃO é ausência de entrada",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result

		// Por USUÁRIO: o operador reconhece contas, não linhas de log.
		type resumo struct {
			n        int
			origens  map[string]bool
			ultima   string
			primeira string
		}
		por := map[string]*resumo{}
		for i := range f.Logins {
			l := &f.Logins[i]
			if l.Falhou || l.Tipo != facts.TipoLoginUsuario {
				continue
			}
			s := por[l.User]
			if s == nil {
				s = &resumo{origens: map[string]bool{}, primeira: l.QuandoU}
				por[l.User] = s
			}
			s.n++
			s.ultima = l.QuandoU
			if o := nz(l.Origem, "(local)"); o != "" {
				s.origens[o] = true
			}
		}
		if len(por) == 0 {
			r.Partial = append(r.Partial, f.PersistDenied["login"]...)
			return r
		}

		users := make([]string, 0, len(por))
		for u := range por {
			users = append(users, u)
		}
		sort.Strings(users)

		for _, u := range users {
			s := por[u]
			origens := make([]string, 0, len(s.origens))
			for o := range s.origens {
				origens = append(origens, o)
			}
			sort.Strings(origens)
			if len(origens) > 6 {
				origens = append(origens[:6:6], "…")
			}

			ev := []string{
				strconv.Itoa(s.n) + " entrada(s) entre " + s.primeira + " e " + s.ultima,
				"de: " + strings.Join(origens, " · "),
				"a ferramenta não sabe quais destas são esperadas — quem reconhece " +
					"é quem opera o host",
			}
			fd := self.F(check.SevManual, u, "", ev...)
			fd.Quando, fd.QuandoFonte = s.ultima, "último login registrado"
			fd.NextSteps = []string{
				"confirme com o time cada ORIGEM que ninguém reconhecer",
				"`last -f /var/log/wtmp.1` e os rotacionados cobrem o período " +
					"anterior a este (runbook §13)",
			}
			r.Findings = append(r.Findings, fd)
		}
		r.Partial = append(r.Partial, f.PersistDenied["login"]...)
		return r
	},
}

// forcaBrutaComSucesso — runbook §13, §16.
//
// É o achado que nenhuma das duas fontes dá sozinha.
//
// O btmp cheio de falhas é ruído de internet: todo host com SSH exposto tem
// milhares, e reportá-los seria descrever o clima. O wtmp com uma entrada
// bem-sucedida é o funcionamento normal do host.
//
// O cruzamento é outra coisa: a MESMA origem que falhou dezenas de vezes
// conseguiu entrar. Isso não é clima — é a descrição de como o invasor chegou,
// com endereço e horário, e é o começo da linha do tempo da §16.
var forcaBrutaComSucesso = check.Check{
	ID:       "auth.bruteforce_success",
	Ref:      "12.5",
	Title:    "origem que falhou muitas vezes conseguiu entrar",
	Group:    "priv",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Optional: env.CapRoot,
	Wtf:      true,
	FalsePositives: []string{
		"automação com credencial expirada produz esta forma: dezenas de falhas " +
			"seguidas de sucesso depois que alguém corrigiu a senha ou a chave. " +
			"O que separa é a ORIGEM ser reconhecida pelo time",
		"o limiar é de 10 falhas POR ORIGEM, e ele é dito aqui de propósito: " +
			"quem lê esta ferramenta pode ficar abaixo dele. É por isso que existe " +
			"o segundo eixo — 5 endereços diferentes falhando contra a MESMA conta, " +
			"nenhum deles cruzando o limiar — que é a forma comum, porque todo " +
			"mundo limita por IP",
		"NAT e balanceador colapsam muitas origens num endereço só: num host " +
			"atrás deles, as falhas do mundo inteiro e o login legítimo do time " +
			"aparecem com o mesmo endereço",
		"sem root o /var/log/btmp é ilegível e este check não forma achado — a " +
			"cobertura diz que as tentativas não foram examinadas",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result

		falhas := map[string]int{}
		alvos := map[string]map[string]bool{}
		for i := range f.Logins {
			l := &f.Logins[i]
			// Tentativa recusada é registrada como login em curso ou concluído; o
			// marcador de boot nunca é uma tentativa.
			if !l.Falhou || l.Tipo == facts.TipoBoot || !origemDeRede(l.Origem) {
				continue
			}
			falhas[l.Origem]++
			if alvos[l.Origem] == nil {
				alvos[l.Origem] = map[string]bool{}
			}
			alvos[l.Origem][l.User] = true
		}
		if len(falhas) == 0 {
			r.Partial = append(r.Partial, f.PersistDenied["login"]...)
			return r
		}

		// origensPorConta é o eixo TRANSPOSTO de `alvos`: para cada conta, de
		// quantos endereços diferentes vieram falhas contra ela.
		origensPorConta := map[string]map[string]bool{}
		for o, contas := range alvos {
			for u := range contas {
				if origensPorConta[u] == nil {
					origensPorConta[u] = map[string]bool{}
				}
				origensPorConta[u][o] = true
			}
		}

		// E agora o cruzamento: quem falhou muito e ENTROU.
		entrou := map[string][]entrada{}
		// espalhado é o mesmo cruzamento pelo outro eixo: conta atacada por
		// muitas origens, e depois uma entrada bem-sucedida.
		espalhado := map[string][]entrada{}
		for i := range f.Logins {
			l := &f.Logins[i]
			if l.Falhou || l.Tipo != facts.TipoLoginUsuario || !origemDeRede(l.Origem) {
				continue
			}
			if falhas[l.Origem] >= minFalhasParaForcaBruta {
				entrou[l.Origem] = append(entrou[l.Origem], entrada{l.User, l.QuandoU})
				continue
			}
			// O SEGUNDO eixo: a origem sozinha ficou abaixo do limiar, mas a
			// conta em que ela entrou foi atacada por muitas origens distintas.
			if len(origensPorConta[l.User]) >= minOrigensPorConta {
				espalhado[l.User] = append(espalhado[l.User], entrada{l.User, l.QuandoU})
			}
		}

		origens := make([]string, 0, len(entrou))
		for o := range entrou {
			origens = append(origens, o)
		}
		sort.Strings(origens)

		for _, o := range origens {
			ss := entrou[o]
			tentados := make([]string, 0, len(alvos[o]))
			for u := range alvos[o] {
				tentados = append(tentados, u)
			}
			sort.Strings(tentados)
			if len(tentados) > 8 {
				tentados = append(tentados[:8:8], "…")
			}

			ev := []string{
				o + " falhou " + strconv.Itoa(falhas[o]) + " vez(es) e depois ENTROU",
				"entrou como: " + descreveSucessos(ss),
				"contas tentadas antes: " + strings.Join(tentados, " "),
				"nenhuma das duas fontes diz isto sozinha: falha em massa é ruído de " +
					"internet, e entrada bem-sucedida é o host funcionando",
			}
			fd := self.F(check.SevCritical, o, "", ev...)
			fd.Quando, fd.QuandoFonte = quandoEntrou(ss), "registro de login bem-sucedido"
			fd.Irreversible = true
			fd.NextSteps = []string{
				"este endereço e este horário são o começo da linha do tempo (runbook §16)",
				"tudo que a conta " + ss[0].user + " fez a partir daí precisa ser " +
					"revisto: chave SSH, sudo, agendamento e histórico de shell",
				"procure a MESMA origem nos outros hosts antes de concluir o " +
					"alcance (runbook §23)",
			}
			r.Findings = append(r.Findings, fd)
		}

		// O segundo eixo, emitido por CONTA e não por origem: é a conta que
		// identifica o alvo quando o ataque veio espalhado.
		contas := make([]string, 0, len(espalhado))
		for u := range espalhado {
			contas = append(contas, u)
		}
		sort.Strings(contas)
		for _, u := range contas {
			ss := espalhado[u]
			de := make([]string, 0, len(origensPorConta[u]))
			for o := range origensPorConta[u] {
				de = append(de, o)
			}
			sort.Strings(de)
			total := 0
			for _, o := range de {
				total += falhas[o]
			}
			mostra := de
			if len(mostra) > 8 {
				mostra = append(mostra[:8:8], "… (+"+strconv.Itoa(len(de)-8)+")")
			}

			fd := self.F(check.SevCritical, u, "",
				"a conta "+u+" recebeu falhas de "+strconv.Itoa(len(de))+
					" endereços diferentes — "+strconv.Itoa(total)+" tentativas ao todo — "+
					"e depois alguém ENTROU nela",
				"origens: "+strings.Join(mostra, " "),
				"entrou como: "+descreveSucessos(ss),
				"NENHUMA das origens sozinha cruzou o limiar de "+
					strconv.Itoa(minFalhasParaForcaBruta)+" falhas: é o ataque "+
					"espalhado, que existe justamente porque se limita por IP",
			)
			fd.Quando, fd.QuandoFonte = quandoEntrou(ss), "registro de login bem-sucedido"
			fd.Irreversible = true
			fd.NextSteps = []string{
				"a credencial de " + u + " deve ser tratada como conhecida: rotacione " +
					"antes de reconectar qualquer coisa (runbook §16)",
				"as origens acima valem como IOC de frota: procure as mesmas nos " +
					"outros hosts (runbook §23)",
			}
			r.Findings = append(r.Findings, fd)
		}
		r.Partial = append(r.Partial, f.PersistDenied["login"]...)
		return r
	},
}

// origemDeRede descarta o que não é um endereço de onde alguém possa tentar
// entrar: `:0` é o display do X, `~` é o marcador de boot e vazio é tty física.
//
// O registro de BOOT também tem texto no campo de origem — a versão do kernel —
// e a primeira versão disto o descartava procurando "MANJARO" na string. Isso
// funcionava num host e em nenhum outro. Quem separa boot de login é o TIPO do
// registro, e é o chamador que o filtra.
func origemDeRede(o string) bool {
	return o != "" && o != "~" && !strings.HasPrefix(o, ":")
}

// entrada é um login bem-sucedido, guardado para o cruzamento.
type entrada struct{ user, quando string }

// quandoEntrou devolve o instante da PRIMEIRA entrada bem-sucedida daquela
// origem — é ele que começa a linha do tempo da §16, não a última.
func quandoEntrou(ss []entrada) string {
	primeiro := ""
	for _, s := range ss {
		if s.quando != "" && (primeiro == "" || s.quando < primeiro) {
			primeiro = s.quando
		}
	}
	return primeiro
}

func descreveSucessos(ss []entrada) string {
	var out []string
	visto := map[string]bool{}
	for _, s := range ss {
		k := s.user + "@" + s.quando
		if visto[k] {
			continue
		}
		visto[k] = true
		out = append(out, s.user+" em "+s.quando)
		if len(out) >= 5 {
			break
		}
	}
	return strings.Join(out, " · ")
}
