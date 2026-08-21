package checks

import (
	"strconv"
	"strings"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

func init() {
	check.Register(driftUnit)
	check.Register(driftCron)
	check.Register(driftSudo)
	check.Register(driftChaveSSH)
	check.Register(driftCobertura)
}

// Os checks de DRIFT respondem uma pergunta que nenhum dos outros faz:
//
//	isto NÃO ERA assim.
//
// O resto do catálogo é conhecimento — cada check sabe que uma forma é
// perigosa, e por isso alcança o que alguém já viu antes. Drift é expectativa,
// e alcança a mudança para a qual NÃO EXISTE regra a escrever: um `ExecStart`
// que passa a apontar para outro binário de pacote, uma chave de SSH trocada
// por outra bem formada, uma regra de sudo reescrita. As duas pontas são
// legítimas em forma; o que denuncia é a transição.
//
// Eles só existem quando alguém informou um estado anterior. Sem isso, o motor
// os declara NÃO VERIFICADOS e os tira do denominador da cobertura — ver
// check.Check.Drift.
//
// # A severidade de um drift, e por que ela quase nunca é crítica sozinha
//
// Servidor real muda o tempo todo: pacote atualizado, aplicação implantada,
// chave rotacionada. Um drift que grita é um drift que ninguém lê depois da
// terceira execução. O que sai como achado é só o campo que É a propriedade de
// segurança — `ExecStart`, `options` de uma chave, o texto de uma regra de
// sudo. Hash, mtime e tamanho mudam em toda atualização e por isso são
// CONTADOS, não impressos.
//
// O peso vem da correlação, que o motor já faz por ator: `authorized_keys`
// mudou MAIS binário novo sem dono de pacote MAIS mesmo uid, na mesma janela, é
// uma história. Cada um sozinho é administração.

// mudancasDe filtra o drift por tipo.
func mudancasDe(f *facts.Facts, tipo string) []facts.MudancaDrift {
	if f.DriftDados == nil {
		return nil
	}
	var out []facts.MudancaDrift
	for _, m := range f.DriftDados.Mudancas {
		if m.Tipo == tipo {
			out = append(out, m)
		}
	}
	return out
}

// janelaDoDrift é a frase que DATA a mudança — e ela é um intervalo, não um
// instante.
//
// Comparando dois retratos, o que se sabe é "mudou ENTRE t0 e t1". Um
// `first_seen: 04:13:02` seria mais bonito de ler e seria inventado: a
// ferramenta não estava lá no momento da mudança, e fingir precisão sobre o
// eixo do tempo é a forma mais fácil de mandar quem investiga para a hora
// errada.
func janelaDoDrift(f *facts.Facts) []string {
	d := f.DriftDados
	if d == nil {
		return nil
	}
	ev := []string{"mudou ENTRE " + nz(d.DeQuando, "?") + " e " + nz(d.AteQuando, "?") +
		" — é o intervalo entre os dois retratos, e é tudo que se sabe: a " +
		"ferramenta não estava presente no momento da mudança"}
	if d.DeHost != "" && d.ParaHost != "" && d.DeHost != d.ParaHost {
		ev = append(ev, "e os dois retratos são de HOSTS DIFERENTES ("+d.DeHost+" → "+
			d.ParaHost+"): serve como comparação com uma referência, e o que for "+
			"específico deste host aparece como mudança sem ter mudado")
	}
	return ev
}

// evidenciaDaMudanca descreve UMA mudança, com o antes e o depois na cara.
func evidenciaDaMudanca(m facts.MudancaDrift) []string {
	switch m.Kind {
	case "surgiu":
		ev := []string{m.Titulo + " que NÃO EXISTIA no retrato anterior: " + m.ID}
		return append(ev, camposDe(m)...)
	case "sumiu":
		ev := []string{m.Titulo + " que existia no retrato anterior e NÃO existe " +
			"mais: " + m.ID}
		return append(ev, camposDe(m)...)
	default:
		// DUAS LINHAS PRIMEIRO, e é uma decisão de leitura: o relatório mostra
		// só as duas primeiras evidências fora do -vv, e um achado que gastasse
		// as duas com "o campo mudou" e "antes: …" deixaria o operador vendo o
		// ANTES sem o DEPOIS — a metade inútil do par.
		//
		// A transição compacta cabe nas duas; o par completo vem depois, para
		// quem abrir. Quando os dois valores são curtos, o par completo seria
		// repetição e não é emitido.
		antes, depois := nz(legivel(m.Antes), "(vazio)"), nz(legivel(m.Depois), "(vazio)")
		out := []string{
			m.Titulo + " `" + m.ID + "`: o campo `" + m.Campo + "` mudou",
			cortaMeio(antes, 80) + "   →   " + cortaMeio(depois, 80),
		}
		if len(antes) > 80 || len(depois) > 80 {
			out = append(out, "antes:  "+antes, "depois: "+depois)
		}
		return out
	}
}

// cortaMeio encurta pelo MEIO: o começo de um ExecStart diz qual binário é, e o fim
// diz o que ele recebe. Cortar só o rabo jogaria fora justamente a metade que
// costuma carregar a mudança.
func cortaMeio(s string, n int) string {
	// POR RUNA, e não por byte: fatiar `s[:38]` parte um caractere multibyte no
	// meio, e o sanitizador da saída entrega o pedaço como `\x?`. É a mesma
	// razão pela qual o `trecho()` da varredura de código converte antes de
	// cortar.
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	meia := (n - 3) / 2
	return string(r[:meia]) + "..." + string(r[len(r)-meia:])
}

func camposDe(m facts.MudancaDrift) []string {
	out := make([]string, 0, len(m.Campos))
	for _, c := range m.Campos {
		out = append(out, "  "+legivel(c))
	}
	return out
}

// legivel troca o separador interno de lista pelo que um humano lê.
//
// `juntar` usa 0x1f (unit separator) para não colidir com conteúdo, e o
// sanitizador da saída o transforma em `\x1f` visível — seguro, e ilegível. A
// evidência de `mudou` imprimia o valor cru: uma unit com dois `Exec*` saía
// como `ExecStart=a\x1fExecStartPre=b`.
func legivel(s string) string { return strings.ReplaceAll(s, "\x1f", ", ") }

// DRIFT SOZINHO É AVISO — os três tipos, sem escada entre eles.
//
// Havia aqui uma `severidadeDoDrift(m)` que ignorava o parâmetro e devolvia
// SevWarn sempre, sob um comentário afirmando que "o que SURGE pesa mais do que
// o que muda, e o que some pesa menos". A escada não existia no código, e não
// existe de propósito: `options` retirado de uma chave que continua a mesma
// (mudou) é pior que uma unit nova (surgiu). Ordenar os três seria inventar uma
// hierarquia que a evidência não sustenta.
//
// O crítico desta ferramenta é a severidade que faz uma frota parar, e gastá-lo
// numa mudança que pode ser um deploy o gasta para sempre. Quem promove é a
// correlação: drift mais um achado com o mesmo ator, na mesma janela.
const severidadeDeDrift = check.SevWarn

// campoDaMudanca devolve o valor de um campo da entidade, venha ele do par
// antes/depois (kind `mudou`) ou da lista inteira (kind `surgiu`/`sumiu`).
func campoDaMudanca(m facts.MudancaDrift, campo string) string {
	if m.Campo == campo {
		return nz(m.Depois, m.Antes)
	}
	for _, c := range m.Campos {
		if v, ok := strings.CutPrefix(c, campo+"="); ok {
			return legivel(v)
		}
	}
	return ""
}

// achadoDeDrift monta o achado com tudo que os dois lados sabem.
func achadoDeDrift(self check.Check, f *facts.Facts, m facts.MudancaDrift, extra ...string) check.Finding {
	ev := evidenciaDaMudanca(m)
	ev = append(ev, extra...)
	ev = append(ev, janelaDoDrift(f)...)
	fd := self.F(severidadeDeDrift, m.ID, "", ev...)
	// O par (tipo, campo, kind) discrimina duas mudanças diferentes sobre a
	// MESMA entidade — sem ele a segunda herdaria a presença da primeira na
	// baseline. Ver check.Finding.Chave.
	fd.Chave = m.Tipo + "|" + m.Kind + "|" + m.Campo
	// A data do achado é o FIM do intervalo: é o instante em que se soube. O
	// começo está na evidência, e é o que o operador usa para cruzar log.
	if f.DriftDados != nil {
		fd.Quando, fd.QuandoFonte = f.DriftDados.AteQuando, "segundo retrato (a mudança é anterior a ele)"
	}
	return fd
}

// driftUnit — runbook §7.4.
var driftUnit = check.Check{
	ID:       "persist.unit_drift",
	Ref:      "7.4",
	Title:    "unit do systemd mudou desde o retrato anterior",
	Group:    "persist",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Drift:    true,
	Wtf:      false,
	FalsePositives: []string{
		"ATUALIZAÇÃO DE PACOTE reescreve unit: o `ExecStart` muda de caminho ou " +
			"ganha uma flag, e o mtime muda em todas as units do pacote. É a " +
			"causa mais comum de drift num servidor mantido, e o que separa das " +
			"outras é o binário apontado continuar com dono de pacote — o " +
			"`integrity.*` responde isso no mesmo relatório",
		"DEPLOY escreve unit e drop-in de propósito: aplicação nova, worker novo, " +
			"timer novo. O que decide é o time reconhecer o nome — e a janela: " +
			"drift dentro do horário de deploy é outra coisa que drift às 3h",
		"unit que SOME é tão comum quanto unit que nasce: pacote removido, " +
			"serviço desativado. Continua saindo porque desligar um agente de " +
			"segurança tem exatamente essa forma",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		for _, m := range mudancasDe(f, "systemd.unit") {
			var extra []string
			if m.Campo == "exec" {
				extra = append(extra, "o `Exec*` é o que a unit EXECUTA: mudá-lo é "+
					"mudar o programa que o host roda sozinho, e nenhuma outra linha "+
					"do arquivo precisa mudar junto")
			}
			if m.Campo == "user" {
				extra = append(extra, "o `User=` decide com que identidade a unit roda: "+
					"de conta de serviço para root é escalada escrita em uma palavra")
			}
			// SÓ QUANDO É DROP-IN DE VERDADE.
			//
			// A condição anterior era `m.Campo == "dropin_for" ||
			// strings.Contains(m.ID, "/") && m.Kind == "surgiu"`, e o ID de uma
			// unit é `nome@caminho` — caminho SEMPRE tem barra. Toda unit que
			// surgia recebia a frase "drop-in ALTERA outra unit sem tocar no
			// arquivo dela", que é falsa sobre uma unit comum. Afirmação falsa
			// na evidência é o defeito que este projeto trata como o mais caro
			// de todos, e ele entrou por um `&&` sem parênteses.
			if alvo := campoDaMudanca(m, "dropin_for"); alvo != "" {
				extra = append(extra, "e é um DROP-IN de `"+alvo+"`: ele altera "+
					"aquela unit sem tocar no arquivo dela, e `cat` na unit original "+
					"não mostra nada")
			}
			if m.Campo == "binds" || m.Campo == "bind_reset" {
				extra = append(extra, "`BindPaths=` monta caminho do HOST dentro do "+
					"namespace da unit: é escrita privilegiada em caminho escolhido, "+
					"e não aparece em nada que olhe só o ExecStart")
			}
			fd := achadoDeDrift(self, f, m, extra...)
			fd.NextSteps = []string{
				"`systemctl cat " + primeiroCampo(m.ID) + "` mostra a unit EFETIVA, " +
					"com os drop-ins aplicados",
				"o ctime do arquivo data a escrita mesmo que o conteúdo pareça antigo",
				"se foi atualização de pacote, o gerenciador sabe: `rpm -qf`/`dpkg -S` " +
					"no arquivo, e a data do pacote bate com a janela",
			}
			r.Findings = append(r.Findings, fd)
		}
		return r
	},
}

// driftCron — runbook §7.5.
var driftCron = check.Check{
	ID:       "persist.cron_drift",
	Ref:      "7.5",
	Title:    "agendamento mudou desde o retrato anterior",
	Group:    "persist",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Drift:    true,
	FalsePositives: []string{
		"pacote que instala job em /etc/cron.d é rotina: logrotate, certbot, " +
			"agente de backup. O nome do arquivo costuma ser o do pacote",
		"crontab de usuário muda porque o usuário mudou: é a superfície mais " +
			"legítima e mais barata de escrever que existe num host",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		for _, m := range mudancasDe(f, "cron") {
			fd := achadoDeDrift(self, f, m,
				"agendamento é persistência que sobrevive a reboot e não deixa "+
					"processo entre execuções: só o comando, num arquivo")
			fd.NextSteps = []string{
				"leia o comando como se fosse malware — e leia o ARQUIVO que ele " +
					"chama, não só a linha",
				"cruze a janela com o log de autenticação: quem estava na máquina",
			}
			r.Findings = append(r.Findings, fd)
		}
		return r
	},
}

// driftSudo — runbook §7.9.
var driftSudo = check.Check{
	ID:       "priv.sudo_drift",
	Ref:      "7.9",
	Title:    "regra de sudo mudou desde o retrato anterior",
	Group:    "priv",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Optional: env.CapRoot,
	Drift:    true,
	FalsePositives: []string{
		"provisionamento reescreve sudoers: Ansible, cloud-init e configuração " +
			"central escrevem em /etc/sudoers.d a cada convergência, e o arquivo " +
			"pode ser reescrito idêntico. O que sai aqui é mudança de TEXTO",
		"uma regra reescrita aparece como uma que SUMIU mais uma que SURGIU — é " +
			"assim que se lê mesmo: para quem investiga, \"a regra mudou\" e " +
			"\"acrescentaram uma regra\" são a mesma pergunta",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		for _, m := range mudancasDe(f, "sudoers") {
			fd := achadoDeDrift(self, f, m,
				"o que a regra CONCEDE está no priv.sudo_nopasswd, no mesmo "+
					"relatório: aqui a pergunta é só se ela é nova")
			fd.NextSteps = []string{
				"`sudo -l -U <usuário>` mostra o que a regra concede de verdade",
				"o ctime do arquivo em sudoers.d data a inserção",
			}
			r.Findings = append(r.Findings, fd)
		}
		return r
	},
}

// driftChaveSSH — runbook §7.3.
var driftChaveSSH = check.Check{
	ID:       "persist.authorized_key_drift",
	Ref:      "7.3",
	Title:    "chave autorizada de SSH mudou desde o retrato anterior",
	Group:    "persist",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Drift:    true,
	FalsePositives: []string{
		"rotação de chave é higiene: uma chave que some e outra que surge, no " +
			"mesmo usuário e na mesma janela, é o que se espera de um time que " +
			"faz a coisa certa",
		"provisionamento distribui chave de operação para a frota inteira. A " +
			"mesma chave aparecendo em vários hosts na mesma janela é isso; numa " +
			"máquina só, não é",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		for _, m := range mudancasDe(f, "ssh.authorized_key") {
			var extra []string
			if m.Campo == "options" {
				// O caso silencioso: a chave continua a mesma, e o que saiu foi
				// o freio dela.
				extra = append(extra, "o `options` é onde moram `command=`, `restrict` "+
					"e `from=`. TIRÁ-LOS de uma chave existente transforma uma chave "+
					"de tarefa única em acesso interativo irrestrito, e o arquivo "+
					"continua com o mesmo número de linhas e a mesma chave")
			}
			if m.Kind == "surgiu" {
				extra = append(extra, "chave nova em authorized_keys é a volta mais "+
					"barata que existe: sobrevive a troca de senha, a reboot e à "+
					"maioria das respostas a incidente")
			}
			fd := achadoDeDrift(self, f, m, extra...)
			fd.NextSteps = []string{
				"confirme o fingerprint com o dono declarado — por um canal que " +
					"não seja a própria máquina",
				"o `authorized_keys` guarda a data do arquivo, não da linha: o " +
					"ctime data a última escrita",
			}
			r.Findings = append(r.Findings, fd)
		}
		return r
	},
}

// driftCobertura é a COBERTURA da comparação, e existe pela mesma razão que a
// cobertura dos coletores existe.
//
// Um drift vazio tem dois significados opostos — "nada mudou" e "nada foi
// comparado" —, e a diferença é a espinha desta ferramenta. Sem este check, uma
// comparação entre um retrato feito com root e outro sem root sairia
// tranquilizadora: as classes que dependem de root simplesmente não teriam
// aparecido, e o relatório diria que o host está igual.
//
// Ele também é o consumidor da lacuna que o motor de drift produz: lacuna
// emitida e nunca lida é o pior falso negativo desta base, e há catraca contra
// isso.
var driftCobertura = check.Check{
	ID:       "integrity.drift_coverage",
	Ref:      "39.3",
	Title:    "o que a comparação com o retrato anterior NÃO alcançou",
	Group:    "integrity",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Drift:    true,
	FalsePositives: []string{
		"não é achado sobre o host: é sobre a COMPARAÇÃO. Sai como informação " +
			"quando tudo pôde ser comparado, e como aviso quando alguma família " +
			"ficou de fora — porque aí o silêncio das outras não vale como resposta",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		d := f.DriftDados
		if d == nil {
			return r
		}
		var completas, restritas []string
		var assimetricas []string
		var motivos []string
		for _, c := range d.Cobertura {
			switch {
			case !c.Simetrico:
				assimetricas = append(assimetricas, c.Titulo)
			case c.Restrita():
				restritas = append(restritas, c.Titulo)
			default:
				completas = append(completas, c.Titulo)
			}
			for _, m := range c.Motivos {
				motivos = append(motivos, "  "+c.Titulo+": "+m)
			}
		}

		ev := []string{
			"comparadas SEM restrição: " + nz(strings.Join(completas, ", "), "nenhuma"),
		}
		ev = append(ev, janelaDoDrift(f)...)
		if len(restritas) > 0 {
			// ESCOPO, e por isso não vira lacuna: os dois retratos enxergaram o
			// mesmo subconjunto, e comparar a interseção é honesto. Uma lacuna
			// aqui nunca fecharia sem root — e lacuna que nunca fecha é lacuna
			// que se aprende a ignorar.
			ev = append(ev, "comparadas sobre a INTERSEÇÃO do que os dois retratos "+
				"enxergaram, com uma direção suprimida: "+strings.Join(restritas, ", "))
			ev = append(ev, "a limitação é a MESMA nos dois lados — é o escopo da "+
				"pergunta, não defeito da comparação. `mudou` continua valendo: ele "+
				"exige a entidade presente nas duas pontas")
		}
		if d.Contadas > 0 {
			ev = append(ev, strconv.Itoa(d.Contadas)+" mudança(s) em campos que NÃO "+
				"decidem privilégio (hash, mtime, tamanho) não foram impressas uma a "+
				"uma — o número está aqui porque corte silencioso se lê como "+
				"\"cobri tudo\"")
		}
		sev := check.SevInfo
		if len(assimetricas) > 0 {
			// ASSIMETRIA é defeito da comparação, e é consertável: recolha as
			// duas pontas com o mesmo privilégio. Por isso vira lacuna de
			// verdade — ela fecha.
			sev = check.SevWarn
			ev = append(ev, "e estas famílias foram comparadas entre retratos de "+
				"ALCANCE DIFERENTE: "+strings.Join(assimetricas, ", "))
			ev = append(ev, "isto é consertável, e vale consertar: recolha as duas "+
				"pontas com o mesmo privilégio. Enquanto durar, uma direção da "+
				"comparação está suprimida e o silêncio dela não é resposta")
		}
		if len(motivos) > 0 {
			ev = append(ev, "por família:")
			ev = append(ev, motivos...)
		}
		fd := self.F(sev, "comparação", "", ev...)
		fd.Chave = "drift-coverage"
		r.Findings = append(r.Findings, fd)
		for _, c := range d.Cobertura {
			if c.Simetrico {
				continue
			}
			r.Partial = append(r.Partial, c.Titulo+": comparação entre retratos de "+
				"alcance diferente — "+strings.Join(c.Motivos, "; "))
		}
		return r
	},
}

// primeiroCampo devolve o que vem antes do primeiro separador da identidade —
// para uma unit, o nome dela.
func primeiroCampo(id string) string {
	if i := strings.IndexAny(id, "@|"); i > 0 {
		return id[:i]
	}
	return id
}
