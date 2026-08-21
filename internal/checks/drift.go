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
	check.Register(driftDeConta)
	check.Register(driftDePrecarga)
	check.Register(driftDeSuid)
	check.Register(driftDePorta)
	check.Register(driftDeKernel)
	check.Register(driftDeConfianca)
	check.Register(driftDePrograma)
	check.Register(driftSSHServidor)
	check.Register(driftSSHCliente)
	check.Register(driftDoas)
	check.Register(driftDefesa)
	check.Register(driftProtecaoDoKernel)
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
			ev = append(ev, strconv.Itoa(d.Contadas)+" mudança(s) não foram impressas "+
				"uma a uma: campo que NÃO decide privilégio (hash, mtime, tamanho) e "+
				"campo OBSERVACIONAL que apareceu ou sumiu do retrato (o dono de um "+
				"socket, que sem root não se lê). O número está aqui porque corte "+
				"silencioso se lê como \"cobri tudo\"")
		}
		sev := check.SevInfo
		if len(assimetricas) > 0 {
			// ASSIMETRIA é defeito da comparação, e é consertável: recolha as
			// duas pontas com o mesmo privilégio. Por isso vira lacuna de
			// verdade — ela fecha.
			sev = check.SevWarn
			ev = append(ev, "e estas famílias foram comparadas entre retratos de "+
				"ALCANCE DIFERENTE: "+strings.Join(assimetricas, ", "))
			ev = append(ev, "e para elas NADA foi reportado: com alcance diferente, "+
				"a diferença de FIDELIDADE aparece como mudança — uma conta cujo "+
				"`sem_senha` só o lado com root conseguiu ler mudaria de valor sem "+
				"nada ter acontecido")
			ev = append(ev, "isto é consertável, e vale consertar: recolha as duas "+
				"pontas com o mesmo privilégio. Enquanto durar, o silêncio destas "+
				"famílias não é resposta")
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

// mudancasDeVarios junta as famílias que respondem à MESMA pergunta do
// operador. Um check por família daria treze entradas no catálogo para
// perguntas que ninguém faz separadas — "quem alcança privilégio mudou?" não é
// duas perguntas por conta que sejam duas tabelas no /etc.
func mudancasDeVarios(f *facts.Facts, tipos ...string) []facts.MudancaDrift {
	var out []facts.MudancaDrift
	for _, t := range tipos {
		out = append(out, mudancasDe(f, t)...)
	}
	return out
}

// achadosDeDrift é o corpo comum: uma família de mudanças, uma nota que explica
// o que aquela superfície concede, e os passos.
func achadosDeDrift(self check.Check, f *facts.Facts, ms []facts.MudancaDrift,
	nota string, passos []string) check.Result {
	var r check.Result
	for _, m := range ms {
		fd := achadoDeDrift(self, f, m, nota)
		fd.NextSteps = passos
		r.Findings = append(r.Findings, fd)
	}
	return r
}

// driftDeConta — runbook §7.9.
var driftDeConta = check.Check{
	ID:       "priv.account_drift",
	Ref:      "7.9",
	Title:    "conta ou grupo mudou desde o retrato anterior",
	Group:    "priv",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Drift:    true,
	FalsePositives: []string{
		"pacote que instala serviço CRIA conta de sistema: `_apt`, `systemd-oom`, " +
			"`nginx`. É a causa mais comum de conta nova num host mantido, e o " +
			"nome costuma ser o do pacote",
		"entrada e saída de gente do time mexem em grupo o tempo todo. O que " +
			"decide é o time reconhecer o nome — e QUAL grupo: `docker`, `sudo` e " +
			"`wheel` equivalem a root, e o `priv.root_group` diz isso no mesmo " +
			"relatório",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		return achadosDeDrift(self, f, mudancasDeVarios(f, "conta", "grupo"),
			"conta e grupo são a forma mais antiga de persistência que existe, e a "+
				"que menos muda num servidor: shell que deixa de ser `nologin`, uid "+
				"que vira 0, senha que fica vazia, alguém entrando em `docker` — "+
				"nenhuma dessas tem forma suspeita quando olhada parada",
			[]string{
				"confirme com quem administra o host: conta e grupo têm dono declarado",
				"`getent passwd`/`getent group` mostram o efetivo, já com NSS aplicado",
				"o ctime de /etc/passwd, /etc/shadow e /etc/group data a escrita",
			})
	},
}

// driftDePrecarga — runbook §7.6.
var driftDePrecarga = check.Check{
	ID:       "persist.preload_drift",
	Ref:      "7.6",
	Title:    "pré-carga de código mudou desde o retrato anterior",
	Group:    "persist",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Drift:    true,
	FalsePositives: []string{
		"pré-carga tem uso legítimo e antigo: agente de APM, `libeatmydata` em " +
			"build, `faketime` em teste, e o sandbox do Firefox num desktop. O que " +
			"decide é o time reconhecer a lib — e onde ela mora",
		"`PERL5OPT` e parentes aparecem em ambiente de CI e de build por " +
			"configuração, não por ataque",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		return achadosDeDrift(self, f, mudancasDeVarios(f, "precarga", "hook_interp"),
			"uma linha em /etc/ld.so.preload injeta código em TODO processo dinâmico "+
				"do host — inclusive nos que a resposta a incidente vai rodar. É a "+
				"superfície de maior alcance por byte escrito que existe em Linux",
			[]string{
				"leia a lib apontada como se fosse malware, e confira o dono do pacote",
				"o binário desta ferramenta é estático de propósito: o que ela vê NÃO " +
					"passou por essa injeção",
			})
	},
}

// driftDeSuid — runbook §7.10.
var driftDeSuid = check.Check{
	ID:       "integrity.suid_drift",
	Ref:      "7.10",
	Title:    "bit de privilégio mudou desde o retrato anterior",
	Group:    "integrity",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Drift:    true,
	FalsePositives: []string{
		"atualização de pacote reescreve o binário e traz o bit de volta: o " +
			"conjunto setuid de fábrica é estável, mas o mtime e o tamanho dele " +
			"mudam junto com o pacote — e é essa coincidência que separa " +
			"atualização de `chmod u+s`",
		"instalação de software que precisa de privilégio (contêiner sem " +
			"userns, ferramenta de rede) acrescenta setuid de propósito",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		return achadosDeDrift(self, f, mudancasDe(f, "suid"),
			"`chmod u+s` não altera conteúdo, não altera dono e não aparece em "+
				"verificação de hash nenhuma: a mudança do MODO é a única coisa que "+
				"denuncia essa porta",
			[]string{
				"`ls -l` e `getcap` no caminho: o bit e a capability contam histórias " +
					"diferentes",
				"se o tamanho e o mtime NÃO mudaram junto, não foi atualização de pacote",
			})
	},
}

// driftDePorta — runbook §7.2.
var driftDePorta = check.Check{
	ID:       "net.listen_drift",
	Ref:      "7.2",
	Title:    "porta em escuta mudou desde o retrato anterior",
	Group:    "net",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive,
	Requires: env.CapProcfs,
	Optional: env.CapRoot,
	Drift:    true,
	FalsePositives: []string{
		"aplicação implantada abre porta: é o que ela existe para fazer. O que " +
			"decide é o time reconhecer a porta e o programa que a atende",
		"porta que SOME é reinício de serviço tanto quanto desligamento: entre " +
			"dois retratos, um serviço parado no segundo aparece igual a um " +
			"serviço removido",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		return achadosDeDrift(self, f, mudancasDe(f, "porta"),
			"o que ESCUTA é a diferença entre um host que fala e um host que "+
				"atende: porta nova é superfície nova, e a MESMA porta atendida por "+
				"outro programa é outra coisa inteiramente",
			[]string{
				"`ss -lntp` mostra quem atende agora; o `aletheia info port N` diz o " +
					"que o número significa",
				"se o programa mudou e a porta não, o serviço foi substituído sem " +
					"ninguém notar a queda",
			})
	},
}

// driftDeKernel — runbook §34.
var driftDeKernel = check.Check{
	ID:       "kernel.surface_drift",
	Ref:      "34",
	Title:    "o que o kernel executa mudou desde o retrato anterior",
	Group:    "kernel",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Drift:    true,
	FalsePositives: []string{
		"módulo carrega e descarrega por HARDWARE e por uso: montar um " +
			"filesystem, plugar um dispositivo, subir um contêiner. A lista de " +
			"módulos de um host vivo não é estável do jeito que um arquivo é",
		"atualização de kernel troca o caminho de TODO módulo (`/lib/modules/<versão>`), " +
			"e a mudança aparece em bloco — em bloco é atualização, isolada não é",
		"`binfmt_misc` é registrado por qemu-user-static, por Java e por .NET: um " +
			"registro novo costuma vir junto de um pacote novo",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		return achadosDeDrift(self, f, mudancasDeVarios(f, "modulo", "binfmt", "boot"),
			"módulo carregado é o único estado que não mora em arquivo nenhum: vem "+
				"do kernel falando de si. E `binfmt_misc` faz o kernel chamar um "+
				"interpretador por conta própria, sem nada mudar no userland",
			[]string{
				"módulo sem arquivo em disco, ou fora de /lib/modules, não veio de pacote",
				"a linha de comando do kernel só muda quando a máquina reinicia: se ela " +
					"mudou entre os dois retratos, houve um reboot no meio — e o " +
					"`uptime` diz se ele bate com a janela",
			})
	},
}

// driftDeConfianca — runbook §7.11.
var driftDeConfianca = check.Check{
	ID:       "integrity.trust_drift",
	Ref:      "7.11",
	Title:    "em quem este host confia mudou desde o retrato anterior",
	Group:    "integrity",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Drift:    true,
	FalsePositives: []string{
		"nome em /etc/hosts é a forma normal de apontar um serviço interno, e " +
			"resolvedor muda com DHCP e com VPN — os dois são rotina em máquina " +
			"que troca de rede. O que pesa é a COMBINAÇÃO: nome fixado mais CA " +
			"nova, na mesma janela, vale muito mais que qualquer um sozinho",
		"CA CORPORATIVA é a causa normal de âncora extra: empresa que inspeciona " +
			"TLS na borda instala a própria em toda a frota. A mesma CA em vários " +
			"hosts é política; em uma máquina só, não é",
		"atualização do pacote de certificados (`ca-certificates`) acrescenta e " +
			"remove âncoras em BLOCO, com o pacote datando a mudança",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		return achadosDeDrift(self, f, mudancasDeVarios(f, "ca", "nss", "nss_servico", "hosts", "resolver", "host_trust"),
			"esta família responde UMA pergunta: em quem, e em quê, este host "+
				"confia para saber a verdade. Uma CA a mais faz ele aceitar "+
				"certificado forjado para QUALQUER nome; a cadeia do nsswitch decide "+
				"quem é usuário; um nome fixado no /etc/hosts e um resolvedor novo "+
				"decidem para onde o tráfego vai antes de qualquer TLS acontecer",
			[]string{
				"confirme a âncora com quem administra a frota, por canal que não " +
					"seja esta máquina",
				"`openssl x509 -noout -text` no arquivo mostra para que ela vale",
			})
	},
}

// driftDePrograma — runbook §2.
var driftDePrograma = check.Check{
	ID:       "proc.program_drift",
	Ref:      "2",
	Title:    "programa passou a rodar sob outra identidade",
	Group:    "proc",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive,
	Requires: env.CapProcfs,
	Optional: env.CapRoot,
	Drift:    true,
	FalsePositives: []string{
		"o mesmo binário roda sob uids diferentes o tempo todo e é normal: " +
			"`bash` de cada pessoa logada, `python3` de cada serviço. O que sai " +
			"aqui é o CONJUNTO de uids mudando — e ele muda quando alguém loga",
		"a família NÃO é exaustiva de propósito: um programa que não estava " +
			"rodando no segundo retrato NÃO some do host, e por isso nada aqui " +
			"sai como remoção",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		for _, m := range mudancasDe(f, "programa") {
			fd := achadoDeDrift(self, f, m,
				"o PID não é identidade e o nome de kthread também não — o que "+
					"identifica é o EXECUTÁVEL, e o que se pergunta dele é sob que "+
					"identidade ele roda. `redis-server` que passa a rodar como root é "+
					"a forma que esta família existe para pegar")
			fd.NextSteps = []string{
				"`aletheia info process <pid>` monta o dossiê de quem está rodando",
				"uid novo num programa de serviço costuma ser reinício com outra " +
					"configuração — ou outro programa com o mesmo caminho",
			}
			// SÓ O UID 0 É AVISO, e a decisão sai do FATO — não do texto que o
			// achado imprime.
			//
			// A primeira versão lia a evidência já renderizada atrás do "→" para
			// descobrir os uids. É a armadilha que o check.Finding.Irreversible
			// documenta com todas as letras: reescrever a string silencia a
			// decisão enquanto todo teste continua verde na própria cópia do
			// literal.
			//
			// O motivo do rebaixamento é seleção natural: num servidor
			// multiusuário o conjunto de uids de um shell ou de um interpretador
			// muda a cada login, e uma família que avisa sempre é uma que o
			// operador aprende a ignorar — levando junto o caso que importa. O
			// caso que importa é estreito e nomeável: um executável que NÃO
			// rodava como root passa a rodar.
			if !ganhouUIDZero(m) {
				fd.Sev = check.SevInfo
				fd.Evidence = append(fd.Evidence, "e NENHUM dos uids novos é 0: sai "+
					"como contexto, não como aviso — o conjunto de uids de um shell "+
					"muda a cada login, e uma família que avisa sempre é uma que se "+
					"aprende a ignorar")
			}
			r.Findings = append(r.Findings, fd)
		}
		return r
	},
}

// ganhouUIDZero diz se o uid 0 apareceu onde não havia. É a única transição
// desta família que vale um aviso, e ela é lida do FATO.
func ganhouUIDZero(m facts.MudancaDrift) bool {
	if m.Campo != "uids" {
		return false
	}
	return temUIDZero(m.Depois) && !temUIDZero(m.Antes)
}

// temUIDZero lê o conjunto serializado pelo juntarConjunto do motor de drift.
func temUIDZero(lista string) bool {
	for _, u := range strings.Split(lista, "\x1f") {
		if strings.TrimSpace(u) == "0" {
			return true
		}
	}
	return false
}

// driftSSHServidor — runbook §7.3.
var driftSSHServidor = check.Check{
	ID:       "persist.ssh_server_drift",
	Ref:      "7.3",
	Title:    "configuração do servidor SSH mudou desde o retrato anterior",
	Group:    "persist",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Drift:    true,
	FalsePositives: []string{
		"endurecimento também é mudança: `PermitRootLogin yes → no` sai aqui do " +
			"mesmo jeito que o contrário, e é o time fazendo a coisa certa. A " +
			"DIREÇÃO está na evidência, e é ela que separa as duas",
		"gerenciamento de configuração reescreve sshd_config a cada convergência: " +
			"Ansible, Puppet e imagem de nuvem mexem nesse arquivo por desenho",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		return achadosDeDrift(self, f, mudancasDe(f, "ssh.servidor"),
			"quatro campos deste arquivo decidem QUEM ENTRA, e todos são legítimos "+
				"em alguma configuração do mundo — o que não é legítimo é a mudança. "+
				"`AuthorizedKeysCommand` é o mais silencioso deles: é um programa que "+
				"o sshd executa para decidir o acesso, e trocá-lo não toca em chave "+
				"nenhuma",
			[]string{
				"`sshd -T` mostra a configuração EFETIVA, já com Match e Include " +
					"resolvidos — o arquivo lido não é necessariamente o que vale",
				"o ctime do arquivo data a escrita; o `systemctl status sshd` diz se " +
					"o daemon já releu",
			})
	},
}

// driftSSHCliente — runbook §7.3.
var driftSSHCliente = check.Check{
	ID:       "persist.ssh_client_drift",
	Ref:      "7.3",
	Title:    "hook de execução do cliente SSH mudou desde o retrato anterior",
	Group:    "persist",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Drift:    true,
	FalsePositives: []string{
		"`ProxyCommand` é a forma NORMAL de alcançar host atrás de bastião, e " +
			"aparece no ~/.ssh/config de quase todo mundo que administra frota. " +
			"`ProxyJump` moderno também vira ProxyCommand internamente",
		"ferramenta de infraestrutura escreve nesses arquivos: cloud CLI, " +
			"gerenciador de bastião e plugin de editor todos mexem em ~/.ssh/config",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		return achadosDeDrift(self, f, mudancasDe(f, "ssh.cliente_exec"),
			"estas diretivas fazem o CLIENTE executar um programa a cada conexão, "+
				"sem privilégio nenhum e sem tocar em serviço do sistema: é "+
				"persistência de conta comum, no arquivo que o dono da conta edita",
			[]string{
				"leia o comando como se fosse malware, e confira quem é dono do arquivo",
				"`ssh -G <host>` mostra a configuração efetiva do cliente para aquele destino",
			})
	},
}

// driftDoas — runbook §7.9.
var driftDoas = check.Check{
	ID:       "priv.doas_drift",
	Ref:      "7.9",
	Title:    "regra de doas mudou desde o retrato anterior",
	Group:    "priv",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Drift:    true,
	FalsePositives: []string{
		"em Alpine e Arch o doas é o mecanismo NORMAL de escalada, e mexer no " +
			"doas.conf é administração de rotina — o mesmo que mexer no sudoers " +
			"em Debian",
		"uma regra reescrita aparece como uma que SUMIU mais uma que SURGIU: a " +
			"identidade é o texto, porque o número da linha anda",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		return achadosDeDrift(self, f, mudancasDe(f, "doas"),
			"sem esta família, Alpine e Arch ficavam com metade da resposta: regra "+
				"nova em sudoers virava drift e regra nova em doas.conf não, no host "+
				"onde o doas é o mecanismo de escalada",
			[]string{
				"`doas -C /etc/doas.conf` valida a sintaxe e diz o que a regra concede",
				"o que a regra concede está no priv.doas_nopasswd, no mesmo relatório",
			})
	},
}

// driftDefesa — runbook §34.
//
// A pergunta é uma só, e nenhum check estático a responde bem: UMA DEFESA FOI
// DESLIGADA? SELinux permissivo e auditd parado não têm forma suspeita — metade
// dos hosts do mundo sempre foi assim. É a transição que denuncia.
var driftDefesa = check.Check{
	ID:       "integrity.defense_drift",
	Ref:      "34",
	Title:    "um controle de segurança foi enfraquecido desde o retrato anterior",
	Group:    "integrity",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Drift:    true,
	FalsePositives: []string{
		"depuração legítima desliga MAC temporariamente: `setenforce 0` para " +
			"achar a causa de um AVC é procedimento normal, e quem o fez costuma " +
			"lembrar. O que pesa é ninguém reconhecer a janela",
		"atualização do pacote de política reescreve regra de audit em bloco, e " +
			"a mudança aparece junto com a do pacote",
		"o ENDURECIMENTO sai aqui do mesmo jeito: `permissive → enforcing` e " +
			"uma regra de audit acrescentada são mudanças, e são as boas. A " +
			"direção está na evidência",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		return achadosDeDrift(self, f, mudancasDeVarios(f, "mac", "audit"),
			"desligar a auditoria é anti-forense por definição: o que ela deixa de "+
				"gravar não volta. E `enforcing → permissive` não deixa rastro em "+
				"arquivo de persistência nenhum",
			[]string{
				"`getenforce`/`aa-status` e `auditctl -s` dizem o que vale AGORA",
				"cruze a janela com o log de autenticação: quem estava na máquina",
			})
	},
}

// driftProtecaoDoKernel — runbook §34.
var driftProtecaoDoKernel = check.Check{
	ID:       "kernel.protection_drift",
	Ref:      "34",
	Title:    "o endurecimento do kernel mudou desde o retrato anterior",
	Group:    "kernel",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Drift:    true,
	FalsePositives: []string{
		"`kernel.protection_context` existe e é CONTEXTO de propósito: " +
			"`ptrace_scope=0` e `lockdown=none` são o padrão de distribuição " +
			"inteira, e acusá-los parados seria acusar o mundo. Aqui a pergunta é " +
			"outra — a TRANSIÇÃO —, e ela não é o padrão de ninguém",
		"boot com outro kernel muda vários destes de uma vez: o conjunto que " +
			"cada versão expõe não é o mesmo. Mudança em BLOCO junto de kernel " +
			"novo é atualização; isolada, não",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		return achadosDeDrift(self, f, mudancasDe(f, "kernel.protecao"),
			"`lockdown: integrity → none` e `module_sig_enforce: Y → N` não são o "+
				"estado de fábrica de ninguém: são alguém desligando a trava, e "+
				"nenhuma delas exige tocar num arquivo que a varredura de persistência "+
				"olhe",
			[]string{
				"nenhum destes sobrevive a reboot sozinho: procure o que os REESCREVE " +
					"— sysctl.d, cmdline do kernel, unit de boot",
				"`sysctl -a` e /sys/kernel/security/lockdown dizem o que vale agora",
			})
	},
}
