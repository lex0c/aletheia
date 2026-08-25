package facts

import (
	"sort"
	"strings"
)

// Eventos de log: o host como TESTEMUNHA do próprio passado (runbook §10, §12).
//
// O resto desta ferramenta responde "o que existe AGORA?". O drift responde "o
// que mudou entre dois retratos?". Nenhum dos dois alcança o que aconteceu e não
// deixou objeto: um binário executado às 03:00 e apagado às 03:05 é invisível
// numa varredura das 10:00 — não há arquivo, não há processo, não há socket. O
// log preservou a única evidência que sobrou.
//
// # A regra que governa tudo aqui
//
// Log é ALEGAÇÃO, não fato. Qualquer usuário escreve em /dev/log com um
// `logger`, e root reescreve o arquivo inteiro. Então:
//
//	alegação sozinha                      nunca CRITICAL
//	alegação + testemunha independente     pode ser CRITICAL
//	  (inode, base de pacotes, /proc, utmp)
//	ausência de alegação                   nunca conclusão
//
// A terceira linha é a que mais custa disciplina, e é por causa dela que
// FonteDeLog existe: sem saber QUAL intervalo do passado foi observado, uma
// lista vazia de eventos é lida como "nada aconteceu".
//
// # O que este coletor NÃO faz
//
// Não reimplementa o que o utmp já dá. O wtmp/btmp registram quem entrou, quem
// falhou e quando, em binário de tamanho fixo — mais difícil de forjar que
// texto —, e checks/login.go já os lê, inclusive a força bruta que teve sucesso.
// O que só o log tem é o MÉTODO da autenticação, o FINGERPRINT da chave usada, o
// COMMAND do sudo, a criação de conta datada, e a execução que não existe mais.

// EventoDeLog é uma ALEGAÇÃO do host sobre o próprio passado.
type EventoDeLog struct {
	Kind string `json:"kind"`

	At      string `json:"at,omitempty"` // RFC3339 UTC
	AtKnown bool   `json:"at_known"`

	// DUAS INCERTEZAS, e não uma: o syslog tradicional não carrega ano NEM
	// offset, e as duas faltas erram em escalas diferentes.
	//
	//	ano inferido    sai do mtime do arquivo (ou da coleta, no arquivo vivo).
	//	                Erra em MESES, e é o que decide se um achado cai dentro
	//	                ou fora de uma janela de investigação
	//	fuso inferido   sai do /etc/localtime do alvo, quando ele pôde ser lido.
	//	                Erra em HORAS, e é o que decide correlação de segundos
	//
	// Juntá-las num bit só foi o defeito: `AtInferido` significava só o fuso, e
	// o Finding.QuandoInferido — construído em cima dele — prometia que "data
	// deduzida não recorta". O ano é exatamente o que a janela recorta, e ele
	// ficava de fora da promessa: com /etc/localtime legível e um `touch -d` no
	// rotacionado, o achado voltava a poder ser escondido.
	//
	// A separação também é o que a correlação da próxima rodada precisa: ligar
	// um EXECVE a um login exige saber se cada relógio erra em segundos ou em
	// meses.
	AtAnoInferido  bool `json:"at_year_inferred,omitempty"`
	AtFusoInferido bool `json:"at_tz_inferred,omitempty"`

	File string `json:"file"`
	Line int    `json:"line,omitempty"`

	User string `json:"user,omitempty"`
	UID  int    `json:"uid,omitempty"`
	// UIDKnown separa "uid 0" de "não sei o uid". Sem ele, o zero-value diria
	// ROOT para todo evento que não menciona uid — a leitura mais grave possível,
	// afirmada por omissão.
	UIDKnown bool   `json:"uid_known,omitempty"`
	RemoteIP string `json:"remote_ip,omitempty"`

	Process string `json:"process,omitempty"`
	PID     int    `json:"pid,omitempty"`

	// Alvos são os programas da linha, pelo resolvedor de execalvo.go: uma linha
	// de shell tem N alvos, não um. AlvoIndeterminado CONVIVE com Alvos
	// preenchido — "vi este, e há uma parte que não sei".
	Alvos             []string `json:"targets,omitempty"`
	AlvoIndeterminado bool     `json:"target_unknown,omitempty"`

	Metodo      string `json:"method,omitempty"`      // password | publickey | …
	Fingerprint string `json:"fingerprint,omitempty"` // SHA256:… da chave usada

	// Serial é a identidade do evento no auditd — `msg=audit(epoch:SERIAL)`. u32
	// porque `audit_serial()` devolve unsigned int (kernel/audit.c), e ele
	// REINICIA: a identidade é o PAR (epoch, serial), nunca o serial sozinho.
	Serial uint32 `json:"audit_serial,omitempty"`

	// Trecho é o texto CRU da mensagem, limitado. Cru de propósito: a redação é
	// da camada de saída (dump.go passa todo campo string por redact.TextoLivre),
	// e redigir aqui destruiria evidência que um check pode precisar interpretar.
	Trecho string `json:"snippet,omitempty"`
}

// FonteDeLog é a observabilidade POR ARQUIVO, e é metade da entrega.
//
// É ela que impede `EventosDeLog == []` de ser lido como "nada aconteceu": a
// lista vazia pode ser um host tranquilo, um arquivo ilegível, um formato que
// este parser não conhece, ou uma cauda que só alcançou as últimas horas. As
// quatro conclusões são diferentes, e nenhuma delas aparece na lista de eventos.
type FonteDeLog struct {
	Path string `json:"path"`
	// Familias é PLURAL porque um arquivo serve mais de uma pergunta: no Alpine
	// o busybox syslogd escreve autenticação, sistema e kernel todos em
	// /var/log/messages. Com um campo singular, ou a família `auth` do Alpine
	// ficaria sem fonte — e sem fonte é "fora de escopo", que apagaria os checks
	// de autenticação de uma distribuição inteira —, ou o arquivo seria lido
	// duas vezes e os contadores sairiam dobrados.
	Familias []string `json:"families"`
	Estado   string   `json:"state"`

	BytesLidos int64 `json:"bytes_read"`

	// Os quatro contadores medem CAPACIDADE DO PARSER, e não frequência de
	// evento. A razão que interessa é reconhecidas/candidatas: contra o total de
	// linhas, um /var/log/messages saudável — cheio de postgres, docker e
	// aplicação — pareceria ter o parser quebrado, porque 99% das linhas dele
	// nunca foram nossas. Num host normal, 0,5% das linhas viram evento.
	LinhasLidas        int `json:"lines_read"`
	LinhasParseadas    int `json:"lines_parsed"`
	LinhasCandidatas   int `json:"lines_candidate"`
	LinhasReconhecidas int `json:"lines_recognized"`
	EventosGerados     int `json:"events"`

	// PrimeiroAt vem da CABEÇA do arquivo e data a rotação. Ele NÃO prova que o
	// miolo foi observado — é para isso que serve CobertoDesde.
	PrimeiroAt string `json:"first_at,omitempty"`
	UltimoAt   string `json:"last_at,omitempty"`

	// CobertoDesde/Ate é o intervalo que este arquivo comprovadamente entregou ao
	// parser: o começo da CAUDA lida, não o começo do arquivo. Num auth.log de
	// 300 MB com teto de 8 MB, a diferença entre os dois é de dias — e é sobre
	// esse intervalo que alguém afirmaria ausência.
	CobertoDesde string `json:"covered_since,omitempty"`
	CobertoAte   string `json:"covered_until,omitempty"`

	// LeituraDescontinua marca o arquivo lido em DUAS pontas com o miolo fora.
	// Sem esta marca, PrimeiroAt e CobertoAte pareceriam um intervalo contínuo.
	// A confiança das datas da COBERTURA, que é propriedade dela e não dos
	// eventos: a cobertura sai de toda linha datada, inclusive das que não
	// viram evento. Um arquivo cheio de linhas de rotina datadas por inferência
	// tem cobertura inferida e evento nenhum — e quem perguntasse aos eventos
	// concluiria que as datas foram lidas.
	CoberturaAnoInferido  bool `json:"coverage_year_inferred,omitempty"`
	CoberturaFusoInferido bool `json:"coverage_tz_inferred,omitempty"`

	LeituraDescontinua bool `json:"discontinuous,omitempty"`
	CorteNoInicio      bool `json:"head_truncated,omitempty"`
	CorteNoFim         bool `json:"tail_truncated,omitempty"`

	// Lacuna é o que ESTE arquivo não entregou, e por quê. Vazia é o normal.
	//
	// Ela existe para que um check degrade pela FAMÍLIA de que depende, e não
	// pela coleta inteira: um audit.log ilegível não pode tornar parcial um
	// check que só lê `auth`. Sem este campo, a única fonte de lacuna era o
	// mapa global Partial["logeventos"], que todo check despejava inteiro — e
	// isso desfazia, no relatório, a granularidade por fonte que os fatos de
	// completude constroem.
	Lacuna string `json:"gap,omitempty"`
}

// Estados de FonteDeLog.
const (
	FonteLida         = "lido"
	FonteIlegivel     = "ilegivel"
	FonteTruncada     = "truncado"
	FonteGrandeDemais = "grande_demais"
	// FonteFormatoNaoLido é o rotacionado em xz, bz2 ou zst: este binário não
	// tem descompressor para eles, e não pode ganhar dependência externa. É
	// escopo do FORMATO, e chamá-lo de "grande demais" seria etiqueta errada
	// dentro do próprio fato.
	FonteFormatoNaoLido = "formato_nao_lido"
	// FonteNaoLida é o arquivo que a coleta NEM CHEGOU A VISITAR, porque um teto
	// global parou a seleção antes dele. Ele existe no host, e é isso que
	// precisa constar: sem a entrada, a família dele sairia como INEXISTENTE, e
	// os checks dela sairiam de escopo dizendo "esta pergunta não cabe neste
	// host" quando a verdade é "eu parei antes de chegar nele".
	FonteNaoLida = "nao_visitada"
)

// lidaOuTruncada diz se o arquivo foi de fato ABERTO e teve conteúdo entregue ao
// parser. `fora_da_janela` e `ilegivel` não foram.
func lidaOuTruncada(estado string) bool {
	return estado == FonteLida || estado == FonteTruncada
}

// EstadoColetaLog é o resumo da coleta para o operador.
//
// Um bool juntaria cinco situações que mandam o leitor para lugares diferentes:
// desligado por escolha, sem fonte neste host, lido inteiro, lido em parte, e
// "não sei" (dump anterior a esta versão).
type EstadoColetaLog string

const (
	// LogDesativado: --no-logs, e o wtf sempre. Não é lacuna — é escolha
	// declarada de quem rodou.
	LogDesativado EstadoColetaLog = "disabled"
	// LogForaDeEscopo: nenhuma fonte em TEXTO existe neste host. É o caso do
	// journald-only (Debian 12, Fedora), onde a distribuição não instala
	// rsyslog. A pergunta não cabe, e não cabe é diferente de não respondida.
	LogForaDeEscopo EstadoColetaLog = "out_of_scope"
	LogColetado     EstadoColetaLog = "collected"
	LogParcial      EstadoColetaLog = "partial"
)

// AgregadoDeLog é a forma como os eventos chegam ao relatório.
//
// NÃO é campo de Facts, e isso é decisão: agregado é derivação determinística de
// EventosDeLog, e serializá-lo criaria dois fatos que precisam ficar
// eternamente consistentes — qualquer defeito de agregação passaria a viajar
// dentro do artefato. Com teto de 5000 eventos, agrupar em memória é trivial.
type AgregadoDeLog struct {
	Kind     string
	Chave    string
	Contagem int
	Primeiro string
	Ultimo   string
	// Exemplos são poucos de propósito: 427 falhas da mesma origem são UM
	// achado com contagem, nunca 427 findings.
	Exemplos []EventoDeLog

	// TemDataInferida é sobre TODOS os eventos do grupo, e não sobre os três
	// Exemplos. Primeiro e Ultimo já eram calculados sobre todos, então tirar a
	// confiança dos exemplos comparava universos diferentes: quatro eventos, com
	// o mais recente inferido e os três primeiros exatos, produziam um achado
	// datado pelo quarto e marcado como exato.
	TemDataInferida bool
}

const maxExemplosPorAgregado = 3

// AgregarLog agrupa os eventos dos Kinds pedidos por (Kind, chave).
//
// A chave é o que o check quer contar: o usuário, a origem, o alvo. Ela sai de
// chaveDoEvento, que é a mesma para todo mundo — dois checks contando a mesma
// coisa de jeitos diferentes produziriam dois números para um fato só.
func (f *Facts) AgregarLog(kinds ...string) []AgregadoDeLog {
	quer := map[string]bool{}
	for _, k := range kinds {
		quer[k] = true
	}
	porChave := map[string]*AgregadoDeLog{}
	var ordem []string
	for i := range f.EventosDeLog {
		ev := &f.EventosDeLog[i]
		if len(quer) > 0 && !quer[ev.Kind] {
			continue
		}
		ch := chaveDoEvento(ev)
		id := ev.Kind + "\x00" + ch
		a := porChave[id]
		if a == nil {
			a = &AgregadoDeLog{Kind: ev.Kind, Chave: ch}
			porChave[id] = a
			ordem = append(ordem, id)
		}
		a.Contagem++
		a.TemDataInferida = a.TemDataInferida || ev.AtAnoInferido || ev.AtFusoInferido
		if len(a.Exemplos) < maxExemplosPorAgregado {
			a.Exemplos = append(a.Exemplos, *ev)
		}
		// Sem data não estreita nem alarga o intervalo: um evento que não pôde
		// ser datado não pode empurrar o primeiro nem o último.
		if ev.At == "" {
			continue
		}
		if a.Primeiro == "" || ev.At < a.Primeiro {
			a.Primeiro = ev.At
		}
		if ev.At > a.Ultimo {
			a.Ultimo = ev.At
		}
	}

	out := make([]AgregadoDeLog, 0, len(ordem))
	for _, id := range ordem {
		out = append(out, *porChave[id])
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Contagem != out[j].Contagem {
			return out[i].Contagem > out[j].Contagem
		}
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Chave < out[j].Chave
	})
	return out
}

// chaveDoEvento é o discriminador do agregado, e ele muda com o Kind porque a
// pergunta muda: uma campanha de autenticação se conta por ORIGEM e conta, uma
// execução se conta por ALVO.
func chaveDoEvento(ev *EventoDeLog) string {
	switch ev.Kind {
	case "auth.accepted", "auth.failed", "auth.invalid_user":
		return strings.TrimSpace(ev.User + " " + ev.RemoteIP)
	case "auth.sudo", "auth.su", "cron.exec", "service.failed", "kernel.module_loaded":
		if len(ev.Alvos) > 0 {
			return strings.TrimSpace(ev.User + " " + strings.Join(ev.Alvos, " "))
		}
		return ev.User
	case "account.created", "account.modified":
		return ev.User
	case "audit.exec":
		return strings.Join(ev.Alvos, " ")
	}
	if ev.Process != "" {
		return ev.Process
	}
	return ev.Kind
}

// CoberturaDeLog é a resposta para "posso afirmar ausência nesta família?".
type CoberturaDeLog struct {
	Familia string
	Existe  bool
	Lida    bool

	// ContinuoDesde/Ate é o intervalo CONTÍNUO que termina no evento mais
	// recente desta família. Sai da junção dos intervalos das gerações, do mais
	// novo para o mais velho, PARANDO no primeiro buraco — porque um buraco no
	// meio destrói a única coisa que um check pode afirmar: que naquele trecho,
	// se algo tivesse acontecido, estaria ali.
	ContinuoDesde string
	ContinuoAte   string
	Buraco        bool
	Motivo        string
}

// CoberturaLog responde pela família inteira, juntando as gerações.
//
// É a autoridade dos checks — NÃO o LogJanelaEfetiva global. Um host pode ter
// sete dias de `auth` e oito horas de `audit`, e um número só para os dois
// mentiria para um dos dois lados.
func (f *Facts) CoberturaLog(familia string) CoberturaDeLog {
	out := CoberturaDeLog{Familia: familia}
	if f.LogEstado == LogDesativado {
		out.Motivo = "a coleta de conteúdo de log foi DESLIGADA nesta execução (--no-logs)"
		return out
	}

	type faixa struct{ de, ate string }
	var faixas []faixa
	for i := range f.FontesDeLog {
		s := &f.FontesDeLog[i]
		if !ehDaFamilia(s, familia) {
			continue
		}
		out.Existe = true
		// LIDA é sobre ter ABERTO o arquivo, e não sobre ele constar da lista.
		// Um arquivo fora da janela nunca foi aberto: marcá-lo como lido faria
		// o Motivo abaixo dizer "os arquivos foram lidos e nenhuma linha pôde
		// ser datada" sobre um arquivo que ninguém tocou.
		if !lidaOuTruncada(s.Estado) {
			continue
		}
		out.Lida = true
		if s.CobertoDesde == "" || s.CobertoAte == "" {
			continue
		}
		faixas = append(faixas, faixa{s.CobertoDesde, s.CobertoAte})
		// Duas pontas com o miolo fora NÃO são um intervalo: o que está entre a
		// cabeça e a cauda não foi observado, e tratá-las como uma faixa só
		// afirmaria cobertura sobre o buraco.
		if s.LeituraDescontinua {
			out.Buraco = true
		}
	}
	if !out.Existe {
		out.Motivo = "não há arquivo de log da família " + familia + " neste host"
		return out
	}
	if len(faixas) == 0 {
		if out.Lida {
			out.Motivo = "os arquivos da família " + familia + " foram lidos e nenhuma " +
				"linha (ou registro) pôde ser datada"
		} else {
			out.Motivo = "nenhum arquivo da família " + familia + " pôde ser lido"
		}
		return out
	}

	sort.Slice(faixas, func(i, j int) bool { return faixas[i].ate > faixas[j].ate })
	out.ContinuoAte = faixas[0].ate
	out.ContinuoDesde = faixas[0].de
	for _, fx := range faixas[1:] {
		// Contíguo é o que ENCOSTA no que já se tem: o fim desta faixa não pode
		// ser anterior ao começo da anterior. O primeiro que não encostar
		// interrompe a corrente — o resto pode até ter sido lido, mas não é
		// contínuo até aqui, e não sustenta afirmação de ausência.
		if fx.ate < out.ContinuoDesde {
			out.Buraco = true
			break
		}
		if fx.de < out.ContinuoDesde {
			out.ContinuoDesde = fx.de
		}
	}
	return out
}

func ehDaFamilia(s *FonteDeLog, familia string) bool {
	for _, fam := range s.Familias {
		if fam == familia {
			return true
		}
	}
	return false
}
