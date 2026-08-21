// Package check define o contrato de um check e o registro deles.
//
// Um check é uma função pura sobre Facts. Ele declara do que precisa, o que
// dispara nele legitimamente, e a qual seção do runbook a conclusão pertence.
// O motor (engine.go) é quem decide se ele roda.
package check

import (
	"fmt"
	"sort"

	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

// Severity ordena o relatório e decide o exit code.
type Severity int

const (
	SevNotChecked Severity = iota // não foi possível verificar — não é "nada encontrado"
	SevInfo
	SevManual // o host não responde isto; segue orientação parametrizada
	SevWarn
	SevCritical
)

func (s Severity) String() string {
	switch s {
	case SevCritical:
		return "CRITICAL"
	case SevWarn:
		return "WARN"
	case SevManual:
		return "MANUAL"
	case SevInfo:
		return "INFO"
	default:
		return "NOT_CHECKED"
	}
}

// Mark é o prefixo visual de cada linha do relatório.
func (s Severity) Mark() string {
	switch s {
	case SevCritical:
		return "⛔"
	case SevWarn:
		return "⚠ "
	case SevManual:
		return "◆ "
	case SevInfo:
		return "· "
	default:
		return "? "
	}
}

// Origin registra se o achado veio de leitura direta ou de um binário do host.
// É o que permite rebaixar a confiança quando o userland está comprometido.
type Origin string

const OriginNative Origin = "native"

func ToolOrigin(tool string) Origin { return Origin("tool:" + tool) }

func (o Origin) IsTool() bool { return len(o) > 5 && o[:5] == "tool:" }

// Mode é o eixo do --mode.
type Mode int

const (
	ModeAuto Mode = iota
	ModeManual
	// ModeAutoWithManualFallback roda automático e, quando NÃO consegue
	// concluir, emite MANUAL em vez de NOT_CHECKED: "cheguei até onde o host
	// permite, o resto é você quem verifica".
	ModeAutoWithManualFallback
)

func (m Mode) String() string {
	switch m {
	case ModeManual:
		return "manual"
	case ModeAutoWithManualFallback:
		return "auto+manual"
	default:
		return "auto"
	}
}

// Finding é uma instância de achado. Um check que dispara em N processos emite
// N findings com o mesmo ID e Subject distinto: o ID agrupa entre hosts, o
// Subject preserva o caso individual.
type Finding struct {
	ID      string   `json:"id"`
	Ref     string   `json:"ref"` // seção do runbook — a da CONCLUSÃO
	Title   string   `json:"title"`
	Subject string   `json:"subject,omitempty"`
	Sev     Severity `json:"-"`
	Origin  Origin   `json:"origin"`

	// Ator é o binário por trás do sujeito, quando o sujeito não é ele: o exe
	// de um pid, o alvo do ExecStart de uma unit. É preenchido pelo MOTOR, e
	// não pelo check — quem escreve o achado conhece o próprio sujeito e não os
	// dos outros, e é justamente a visão de conjunto que faltava. Vazio é o
	// normal.
	Ator string `json:"actor,omitempty"`

	Evidence  []string `json:"evidence,omitempty"`
	NextSteps []string `json:"next_steps,omitempty"`

	// Quando é o instante que DATA este achado, em UTC, e vazio é o normal:
	// nem todo achado tem data. A diferença decide o que a janela de
	// investigação (--since) faz com ele — o que tem data e ficou fora sai do
	// relatório e é CONTADO; o que não tem data FICA, porque descartá-lo seria
	// esconder achado por ignorância, não por escolha.
	Quando string `json:"when,omitempty"`
	// QuandoFonte diz o que aquela data significa. Sem isso, "2026-04-30" não
	// distingue "o arquivo foi modificado" de "o processo subiu" — e essas duas
	// frases mandam o operador para lugares diferentes.
	QuandoFonte string `json:"when_source,omitempty"`

	// Irreversible marca o achado cujo passo seguinte se perde para sempre se
	// for pulado — matar um processo memfd destrói a única cópia do binário.
	// O relatório promove estes ao passo 1 por ESTE campo, não por casar o
	// texto do comando: reescrever a string silenciava o passo irreversível
	// enquanto todo teste continuava verde na própria cópia do literal.
	Irreversible bool `json:"irreversible,omitempty"`

	// Downgraded é marcado pelo motor quando algo invalidou a confiança em
	// binário do host nesta execução.
	Downgraded bool `json:"downgraded,omitempty"`

	// Baseline marca o achado que JÁ ESTAVA presente na baseline informada. Ele
	// desce um nível de severidade e continua no relatório: estar na baseline
	// diz que não é novo, e não diz que é legítimo.
	Baseline bool `json:"baseline,omitempty"`
	// Novo marca o achado AUSENTE da baseline. Só tem significado quando uma
	// baseline foi informada — sem ela, tudo seria "novo" e a marca não
	// informaria nada.
	Novo bool `json:"new,omitempty"`
	// Driftou marca o achado cujo OBJETO mudou desde o retrato anterior — não o
	// achado, o objeto. A distinção é o que a baseline não consegue expressar:
	// um achado que já estava na baseline (não é novo) sobre uma unit cujo
	// ExecStart mudou ontem descreve outra coisa. Ver marcarDrift.
	Driftou bool `json:"drifted,omitempty"`
	// FalsePositives é copiado do check para o achado: o operador precisa
	// saber o que descartar ANTES de investigar.
	FalsePositives []string `json:"false_positives,omitempty"`

	// Chave é o discriminador ESTÁVEL deste achado dentro do par (ID, Subject),
	// para quem compara execuções — a baseline.
	//
	// Existe porque `ID|Subject` colide sempre que um check emite mais de um
	// achado sobre o MESMO sujeito, e a colisão erra para o lado perigoso:
	// priv.sudo_nopasswd usa o USUÁRIO como Subject, então uma regra
	// recém-inserida em sudoers.d saía marcada como "já estava na baseline",
	// sem a marca ✳NOVO, sob uma linha de evidência afirmando "já estava
	// presente na baseline de …" — uma frase falsa sobre uma regra que nunca
	// esteve lá. O mesmo valia para ioc.match, que usa o mesmo pid para
	// indicadores diferentes.
	//
	// Preenchê-la é OPCIONAL e só faz sentido para esses checks. O valor precisa
	// ser estável entre execuções: o TEXTO da regra serve, o número da linha
	// não (ele anda quando alguém edita o arquivo acima).
	Chave string `json:"key,omitempty"`
}

// Result é o que um check devolve.
type Result struct {
	Findings []Finding
	// Partial diz o que ESTE check não conseguiu cobrir, e por quê. É o que
	// impede que uma execução sem /root pareça uma execução completa.
	Partial []string
}

// Check é a unidade registrada.
type Check struct {
	ID    string
	Ref   string
	Title string
	Group string

	Mode     Mode
	Sources  env.Source
	Requires env.Cap
	Optional env.Cap

	// FalsePositives é OBRIGATÓRIO em check automático. Sem um lugar onde o
	// autor declare a classe de falso positivo, todo check nasce otimista e o
	// operador descobre o ruído no meio do incidente.
	FalsePositives []string

	// Wtf marca os checks que cabem no orçamento de ~1s do overview.
	Wtf bool

	// Drift marca o check que só tem o que responder quando DUAS pontas foram
	// comparadas — ele lê f.DriftDados, e sem comparação não há pergunta.
	//
	// Sem esta marca ele cairia na mesma armadilha que a ferramenta evita em
	// todo lugar: rodar sobre fato ausente e concluir "nada encontrado" quando
	// o certo é "não houve o que olhar". Com ela, o motor o declara NÃO
	// VERIFICADO na cobertura — que é a resposta honesta — e o `aletheia drift`
	// o usa como seleção.
	Drift bool

	// Run recebe o próprio Check para poder montar Findings com o ID, o Ref
	// e os FalsePositives dele — sem referenciar a var de pacote, o que
	// criaria ciclo de inicialização.
	Run func(c Check, f *facts.Facts, e *env.Env) Result
}

var registry = map[string]Check{}

// Register valida e registra. Falha aqui é erro de programação e o binário nem
// sobe — é assim que "FalsePositives obrigatório" deixa de ser boa intenção.
func Register(c Check) {
	switch {
	case c.ID == "":
		panic("check sem ID")
	case c.Ref == "":
		panic("check " + c.ID + " sem Ref do runbook")
	case c.Title == "":
		panic("check " + c.ID + " sem Title")
	case c.Group == "":
		panic("check " + c.ID + " sem Group")
	case c.Run == nil:
		panic("check " + c.ID + " sem Run")
	case c.Sources == 0:
		panic("check " + c.ID + " sem Sources")
	}
	if c.Mode != ModeManual && len(c.FalsePositives) == 0 {
		panic("check " + c.ID + ": FalsePositives é obrigatório (SPEC 5.2). " +
			"Se realmente não houver, declare explicitamente com \"nenhum: <por quê>\"")
	}
	// Invariante estrutural: quem lê /proc de processo alheio depende de root
	// para enxergar exe, environ e fds. Sem declarar CapRoot em Requires ou
	// Optional, o motor conta o check como COMPLETO numa execução em que ele
	// não viu quase nada — que é exatamente a mentira que esta ferramenta
	// existe para não cometer.
	if c.Mode != ModeManual && c.Requires&env.CapProcfs != 0 &&
		(c.Requires|c.Optional)&env.CapRoot == 0 {
		panic("check " + c.ID + ": lê /proc mas não declara CapRoot em Requires nem em " +
			"Optional. Sem root, exe/environ/fd de processo alheio são invisíveis e a " +
			"cobertura sairia como completa (SPEC 5.5)")
	}
	if _, dup := registry[c.ID]; dup {
		panic("check duplicado: " + c.ID)
	}
	registry[c.ID] = c
}

// All devolve o catálogo, ordenado por ID.
func All() []Check {
	out := make([]Check, 0, len(registry))
	for _, c := range registry {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Selection filtra o catálogo. O resultado é o DENOMINADOR da cobertura: um
// scan --only proc completo é 12/12, não 12/47 (SPEC 7.9).
type Selection struct {
	Groups []string // vazio = todos
	Mode   string   // "", "auto", "manual"
	OnlyID []string // vazio = todos
	Wtf    bool
	// Drift seleciona SÓ os checks que comparam duas pontas. É o `aletheia
	// drift`, que responde "o que mudou" e não "o que há de errado".
	Drift bool
}

func Select(s Selection) []Check {
	var out []Check
	for _, c := range All() {
		if s.Wtf && !c.Wtf {
			continue
		}
		if s.Drift && !c.Drift {
			continue
		}
		if len(s.Groups) > 0 && !contains(s.Groups, c.Group) {
			continue
		}
		if len(s.OnlyID) > 0 && !contains(s.OnlyID, c.ID) {
			continue
		}
		switch s.Mode {
		case "auto":
			if c.Mode == ModeManual {
				continue
			}
		case "manual":
			if c.Mode == ModeAuto {
				continue
			}
		}
		out = append(out, c)
	}
	return out
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

// F é um atalho para montar Finding sem repetir os campos do check.
func (c Check) F(sev Severity, subject, title string, evidence ...string) Finding {
	t := title
	if t == "" {
		t = c.Title
	}
	return Finding{
		ID:             c.ID,
		Ref:            c.Ref,
		Title:          t,
		Subject:        subject,
		Sev:            sev,
		Origin:         OriginNative,
		Evidence:       evidence,
		FalsePositives: c.FalsePositives,
	}
}

func (c Check) String() string { return fmt.Sprintf("%s (§%s)", c.ID, c.Ref) }

// Groups devolve os grupos que têm ao menos um check registrado.
func Groups() []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range registry {
		if !seen[c.Group] {
			seen[c.Group] = true
			out = append(out, c.Group)
		}
	}
	sort.Strings(out)
	return out
}

// UnknownGroups devolve os nomes pedidos que não correspondem a grupo algum.
// Um grupo vazio não contribui para o denominador da cobertura, então aceitar
// silenciosamente um nome inexistente transforma "não varri" em "varri e está
// limpo".
func UnknownGroups(want []string) []string {
	have := map[string]bool{}
	for _, g := range Groups() {
		have[g] = true
	}
	var out []string
	for _, w := range want {
		if !have[w] {
			out = append(out, w)
		}
	}
	return out
}
