package check

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

// NotChecked registra um check que não pôde rodar. Isto NÃO é "nada
// encontrado": é "não foi possível olhar", e a diferença é o motivo de a
// ferramenta existir.
type NotChecked struct {
	ID     string `json:"id"`
	Ref    string `json:"ref"`
	Title  string `json:"title"`
	Reason string `json:"reason"`
	// Manual é o que o operador pode rodar à mão para cobrir esta lacuna.
	Manual []string `json:"manual,omitempty"`
}

// Partial é um check que rodou, mas não cobriu tudo.
type Partial struct {
	ID      string   `json:"id"`
	Ref     string   `json:"ref"`
	Reasons []string `json:"reasons"`
}

// Coverage é o rodapé obrigatório. O denominador é o conjunto SELECIONADO para
// esta execução, não o catálogo inteiro (SPEC 7.9).
type Coverage struct {
	Total      int          `json:"total"`
	Complete   int          `json:"complete"`
	Partial    []Partial    `json:"partial,omitempty"`
	NotChecked []NotChecked `json:"not_checked,omitempty"`

	// CollectorGaps é o que a COLETA não conseguiu ler — eixo diferente dos
	// checks, e por isso fora da aritmética completos+parciais+não verificados.
	// "Não consegui ler o fd de 250 processos" degrada a cobertura mesmo que
	// todos os checks tenham rodado.
	CollectorGaps []string `json:"collector_gaps,omitempty"`
}

// Incomplete diz se algo deixou de cobrir o que deveria. Parcial conta como
// não-completo: um check que rodou sem /root não cobriu o que deveria. Falha de
// coleta também conta — é literalmente "não olhei".
func (c Coverage) Incomplete() bool {
	return c.Complete < c.Total || len(c.CollectorGaps) > 0
}

// Report é o resultado de uma execução.
type Report struct {
	Findings []Finding
	Coverage Coverage

	// TrustBroken lista os motivos pelos quais achados de binário do host
	// foram rebaixados nesta execução.
	TrustBroken []string
}

// trustBreakers são os IDs cujo disparo invalida a confiança em qualquer
// resultado vindo de binário do host. É a propriedade emergente de ter Origin
// no modelo (SPEC 7.5).
var trustBreakers = map[string]string{
	"persist.ld_preload_global": "/etc/ld.so.preload presente: o loader injeta biblioteca em todo processo dinâmico",
	"proc.ld_preload_env":       "LD_PRELOAD definido no environ de um processo",
}

// runGuarded isola a falha de um check. Um defeito em um não pode calar os
// outros 46 nem falsificar o veredito da execução inteira.
func runGuarded(c Check, f *facts.Facts, e *env.Env) (res Result, panicked string) {
	defer func() {
		if r := recover(); r != nil {
			panicked = fmt.Sprint(r)
			res = Result{}
		}
	}()
	return c.Run(c, f, e), ""
}

// RunOptions são os limites da execução, não a apresentação dela.
type RunOptions struct {
	// Deadline é o teto do `wtf` (SPEC 6.1). Zero = sem teto.
	//
	// O que estourar o prazo vira NÃO VERIFICADO, nunca "nada encontrado": um
	// overview que fica rápido calando check é pior que um overview lento,
	// porque a mentira sai com cara de resposta.
	Deadline time.Time
	// Budget é só para o texto do motivo.
	Budget time.Duration
}

// Run executa a seleção e monta o relatório.
func Run(checks []Check, f *facts.Facts, e *env.Env) *Report {
	return RunWith(checks, f, e, RunOptions{})
}

// RunWith é o Run com limites.
func RunWith(checks []Check, f *facts.Facts, e *env.Env, o RunOptions) *Report {
	// Um Facts vindo de dump ainda não tem índice, e sem ele as buscas por PID
	// e por inode voltam a ser lineares dentro de um laço sobre processos.
	f.Index()

	r := &Report{Coverage: Coverage{Total: len(checks)}}

	for _, c := range checks {
		if !o.Deadline.IsZero() && time.Now().After(o.Deadline) {
			r.Coverage.NotChecked = append(r.Coverage.NotChecked, NotChecked{
				ID: c.ID, Ref: c.Ref, Title: c.Title,
				Reason: "orçamento de " + o.Budget.String() + " esgotado antes deste check",
				Manual: []string{"rode `aletheia scan`, que não tem teto de tempo"},
			})
			continue
		}
		if c.Sources&e.Source == 0 {
			r.Coverage.NotChecked = append(r.Coverage.NotChecked, NotChecked{
				ID: c.ID, Ref: c.Ref, Title: c.Title,
				Reason: "não se aplica ao modo " + e.Source.String(),
			})
			continue
		}
		if missing := e.Missing(c.Requires); missing != 0 {
			r.Coverage.NotChecked = append(r.Coverage.NotChecked, NotChecked{
				ID: c.ID, Ref: c.Ref, Title: c.Title,
				Reason: e.Reason(missing),
			})
			continue
		}

		res, panicked := runGuarded(c, f, e)
		if panicked != "" {
			// Sem isto, o panic aborta o processo com status 2 — que o contrato
			// desta ferramenta define como "CRITICAL: indicador de alta
			// confiança". O modo de falha que ela existe para distinguir
			// ("não consegui ver") sairia como a afirmação positiva mais forte
			// possível, e a automação de frota marcaria o host como
			// comprometido. Um check que quebra vira NÃO VERIFICADO.
			r.Coverage.NotChecked = append(r.Coverage.NotChecked, NotChecked{
				ID: c.ID, Ref: c.Ref, Title: c.Title,
				Reason: "o check falhou durante a execução: " + panicked,
				Manual: []string{"defeito na ferramenta — verifique esta seção do runbook à mão"},
			})
			continue
		}

		// Capacidade opcional ausente vira cobertura degradada, não perda do
		// check inteiro: §7 do runbook roda quase toda sem root, e só /root e
		// /etc/shadow falham.
		if missing := e.Missing(c.Optional); missing != 0 {
			res.Partial = append(res.Partial, e.Reason(missing))
		}

		for i := range res.Findings {
			if res.Findings[i].Origin == "" {
				res.Findings[i].Origin = OriginNative
			}
			if len(res.Findings[i].FalsePositives) == 0 {
				res.Findings[i].FalsePositives = c.FalsePositives
			}
		}
		r.Findings = append(r.Findings, res.Findings...)

		if len(res.Partial) > 0 {
			r.Coverage.Partial = append(r.Coverage.Partial, Partial{
				ID: c.ID, Ref: c.Ref, Reasons: res.Partial,
			})
		} else {
			r.Coverage.Complete++
		}
	}

	r.applyTrustDowngrade()
	r.sortFindings()
	return r
}

// applyTrustDowngrade marca retroativamente os achados que dependeram de um
// binário do host, quando algo nesta execução mostrou que o userland não é
// confiável.
func (r *Report) applyTrustDowngrade() {
	for _, f := range r.Findings {
		if reason, ok := trustBreakers[f.ID]; ok {
			r.TrustBroken = append(r.TrustBroken, reason)
		}
	}
	if len(r.TrustBroken) == 0 {
		return
	}
	for i := range r.Findings {
		if r.Findings[i].Origin.IsTool() {
			r.Findings[i].Downgraded = true
		}
	}
}

func (r *Report) sortFindings() {
	sort.SliceStable(r.Findings, func(i, j int) bool {
		a, b := r.Findings[i], r.Findings[j]
		if a.Sev != b.Sev {
			return a.Sev > b.Sev
		}
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		return a.Subject < b.Subject
	})
}

// Irreversible devolve os achados cujo passo seguinte se perde se for pulado.
func (r *Report) Irreversible() []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if f.Irreversible {
			out = append(out, f)
		}
	}
	return out
}

// Counts devolve a contagem por severidade.
func (r *Report) Counts() (critical, warn, manual, info int) {
	for _, f := range r.Findings {
		switch f.Sev {
		case SevCritical:
			critical++
		case SevWarn:
			warn++
		case SevManual:
			manual++
		case SevInfo:
			info++
		}
	}
	return
}

// Exit implementa SPEC 7.9: zero exige achado nenhum E cobertura completa.
// Uma execução sem root, sem debugfs e sem bpftool NÃO sai zero — seria a
// ferramenta contradizendo o próprio nome.
func (r *Report) Exit() int {
	crit, warn, _, _ := r.Counts()
	switch {
	case crit > 0:
		return 2
	case warn > 0:
		return 1
	case r.Coverage.Incomplete():
		return 1
	default:
		return 0
	}
}

// Verdict é a palavra do RESULT.
func (r *Report) Verdict() string {
	crit, warn, _, _ := r.Counts()
	switch {
	case crit > 0:
		return "CRITICAL"
	case warn > 0:
		return "WARNING"
	case r.Coverage.Incomplete():
		return "INCOMPLETE"
	default:
		return "OK"
	}
}

// GroupedFindings agrupa por ID para a saída compacta: "8× exe em local
// suspeito" no lugar de oito linhas. O tamanho do relatório deixa de crescer
// com o tamanho do incidente.
type Group struct {
	Findings []Finding
}

func (g Group) First() Finding { return g.Findings[0] }
func (g Group) N() int         { return len(g.Findings) }

// Subjects resume os alvos do grupo.
func (g Group) Subjects(max int) string {
	var ss []string
	for i, f := range g.Findings {
		if i >= max {
			ss = append(ss, "…")
			break
		}
		if f.Subject != "" {
			ss = append(ss, f.Subject)
		}
	}
	return strings.Join(ss, ", ")
}

func (r *Report) Grouped() []Group {
	var order []string
	byID := map[string][]Finding{}
	for _, f := range r.Findings {
		if _, ok := byID[f.ID]; !ok {
			order = append(order, f.ID)
		}
		byID[f.ID] = append(byID[f.ID], f)
	}
	out := make([]Group, 0, len(order))
	for _, id := range order {
		out = append(out, Group{Findings: byID[id]})
	}
	return out
}
