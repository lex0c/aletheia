package report

import (
	"encoding/json"
	"io"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

// findingLine é uma finding no JSONL. O `sev` vai como string porque o
// consumidor é jq, não Go.
type findingLine struct {
	Host string `json:"host"`
	TS   string `json:"ts"`
	Tool string `json:"tool"`
	Mode string `json:"mode"`

	ID      string `json:"id"`
	Ref     string `json:"ref"`
	Sev     string `json:"sev"`
	Origin  string `json:"origin"`
	Subject string `json:"subject,omitempty"`
	Title   string `json:"title"`

	Evidence       []string `json:"evidence,omitempty"`
	NextSteps      []string `json:"next_steps,omitempty"`
	FalsePositives []string `json:"false_positives,omitempty"`
	Downgraded     bool     `json:"downgraded,omitempty"`

	// Baseline e Novo só têm significado numa execução com referência. O
	// agregador de frota usa Novo para separar deriva de mudança.
	Baseline bool `json:"baseline,omitempty"`
	Novo     bool `json:"new,omitempty"`
}

// coverageLine acompanha SEMPRE o JSONL. Sem ela, a agregação de frota mostra
// "web-02 sem achados" escondendo que lá metade dos checks não rodou — que é
// precisamente o erro que a ferramenta existe para não cometer (SPEC 7.4).
type coverageLine struct {
	Host       string             `json:"host"`
	TS         string             `json:"ts"`
	Tool       string             `json:"tool"`
	ID         string             `json:"id"` // sempre "coverage"
	Total      int                `json:"total"`
	Complete   int                `json:"complete"`
	Partial    []check.Partial    `json:"partial,omitempty"`
	NotChecked []check.NotChecked `json:"not_checked,omitempty"`
	// CollectorGaps é o eixo que pode ser o ÚNICO motivo do INCOMPLETE.
	// Sem ele aqui, `jq 'select(.complete < .total)'` descarta exatamente o
	// host degradado — o "web-02 sem achados" que esta linha existe para
	// impedir.
	CollectorGaps []string `json:"collector_gaps,omitempty"`
	TrustBroken   []string `json:"trust_broken,omitempty"`

	Verdict string `json:"verdict"`
	Exit    int    `json:"exit"`
}

// JSONL escreve uma finding por linha, mais a linha de cobertura.
// Nunca é afetado pela verbosidade.
func JSONL(w io.Writer, r *check.Report, f *facts.Facts, e *env.Env, bl *BaselineInfo) error {
	enc := json.NewEncoder(w)
	host := f.Host.Hostname
	ts := e.Now.Format("2006-01-02T15:04:05Z")
	tool := "aletheia/" + nz(e.ToolVersion, "dev")

	for _, fd := range r.Findings {
		if err := enc.Encode(findingLine{
			Host: host, TS: ts, Tool: tool, Mode: e.Source.String(),
			ID: fd.ID, Ref: fd.Ref, Sev: fd.Sev.String(), Origin: string(fd.Origin),
			Subject: fd.Subject, Title: fd.Title,
			Evidence: fd.Evidence, NextSteps: fd.NextSteps,
			FalsePositives: fd.FalsePositives, Downgraded: fd.Downgraded,
			Baseline: fd.Baseline, Novo: fd.Novo,
		}); err != nil {
			return err
		}
	}

	// A BASELINE PRECISA APARECER AQUI, e não só no relatório humano.
	//
	// É o JSONL que a automação de frota lê. Sem esta linha, um agregador vê
	// `verdict: OK` e não tem como distinguir "host limpo" de "host cujos
	// achados foram todos rebaixados por uma referência velha, de outra
	// máquina, capturada com metade da cobertura".
	//
	// Uma autoridade que rebaixa achado tem de se declarar nos DOIS canais.
	if bl != nil {
		if err := enc.Encode(baselineLine{
			Host: host, TS: ts, Tool: tool, ID: "baseline",
			BaseHost: bl.Host, CapturedAt: bl.CapturedAt,
			Conhecidos: bl.Conhecidos, Rebaixados: bl.Rebaixados,
			Ressalvas: bl.Ressalvas,
		}); err != nil {
			return err
		}
	}

	return enc.Encode(coverageLine{
		Host: host, TS: ts, Tool: tool, ID: "coverage",
		Total: r.Coverage.Total, Complete: r.Coverage.Complete,
		Partial: r.Coverage.Partial, NotChecked: r.Coverage.NotChecked,
		CollectorGaps: r.Coverage.CollectorGaps, TrustBroken: r.TrustBroken,
		Verdict: r.Verdict(), Exit: r.Exit(),
	})
}

// baselineLine declara a referência usada. Existe pelo mesmo motivo da linha de
// cobertura: o que a ferramenta NÃO viu, ou deixou de gritar, precisa ser
// legível por máquina — não só por quem lê o relatório.
type baselineLine struct {
	Host string `json:"host"`
	TS   string `json:"ts"`
	Tool string `json:"tool"`
	ID   string `json:"id"`

	BaseHost   string   `json:"baseline_host,omitempty"`
	CapturedAt string   `json:"baseline_captured_at,omitempty"`
	Conhecidos int      `json:"baseline_known"`
	Rebaixados int      `json:"baseline_downgraded"`
	Ressalvas  []string `json:"baseline_caveats,omitempty"`
}
