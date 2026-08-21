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

	// Os quatro campos abaixo existem em check.Finding, COM tag JSON, e não
	// eram copiados para cá — findingLine é uma struct paralela, e o que ela
	// não lista some. O consumidor deste arquivo é a agregação de frota, e sem
	// eles ela não vê a DATA do achado (o eixo inteiro do --since e da âncora
	// §9), não vê o ator que o motor resolveu, e não consegue separar o achado
	// cuja evidência morre se alguém agir. A linha de janela reporta o recorte
	// da execução, não a data de cada achado.
	Quando       string `json:"when,omitempty"`
	QuandoFonte  string `json:"when_source,omitempty"`
	Ator         string `json:"actor,omitempty"`
	Irreversible bool   `json:"irreversible,omitempty"`

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

	// Replay marca a cobertura que veio de um dump. Fica na linha de COBERTURA,
	// e não só na de análise, porque é esta que o agregador consulta para
	// decidir se um host foi verificado — e "verificado quando?" faz parte da
	// resposta.
	Replay bool `json:"replay,omitempty"`

	Verdict string `json:"verdict"`
	Exit    int    `json:"exit"`
}

// analiseLine declara que a execução leu um retrato, não um host.
type analiseLine struct {
	Host string `json:"host"`
	TS   string `json:"ts"`
	Tool string `json:"tool"`
	ID   string `json:"id"`

	Arquivo     string `json:"from,omitempty"`
	ColetadoEm  string `json:"collected_at,omitempty"`
	ColetadoPor string `json:"collected_by,omitempty"`
	ColetaSHA   string `json:"collector_sha256,omitempty"`

	AnalisadoEm  string `json:"analyzed_at,omitempty"`
	AnalisadoPor string `json:"analyzed_by,omitempty"`

	Estranhas []string `json:"unknown_caps,omitempty"`
}

// JSONL escreve uma finding por linha, mais a linha de cobertura.
// Nunca é afetado pela verbosidade.
//
// O `an` não-nulo diz que estes achados vieram de um DUMP. A automação de frota
// precisa disso tanto quanto o humano: sem a linha, um replay de um retrato de
// três dias atrás entra no agregador indistinguível de uma varredura de agora, e
// o `ts` — que é o da COLETA, e não o da análise — vira uma data que ninguém
// sabe interpretar.
func JSONL(w io.Writer, r *check.Report, f *facts.Facts, e *env.Env, bl *BaselineInfo, jn *JanelaInfo, an *AnaliseInfo) error {
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
			Quando: fd.Quando, QuandoFonte: fd.QuandoFonte,
			Ator: fd.Ator, Irreversible: fd.Irreversible,
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

	// A JANELA PRECISA APARECER AQUI pelo mesmo motivo da baseline, e com mais
	// razão: a baseline REBAIXA achado, a janela o REMOVE. Sem esta linha, um
	// agregador de frota vê `verdict: OK` sem ter como distinguir "host limpo"
	// de "host onde a janela cortou três achados, um deles crítico".
	if jn != nil && (jn.Desde != "" || jn.Ancora != "") {
		if err := enc.Encode(janelaLine{
			Host: host, TS: ts, Tool: tool, ID: "window",
			Desde: jn.Desde, Spec: jn.Spec, Fora: jn.Fora,
			ForaTexto: jn.ForaTexto, SemData: jn.SemData,
			Ancora: jn.Ancora, AncoraOrigem: jn.AncoraOrigem, AncoraDe: jn.AncoraDe,
		}); err != nil {
			return err
		}
	}

	if an != nil {
		if err := enc.Encode(analiseLine{
			Host: host, TS: ts, Tool: tool, ID: "analysis",
			Arquivo: an.Arquivo, ColetadoEm: an.ColetadoEm, ColetadoPor: an.ColetadoPor,
			ColetaSHA: an.ColetaSHA, AnalisadoEm: an.AnalisadoEm,
			AnalisadoPor: an.AnalisadoPor, Estranhas: an.Estranhas,
		}); err != nil {
			return err
		}
	}

	return enc.Encode(coverageLine{
		Host: host, TS: ts, Tool: tool, ID: "coverage",
		Replay: an != nil,
		Total:  r.Coverage.Total, Complete: r.Coverage.Complete,
		Partial: r.Coverage.Partial, NotChecked: r.Coverage.NotChecked,
		CollectorGaps: r.Coverage.CollectorGaps, TrustBroken: r.TrustBroken,
		Verdict: r.Verdict(), Exit: r.Exit(),
	})
}

// janelaLine declara o recorte temporal e o âncora derivado.
type janelaLine struct {
	Host string `json:"host"`
	TS   string `json:"ts"`
	Tool string `json:"tool"`
	ID   string `json:"id"`

	Desde     string `json:"since,omitempty"`
	Spec      string `json:"since_spec,omitempty"`
	Fora      int    `json:"outside_window,omitempty"`
	ForaTexto string `json:"outside_by_severity,omitempty"`
	SemData   int    `json:"undated_kept,omitempty"`

	Ancora       string `json:"anchor,omitempty"`
	AncoraOrigem string `json:"anchor_origin,omitempty"`
	AncoraDe     string `json:"anchor_from,omitempty"`
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
