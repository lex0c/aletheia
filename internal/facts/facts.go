// Package facts coleta o estado do host UMA vez, para que os checks sejam
// funções puras sobre o resultado (SPEC 3, princípio 1).
//
// Consequência prática: todo check é testável sem root e sem host comprometido,
// bastando uma fixture. Consequência de projeto: correlação é possível, porque
// os fatos de rede, processo e systemd estão no mesmo lugar.
//
// Regra que atravessa o pacote: campo ausente nunca vira zero. Vira "desconhecido",
// e quem dependia dele reporta cobertura parcial.
package facts

import (
	"github.com/lex0c/aletheia/internal/env"
)

// SchemaVersion versiona o facts.json. Um binário novo lendo um dump antigo
// precisa saber o que mudou — e isso acontece no meio de incidente, com a VM
// já destruída.
const SchemaVersion = 1

// Facts é o retrato do host.
type Facts struct {
	SchemaVersion int    `json:"schema_version"`
	CollectedAt   string `json:"collected_at"` // RFC3339 UTC
	Source        string `json:"source"`       // live | image

	Host      Host      `json:"host"`
	Processes []Process `json:"processes,omitempty"`

	// Partial registra o que a própria coleta não conseguiu ler, por coletor.
	// Não é o mesmo que "não havia nada": é "não deu para olhar".
	Partial map[string][]string `json:"partial,omitempty"`
}

func (f *Facts) partial(collector, reason string) {
	if f.Partial == nil {
		f.Partial = map[string][]string{}
	}
	f.Partial[collector] = append(f.Partial[collector], reason)
}

// Collect roda os coletores disponíveis para o ambiente sondado.
func Collect(e *env.Env) *Facts {
	f := &Facts{
		SchemaVersion: SchemaVersion,
		CollectedAt:   e.Now.Format("2006-01-02T15:04:05Z"),
		Source:        e.Source.String(),
	}

	collectHost(f, e)

	if e.Has(env.CapProcfs) {
		collectProcesses(f, e)
	} else {
		f.partial("proc", e.Reason(env.CapProcfs))
	}

	return f
}

// ProcessByPID devolve o processo, ou nil.
func (f *Facts) ProcessByPID(pid int) *Process {
	for i := range f.Processes {
		if f.Processes[i].PID == pid {
			return &f.Processes[i]
		}
	}
	return nil
}
