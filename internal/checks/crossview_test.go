package checks

import (
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/facts"
)

// As duas vias não valem o mesmo. A do ppid não tem corrida — o filho existe
// AGORA e declara o pai —, e por isso é crítica. A sondagem pode pegar processo
// nascido entre a listagem e ela.
func TestPidOcultoSeveridadePelaVia(t *testing.T) {
	f := &facts.Facts{Cross: facts.CrossView{
		ProbeAte: 40000, PidMax: 4194304,
		Hidden: []facts.HiddenPid{
			{PID: 666, Como: "ppid de processo visível", Comm: "x"},
			{PID: 777, Como: "sondagem: responde a stat e não aparece na listagem", Comm: "y"},
		},
	}}
	r := pidOculto.Run(pidOculto, f, testEnv())
	sev := map[string]check.Severity{}
	for _, fd := range r.Findings {
		sev[fd.Subject] = fd.Sev
	}
	if sev["pid=666"] != check.SevCritical {
		t.Error("a via do ppid não tem corrida: a listagem é que omitiu")
	}
	if sev["pid=777"] != check.SevWarn {
		t.Error("a sondagem pode pegar processo recém-nascido")
	}
	// Sem dizer até onde sondou, "nenhum PID oculto" não significa nada.
	if !strings.Contains(strings.Join(r.Findings[0].Evidence, " "), "sondagem foi até") {
		t.Error("o alcance da sondagem precisa aparecer na evidência")
	}
}

// Runtime com pool de threads cria e encerra thread o tempo todo: uma de
// diferença entre as duas leituras é corrida, não ocultação.
func TestThreadOcultaIgnoraDiferencaDeUm(t *testing.T) {
	f := &facts.Facts{
		Processes: []facts.Process{{PID: 10, Comm: "java"}, {PID: 11, Comm: "x"}},
		Cross: facts.CrossView{Threads: []facts.ThreadDiff{
			{PID: 10, Status: 41, Task: 40}, // corrida de pool
			{PID: 11, Status: 8, Task: 3},   // divergência real
		}},
	}
	r := threadOculta.Run(threadOculta, f, testEnv())
	if len(r.Findings) != 1 || r.Findings[0].Subject != "pid=11" {
		t.Fatalf("achados = %v", r.Findings)
	}
}

func TestModuloDivergenteReportaSoUmaDirecao(t *testing.T) {
	f := &facts.Facts{Cross: facts.CrossView{
		ModDiff: []string{"rootkit está em /proc/modules e NÃO em /sys/module"},
	}}
	r := moduloDivergente.Run(moduloDivergente, f, testEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevCritical {
		t.Fatalf("achados = %v", r.Findings)
	}
	if !strings.Contains(strings.Join(r.Findings[0].NextSteps, " "), "§35.6") {
		t.Error("depois disto, resultado vindo do host não vale: precisa mandar analisar de fora")
	}
}

// A sondagem sem alcance declarado é pior que nenhuma sondagem.
func TestPidOcultoDeclaraTruncamento(t *testing.T) {
	f := &facts.Facts{Partial: map[string][]string{
		"cross": {"sondagem de PID foi até 65536 de um pid_max de 4194304"},
	}}
	if r := pidOculto.Run(pidOculto, f, testEnv()); len(r.Partial) == 0 {
		t.Error("sondagem truncada precisa virar cobertura parcial")
	}
}
