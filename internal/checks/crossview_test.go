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

// O filtro de corrida MUDOU DE LUGAR, e a mudança tem motivo.
//
// A primeira versão descartava diferença de 1 aqui, no check. Não bastou: o
// helper desta suíte, que é Go, produziu uma diferença de 5 num contêiner —
// runtime com pool encerra threads em rajada, e nenhum limiar fixo separa isso
// de ocultação.
//
// O que separa é PERSISTIR. O coletor relê as duas fontes e só entrega o que
// sobreviveu à segunda leitura, então tudo que chega aqui já foi confirmado — e
// o check não pode descartar mais nada sem descartar ocultação real.
func TestThreadOcultaReportaOQueOColetorConfirmou(t *testing.T) {
	f := &facts.Facts{
		Processes: []facts.Process{{PID: 11, Comm: "x"}},
		Cross: facts.CrossView{Threads: []facts.ThreadDiff{
			{PID: 11, Status: 8, Task: 3},
		}},
	}
	r := threadOculta.Run(threadOculta, f, testEnv())
	if len(r.Findings) != 1 || r.Findings[0].Subject != "pid=11" {
		t.Fatalf("achados = %v", r.Findings)
	}
	if !strings.Contains(strings.Join(r.Findings[0].Evidence, " "), "status declara 8") {
		t.Error("a evidência precisa trazer os DOIS números: sem eles o operador " +
			"não sabe o tamanho da divergência")
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

// O achado do ftrace vira CRÍTICO e nomeia o módulo. É a via que pega o LKM que
// o crossview de sysfs não pega — ver test/vm/ftrace-hidden-module.sh.
func TestModuloEscondidoNoFtraceViraCritico(t *testing.T) {
	f := &facts.Facts{Cross: facts.CrossView{
		ModFtraceDiff: []string{"evil tem função rastreável no ftrace e NÃO está em /proc/modules"},
	}}
	r := moduloDivergente.Run(moduloDivergente, f, testEnv())
	if len(r.Findings) != 1 {
		t.Fatalf("achados = %v", r.Findings)
	}
	if r.Findings[0].Sev != check.SevCritical {
		t.Errorf("sev = %v, queria crítico", r.Findings[0].Sev)
	}
	if !strings.Contains(r.Findings[0].Subject, "evil") {
		t.Errorf("o módulo precisa ser nomeado no subject: %q", r.Findings[0].Subject)
	}
	if !strings.Contains(strings.Join(r.Findings[0].NextSteps, " "), "available_filter_functions") {
		t.Error("o passo seguinte precisa apontar para a interface que ainda tem o módulo")
	}
}

// As duas vias de módulo coexistem sem se atropelar: sysfs e ftrace são
// achados distintos, e um host com os dois problemas reporta os dois.
func TestAsDuasViasDeModuloConvivem(t *testing.T) {
	f := &facts.Facts{Cross: facts.CrossView{
		ModDiff:       []string{"rk está em /proc/modules e NÃO em /sys/module"},
		ModFtraceDiff: []string{"evil tem função rastreável no ftrace e NÃO está em /proc/modules"},
	}}
	r := moduloDivergente.Run(moduloDivergente, f, testEnv())
	if len(r.Findings) != 2 {
		t.Fatalf("as duas vias são achados separados: %v", r.Findings)
	}
}

// Regressão do loop duplicado: um módulo escondido (ModFtraceDiff) é achado de
// cross.module_view e SÓ dele. pidOculto tinha um loop copiado que o fazia
// virar cross.hidden_pid também — errado, e pior: cross.hidden_pid é
// kernelBreaker, então o relatório passava a acusar "um PID responde a /proc"
// sem PID oculto nenhum. O teste antigo exercitava moduloDivergente direto e
// não via a duplicação.
func TestModuloEscondidoNaoViraPidOculto(t *testing.T) {
	f := &facts.Facts{Cross: facts.CrossView{
		ModFtraceDiff: []string{"evil tem função rastreável no ftrace e NÃO está em /proc/modules"},
	}}
	if r := pidOculto.Run(pidOculto, f, testEnv()); len(r.Findings) != 0 {
		t.Errorf("pidOculto tem de IGNORAR ModFtraceDiff — módulo não é PID oculto: %v", r.Findings)
	}
	r := moduloDivergente.Run(moduloDivergente, f, testEnv())
	if len(r.Findings) != 1 || r.Findings[0].ID != "cross.module_view" {
		t.Errorf("moduloDivergente é o ÚNICO que reporta o módulo escondido: %v", r.Findings)
	}
}
