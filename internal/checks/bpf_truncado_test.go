package checks

import (
	"testing"

	"github.com/lex0c/aletheia/internal/facts"
	"github.com/lex0c/aletheia/internal/kbpf"
)

// cross.bpf_hidden é kernelBreaker: um CRÍTICO irreversível. Com a enumeração
// truncada, "citado e não listado" e "trampolim sem programa" podem ser o
// próprio teto, não manipulação — e não podem virar achado.
func TestBpfHiddenNaoAcusaComEnumeracaoCortada(t *testing.T) {
	f := &facts.Facts{}
	f.BPF.Enumerado = true
	f.BPF.Cortado = true
	// simula um trampolim de tracing sem programa enumerado (a lista foi cortada)
	f.Ftrace = []facts.HookFtrace{{
		Simbolo: "__x64_sys_openat", Callback: "bpf_trampoline_123+0x0/0x10",
	}}
	// e um id citado que não está na lista
	f.BPF.Ocultos = nil // confirmarOcultosBPF já suprime na coleta; aqui garante o check

	r := bpfOculto.Run(bpfOculto, f, testEnv())
	for _, fd := range r.Findings {
		t.Errorf("com enumeração cortada não pode haver achado de oculto: %v %s", fd.Sev, fd.Subject)
	}
	// e o inconclusivo tem de virar lacuna DECLARADA
	if len(r.Partial) == 0 {
		t.Error("truncagem com trampolim inexplicado tem de declarar lacuna, não silenciar")
	}
}

// Controle: com a enumeração COMPLETA, o trampolim sem programa continua sendo
// o CRÍTICO que este check existe para dar.
func TestBpfHiddenAcusaComEnumeracaoCompleta(t *testing.T) {
	f := &facts.Facts{}
	f.BPF.Enumerado = true
	f.BPF.Cortado = false
	f.Ftrace = []facts.HookFtrace{{
		Simbolo: "__x64_sys_openat", Callback: "bpf_trampoline_123+0x0/0x10",
	}}
	// nenhum programa de tipo-trampolim enumerado
	r := bpfOculto.Run(bpfOculto, f, testEnv())
	achou := false
	for _, fd := range r.Findings {
		if fd.Subject == "trampolim de eBPF" {
			achou = true
		}
	}
	if !achou {
		t.Errorf("com lista completa e trampolim sem programa, é CRÍTICO: %+v / partial=%v", r.Findings, r.Partial)
	}
}

var _ = kbpf.FixSocket
