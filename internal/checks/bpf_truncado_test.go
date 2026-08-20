package checks

import (
	"testing"

	"github.com/lex0c/aletheia/internal/check"
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
	// O corte que importa para a rota de trampolim é o da lista de PROGRAMAS: é
	// ele que torna "trampolim sem programa" possivelmente o próprio teto.
	f.BPF.ProgramasCortado = true
	// simula um trampolim de tracing sem programa enumerado (a lista foi cortada)
	f.Ftrace = []facts.HookFtrace{{
		Simbolo: "__x64_sys_openat", Callback: "bpf_trampoline_123+0x0/0x10",
	}}
	// e um id citado que não está na lista
	f.BPF.Ocultos = nil // confirmarOcultosBPF já suprime na coleta; aqui garante o check

	r := bpfOculto.Run(bpfOculto, f, testEnv())
	for _, fd := range r.Findings {
		t.Errorf("com enumeração de programas cortada não pode haver achado de oculto: %v %s", fd.Sev, fd.Subject)
	}
	// e o inconclusivo tem de virar lacuna DECLARADA
	if len(r.Partial) == 0 {
		t.Error("truncagem com trampolim inexplicado tem de declarar lacuna, não silenciar")
	}
}

// O corte de OUTRO subsistema (link/pin/tail call) NÃO cancela a contradição de
// trampolim: se a lista de PROGRAMAS está completa, um trampolim sem programa é
// anomalia real. Antes, o Cortado agregado suprimia isso à toa (item da revisão).
func TestBpfHiddenTrampolimDisparaComSoLinksCortados(t *testing.T) {
	f := &facts.Facts{}
	f.BPF.Enumerado = true
	f.BPF.Cortado = true           // agregado ligado por corte de link/pin
	f.BPF.ProgramasCortado = false // MAS a lista de programas está completa
	f.Ftrace = []facts.HookFtrace{{
		Simbolo: "__x64_sys_openat", Callback: "bpf_trampoline_123+0x0/0x10",
	}}
	r := bpfOculto.Run(bpfOculto, f, testEnv())
	achou := false
	for _, fd := range r.Findings {
		if fd.Sev == check.SevCritical {
			achou = true
		}
	}
	if !achou {
		t.Error("programas completos + trampolim sem programa = CRÍTICO, mesmo com link/pin cortado")
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
