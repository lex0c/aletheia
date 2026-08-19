package checks

import (
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/facts"
)

// --- kernel.binfmt_interpreter ---

// QEMU é o uso legítimo: interpretador com dono de pacote e magic longo (que só
// pega a arquitetura estrangeira). Não pode disparar.
func TestBinfmtQemuLegitimoNaoDispara(t *testing.T) {
	f := &facts.Facts{
		Binfmt: []facts.BinfmtRegistro{{
			Nome: "qemu-aarch64", Fonte: "/proc/sys/fs/binfmt_misc/qemu-aarch64",
			Interpreter: "/usr/bin/qemu-aarch64-static", Habilitado: true,
			Magic: "7f454c460201010000000000000000000200b700",
		}},
		Ownership: []facts.Ownership{{Path: "/usr/bin/qemu-aarch64-static", Owned: true}},
	}
	if r := binfmtInterpreter.Run(binfmtInterpreter, f, testEnv()); len(r.Findings) != 0 {
		t.Errorf("qemu de pacote não pode disparar: %+v", r.Findings)
	}
}

// Interpretador em diretório gravável é crítico: nada se instala em /tmp.
func TestBinfmtInterpretadorEmTmpECritico(t *testing.T) {
	f := &facts.Facts{Binfmt: []facts.BinfmtRegistro{{
		Nome: "x", Fonte: "/proc/sys/fs/binfmt_misc/x",
		Interpreter: "/tmp/.x", Habilitado: true,
	}}}
	r := binfmtInterpreter.Run(binfmtInterpreter, f, testEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevCritical {
		t.Fatalf("achados = %+v, quer 1 CRITICAL", r.Findings)
	}
}

// O caso de maior impacto: magic que casa com ELF NATIVO sequestra TODA
// execução do host, e é CRITICAL mesmo com o interpretador tendo dono de
// pacote — nenhum uso legítimo faz isso.
func TestBinfmtMagicELFNativoECriticoMesmoComDono(t *testing.T) {
	f := &facts.Facts{
		Binfmt: []facts.BinfmtRegistro{{
			Nome: "sequestro", Fonte: "/proc/sys/fs/binfmt_misc/sequestro",
			// O kernel SEMPRE publica `offset %i` num registro por magic
			// (bm_entry_show, fs/binfmt_misc.c): uma fixture sem offset descreve
			// um estado que /proc não produz.
			Interpreter: "/usr/bin/interp", Habilitado: true,
			Magic: "7f454c46", Offset: 0, OffsetLido: true,
		}},
		Ownership: []facts.Ownership{{Path: "/usr/bin/interp", Owned: true}},
	}
	r := binfmtInterpreter.Run(binfmtInterpreter, f, testEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevCritical {
		t.Fatalf("achados = %+v, quer 1 CRITICAL", r.Findings)
	}
	if !strings.Contains(strings.Join(r.Findings[0].Evidence, " "), "ELF NATIVO") {
		t.Errorf("a evidência precisa dizer que sequestra ELF nativo: %v", r.Findings[0].Evidence)
	}
}

// sequestraELFNativo discrimina por magic, COMPRIMENTO e OFFSET. O cabeçalho de
// 4 bytes no byte 0 pega tudo; o magic longo do QEMU restringe a arquitetura; e
// o mesmo magic num offset diferente não é sequestro de coisa nenhuma.
func TestSequestraELFNativoExigeOffsetZero(t *testing.T) {
	reg := func(magic string, off int, lido bool) *facts.BinfmtRegistro {
		return &facts.BinfmtRegistro{Magic: magic, Offset: off, OffsetLido: lido}
	}
	if !sequestraELFNativo(reg("7f454c46", 0, true)) {
		t.Error("magic de 4 bytes no offset 0 casa com ELF nativo")
	}
	if sequestraELFNativo(reg("7f454c460201010000000000000000000200b700", 0, true)) {
		t.Error("magic longo do QEMU NÃO casa com ELF nativo — restringe a arquitetura")
	}
	if sequestraELFNativo(reg("cafebabe", 0, true)) {
		t.Error("magic que não é ELF não conta")
	}
	// O byte 100 por acaso ser 0x7f não sequestra a execução do host.
	if sequestraELFNativo(reg("7f454c46", 100, true)) {
		t.Error("o cabeçalho ELF mora no byte 0: offset 100 não é sequestro")
	}
	// Offset não lido não vira offset 0: o zero do Go é o caso mais grave, e
	// produzir o achado mais forte a partir de leitura que falhou é a inversão
	// que a ferramenta não pode cometer.
	if sequestraELFNativo(reg("7f454c46", 0, false)) {
		t.Error("sem offset lido não se pode AFIRMAR sequestro")
	}
}

// Registro desabilitado não roteia agora: desce para INFO, mas continua no
// relatório porque um echo o reativa.
func TestBinfmtDesabilitadoDesceParaInfo(t *testing.T) {
	f := &facts.Facts{
		Binfmt: []facts.BinfmtRegistro{{
			Nome: "x", Fonte: "/proc/sys/fs/binfmt_misc/x",
			Interpreter: "/usr/local/bin/x", Habilitado: false,
		}},
		Ownership: []facts.Ownership{{Path: "/usr/local/bin/x", Owned: false}},
	}
	r := binfmtInterpreter.Run(binfmtInterpreter, f, testEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevInfo {
		t.Fatalf("achados = %+v, quer 1 INFO (desabilitado)", r.Findings)
	}
}

// A flag F é anotada: o interpretador é fixado no registro, e trocar o arquivo
// em disco não muda o que roda.
func TestBinfmtFlagFEhAnotada(t *testing.T) {
	f := &facts.Facts{
		Binfmt: []facts.BinfmtRegistro{{
			Nome: "x", Fonte: "/proc/sys/fs/binfmt_misc/x",
			Interpreter: "/usr/local/bin/x", Habilitado: true, Flags: "OCF",
		}},
		Ownership: []facts.Ownership{{Path: "/usr/local/bin/x", Owned: false}},
	}
	r := binfmtInterpreter.Run(binfmtInterpreter, f, testEnv())
	if !strings.Contains(strings.Join(r.Findings[0].Evidence, " "), "flag F") {
		t.Errorf("a flag F precisa ser anotada: %v", r.Findings[0].Evidence)
	}
}

// --- persist.binfmt_config ---

// qemu-user-static entrega /usr/lib/binfmt.d/qemu-*.conf com dono: não dispara.
func TestBinfmtConfigQemuNaoDispara(t *testing.T) {
	f := &facts.Facts{
		BinfmtConfig: []facts.BinfmtConfig{{
			Fonte: "/usr/lib/binfmt.d/qemu-aarch64.conf", Nome: "qemu-aarch64",
			Interpreter: "/usr/bin/qemu-aarch64-static",
		}},
		Ownership: []facts.Ownership{{Path: "/usr/bin/qemu-aarch64-static", Owned: true}},
	}
	if r := binfmtConfig.Run(binfmtConfig, f, testEnv()); len(r.Findings) != 0 {
		t.Errorf("qemu de pacote não dispara: %+v", r.Findings)
	}
}

// Config com interpretador sem dono: a persistência que volta no boot.
func TestBinfmtConfigInterpretadorSuspeitoDispara(t *testing.T) {
	f := &facts.Facts{BinfmtConfig: []facts.BinfmtConfig{{
		Fonte: "/etc/binfmt.d/evil.conf", Nome: "evil", Interpreter: "/tmp/.x",
	}}}
	r := binfmtConfig.Run(binfmtConfig, f, testEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevCritical {
		t.Fatalf("achados = %+v, quer 1 CRITICAL", r.Findings)
	}
	if !strings.Contains(strings.Join(r.Findings[0].Evidence, " "), "reaplica isto no boot") {
		t.Errorf("a evidência precisa dizer que volta no boot: %v", r.Findings[0].Evidence)
	}
}
