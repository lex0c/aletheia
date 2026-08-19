package checks

import (
	"strings"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

func init() {
	check.Register(binfmtInterpreter)
	check.Register(binfmtConfig)
}

// magicELF é o cabeçalho \x7fELF em hex. Um registro cujo magic é EXATAMENTE
// isto casa com TODO ELF — inclusive o nativo —, e portanto sequestra a
// execução do host inteiro. O QEMU casa ELF também, mas o magic dele é longo
// (20 bytes) e inclui o e_machine, então só pega a arquitetura estrangeira.
const magicELF = "7f454c46"

// sequestraELFNativo diz se o magic casa com ELF nativo. O discriminador é o
// COMPRIMENTO: só o cabeçalho de 4 bytes (ou menos) casa com qualquer ELF; o
// magic do QEMU é longo e restringe a arquitetura.
func sequestraELFNativo(magic string) bool {
	magic = strings.ReplaceAll(magic, " ", "")
	return strings.HasPrefix(magic, magicELF) && len(magic) <= 8
}

// binfmtInterpreter — runbook §7.12.
//
// # O kernel está roteando execução AGORA
//
// Um registro em /proc/sys/fs/binfmt_misc associa uma assinatura de arquivo a
// um interpretador: executar um arquivo que casa faz o kernel invocar aquele
// programa. QEMU e Wine são os usos legítimos — a documentação do próprio
// kernel usa o Wine de exemplo —, e por isso o discriminador é de onde vem o
// interpretador, nunca o mecanismo.
//
// # Dois gatilhos independentes
//
//	interpretador sem dono ou em diretório gravável   a escada do §24
//	magic que casa com ELF NATIVO                      sequestra TODA execução,
//	                                                   e nenhum uso legítimo faz
//	                                                   isso — nem QEMU, nem Wine
var binfmtInterpreter = check.Check{
	ID:       "kernel.binfmt_interpreter",
	Ref:      "7.12",
	Title:    "o kernel roteia execução para um interpretador registrado",
	Group:    "kernel",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive,
	Requires: env.CapProcfs,
	Optional: env.CapRoot | env.CapPkgDB,
	Wtf:      true,
	FalsePositives: []string{
		"QEMU e Wine são os usos LEGÍTIMOS do binfmt e vêm de pacote: um host " +
			"com docker buildx tem meia dúzia de registros de qemu-user-static, " +
			"todos com dono, e nenhum casa com ELF nativo — o magic deles é longo " +
			"e restringe a arquitetura",
		"registro por CONTÊINER aparece no host inteiro (o registro é global), e " +
			"o interpretador pode estar num caminho que o host não reconhece",
		"sem a base de pacotes legível a pergunta de propriedade não tem resposta, " +
			"e o que degrada é a cobertura",
		"registro DESABILITADO não roteia agora, e sai como INFO — mas continua " +
			"registrado, e um `echo 1 > .../nome` o reativa sem deixar outro rastro",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		// Registro ativo cujo corpo o coletor não entendeu vira lacuna, não
		// silêncio: o kernel está roteando execução para algum lugar agora.
		r.Partial = append(r.Partial, f.Partial["binfmt"]...)
		semDono := caminhosSemDono(f)
		for i := range f.Binfmt {
			b := &f.Binfmt[i]

			// Um registro 'B' liga VÁRIOS interpretadores e nenhum deles está
			// no campo Interpreter. Pesa-se o pior de todos, e a evidência
			// nomeia justamente esse.
			var sev check.Severity
			var nota, alvo string
			var acusa bool
			for _, c := range b.Interpretadores() {
				s, n, a := pesoDoInterpretador(c, semDono)
				if a && (!acusa || s > sev) {
					sev, nota, alvo, acusa = s, n, c, true
				}
			}
			elf := sequestraELFNativo(b.Magic)
			if elf {
				// Sequestro de ELF nativo é crítico por si só, doa a quem doer o
				// interpretador: nenhum uso legítimo casa com o binário nativo.
				sev, acusa = check.SevCritical, true
			}
			if !acusa {
				continue
			}

			ev := []string{
				b.Fonte + " → interpreter=" + nz(alvo, nz(b.Interpreter, "(nenhum)")),
				"executar um arquivo com a assinatura registrada faz o kernel rodar isto",
			}
			if b.BPFOps != "" {
				ev = append(ev, "registro do tipo 'B' (bpf): o roteamento é decidido "+
					"por um programa eBPF chamado "+b.BPFOps+", e o conjunto de "+
					"interpretadores ligados a ele pode crescer sem tocar neste arquivo")
			}
			if elf {
				ev = append(ev, "e o magic casa com ELF NATIVO (7f454c46): este registro "+
					"sequestra TODA execução de binário do host — nenhum QEMU/Wine faz isso")
			}
			if nota != "" {
				ev = append(ev, nota)
			}
			if strings.ContainsRune(b.Flags, 'F') {
				ev = append(ev, "flag F: o interpretador é ABERTO e fixado no registro — "+
					"trocar o arquivo em disco depois NÃO muda o que roda, e limpar o "+
					"disco não desfaz a persistência")
			}
			if !b.Habilitado {
				ev = append(ev, "registro DESABILITADO: não roteia agora, mas continua "+
					"registrado e pode ser reativado")
				if sev == check.SevWarn {
					sev = check.SevInfo
				}
			}

			fd := self.F(sev, b.Nome, "", ev...)
			fd.Irreversible = true
			fd.NextSteps = []string{
				"guarde o registro antes de mexer: `cat " + check.Arg(b.Fonte) + "`",
				"desative-o escrevendo -1 nele: `echo -1 | sudo tee " + check.Arg(b.Fonte) + "`",
				"e veja se ele volta no boot — a persistência mora em /etc/binfmt.d " +
					"e /usr/lib/binfmt.d (persist.binfmt_config)",
			}
			r.Findings = append(r.Findings, fd)
		}
		return r
	},
}

// binfmtConfig — runbook §7.12.
//
// # Isso VOLTA depois do reboot
//
// O registro vivo some no reboot; a configuração em /etc/binfmt.d e
// /usr/lib/binfmt.d é o que o systemd-binfmt reaplica. É a persistência, e vale
// em modo image — onde o kernel é o do analista e ocultamento não acontece.
var binfmtConfig = check.Check{
	ID:       "persist.binfmt_config",
	Ref:      "7.12",
	Title:    "configuração de binfmt que recria um interpretador no boot",
	Group:    "persist",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Optional: env.CapRoot | env.CapPkgDB,
	Wtf:      true,
	FalsePositives: []string{
		"qemu-user-static entrega /usr/lib/binfmt.d/qemu-*.conf com dono de " +
			"pacote: é o normal em host com emulação, e a pergunta de propriedade " +
			"o reconhece",
		"o que dá sinal é o interpretador — sem dono, em diretório gravável — e " +
			"não a presença de um .conf de binfmt",
		"sem a base de pacotes legível a pergunta de propriedade não tem resposta",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		semDono := caminhosSemDono(f)
		for i := range f.BinfmtConfig {
			c := &f.BinfmtConfig[i]
			sev, nota, acusa := pesoDoInterpretador(c.Interpreter, semDono)
			if !acusa {
				continue
			}
			ev := []string{
				c.Fonte + " → interpreter=" + c.Interpreter,
				"o systemd-binfmt reaplica isto no boot: o registro volta mesmo depois " +
					"de removido do kernel vivo",
				nota,
			}
			if strings.ContainsRune(c.Flags, 'F') {
				ev = append(ev, "flag F: o interpretador é fixado no registro")
			}
			fd := self.F(sev, baseDe(c.Fonte)+":"+c.Nome, "", ev...)
			fd.Irreversible = true
			fd.NextSteps = []string{
				"guarde o arquivo antes de mexer: sudo cp " + check.Arg(c.Fonte) + " \"$IR/\"",
				"compare com outro host da frota: o mesmo .conf em vários é " +
					"provisionamento; em um só, é alteração (runbook §23)",
			}
			r.Findings = append(r.Findings, fd)
		}
		r.Partial = append(r.Partial, f.PersistDenied["binfmt"]...)
		return r
	},
}

// pesoDoInterpretador é a escada do §24 aplicada ao programa que o kernel
// invoca por binfmt. É a MESMA lógica do pesoDoHelper, por decisão: o que
// separa o QEMU legítimo de um implante não é o mecanismo, é de onde vem o
// binário e em que diretório ele está.
func pesoDoInterpretador(alvo string, semDono map[string]bool) (check.Severity, string, bool) {
	if alvo == "" {
		return check.SevInfo, "", false
	}
	if motivo, gravavel := suspectDir(alvo); gravavel {
		return check.SevCritical, "e o interpretador está " + motivo +
			": nada se instala ali de propósito", true
	}
	if semDono[alvo] {
		if dirDePacote(alvo) {
			return check.SevCritical, "e o interpretador está em diretório do " +
				"gerenciador de pacotes e nenhum pacote o reivindica", true
		}
		return check.SevWarn, "e nenhum pacote reivindica o interpretador — em " +
			"/usr/local ou /opt isso é comum, e o que dá sinal é o kernel invocá-lo", true
	}
	return check.SevInfo, "", false
}
