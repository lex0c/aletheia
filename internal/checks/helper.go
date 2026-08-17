package checks

import (
	"strings"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

func init() { check.Register(helperDoKernel) }

// helperDoKernel — runbook §7.12.
//
// # A classe de persistência que não passa por userland
//
// Toda a §7 pergunta "o que faz este host executar alguma coisa?", e responde
// olhando unit, cron, perfil de shell e hook de pacote. Todos são mecanismos de
// USERLAND: alguém agenda, alguém inicia, alguém faz login.
//
// Existe uma classe que não passa por nenhum deles — o próprio KERNEL guarda o
// nome de um programa e o executa, como root, por conta própria:
//
//	modprobe       disparado quando algo pede um módulo. `ip link add`, montar
//	               um filesystem, um socket de protocolo incomum: qualquer um
//	               serve de gatilho, e nenhum parece ataque
//	core_pattern   com "|" na frente, o kernel PIPA o core dump para o programa.
//	               O gatilho é um processo morrer com SIGSEGV — trivial de
//	               provocar, e o programa roda como root, no namespace inicial
//	uevent_helper  invocado a cada evento de dispositivo. Legado: em sistema
//	               moderno está vazio porque o udev escuta por netlink
//	binfmt_misc    interpretador registrado por assinatura de arquivo: executar
//	               um arquivo com aquele magic invoca o interpretador
//
// Não há unit para achar, não há processo pai suspeito, não há entrada de cron.
// Há uma linha num arquivo de uma linha.
//
// # O discriminador é o mesmo da §24
//
// Os quatro têm valor legítimo, e três vêm preenchidos de fábrica: num host com
// systemd o core_pattern aponta para o `systemd-coredump`, no Ubuntu para o
// `apport`, e um host com docker buildx tem meia dúzia de registros de binfmt
// para qemu. Acusar o mecanismo acusaria todos eles.
//
// O que a ferramenta pergunta é de onde vem o PROGRAMA. O que o kernel invoca
// como root deveria vir de um pacote — e quando não vem, ou quando está em
// diretório gravável, é a persistência mais silenciosa que este sistema oferece.
var helperDoKernel = check.Check{
	ID:       "persist.kernel_helper",
	Ref:      "7.12",
	Title:    "o kernel invoca um programa que nenhum pacote entregou",
	Group:    "persist",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive,
	Requires: env.CapFilesystem,
	Optional: env.CapRoot,
	Wtf:      true,
	FalsePositives: []string{
		"OS VALORES DE FÁBRICA NÃO DISPARAM: `core_pattern` apontando para o " +
			"systemd-coredump ou para o apport, `modprobe` em /sbin/modprobe e " +
			"binfmt de qemu vindo do qemu-user-static são o normal, e todos têm " +
			"dono de pacote",
		"KERNEL ANTIGO tem valor de fábrica onde o moderno tem vazio: até a série " +
			"4.x o uevent_helper vinha com /sbin/hotplug, e um guest de 3.18 " +
			"produziu exatamente esse aviso antes desta ressalva existir",
		"ferramenta INTERNA em /usr/local ou /opt cai aqui com severidade menor: " +
			"empresa que escreve o próprio coletor de core dump existe, e ali " +
			"não ter dono de pacote é a norma",
		"binfmt registrado por um contêiner (docker buildx instala qemu por " +
			"binfmt) aparece no host inteiro, porque o registro é global — e o " +
			"interpretador pode estar num caminho que o host não reconhece",
		"sem a base de pacotes legível a pergunta de propriedade não tem " +
			"resposta, e o que degrada é a cobertura",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		semDono := caminhosSemDono(f)

		for i := range f.Helpers {
			h := &f.Helpers[i]
			if h.Alvo == "" {
				continue // valor que não executa programa nenhum
			}

			sev, nota, acusa := pesoDoHelper(h, semDono)
			if !acusa {
				continue
			}
			ev := []string{
				h.Fonte + " = " + h.Valor,
				"o kernel executa isto COMO ROOT: " + gatilhoDe(h.Nome),
				nota,
			}
			if h.Nome == "modprobe" && !h.Padrao {
				ev = append(ev, "e o caminho não é o de fábrica: a distribuição "+
					"entrega /sbin/modprobe, e trocar este valor não deixa rastro "+
					"em unit, cron nem perfil de shell")
			}

			fd := self.F(sev, h.Nome, "", ev...)
			fd.Irreversible = true
			fd.NextSteps = []string{
				"guarde o valor atual antes de mexer: `cat " + h.Fonte + "`",
				"sudo cp " + h.Alvo + " \"$IR/\"   # a amostra, antes de qualquer coisa (runbook §6)",
				"compare com outro host da frota: o mesmo valor em vários é " +
					"provisionamento; em um só, é alteração (runbook §23)",
			}
			r.Findings = append(r.Findings, fd)
		}
		r.Partial = append(r.Partial, f.PersistDenied["pkg"]...)
		return r
	},
}

// pesoDoHelper decide, e é aqui que os valores de fábrica ficam calados.
//
// A escala é a mesma do §24, pela mesma razão: o que separa o coletor de core
// dump da distribuição de um implante não é o mecanismo — é de onde veio o
// programa e em que diretório ele está.
func pesoDoHelper(h *facts.HelperDoKernel, semDono map[string]bool) (check.Severity, string, bool) {
	if motivo, gravavel := suspectDir(h.Alvo); gravavel {
		// Nada se instala num diretório gravável de propósito, e o kernel
		// executando de lá não tem leitura inocente.
		return check.SevCritical, "e o programa está " + motivo, true
	}
	if semDono[h.Alvo] {
		if dirDePacote(h.Alvo) {
			return check.SevCritical, "e o programa está em diretório do " +
				"GERENCIADOR DE PACOTES e nenhum pacote o reivindica: tudo ali " +
				"deveria vir de um pacote", true
		}
		return check.SevWarn, "e nenhum pacote reivindica o programa — em " +
			"/usr/local ou /opt isso é comum, e o que dá sinal é o kernel " +
			"invocá-lo como root", true
	}
	// Alvo com dono de pacote. Dois mecanismos ainda merecem uma linha, porque
	// o ESTADO já é anômalo: um uevent_helper preenchido não existe em sistema
	// moderno, e um modprobe trocado é troca mesmo que o novo alvo venha de
	// pacote.
	switch {
	case h.Nome == "uevent_helper" && !h.Padrao:
		return check.SevWarn, "e este mecanismo está VAZIO em sistema moderno: " +
			"o udev escuta por netlink e o kernel não precisa executar nada", true
	case h.Nome == "modprobe" && !h.Padrao:
		return check.SevWarn, "o programa vem de pacote, mas não é o caminho de " +
			"fábrica: alguém trocou o helper", true
	}
	return check.SevInfo, "", false
}

// gatilhoDe diz O QUE faz o kernel executar aquilo. Sem isso o operador lê
// "o kernel invoca" e não sabe se o gatilho é raro ou trivial — e em três dos
// quatro ele é trivial.
func gatilhoDe(nome string) string {
	switch {
	case nome == "modprobe":
		return "qualquer coisa que peça um módulo dispara — montar um " +
			"filesystem, criar uma interface, abrir um socket de protocolo incomum"
	case nome == "core_pattern":
		return "qualquer processo que morra com SIGSEGV dispara, e provocar isso " +
			"é trivial para quem já tem uma conta"
	case nome == "uevent_helper":
		return "qualquer evento de dispositivo dispara"
	case strings.HasPrefix(nome, "binfmt:"):
		return "executar um arquivo com a assinatura registrada dispara"
	}
	return "o gatilho é um evento comum do sistema"
}
