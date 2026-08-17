package checks

import (
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/facts"
)

func fatosDeHelper(hs []facts.HelperDoKernel, donos map[string]bool) *facts.Facts {
	f := &facts.Facts{Helpers: hs, Pkg: facts.PkgDB{Kind: "dpkg"}}
	for p, dono := range donos {
		f.Ownership = append(f.Ownership, facts.Ownership{Path: p, Owned: dono})
	}
	return f
}

// O caso que decide se o check é usável: os valores de FÁBRICA não podem
// disparar. Este par saiu de um desktop real — core_pattern apontando para o
// systemd-coredump e modprobe em /sbin/modprobe.
func TestHelperDeFabricaNaoDispara(t *testing.T) {
	f := fatosDeHelper([]facts.HelperDoKernel{
		{Nome: "core_pattern", Fonte: "/proc/sys/kernel/core_pattern",
			Valor: "|/usr/lib/systemd/systemd-coredump %P %u %g",
			Alvo:  "/usr/lib/systemd/systemd-coredump"},
		{Nome: "modprobe", Fonte: "/proc/sys/kernel/modprobe",
			Valor: "/sbin/modprobe", Alvo: "/sbin/modprobe", Padrao: true},
		// uevent_helper vazio é o normal em sistema moderno: sem alvo, sem achado.
		{Nome: "uevent_helper", Fonte: "/sys/kernel/uevent_helper", Padrao: true},
		// binfmt de qemu vindo do pacote: é o que docker buildx instala.
		{Nome: "binfmt:qemu-aarch64", Fonte: "/proc/sys/fs/binfmt_misc/qemu-aarch64",
			Valor: "/usr/bin/qemu-aarch64-static", Alvo: "/usr/bin/qemu-aarch64-static"},
	}, map[string]bool{
		"/usr/lib/systemd/systemd-coredump": true,
		"/sbin/modprobe":                    true,
		"/usr/bin/qemu-aarch64-static":      true,
	})
	if r := helperDoKernel.Run(helperDoKernel, f, testEnv()); len(r.Findings) != 0 {
		t.Errorf("valor de fábrica não pode disparar: %v", r.Findings)
	}
}

// E o oposto: o kernel executando algo de diretório gravável não tem leitura
// inocente. O gatilho precisa estar dito — sem ele o operador não sabe se é
// raro ou trivial, e no core_pattern é trivial.
func TestHelperEmDiretorioGravavelEhCritico(t *testing.T) {
	f := fatosDeHelper([]facts.HelperDoKernel{
		{Nome: "core_pattern", Fonte: "/proc/sys/kernel/core_pattern",
			Valor: "|/tmp/.x", Alvo: "/tmp/.x"},
		{Nome: "modprobe", Fonte: "/proc/sys/kernel/modprobe",
			Valor: "/dev/shm/.m", Alvo: "/dev/shm/.m"},
	}, nil)
	r := helperDoKernel.Run(helperDoKernel, f, testEnv())
	if len(r.Findings) != 2 {
		t.Fatalf("achados = %v", r.Findings)
	}
	for _, fd := range r.Findings {
		if fd.Sev != check.SevCritical {
			t.Errorf("%s: sev = %v, queria CRITICAL", fd.Subject, fd.Sev)
		}
		if !fd.Irreversible {
			t.Errorf("%s: o valor some no reboot — o achado é irreversível", fd.Subject)
		}
		junto := strings.Join(fd.Evidence, " | ")
		if !strings.Contains(junto, "COMO ROOT") {
			t.Errorf("%s: falta dizer que o kernel executa como root: %q", fd.Subject, junto)
		}
	}
	// O gatilho do core_pattern é o que torna o achado acionável.
	if !strings.Contains(strings.Join(r.Findings[0].Evidence, " "), "SIGSEGV") {
		t.Errorf("o gatilho do core_pattern precisa estar dito: %v", r.Findings[0].Evidence)
	}
}

// Ferramenta interna em /usr/local existe, e ali não ter dono de pacote é a
// norma. Continua valendo olhar — o kernel a executa como root —, mas é aviso.
func TestHelperEmUsrLocalEhAviso(t *testing.T) {
	f := fatosDeHelper([]facts.HelperDoKernel{
		{Nome: "core_pattern", Fonte: "/proc/sys/kernel/core_pattern",
			Valor: "|/usr/local/sbin/coletor-de-core", Alvo: "/usr/local/sbin/coletor-de-core"},
	}, map[string]bool{"/usr/local/sbin/coletor-de-core": false})
	r := helperDoKernel.Run(helperDoKernel, f, testEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevWarn {
		t.Fatalf("achados = %v", r.Findings)
	}
}

// Em diretório do gerenciador de pacotes, sem dono, é outra conversa: tudo ali
// deveria vir de um pacote.
func TestHelperEmDiretorioDePacoteSemDonoEhCritico(t *testing.T) {
	f := fatosDeHelper([]facts.HelperDoKernel{
		{Nome: "modprobe", Fonte: "/proc/sys/kernel/modprobe",
			Valor: "/usr/sbin/modprobe-real", Alvo: "/usr/sbin/modprobe-real"},
	}, map[string]bool{"/usr/sbin/modprobe-real": false})
	r := helperDoKernel.Run(helperDoKernel, f, testEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevCritical {
		t.Fatalf("achados = %v", r.Findings)
	}
	if !strings.Contains(strings.Join(r.Findings[0].Evidence, " "), "não é o de fábrica") {
		t.Errorf("o desvio do caminho de fábrica precisa aparecer: %v", r.Findings[0].Evidence)
	}
}

// Dois estados que são anômalos por si, mesmo com o alvo vindo de pacote: um
// uevent_helper preenchido não existe em sistema moderno, e um modprobe trocado
// é troca — o programa novo vir de pacote não desfaz a troca.
func TestHelperComDonoMasEstadoAnomalo(t *testing.T) {
	// O uevent_helper aqui NÃO é o /sbin/hotplug de fábrica: é outro caminho,
	// vindo de pacote, num mecanismo que em sistema moderno fica vazio.
	f := fatosDeHelper([]facts.HelperDoKernel{
		{Nome: "uevent_helper", Fonte: "/sys/kernel/uevent_helper",
			Valor: "/usr/sbin/uevent-forwarder", Alvo: "/usr/sbin/uevent-forwarder"},
		{Nome: "modprobe", Fonte: "/proc/sys/kernel/modprobe",
			Valor: "/usr/bin/env", Alvo: "/usr/bin/env"},
	}, map[string]bool{"/usr/sbin/uevent-forwarder": true, "/usr/bin/env": true})
	r := helperDoKernel.Run(helperDoKernel, f, testEnv())
	if len(r.Findings) != 2 {
		t.Fatalf("achados = %v", r.Findings)
	}
	for _, fd := range r.Findings {
		if fd.Sev != check.SevWarn {
			t.Errorf("%s: sev = %v, queria WARN", fd.Subject, fd.Sev)
		}
	}
}

// core_pattern sem o cano é modelo de NOME DE ARQUIVO: não executa nada, e
// acusá-lo acusaria todo host que só escolheu onde gravar o core.
func TestHelperSemProgramaNaoDispara(t *testing.T) {
	f := fatosDeHelper([]facts.HelperDoKernel{
		{Nome: "core_pattern", Fonte: "/proc/sys/kernel/core_pattern",
			Valor: "/var/crash/core.%e.%p", Padrao: true},
	}, nil)
	if r := helperDoKernel.Run(helperDoKernel, f, testEnv()); len(r.Findings) != 0 {
		t.Errorf("modelo de nome de arquivo não executa nada: %v", r.Findings)
	}
}

// O valor de fábrica de um kernel ANTIGO não pode virar achado.
//
// Até a série 4.x o CONFIG_UEVENT_HELPER_PATH vinha preenchido com
// /sbin/hotplug, e a regra "vazio é o normal" — que vale para kernel moderno —
// acusava um guest de 3.18 pelo estado de fábrica dele. Foi o kernel legado da
// suíte que pegou, pela terceira vez.
//
// O que continua protegido é o caso que importa: se alguém CRIAR um
// /sbin/hotplug, o arquivo passa a existir, a propriedade é perguntada, e um
// binário sem dono em diretório de pacote continua crítico.
func TestUeventHelperDeKernelAntigoNaoDispara(t *testing.T) {
	fabrica := fatosDeHelper([]facts.HelperDoKernel{
		{Nome: "uevent_helper", Fonte: "/sys/kernel/uevent_helper",
			Valor: "/sbin/hotplug", Alvo: "/sbin/hotplug", Padrao: true},
	}, nil)
	if r := helperDoKernel.Run(helperDoKernel, fabrica, testEnv()); len(r.Findings) != 0 {
		t.Errorf("o padrão do kernel antigo não pode virar achado: %v", r.Findings)
	}

	plantado := fatosDeHelper([]facts.HelperDoKernel{
		{Nome: "uevent_helper", Fonte: "/sys/kernel/uevent_helper",
			Valor: "/sbin/hotplug", Alvo: "/sbin/hotplug", Padrao: true},
	}, map[string]bool{"/sbin/hotplug": false})
	r := helperDoKernel.Run(helperDoKernel, plantado, testEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevCritical {
		t.Fatalf("um /sbin/hotplug que EXISTE e não vem de pacote é crítico: %v", r.Findings)
	}
}
