package checks

import (
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/facts"
)

// --- persist.kernel_cmdline_weakening ---

func bootF(config bool, linhas ...facts.LinhaDeBoot) *facts.Facts {
	return &facts.Facts{Boot: linhas, BootConfigLido: config}
}

func rodando(v string) facts.LinhaDeBoot {
	return facts.LinhaDeBoot{Fonte: "/proc/cmdline", Valor: v, Rodando: true}
}

func configurado(fonte, v string) facts.LinhaDeBoot {
	return facts.LinhaDeBoot{Fonte: fonte, Valor: v}
}

func evidencia(fd check.Finding) string { return strings.Join(fd.Evidence, " ") }

func acha(t *testing.T, r check.Result, subject string) check.Finding {
	t.Helper()
	for _, fd := range r.Findings {
		if fd.Subject == subject {
			return fd
		}
	}
	var tudo []string
	for _, fd := range r.Findings {
		tudo = append(tudo, fd.Subject)
	}
	t.Fatalf("nenhum achado com subject %q; havia %v", subject, tudo)
	return check.Finding{}
}

// O parâmetro que está valendo e NÃO está na configuração não sobrevive a um
// reboot: alguém subiu este kernel assim. É a metade do check que um scanner de
// hardening não faz.
func TestCmdlineRodandoSemEstarNaConfiguracao(t *testing.T) {
	f := bootF(true, rodando("ro audit=0"), configurado("/etc/default/grub", "ro quiet"))
	r := cmdlineEnfraquecida.Run(cmdlineEnfraquecida, f, testEnv())
	ev := evidencia(acha(t, r, "audit=0"))
	if !strings.Contains(ev, "NÃO está na configuração") {
		t.Errorf("evidência = %q", ev)
	}
}

// Sem configuração LEGÍVEL, a divergência não pode ser afirmada — é o host que
// boota por QEMU com -append, por iPXE ou por kexec. Afirmar ali produziria
// achado em toda frota que não usa bootloader.
func TestCmdlineNaoAfirmaDivergenciaSemConfiguracaoLida(t *testing.T) {
	f := bootF(false, rodando("ro audit=0"))
	r := cmdlineEnfraquecida.Run(cmdlineEnfraquecida, f, testEnv())
	ev := evidencia(acha(t, r, "audit=0"))
	if strings.Contains(ev, "NÃO está na configuração") {
		t.Errorf("sem configuração lida não há divergência a afirmar: %q", ev)
	}
	if !strings.Contains(ev, "não havia configuração") {
		t.Errorf("a lacuna precisa ser dita: %q", ev)
	}
}

// Valendo agora E configurado: sobrevive ao reboot. É a forma da persistência,
// e é diferente das outras duas.
func TestCmdlineRodandoEConfiguradoDizQueSobrevive(t *testing.T) {
	f := bootF(true, rodando("ro audit=0"), configurado("/etc/default/grub", "ro audit=0"))
	r := cmdlineEnfraquecida.Run(cmdlineEnfraquecida, f, testEnv())
	if ev := evidencia(acha(t, r, "audit=0")); !strings.Contains(ev, "sobrevive") {
		t.Errorf("evidência = %q", ev)
	}
}

// Configurado e não valendo: a proteção cai no PRÓXIMO boot. É persistência à
// espera, e o operador precisa saber antes de reiniciar o host.
func TestCmdlineConfiguradoENaoRodandoAvisaDoProximoBoot(t *testing.T) {
	f := bootF(true, rodando("ro quiet"), configurado("/etc/default/grub", "ro audit=0"))
	r := cmdlineEnfraquecida.Run(cmdlineEnfraquecida, f, testEnv())
	if ev := evidencia(acha(t, r, "audit=0")); !strings.Contains(ev, "próximo boot") {
		t.Errorf("evidência = %q", ev)
	}
}

// Em modo image não existe linha rodando. Dizer "ainda não vale" ali afirmaria
// sobre o host desligado uma coisa que ninguém olhou.
func TestCmdlineSemLinhaRodandoNaoAfirmaQueNaoVale(t *testing.T) {
	f := bootF(true, configurado("/etc/default/grub", "ro audit=0"))
	r := cmdlineEnfraquecida.Run(cmdlineEnfraquecida, f, testEnv())
	if ev := evidencia(acha(t, r, "audit=0")); strings.Contains(ev, "ainda não vale") {
		t.Errorf("sem linha rodando não há o que comparar: %q", ev)
	}
}

// O valor é parte da regra. `selinux=1` LIGA, e casar com ele acusaria
// exatamente quem fez a coisa certa.
func TestCmdlineNaoCasaComOValorQueLiga(t *testing.T) {
	f := bootF(true, rodando("selinux=1 audit=1 apparmor=1"))
	if r := cmdlineEnfraquecida.Run(cmdlineEnfraquecida, f, testEnv()); len(r.Findings) != 0 {
		t.Errorf("achados = %+v, quer 0", r.Findings)
	}
}

// `audit` solto é o oposto de `audit=0`. Tratar token sem valor como se
// tivesse faria a regra casar com quem LIGOU a auditoria.
func TestCmdlineTokenSoltoNaoCasaComRegraDeValor(t *testing.T) {
	f := bootF(true, rodando("ro audit"))
	if r := cmdlineEnfraquecida.Run(cmdlineEnfraquecida, f, testEnv()); len(r.Findings) != 0 {
		t.Errorf("achados = %+v, quer 0", r.Findings)
	}
}

// Mitigação de CPU é afinação de desempenho em host normal. Como aviso, ela
// mexeria no exit code de toda frota de banco de dados e de virtualização.
func TestCmdlineMitigacaoSaiComoInformativo(t *testing.T) {
	f := bootF(true, rodando("ro mitigations=off nokaslr"))
	r := cmdlineEnfraquecida.Run(cmdlineEnfraquecida, f, testEnv())
	if len(r.Findings) != 2 {
		t.Fatalf("achados = %d, quer 2", len(r.Findings))
	}
	for _, fd := range r.Findings {
		if fd.Sev != check.SevInfo {
			t.Errorf("%s = %v, quer INFO", fd.Subject, fd.Sev)
		}
	}
}

// O que o kernel RESPONDE vale mais que o que a linha PEDE. O parâmetro de
// assinatura de módulo é o caso em que os dois costumam divergir.
func TestCmdlineConfrontaPedidoComOQueOKernelResponde(t *testing.T) {
	f := bootF(true, rodando("ro module.sig_enforce=0"))
	f.Protecao.SigEnforce = "Y"
	if ev := evidencia(acha(t, cmdlineEnfraquecida.Run(cmdlineEnfraquecida, f, testEnv()),
		"module.sig_enforce=0")); !strings.Contains(ev, "não teve efeito") {
		t.Errorf("com o kernel exigindo assinatura, o pedido não pegou: %q", ev)
	}

	f2 := bootF(true, rodando("ro module.sig_enforce=0"))
	f2.Protecao.SigEnforce = "N"
	if ev := evidencia(acha(t, cmdlineEnfraquecida.Run(cmdlineEnfraquecida, f2, testEnv()),
		"module.sig_enforce=0")); !strings.Contains(ev, "carrega neste host") {
		t.Errorf("com o kernel não exigindo, o efeito é real: %q", ev)
	}
}

// init= em diretório gravável não tem leitura inocente: é o PID 1 vindo de um
// lugar onde nada se instala.
func TestInitEmDiretorioGravavelECritico(t *testing.T) {
	f := bootF(true, rodando("ro init=/tmp/.x"))
	fd := acha(t, cmdlineEnfraquecida.Run(cmdlineEnfraquecida, f, testEnv()), "init=/tmp/.x")
	if fd.Sev != check.SevCritical {
		t.Errorf("severidade = %v, quer CRITICAL", fd.Sev)
	}
	if !fd.Irreversible {
		t.Error("o binário do PID 1 precisa ser guardado antes de mexer")
	}
}

// Em diretório do gerenciador de pacotes, "nenhum pacote reivindica" é a
// resposta mais forte que existe: tudo ali deveria vir de um pacote.
func TestInitSemDonoEmDiretorioDePacoteECritico(t *testing.T) {
	f := bootF(true, rodando("ro init=/usr/sbin/init2"))
	f.Ownership = []facts.Ownership{{Path: "/usr/sbin/init2", Owned: false}}
	fd := acha(t, cmdlineEnfraquecida.Run(cmdlineEnfraquecida, f, testEnv()), "init=/usr/sbin/init2")
	if fd.Sev != check.SevCritical {
		t.Errorf("severidade = %v, quer CRITICAL", fd.Sev)
	}
}

// Vem de pacote e é um SHELL: não é implante, é console de root sem senha.
func TestInitQueEShellAvisaMesmoVindoDePacote(t *testing.T) {
	f := bootF(true, rodando("ro init=/bin/bash"))
	f.Ownership = []facts.Ownership{{Path: "/bin/bash", Owned: true}}
	fd := acha(t, cmdlineEnfraquecida.Run(cmdlineEnfraquecida, f, testEnv()), "init=/bin/bash")
	if fd.Sev != check.SevWarn {
		t.Errorf("severidade = %v, quer WARN", fd.Sev)
	}
}

// O init= legítimo existe e é comum: distribuição e initramfs o passam
// apontando para o próprio systemd. Acusá-lo seria acusar o estado de fábrica.
func TestInitLegitimoNaoDispara(t *testing.T) {
	f := bootF(true, rodando("ro init=/usr/lib/systemd/systemd"))
	f.Ownership = []facts.Ownership{{Path: "/usr/lib/systemd/systemd", Owned: true}}
	if r := cmdlineEnfraquecida.Run(cmdlineEnfraquecida, f, testEnv()); len(r.Findings) != 0 {
		t.Errorf("achados = %+v, quer 0", r.Findings)
	}
}

// Nada lido de lugar nenhum NÃO é "nada enfraquecido". É não ter olhado, e a
// diferença é o motivo desta ferramenta existir.
func TestCmdlineSemFonteAlgumaDeclaraLacuna(t *testing.T) {
	r := cmdlineEnfraquecida.Run(cmdlineEnfraquecida, bootF(false), testEnv())
	if len(r.Findings) != 0 {
		t.Errorf("achados = %+v, quer 0", r.Findings)
	}
	if len(r.Partial) == 0 || !strings.Contains(strings.Join(r.Partial, " "), "NÃO foram avaliados") {
		t.Errorf("a lacuna precisa ser declarada: %v", r.Partial)
	}
}
