package checks

import (
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/facts"
)

// FALSOS POSITIVOS MEDIDOS EM HOSTS REAIS, travados aqui.
//
// Todos foram encontrados rodando a ferramenta em máquinas de verdade, e todos
// foram corrigidos sem que nada impedisse o retorno. Um cenário de contêiner
// não os alcança: dependem de UEFI, de driver Intel, de empacotamento do
// Manjaro e da imagem do Ubuntu — coisas que a matriz de teste não tem.
//
// O dado de cada teste é o que a máquina real produziu, não uma invenção
// próxima. Sem isso o teste passa a proteger a versão simplificada do problema
// em vez do problema.

// /boot/efi é a partição EFI de TODA máquina UEFI. Chamar particionamento de
// ocultação foi o primeiro achado do check de montagem num host real.
func TestParticaoNaoEhOcultacao(t *testing.T) {
	casos := []struct {
		nome   string
		m      facts.Montagem
		quer   bool
		motivo string
	}{
		{"partição EFI", facts.Montagem{
			Ponto: "/boot/efi", Tipo: "vfat", Origem: "/dev/nvme0n1p1", Raiz: "/",
		}, false, "disco real em ponto de montagem real é particionamento"},

		{"/boot separado", facts.Montagem{
			Ponto: "/boot", Tipo: "ext4", Origem: "/dev/sda1", Raiz: "/",
		}, false, "/boot em partição própria é a norma"},

		{"bind sobre /etc", facts.Montagem{
			Ponto: "/etc", Tipo: "ext4", Origem: "/dev/sda2", Raiz: "/fake",
		}, true, "raiz diferente de / é BIND: pedaço de outra árvore por cima"},

		{"tmpfs sobre /etc", facts.Montagem{
			Ponto: "/etc", Tipo: "tmpfs", Origem: "tmpfs", Raiz: "/",
		}, true, "filesystem de memória nasce vazio e some no reboot"},
	}
	// Pelo CHECK e não pela função auxiliar: testar o auxiliar deixaria passar
	// quem apagasse a chamada dele, e o falso positivo voltaria com o teste
	// verde.
	for _, c := range casos {
		f := &facts.Facts{Mounts: []facts.Montagem{c.m}}
		r := montagemSobreSistema.Run(montagemSobreSistema, f, testEnv())
		got := len(r.Findings) > 0
		if got != c.quer {
			t.Errorf("%s: achado = %v, quer %v — %s", c.nome, got, c.quer, c.motivo)
		}
	}
}

// O Manjaro empacota lightdm-settings e xflock4 em /usr/local. A premissa
// "distribuição nenhuma instala ali" é política do Debian, não regra da FHS — e
// afirmá-la rendeu três críticos num host limpo.
func TestReivindicacaoEmUsrLocalNaoEhCriticaSozinha(t *testing.T) {
	f := &facts.Facts{PkgEstranho: []facts.ReivindicacaoEstranha{
		{Path: "/usr/local/bin/lightdm-settings", File: "/var/lib/pacman/local/x/files"},
	}}
	r := baseDePacotesAdulterada.Run(baseDePacotesAdulterada, f, testEnv())
	if len(r.Findings) != 1 {
		t.Fatalf("achados = %v", r.Findings)
	}
	if r.Findings[0].Sev != check.SevWarn {
		t.Errorf("sev = %v: distribuição que empacota em /usr/local existe, e a "+
			"reivindicação sozinha é aviso", r.Findings[0].Sev)
	}

	// E vira crítica quando está FAZENDO TRABALHO: o mesmo caminho, agora com
	// bit setuid, é a linha que esconde um binário com privilégio.
	f.Suid = []facts.SuidFile{{Path: "/usr/local/bin/lightdm-settings", Setuid: true}}
	r = baseDePacotesAdulterada.Run(baseDePacotesAdulterada, f, testEnv())
	if r.Findings[0].Sev != check.SevCritical {
		t.Error("com setuid a reivindicação está escondendo privilégio: é crítica")
	}
}

// O driver TrueScale da Intel encadeia carga chamando um script em /usr/lib/rdma
// e vem empacotado. Foi o falso positivo do primeiro host real com o check de
// modprobe.
func TestDiretivaDeDriverEmpacotadoNaoEhAchado(t *testing.T) {
	m := facts.ModuleConf{
		File: "/lib/modprobe.d/truescale.conf", Line: 1, Kind: "install",
		Module: "ib_qib",
		Cmd:    "modprobe -i ib_qib $CMDLINE_OPTS && /usr/lib/rdma/truescale-serdes.cmds start",
	}

	// Sem prova de integridade, o check FALA — é o comportamento seguro.
	f := &facts.Facts{Modules: []facts.ModuleConf{m}}
	if r := modprobeInstall.Run(modprobeInstall, f, testEnv()); len(r.Findings) != 1 {
		t.Fatalf("sem prova de que o arquivo está intacto, o check não pode calar: %v", r.Findings)
	}

	// Com o arquivo verificado contra o pacote, cala.
	f.Ownership = []facts.Ownership{{Path: m.File, Owned: true, Pacote: "rdma-core"}}
	f.HashOK = []string{m.File}
	if r := modprobeInstall.Run(modprobeInstall, f, testEnv()); len(r.Findings) != 0 {
		t.Errorf("driver empacotado e íntegro não é achado: %v", r.Findings)
	}
}

// CHAVE DE HOST é sempre sem senha por desenho: o sshd sobe no boot e não há
// quem digite. Se a exclusão quebrar, TODO host com SSH vira achado — é o falso
// positivo de maior alcance possível neste check.
func TestChaveDeHostNaoEhAchado(t *testing.T) {
	f := &facts.Facts{ChavesPrivadas: []facts.ChavePrivada{
		{Path: "/etc/ssh/ssh_host_ed25519_key", Tipo: "openssh", Cifrada: false, DeHost: true},
		{Path: "/etc/ssh/ssh_host_rsa_key", Tipo: "rsa", Cifrada: false, DeHost: true},
		{Path: "/root/.ssh/id_ed25519", Tipo: "openssh", Cifrada: false},
	}}
	r := chavePrivadaSemSenha.Run(chavePrivadaSemSenha, f, testEnv())
	if len(r.Findings) != 1 {
		t.Fatalf("só a chave de USUÁRIO é achado; as de host são sem senha por "+
			"desenho: %v", r.Findings)
	}
	if r.Findings[0].Subject != "/root/.ssh/id_ed25519" {
		t.Errorf("achado errado: %s", r.Findings[0].Subject)
	}
	if r.Findings[0].Sev != check.SevWarn {
		t.Errorf("chave de usuário sem senha é aviso, não inventário")
	}
}

// As quatro formas de desligar o histórico. O cenário exercita uma; as outras
// três só existem aqui, e cada uma é uma linha que ninguém escreve sem querer.
func TestFormasDeDesligarHistorico(t *testing.T) {
	desliga := []string{
		"unset HISTFILE",
		"export HISTFILE=/dev/null",
		"HISTFILE=",
		"HISTSIZE=0",
		"export HISTFILESIZE=0",
		"set +o history",
	}
	for _, l := range desliga {
		if _, ok := facts.DesligaHistorico(l); !ok {
			t.Errorf("%q desliga o histórico e não foi reconhecida", l)
		}
	}

	naoDesliga := []string{
		"HISTSIZE=1000",
		"export HISTFILE=$HOME/.bash_history",
		"HISTCONTROL=ignoredups",
		"export PATH=/usr/local/bin:$PATH",
		"# HISTSIZE=0",
	}
	for _, l := range naoDesliga {
		if motivo, ok := facts.DesligaHistorico(l); ok {
			t.Errorf("%q é configuração normal e foi acusada: %s", l, motivo)
		}
	}
}

func TestNoExecEntraNaEvidencia(t *testing.T) {
	f := &facts.Facts{
		Processes: []facts.Process{{PID: 9, Comm: "x", Exe: "/tmp/.x", UID: 0}},
		Mounts:    []facts.Montagem{{Ponto: "/tmp", Tipo: "tmpfs", NoExec: true}},
	}
	r := suspiciousPath.Run(suspiciousPath, f, testEnv())
	if len(r.Findings) != 1 {
		t.Fatalf("achados = %v", r.Findings)
	}
	if !strings.Contains(strings.Join(r.Findings[0].Evidence, " "), "noexec") {
		t.Error("o filesystem impedir a execução muda a urgência, e precisa aparecer")
	}
}
