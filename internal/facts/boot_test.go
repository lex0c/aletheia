package facts

import (
	"strings"
	"testing"
)

// O kernel separa por espaço mas honra ASPAS. Um Fields simples quebraria
// `systemd.setenv="A B"` no meio e produziria um token `B"` que não casa com
// nada — some em silêncio, que é a pior forma de perder um parâmetro.
func TestTokensDeBootHonraAspas(t *testing.T) {
	ts := TokensDeBoot(`ro systemd.setenv="A B" audit=0`)
	if len(ts) != 3 {
		t.Fatalf("tokens = %+v, quer 3", ts)
	}
	if ts[1].Chave != "systemd.setenv" || ts[1].Valor != "A B" {
		t.Errorf("token com aspas = %+v", ts[1])
	}
}

// `audit` e `audit=0` são coisas OPOSTAS: o token solto liga o mecanismo. Sem
// o TemValor, a regra de desligamento casaria com quem ligou.
func TestTokensDeBootSeparaTokenSoltoDeAtribuicao(t *testing.T) {
	ts := TokensDeBoot("audit nokaslr audit=0")
	if ts[0].TemValor || ts[0].Chave != "audit" {
		t.Errorf("token solto = %+v", ts[0])
	}
	if !ts[2].TemValor || ts[2].Valor != "0" {
		t.Errorf("atribuição = %+v", ts[2])
	}
}

// O kernel resolve repetição pelo ÚLTIMO. Um `selinux=1` provisionado com um
// `selinux=0` acrescentado no fim está DESLIGADO, e ler o primeiro diria o
// contrário — com a mesma linha na tela do operador.
func TestValorDeBootPegaAUltimaOcorrencia(t *testing.T) {
	v, ok := ValorDeBoot("selinux=1 quiet selinux=0", "selinux")
	if !ok || v != "0" {
		t.Errorf("valor = %q ok=%v, quer 0", v, ok)
	}
	if _, ok := ValorDeBoot("ro quiet", "selinux"); ok {
		t.Error("chave ausente não pode devolver ok")
	}
}

// A linha do grub tem o CAMINHO DA IMAGEM no segundo campo. Incluí-lo faria o
// caminho do kernel virar um parâmetro — e um `/vmlinuz-6.1` seria comparado
// com as regras como se fosse um.
func TestCmdlineDoGrubDescartaOCaminhoDaImagem(t *testing.T) {
	v, ok := cmdlineDoGrub("\tlinux\t/vmlinuz-6.1 root=UUID=1 ro quiet")
	if !ok || v != "root=UUID=1 ro quiet" {
		t.Errorf("cmdline = %q ok=%v", v, ok)
	}
	if _, ok := cmdlineDoGrub("\tinitrd\t/initrd.img"); ok {
		t.Error("initrd não é linha de comando de kernel")
	}
	if _, ok := cmdlineDoGrub("\tlinux\t/vmlinuz-6.1"); ok {
		t.Error("sem parâmetro nenhum não há linha de comando")
	}
}

// As quatro formas que as distribuições usam. Ler só o grub deixaria Arch e
// Fedora com boot por UKI sem cobertura nenhuma — e o relatório diria "nada
// enfraquecido" onde ninguém tinha olhado.
func TestCollectBootLeAsQuatroFontes(t *testing.T) {
	f := imagem(t, map[string]string{
		// `export` porque o arquivo é sourced por shell e escrever assim é
		// válido; a linha comentada porque ela NÃO pode virar configuração.
		"etc/default/grub": "GRUB_TIMEOUT=5\n" +
			"#GRUB_CMDLINE_LINUX=\"comentado\"\n" +
			"export GRUB_CMDLINE_LINUX=\"root=UUID=1 selinux=0\"\n",
		"boot/grub/grub.cfg":            "menuentry 'L' {\n\tlinux\t/vmlinuz root=UUID=1 audit=0\n}\n",
		"boot/loader/entries/arch.conf": "title Arch\noptions root=UUID=2 rd.break\n",
		"etc/kernel/cmdline":            "root=UUID=3\nima_appraise=off\n",
	})

	if !f.BootConfigLido {
		t.Fatal("BootConfigLido: quatro configurações foram lidas")
	}
	quer := map[string]string{
		"/etc/default/grub:GRUB_CMDLINE_LINUX": "root=UUID=1 selinux=0",
		"/boot/grub/grub.cfg":                  "root=UUID=1 audit=0",
		"/boot/loader/entries/arch.conf":       "root=UUID=2 rd.break",
		// O arquivo solto é concatenado por espaço, que é como o kernel-install
		// e o dracut o entregam: duas linhas viram uma linha de comando.
		"/etc/kernel/cmdline": "root=UUID=3 ima_appraise=off",
	}
	achado := map[string]string{}
	for _, b := range f.Boot {
		if b.Rodando {
			t.Errorf("modo image não tem linha rodando: %+v", b)
		}
		achado[b.Fonte] = b.Valor
	}
	for fonte, valor := range quer {
		if achado[fonte] != valor {
			t.Errorf("%s = %q, quer %q", fonte, achado[fonte], valor)
		}
	}
	// A linha comentada não entra: `#GRUB_CMDLINE_LINUX=` é comentário, e
	// tratá-lo como configuração acusaria o que o administrador DESLIGOU.
	for _, b := range f.Boot {
		if strings.Contains(b.Valor, "comentado") {
			t.Errorf("linha comentada virou configuração: %+v", b)
		}
	}
}

// Um host com oito kernels tem dezesseis entradas no grub com a MESMA linha.
// Sem deduplicar, um parâmetro vira dezesseis achados do mesmo fato.
func TestCollectBootDeduplicaLinhaRepetida(t *testing.T) {
	f := imagem(t, map[string]string{
		"boot/grub/grub.cfg": "menuentry 'a' {\n\tlinux /vmlinuz-1 root=UUID=1 ro\n}\n" +
			"menuentry 'b' {\n\tlinux /vmlinuz-2 root=UUID=1 ro\n}\n" +
			"menuentry 'c' {\n\tlinux /vmlinuz-3 root=UUID=1 ro single\n}\n",
	})
	if len(f.Boot) != 2 {
		t.Errorf("linhas = %+v, quer 2: as duas primeiras entradas são idênticas", f.Boot)
	}
}

// Sem bootloader nenhum, "nada enfraquecido" seria mentira: ninguém olhou.
func TestCollectBootSemConfiguracaoNaoAfirmaNada(t *testing.T) {
	f := imagem(t, map[string]string{"etc/hostname": "x\n"})
	if f.BootConfigLido {
		t.Error("nenhuma configuração existe nesta imagem")
	}
	if len(f.Boot) != 0 {
		t.Errorf("linhas = %+v, quer nenhuma", f.Boot)
	}
}

// O init= é um programa que o kernel executa como PID 1. Se ele não entrar na
// pergunta de propriedade, o único discriminador que existe para ele — que
// pacote entregou este arquivo — nunca é feito.
func TestInitDaLinhaDeBootEntraNaPerguntaDePropriedade(t *testing.T) {
	f := imagem(t, map[string]string{
		"boot/grub/grub.cfg": "menuentry 'L' {\n\tlinux /vmlinuz root=UUID=1 init=/sbin/meu-init\n}\n",
		"sbin/meu-init":      "#!/bin/sh\n",
		// Sem base de pacotes a pergunta de propriedade não é feita por
		// ninguém, e o teste passaria a medir a ausência dela.
		"var/lib/dpkg/status":         "Package: base\nStatus: install ok installed\n",
		"var/lib/dpkg/info/base.list": "/sbin/init\n",
	})
	for _, o := range f.Ownership {
		if o.Path == "/sbin/meu-init" {
			return
		}
	}
	var paths []string
	for _, o := range f.Ownership {
		paths = append(paths, o.Path)
	}
	t.Errorf("/sbin/meu-init não virou candidato a propriedade: %v", paths)
}
