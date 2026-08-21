package scenario

import "strings"

// registraDonoDePacote faz a base de pacotes da imagem REIVINDICAR um arquivo.
//
// Vários cenários precisam da diferença entre "binário plantado" e "binário que
// veio da distribuição", e ela não é do arquivo: é da base de pacotes. Instalar
// um pacote de verdade exigiria rede e dezenas de segundos por execução; anexar
// à lista de arquivos é o que o dpkg e o apk leem, e é o que a ferramenta lê
// também — ela não chama `dpkg -V`, lê o texto.
//
// Serve as duas bases da matriz. Onde não houver nenhuma das duas, não faz nada:
// a imagem sem base de pacotes já é outro cenário.
func registraDonoDePacote(caminho, pacote string) string {
	dir := caminho[:strings.LastIndex(caminho, "/")]
	nome := caminho[strings.LastIndex(caminho, "/")+1:]
	return "if [ -d /var/lib/dpkg/info ]; then echo " + caminho +
		" >> /var/lib/dpkg/info/coreutils.list; " +
		"elif [ -f /lib/apk/db/installed ]; then printf 'P:" + pacote +
		"\\nF:" + strings.TrimPrefix(dir, "/") + "\\nR:" + nome +
		"\\n' >> /lib/apk/db/installed; fi"
}

// Os programas que o KERNEL invoca sozinho (§7.12).
//
// Todos em VM porque são sysctl e mecanismo de kernel: contêiner não os escreve,
// e o valor é global — mexer neles dentro de um contêiner mexeria no host de
// quem roda a suíte.
//
// O par que importa está entre U1/U2 e o resto da suíte de VM: aqui os valores
// são plantados e viram crítico; nos outros cenários de VM o guest tem os
// valores de fábrica e este check precisa ficar calado — e como todos eles
// declaram orçamento de ruído, o silêncio está travado lá.
//
//	U1  core_pattern com cano para /tmp    o gatilho é um SIGSEGV
//	U2  modprobe trocado                   o gatilho é pedir um módulo
//	U3  binfmt registrado por extensão     o gatilho é executar o arquivo

func init() {
	Register(Scenario{
		ID:   "U1-core-pattern-sequestrado",
		Desc: "o kernel pipa o core dump para um programa em /tmp: execução como root sem unit, sem cron e sem processo pai",
		Mode: VM,
		// É a forma mais silenciosa desta família. Não há o que achar em unit,
		// cron ou perfil de shell — há uma linha num arquivo de uma linha —, e o
		// gatilho é qualquer processo morrendo com SIGSEGV, que quem já tem uma
		// conta provoca à vontade.
		Setup: `printf '#!/bin/sh\nexit 0\n' > /tmp/.coredump
			chmod +x /tmp/.coredump
			echo '|/tmp/.coredump %P %u' > /proc/sys/kernel/core_pattern`,
		Expect: []Expect{
			{ID: "persist.kernel_helper", Sev: "CRITICAL", Subject: "core_pattern"},
			{ID: "persist.kernel_helper", Evidence: "COMO ROOT"},
			{ID: "persist.kernel_helper", Evidence: "SIGSEGV"},
		},
		Exit: 2,
	})

	Register(Scenario{
		ID:   "U2-modprobe-trocado",
		Desc: "o helper que o kernel executa ao carregar módulo aponta para um caminho gravável",
		Mode: VM,
		// O gatilho aqui é ainda mais banal: montar um filesystem, criar uma
		// interface de rede ou abrir um socket de protocolo incomum faz o kernel
		// pedir um módulo — e executar este caminho como root.
		Setup: `printf '#!/bin/sh\nexit 0\n' > /tmp/.mod
			chmod +x /tmp/.mod
			echo /tmp/.mod > /proc/sys/kernel/modprobe`,
		Expect: []Expect{
			{ID: "persist.kernel_helper", Sev: "CRITICAL", Subject: "modprobe"},
			{ID: "persist.kernel_helper", Evidence: "não é o de fábrica"},
		},
		Exit: 2,
	})

	Register(Scenario{
		ID:   "U3-binfmt-com-interpretador-plantado",
		Desc: "interpretador registrado por assinatura: executar um arquivo comum passa a executar outro programa",
		Mode: VM,
		// O binfmt_misc é o mecanismo que faz `./programa.exe` rodar sob wine e
		// binário de outra arquitetura rodar sob qemu. Registrado por extensão,
		// ele transforma abrir um arquivo qualquer em executar o interpretador —
		// e o registro é global, não do usuário que o criou.
		Setup: `printf '#!/bin/sh\nexit 0\n' > /tmp/.interp
			chmod +x /tmp/.interp
			mkdir -p /proc/sys/fs/binfmt_misc
			mount -t binfmt_misc binfmt_misc /proc/sys/fs/binfmt_misc
			printf ':relatorio:E::rel::/tmp/.interp:\n' > /proc/sys/fs/binfmt_misc/register`,
		// O binfmt_misc SAIU do persist.kernel_helper.
		//
		// O 129ab2a dividiu a pergunta em duas: `persist.kernel_helper` ficou com
		// o que o kernel executa por configuração (modprobe, core_pattern) e
		// `kernel.binfmt_interpreter` ficou com o registro VIVO em
		// /proc/sys/fs/binfmt_misc. O ID antigo continuou existindo, então nada
		// falhou até alguém rodar a suíte — este contrato passou trinta commits
		// cobrando de um check uma coisa que já não era dele.
		Expect: []Expect{
			{ID: "kernel.binfmt_interpreter", Sev: "CRITICAL", Subject: "relatorio"},
			{ID: "kernel.binfmt_interpreter", Evidence: "assinatura registrada"},
		},
		Exit: 2,
	})
}
