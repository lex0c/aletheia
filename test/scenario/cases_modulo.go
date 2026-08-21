package scenario

// O módulo que não tem arquivo (§35.3), e o contexto que pesa o achado.
//
// A ferramenta já sabia decodificar a marca de taint e comparar as duas
// interfaces do kernel. Faltava a pergunta mais direta — que ARQUIVO entregou
// este módulo? —, que é a mesma que ela faz para binário em execução desde a
// fase 7, e que aqui vale mais: código de módulo roda DENTRO do kernel, e a
// partir dali todos os outros checks podem estar recebendo mentira.
//
//	Z1  insmod + rm            o módulo continua carregado e o arquivo sumiu
//	Z2  o mesmo, sem assinatura  o kernel marca (E), e aí é crítico
//	Z3  em contêiner            o check se CALA: /proc/modules é o do host
//
// Os dois primeiros exigem carregar um módulo DE VERDADE — o fato vem de
// /proc/modules, e plantar arquivo não carrega módulo nenhum. O `make vm-image`
// prepara um `dummy.ko` do host quando consegue; quando não consegue, o cenário
// é pulado com o motivo dito.

// arvoreComOutroModulo monta uma árvore de módulos LEGÍTIMA no guest.
//
// Sem ela o cenário não provaria nada: a ferramenta trata "nenhum arquivo de
// módulo em lugar nenhum" como LACUNA DE COLETA, não como achado — porque ali
// ninguém olhou. É preciso que a árvore exista e tenha arquivo para que a
// ausência de UM módulo signifique alguma coisa.
const arvoreComOutroModulo = `
	rel=$(uname -r)
	mkdir -p /lib/modules/$rel/kernel/drivers/net
	cp /modulos/dummy.ko /lib/modules/$rel/kernel/drivers/net/decoy.ko
`

func init() {
	Register(Scenario{
		ID:           "Z1-modulo-carregado-sem-arquivo",
		Desc:         "insmod seguido de rm: o código continua dentro do kernel e não há arquivo em disco que o explique",
		Mode:         VM,
		RequerModulo: true,
		Setup: arvoreComOutroModulo + `
			insmod /modulos/dummy.ko
			rm -f /modulos/dummy.ko`,
		Expect: []Expect{
			// AVISO, não crítico: atualizar o pacote do kernel remove os .ko da
			// versão antiga e a máquina segue rodando a antiga por semanas. Todo
			// servidor que atualiza sem reiniciar passa por este estado.
			{ID: "kernel.module_no_file", Sev: "WARN", Subject: "dummy"},
			{ID: "kernel.module_no_file", Evidence: "não está em disco"},
			// E o contexto do kernel viaja JUNTO do achado: num host que exige
			// assinatura o mesmo achado pesa muito mais.
			{ID: "kernel.module_no_file", Evidence: "assinatura de módulo"},
			// O inventário de proteção sai em toda execução viva.
			{ID: "kernel.protection_context", Sev: "INFO"},
		},
		// `-v` porque o passo irreversível de um AVISO não entra no bloco de
		// ações — ele é reservado para quando há crítico. Quem lê o aviso com
		// evidência precisa receber a ordem junto, e é isso que se afirma aqui.
		Args:         []string{"-v"},
		ExpectOutput: []string{"NÃO descarregue antes de preservar"},
		Exit:         1,
	})

	Register(Scenario{
		ID:           "Z2-modulo-sem-assinatura-e-sem-arquivo",
		Desc:         "o kernel marca o módulo como não assinado E não há arquivo: as duas coisas juntas não têm explicação de rotina",
		Mode:         VM,
		RequerModulo: true,
		// Acrescentar bytes ao fim do .ko invalida a assinatura anexada — é onde
		// ela mora. O módulo continua carregando (este kernel não exige
		// assinatura) e o kernel passa a marcá-lo com (E).
		Setup: arvoreComOutroModulo + `
			cp /modulos/dummy.ko /tmp/implante.ko
			printf 'AAAA' >> /tmp/implante.ko
			insmod /tmp/implante.ko
			rm -f /tmp/implante.ko /modulos/dummy.ko`,
		Expect: []Expect{
			{ID: "kernel.module_no_file", Sev: "CRITICAL", Subject: "dummy"},
			{ID: "kernel.module_no_file", Evidence: "SEM assinatura válida"},
			// O comando que preserva o módulo antes do rmmod é NextStep, e o
			// lugar dele é o JSONL: o nível 0 do relatório resume a ação em uma
			// linha e não imprime o comando.
			{ID: "kernel.module_no_file", NextStep: "cp /proc/kcore"},
			// O taint do kernel confirma pelo outro lado: a marca existe e tem
			// dono declarado, então o check de taint sem dono NÃO dispara.
			{ID: "kernel.protection_context", Sev: "INFO"},
		},
		Forbid: []string{"kernel.taint_unexplained"},
		// Sendo crítico, o passo irreversível sobe para o bloco de ações — que é
		// a lista curta do que fazer AGORA, antes de qualquer outra coisa.
		// O relatório precisa AVISAR que há passo irreversível antes de o operador
		// agir — isso é trabalho dele, e por isso continua aqui. O texto mudou:
		// "irreversível se pulado" era o sufixo do comando na saída antiga, e não
		// é produzido por código nenhum desde a reformulação (só sobreviveu num
		// comentário do preserve). Cobrar dele era cobrar de ninguém.
		ExpectOutput: []string{"há passo irreversível"},
		Exit:         2,
	})

	Register(Scenario{
		ID:     "Z3-em-container-o-check-se-cala",
		Desc:   "dentro de contêiner /proc/modules é o do HOST e /lib/modules é o da imagem: a comparação acusaria todo módulo do host",
		Images: []string{"debian:12"},
		// A armadilha é a mesma que derrubou a enumeração de eBPF, e o custo de
		// errar aqui é maior: um host de CI com 200 módulos carregados produziria
		// 200 achados de uma vez, todos falsos, todos convincentes.
		//
		// A árvore é criada com um módulo dentro justamente para tirar a saída
		// fácil: sem ela o check se calaria por "árvore não lida", e o cenário
		// não estaria provando o guarda de contêiner.
		Plant: `mkdir -p /lib/modules/$(uname -r)/kernel
			printf 'nao-e-um-modulo-de-verdade' > /lib/modules/$(uname -r)/kernel/decoy.ko`,
		// `-v` para que o motivo da recusa apareça INTEIRO: sem ele a cobertura
		// resume os três primeiros motivos, e o que está sendo protegido aqui é
		// justamente o texto do guarda.
		Args:   []string{"--only", "kernel,proc", "-vv"},
		Forbid: []string{"kernel.module_no_file"},
		ExpectOutput: []string{
			// O escopo é declarado UMA vez, pelo boundary — e não como cobertura
			// degradada em cada check de kernel. Marcar parcial faria toda
			// varredura dentro de contêiner sair incompleta e com exit 1,
			// inclusive a de um contêiner limpo.
			"são sobre o host",
		},
		// O contêiner não vê os sysctl do kernel como um host vê, mas vê alguns:
		// o inventário de proteção continua saindo, e é o que dá contexto.
		Expect: []Expect{
			{ID: "kernel.protection_context", Sev: "INFO"},
			{ID: "proc.container_boundary", Sev: "INFO", Evidence: "são sobre o host"},
		},
		// E a cobertura NÃO cai por isso: um contêiner limpo continua saindo
		// completo. É a propriedade que a suíte inteira cobrava — trinta
		// cenários de contêiner viraram incompletos quando este check declarou
		// lacuna aqui, e foi assim que a regra apareceu.
		MustBeComplete: true,
		Exit:           -1,
	})

	// O antigo Q1 vivia AQUI, declarando cross.socket_view impossível de provar
	// neste harness ("só carrega dummy.ko, não compila módulo arbitrário"). Isso
	// deixou de ser verdade: o build-modulos.sh compila o socket-hidden-module.c
	// contra o linux-lts e o enfia no initramfs, e o RK-cross-socket-view
	// (cases_ocultacao.go) o carrega e EXIGE o achado — Expect, não Untestable. O
	// mesmo para cross.module_view (RK-cross-module-view). O que era prova só no
	// vm-matrix agora também é contrato Go.
}
