//go:build scenarios

package scenario

// Ocultação por kernel, MEDIDA contra kernel real.
//
// Estes três eram o buraco mais antigo da suíte: cross.socket_view e
// cross.module_view — a arma anti-rootkit da ferramenta — só apareciam como
// UntestableChecks (o 91 e o Q1), "provados" fora do registro, no
// test/matrix/vm-matrix.sh. A justificativa de então ("carregar um LKM de
// ocultação perderia o controle do ambiente") era do tier de CONTÊINER; o tier
// de VM torna o carregamento seguro — o módulo morre com o QEMU, e o kernel do
// host nunca é tocado. Então o que estava medido em shell vira contrato Go, com
// Expect/Forbid, e os checks deixam de ser só declarados.
//
// O que difere do vm-matrix: lá a medição é uma tabela de shell; aqui é o mesmo
// binário sob o mesmo contrato do resto da suíte — exit code, cobertura e a
// invalidação de ausências entram na asserção. socknd e modhide são os MESMOS
// .c que o vm-matrix compila (test/vm/socket-hidden-module.c,
// ftrace-hidden-module.c), agora compilados pelo build-modulos.sh contra o
// linux-lts e enfiados no initramfs do harness.
//
// Todos usam Kernel:"lts" porque o .ko casa com ESSE kernel, e ModulosOcultacao
// para que o harness pule com motivo quando o `make vm-modulos` não correu.
func init() {
	// --- cross.socket_view: /proc/net esconde, o netlink mostra. ---
	//
	// socknd cria um LISTEN na porta mágica de dentro do kernel e, com
	// esconder=1, hooka tcp4_seq_show para a linha sumir de /proc/net/tcp. O
	// NETLINK_INET_DIAG não passa por tcp4_seq_show: a conexão continua lá. Essa
	// divergência entre duas visões do MESMO kernel é o achado.
	//
	// inet_diag/tcp_diag precisam estar carregados: sem o handler, o dump por
	// netlink não acontece e o check viraria cobertura parcial em vez de achado —
	// mediria uma cegueira da ferramenta, não a ocultação.
	Register(Scenario{
		ID:               "RK-cross-socket-view",
		Desc:             "conexão escondida de /proc/net/tcp por hook em tcp4_seq_show, visível pelo INET_DIAG",
		Mode:             VM,
		Kernel:           "lts",
		ModulosOcultacao: true,
		Setup: `insmod /modulos/inet_diag.ko
			insmod /modulos/tcp_diag.ko
			insmod /modulos/socknd.ko esconder=1`,
		Expect: []Expect{
			// CRITICAL e kernelBreaker: duas interfaces do mesmo kernel deram
			// respostas incompatíveis sobre a tabela de conexões.
			{ID: "cross.socket_view", Sev: "CRITICAL"},
			{ID: "cross.socket_view", Evidence: "o netlink entrega este socket e /proc/net não o lista"},
		},
		// O disparo invalida as ausências desta execução: quem serve /proc já
		// mostrou que responde o que quer, então "não achei mais nada" deixa de
		// valer e a cobertura cai. É a tese central da ferramenta, e aqui ela é
		// exercitada de ponta a ponta, não só no teste unitário do motor.
		ExpectOutput:     []string{"O KERNEL SE CONTRADISSE"},
		MustBeIncomplete: true,
		Exit:             2,
	})

	// --- cross.module_view: some das duas interfaces, o ftrace o delata. ---
	//
	// modhide esconder=2 se desencadeia de /proc/modules E de /sys/module — as
	// duas fontes que o crossview clássico compara concordam (as duas o omitem).
	// O que NÃO some é available_filter_functions: a função rastreável do módulo
	// (evil_marcador) continua anotada com `[modhide]`, porque list_del/kobject_del
	// não tocam no registro do ftrace. É por essa terceira interface que o achado
	// nasce — a que o crossview de sysfs não alcança.
	//
	// tracefs montado de verdade (não o tmpfs sintético do G3): aqui o hook é real
	// e a função aparece porque o kernel a registrou, não porque o /helper a
	// escreveu.
	Register(Scenario{
		ID:               "RK-cross-module-view",
		Desc:             "LKM some de /proc/modules e /sys/module, mas o ftrace ainda retém sua função rastreável",
		Mode:             VM,
		Kernel:           "lts",
		ModulosOcultacao: true,
		Setup: `mkdir -p /sys/kernel/tracing
			mount -t tracefs tracefs /sys/kernel/tracing
			insmod /modulos/modhide.ko esconder=2`,
		Expect: []Expect{
			{ID: "cross.module_view", Sev: "CRITICAL", Subject: "modhide"},
			{ID: "cross.module_view", Evidence: "NÃO está em /proc/modules"},
		},
		ExpectOutput:     []string{"O KERNEL SE CONTRADISSE"},
		MustBeIncomplete: true,
		Exit:             2,
	})

	// --- DUPLO HIDE: a arma principal cega, o mecanismo continua visível. ---
	//
	// socknd esconder=2 esconde a porta de /proc/net/tcp E do SOCK_DIAG ao mesmo
	// tempo. Agora as duas visões concordam, e o cross.socket_view NÃO tem
	// divergência para achar — é o ponto cego REAL da comparação, e o cenário o
	// afirma com Forbid, não o varre para debaixo do tapete.
	//
	// O que salva é o mecanismo: os hooks de ftrace (tcp4_seq_show e
	// inet_sk_diag_fill) aparecem em enabled_functions, e o kernel.ftrace_hook os
	// pega. O ataque que apaga o EFEITO das duas fontes não apaga o próprio hook —
	// e é esse sinal independente que sobra. É a forma forte do G3: lá o
	// enabled_functions é sintetizado pelo /helper; aqui o hook é de verdade.
	Register(Scenario{
		ID:               "RK-duplo-hide-ftrace",
		Desc:             "esconde socket das DUAS fontes: o cross-view cega, mas o hook de ftrace continua delatando o mecanismo",
		Mode:             VM,
		Kernel:           "lts",
		ModulosOcultacao: true,
		Setup: `mkdir -p /sys/kernel/tracing
			mount -t tracefs tracefs /sys/kernel/tracing
			insmod /modulos/inet_diag.ko
			insmod /modulos/tcp_diag.ko
			insmod /modulos/socknd.ko esconder=2`,
		Expect: []Expect{
			{ID: "kernel.ftrace_hook", Sev: "CRITICAL", Evidence: "esconde CONEXÃO"},
		},
		// A negativa é o coração deste cenário: com as duas fontes mentindo igual,
		// o cross.socket_view não pode disparar. Se um dia disparar, ou a evasão
		// ficou incompleta ou o check ganhou um sinal novo — e aí este Forbid
		// falha e manda reexaminar o que mudou.
		Forbid: []string{"cross.socket_view"},
		Exit:   2,
	})
}
