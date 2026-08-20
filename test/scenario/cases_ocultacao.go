//go:build scenarios

package scenario

// Ocultação por kernel, MEDIDA contra kernel real.
//
// A família cross.* — a arma anti-rootkit da ferramenta: "o que vejo é TUDO que
// existe?" — era o buraco mais antigo da suíte. As CINCO comparações
// (cross.socket_view, .module_view, .hidden_pid, .thread_count, .bpf_hidden) só
// apareciam como UntestableChecks (o 91 e o Q1), "provadas" fora do registro ou
// não medidas. A justificativa de então ("carregar um LKM de ocultação perderia
// o controle do ambiente") era do tier de CONTÊINER; o tier de VM torna o
// carregamento seguro — o módulo morre com o QEMU, e o kernel do host nunca é
// tocado. Agora cada uma é contrato Go, com Expect/Forbid, exit code, cobertura
// e a invalidação de ausências na asserção. O 91 foi removido; nada de cross.*
// fica só declarado.
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

// --- cross.hidden_pid: um filho visível aponta para um pai que sumiu. ---
//
// A rota PPID é a mais forte do check: não tem corrida. Um pai P forka um filho
// C (que fica VISÍVEL), P segue vivo, e o pidhide filtra o d_name de P do
// getdents64 — P some da listagem de /proc mas /proc/P/stat continua resolvendo
// (lookup não passa por readdir). C declara PPID=P, P responde a stat e não está
// na lista: a listagem mentiu. CRITICAL, e kernelBreaker — invalida as ausências
// desta execução.
//
// A montagem: `sh -c 'C & exec P'` faz o pid do sh (capturado por $!) forkar C e
// depois virar P por exec; C nasceu antes do exec, então seu PPID é P. Esconde-se
// P. Ambos são /helper (Go) só para terem vida longa; o que importa é a relação.
func init() {
	Register(Scenario{
		ID:               "RK-hidden-pid",
		Desc:             "processo some da listagem de /proc mas um filho visível o declara como pai e ele responde a stat",
		Mode:             VM,
		Kernel:           "lts",
		ModulosOcultacao: true,
		Setup: `sh -c '/helper sleep 300 & exec /helper sleep 300' &
			P=$!
			sleep 0.5
			insmod /modulos/pidhide.ko oculto=$P`,
		Expect: []Expect{
			// A via PPID é CRITICAL de propósito: ela não tem a corrida da
			// sondagem, então a divergência é prova, não indício.
			{ID: "cross.hidden_pid", Sev: "CRITICAL"},
			{ID: "cross.hidden_pid", Evidence: "a LISTAGEM de /proc é que o omitiu"},
		},
		ExpectOutput:     []string{"O KERNEL SE CONTRADISSE"},
		MustBeIncomplete: true,
		Exit:             2,
	})

	// --- cross.thread_count: o status conta N, o diretório de tarefas mostra N-1. ---
	//
	// Um processo Go (/helper) tem várias threads de runtime. O status DECLARA a
	// contagem (o kernel a soma das tasks reais, que o hook não toca); o
	// diretório /proc/<pid>/task tem uma entrada por TID, e o pidhide filtra UMA
	// do getdents64. As duas leituras divergem, e a releitura do coletor confirma
	// que persiste — não é thread que morreu no intervalo.
	//
	// WARN, não CRITICAL, e por isso NÃO invalida ausências: esconder uma thread
	// é forte indício, mas runtime com pool encolhe o task dir o tempo todo, e o
	// check paga essa incerteza em severidade. Escolhe-se um TID que não é o líder
	// (TID != PID) para não mexer na entrada que também nomeia o processo.
	Register(Scenario{
		ID:               "RK-thread-count",
		Desc:             "contagem de threads do status diverge do diretório task porque uma entrada de TID foi filtrada do readdir",
		Mode:             VM,
		Kernel:           "lts",
		ModulosOcultacao: true,
		Setup: `/helper sleep 300 &
			HP=$!
			sleep 0.5
			TID=$(ls /proc/$HP/task | grep -v "^$HP\$" | head -1)
			insmod /modulos/pidhide.ko oculto=$TID`,
		Expect: []Expect{
			{ID: "cross.thread_count", Sev: "WARN"},
			{ID: "cross.thread_count", Evidence: "esconder uma thread exige mentir nos dois"},
		},
		// Exit 1: o achado é WARN. Um WARN de ocultação de thread ainda tira o
		// exit de zero — a automação de frota não pode arquivar isto como limpo.
		Exit: 1,
	})
}

// --- cross.bpf_hidden: fdinfo cita um programa que a enumeração da bpf(2) nega. ---
//
// A forma do PID oculto, um nível acima, no kernel. Um processo carrega um
// programa eBPF e SEGURA o descritor (`helper bpf hold`), então
// /proc/<pid>/fdinfo mostra prog_id=X. O bpfhide hooka a bpf(2) e faz o
// BPF_PROG_GET_NEXT_ID pular X — a enumeração não o devolve. A leitura de fdinfo
// não passa pela bpf(2), então continua citando X. Duas fontes do mesmo kernel:
// uma cita o objeto, a outra o nega.
//
// É o ÚLTIMO cross.* a sair dos UntestableChecks. Precisou de um hook DIFERENTE
// (a bpf(2), não o getdents64), mas do mesmo arcabouço ftrace+`call *` cru do
// pidhide. O achado exige confirmação por DUAS enumerações completas
// (confirmarOcultosBPF); o hook esconde X das duas.
func init() {
	Register(Scenario{
		ID:               "RK-bpf-hidden",
		Desc:             "programa eBPF citado pelo fdinfo de um processo e escondido da enumeração da bpf(2)",
		Mode:             VM,
		Kernel:           "lts",
		ModulosOcultacao: true,
		Setup: `/helper bpf hold implante &
			HP=$!
			sleep 0.5
			ID=$(grep -h '^prog_id:' /proc/$HP/fdinfo/* 2>/dev/null | awk '{print $2}' | head -1)
			insmod /modulos/bpfhide.ko oculto=$ID`,
		Expect: []Expect{
			{ID: "cross.bpf_hidden", Sev: "CRITICAL"},
			{ID: "cross.bpf_hidden", Evidence: "citado por um descritor aberto"},
		},
		ExpectOutput:     []string{"O KERNEL SE CONTRADISSE"},
		MustBeIncomplete: true,
		Exit:             2,
	})
}

// --- RK3: full-stealth multivetor (os padrões do Singularity), a prova de
// HONESTIDADE. ---
//
// O Singularity ataca as TESTEMUNHAS: esconde de /proc, /proc/net, module list,
// sysfs, SOCK_DIAG, ftrace ao mesmo tempo. O contrato dele (cases_rootkits.go)
// não é detecção — é o LIMITE: quando o kernel mente consistentemente em TODAS
// as fontes, o cross-view cega e não há divergência para achar. A ferramenta
// perde a APARÊNCIA, mas NÃO pode alegar host íntegro.
//
// Este cenário reproduz os padrões de evasão de que já disponho — carregados
// JUNTOS, como um rootkit multivetor faria — e mede a honestidade:
//   - eixo CEGADO: socknd esconder=2 esconde o socket de /proc/net E do
//     SOCK_DIAG. As duas visões concordam, e cross.socket_view NÃO acha nada.
//     A ferramenta é honestamente cega a esse socket.
//   - eixos PEGOS: a evasão é INCOMPLETA nos outros — modhide/pidhide não
//     falsificam o ftrace, então cross.module_view, kernel.ftrace_hook e
//     cross.hidden_pid disparam. É a "única salvação" do contrato.
//   - HONESTIDADE: uma inconsistência quebra a confiança de TUDO. Mesmo cega num
//     eixo, a ferramenta NÃO imprime RESULT: OK — a cobertura é rebaixada e o
//     veredito é CRITICAL.
//
// O que fica FORA (o Untestable de verdade): a versão que também falsifica o
// ftrace de forma consistente. Aí não sobra divergência nenhuma e a ferramenta
// reportaria limpo — o limite documentado, que exige o rootkit real.
func init() {
	Register(Scenario{
		ID:               "RK3-multivetor-cegueira-parcial",
		Desc:             "full-stealth multivetor: cega o cross-view de socket, é pego em módulo/pid/ftrace, e NÃO alega host íntegro",
		Mode:             VM,
		Kernel:           "lts",
		ModulosOcultacao: true,
		Setup: `mkdir -p /sys/kernel/tracing
			mount -t tracefs tracefs /sys/kernel/tracing
			insmod /modulos/inet_diag.ko
			insmod /modulos/tcp_diag.ko
			insmod /modulos/socknd.ko esconder=2
			insmod /modulos/modhide.ko esconder=2
			sh -c '/helper sleep 300 & exec /helper sleep 300' &
			P=$!
			sleep 0.5
			insmod /modulos/pidhide.ko oculto=$P`,
		Expect: []Expect{
			// A evasão incompleta: o ftrace delata o que /proc/modules e o
			// SOCK_DIAG esconderam.
			{ID: "cross.module_view", Sev: "CRITICAL", Subject: "modhide"},
			{ID: "kernel.ftrace_hook", Sev: "CRITICAL", Evidence: "esconde CONEXÃO"},
			{ID: "cross.hidden_pid", Sev: "CRITICAL"},
		},
		// O eixo CEGADO: a duplo-ocultação de socket funcionou, e a ferramenta é
		// honestamente cega — cross.socket_view NÃO pode produzir achado. Se ele
		// disparar, ou a evasão ficou incompleta ou o check ganhou sinal novo.
		Forbid: []string{"cross.socket_view"},
		// A HONESTIDADE, afirmada como negativa de saída: mesmo vencida na
		// aparência de um eixo, a ferramenta NÃO pode certificar o host limpo.
		ForbidOutput:     []string{"RESULT: OK"},
		ExpectOutput:     []string{"O KERNEL SE CONTRADISSE"},
		MustBeIncomplete: true,
		Exit:             2,
	})
}
