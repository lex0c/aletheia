package scenario

// eBPF: o implante que mora DENTRO do kernel (fase 8).
//
// Todos rodam em VM porque contêiner não alcança: a bpf(2) é bloqueada pelo
// seccomp padrão do runtime, e sem CAP_BPF não há enumeração nenhuma. É o
// mesmo motivo que levou os cenários de MAC e de ftrace para lá.
//
// O par que importa é P1/P2. Os dois carregam o MESMO programa, com a mesma
// syscall, no mesmo kernel — e a única diferença é quem fica segurando o
// descritor depois. Um vira crítico, o outro não pode virar nada. Sem os dois,
// o check não estaria demonstrado: estaria só disparando.
//
//	P1  descritor fechado, socket segura      implante: crítico
//	P2  descritor aberto pelo carregador      ferramenta com libbpf: silêncio
//	P3  pin no bpffs                          persistência DECLARADA: silêncio
//	P4  perf_event legado                     bpftrace antigo: silêncio
//	P5  taint sem módulo que o admita         módulo que carregou e sumiu

func init() {
	Register(Scenario{
		ID:   "P1-bpf-sem-dono",
		Desc: "programa eBPF carregado, anexado a um socket e com o descritor fechado: ninguém visível o segura",
		Mode: VM,
		// O programa é o menor programa válido que existe — devolve zero e
		// termina. O que está sob teste é a FORMA (algo carregado no kernel
		// sem dono aparente), não comportamento de implante nenhum.
		//
		// O `sleep` existe porque o carregamento é assíncrono do ponto de vista
		// do shell: sem ele a varredura pode começar antes de a syscall ter
		// devolvido.
		Setup: `/helper bpf socket implante &
			sleep 1`,
		Expect: []Expect{
			{ID: "kernel.bpf_unowned", Sev: "CRITICAL", Evidence: "socket_filter"},
			{ID: "kernel.bpf_unowned", Evidence: "nenhum processo tem descritor aberto"},
			{ID: "kernel.bpf_unowned", Evidence: "SOCKET"},
			{ID: "kernel.bpf_inventory", Sev: "MANUAL"},
		},
		Exit: 2,
	})

	Register(Scenario{
		ID:   "P2-bpf-com-dono-nao-acusa",
		Desc: "o MESMO programa, com o descritor mantido aberto: é o que toda ferramenta com libbpf faz",
		Mode: VM,
		// Este é o cenário que mede o custo do check em host legítimo. Falco,
		// tetragon, cilium e bpftrace carregam programa eBPF e mantêm o
		// descritor — se isto virasse achado, o check falaria em todo host com
		// observabilidade e ninguém leria a saída.
		Setup: `/helper bpf hold observador &
			sleep 1`,
		Forbid: []string{"kernel.bpf_unowned"},
		Expect: []Expect{
			{ID: "kernel.bpf_inventory", Sev: "MANUAL", Evidence: "helper(1)"},
		},
		Exit: -1,
	})

	Register(Scenario{
		ID:   "P3-bpf-pin-e-dono-visivel",
		Desc: "programa preso no bpffs e o carregador SAIU: o pin é dono, e persistência declarada não é achado",
		Mode: VM,
		// O pin é como um programa sobrevive à saída de quem o carregou de
		// forma legítima — é assim que cilium e bpfman fazem. Tem caminho, tem
		// data e tem dono: o oposto do órfão do P1, embora o carregador tenha
		// morrido nos dois.
		Setup: `mkdir -p /sys/fs/bpf
			mount -t bpf bpf /sys/fs/bpf
			/helper bpf pin /sys/fs/bpf/agente pinado`,
		Forbid: []string{"kernel.bpf_unowned"},
		Expect: []Expect{
			{ID: "kernel.bpf_inventory", Sev: "MANUAL", Evidence: "pin(s)"},
		},
		Exit: -1,
	})

	Register(Scenario{
		ID:   "P4-bpf-perf-event-legado",
		Desc: "anexo legado por perf_event, sem link nenhum: o kernel é quem sabe quem segura",
		Mode: VM,
		// O falso positivo que este cenário existe para travar.
		//
		// No caminho antigo — perf_event_open no tracepoint e o programa
		// pendurado por ioctl — não há link, e o descritor que segura é um
		// perf_event, cujo fdinfo NÃO cita o programa. De fora, ele parece
		// órfão. É como bpftrace e agente com libbpf antiga anexam.
		//
		// A resposta é perguntar ao kernel (BPF_TASK_FD_QUERY), e é isso que
		// está sob teste aqui.
		Setup: `mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null ||
				{ mount -t debugfs none /sys/kernel/debug && mount -t tracefs tracefs /sys/kernel/debug/tracing; }
			/helper bpf tracepoint syscalls/sys_enter_execve sonda &
			sleep 1`,
		Forbid: []string{"kernel.bpf_unowned"},
		Expect: []Expect{
			{ID: "kernel.bpf_inventory", Sev: "MANUAL", Evidence: "perf_event"},
		},
		Exit: -1,
	})

	Register(Scenario{
		ID:   "P6-bpf-anexo-por-cgroup",
		Desc: "programa anexado a um cgroup sem link e sem descritor: a população legítima que NÃO pode virar achado",
		Mode: VM,
		// A forma mais comum em servidor moderno, e o falso positivo mais caro
		// que este check poderia cometer. `BPF_PROG_ATTACH` não deixa descritor,
		// não deixa pin e não deixa link — quem segura é o CGROUP —, e é assim
		// que o systemd aplica controle de dispositivo e de rede por unit.
		//
		// Resolver isso exigiria BPF_PROG_QUERY em cada cgroup da árvore, que
		// esta ferramenta não faz. A resposta certa é DECLARAR a lacuna, com o
		// número junto, em vez de acusar — e é o que este cenário trava.
		//
		// O `-vv` está aqui porque o motivo de cobertura parcial sai resumido no
		// relatório compacto, e o que precisa ser verificado é a frase inteira.
		Setup: `mkdir -p /sys/fs/cgroup
			mount -t cgroup2 none /sys/fs/cgroup
			mkdir -p /sys/fs/cgroup/teste
			/helper bpf cgroup /sys/fs/cgroup/teste filtro`,
		Args:             []string{"-vv"},
		Forbid:           []string{"kernel.bpf_unowned"},
		ExpectOutput:     []string{"CGROUP"},
		MustBeIncomplete: true,
		Exit:             -1,
		// Orçamento de ruído MEDIDO: silêncio é o contrato deste cenário.
		MaxWarn: SemAvisos,
	})

	Register(Scenario{
		ID:   "P7-bpf-preso-a-mapa",
		Desc: "programa vivo apenas por estar num prog_array: é o mapa que segura, e é como o cilium encadeia",
		Mode: VM,
		// Sem a leitura de prog_array, todo programa encadeado por tail call
		// apareceria órfão — e num nó com cilium são dezenas. O helper segura o
		// MAPA e larga o descritor do programa, que é exatamente a forma.
		Setup: `/helper bpf tailcall encadeado &
			sleep 1`,
		Forbid: []string{"kernel.bpf_unowned"},
		Expect: []Expect{
			{ID: "kernel.bpf_inventory", Sev: "MANUAL", Evidence: "tail call"},
		},
		Exit: -1,
	})

	Register(Scenario{
		ID:   "P8-bpfdoor-completo",
		Desc: "socket AF_PACKET com filtro eBPF e descritor fechado: o implante que não abre porta, e quem o segura nomeado",
		Mode: VM,
		// A forma inteira, e o que ela tem de traiçoeiro: o processo existe, o
		// programa existe, e a tabela de conexões não mostra NADA. Não há porta
		// escutando, não há conexão estabelecida — o kernel entrega o quadro
		// direto ao filtro, e o gatilho é um pacote que ninguém vê chegar.
		//
		// O par de achados é o ponto: o eBPF órfão diz que algo está carregado
		// sem dono, e a leitura da §2.6 diz QUEM tem socket de captura neste
		// host. Junto, o relatório para de mandar procurar e passa a apontar.
		Setup: `/helper bpf pacote implante &
			sleep 1`,
		Expect: []Expect{
			{ID: "kernel.bpf_unowned", Sev: "CRITICAL", Evidence: "socket_filter"},
			{ID: "kernel.bpf_unowned", Evidence: "candidatos a detentor"},
			{ID: "kernel.bpf_unowned", Evidence: "helper"},
			{ID: "net.packet_socket", Sev: "MANUAL", Evidence: "ETH_P_ALL"},
		},
		Exit: 2,
	})

	Register(Scenario{
		ID:   "P9-socket-de-captura-sem-implante",
		Desc: "o MESMO socket de captura, sem programa nenhum: é o gerenciador de rede, e não pode virar acusação",
		// Em contêiner de propósito: AF_PACKET só exige CAP_NET_RAW, que o
		// runtime concede por padrão — e é ali que a leitura precisa funcionar
		// em distribuições diferentes.
		//
		// O que ele trava é a metade negativa da §2.6: um socket de captura
		// sozinho é INVENTÁRIO. Cliente de DHCP e wpa_supplicant abrem
		// exatamente este socket em todo host com rede, e se isso virasse aviso
		// a ferramenta gritaria em todos eles.
		Images: matriz,
		Plant: `/helper pacote &
			sleep 0.5`,
		Expect: []Expect{
			{ID: "net.packet_socket", Sev: "MANUAL", Evidence: "helper"},
			{ID: "net.packet_socket", Evidence: "ETH_P_ALL"},
		},
		Forbid: []string{"kernel.bpf_unowned"},
		Exit:   -1,
	})

	Register(Scenario{
		ID:   "P5-taint-sem-modulo-que-admita",
		Desc: "o kernel registra módulo não assinado e nenhum módulo carregado assume: o que fica depois que o módulo sai",
		Mode: VM,
		// A marca é plantada pela própria interface do kernel, que só faz OR: o
		// estado resultante é REAL e indistinguível do que um módulo teria
		// deixado. E ele não sai mais — nem com root, nem apagando arquivo.
		// Só reiniciando, e reiniciar é o que a resposta a incidente evita.
		//
		// O guest não tem módulo nenhum carregado, que é justamente a situação
		// de "quem sujou já foi embora".
		Setup: `echo 8192 > /proc/sys/kernel/tainted`,
		Expect: []Expect{
			{ID: "kernel.taint_unexplained", Sev: "WARN", Subject: "taint E"},
			{ID: "kernel.taint_unexplained", Evidence: "NÃO ASSINADO"},
			{ID: "kernel.taint_unexplained", Evidence: "não pode ser apagada"},
		},
		Exit: 1,
	})
}

// P10 é o cenário COMPOSTO desta fase: ele junta a detecção (fase 8) com a
// caça (fase 5) no mesmo host, e é a única coisa da suíte que prova o pivô de
// frota para um implante que não tem arquivo.
//
// A tag do programa é determinística — o kernel a calcula do bytecode, e o
// helper carrega sempre as mesmas duas instruções —, então ela funciona como o
// indicador que veio do host anterior.
func init() {
	Register(Scenario{
		ID:   "P10-tag-de-ebpf-como-indicador",
		Desc: "a tag do implante em eBPF, trazida do host anterior, encontra o mesmo programa aqui",
		Mode: VM,
		// A pergunta que este cenário responde é a da §23, para o tipo de
		// artefato mais difícil que existe: um programa eBPF não tem caminho,
		// não tem inode, não tem data de arquivo e some no reboot. A tag é a
		// única coisa dele que atravessa hosts.
		//
		// Os dois achados juntos são o produto: um diz "há algo carregado sem
		// dono", o outro diz "e é EXATAMENTE o que já vimos no outro host".
		Setup: `printf 'strings: [a04f5eef06a7f555]\n' > /ioc.yaml
			/helper bpf socket implante &
			sleep 1`,
		Args: []string{"--ioc", "/ioc.yaml"},
		Expect: []Expect{
			{ID: "kernel.bpf_unowned", Sev: "CRITICAL", Evidence: "socket_filter"},
			{ID: "ioc.match", Sev: "CRITICAL", Evidence: "tag do programa eBPF"},
			{ID: "ioc.match", Subject: "bpf prog id="},
		},
		Exit: 2,
	})
}
