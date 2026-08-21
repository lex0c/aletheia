package scenario

// Rootkits nomeados como PADRÕES de cenário adversarial.
//
// Estes cenários NÃO rodam na suíte: cada um exige o rootkit de verdade —
// código-fonte, kernel casado, compilação e um insmod/attach que só é seguro
// numa VM descartável (o `make vm-matrix`), nunca no host que roda o teste. É a
// mesma recusa do cenário 91 (cross-view): carregar um LKM de ocultação aqui
// trocaria a garantia de um check pela perda de controle do ambiente.
//
// O que eles SÃO: o contrato de detecção ESCRITO, por rootkit — a mecânica, os
// checks que DEVEM disparar (o piso que a ferramenta não pode perder) e os que o
// rootkit DERROTA (a lacuna honesta). Cada um traz a receita de como torná-lo
// executável. Quando alguém plantar o rootkit numa VM e a ferramenta se
// comportar como escrito aqui, o Untestable vira Expect e o cenário roda.
//
// O contrato é PREVISÃO pela mecânica, não medição — por isso Untestable, e não
// KnownGap: KnownGap AFIRMA o silêncio medido, e afirmar sem rodar seria a
// tautologia que a suíte existe para recusar.

func init() {
	// --- BASELINES: o piso. Se a ferramenta perde um destes, algo regrediu. ---

	Register(Scenario{
		ID:   "RK1-diamorphine",
		Desc: "LKM clássico: esconde módulo de /proc/modules, esconde PID por sinal, dá root por sinal",
		// github.com/m0nad/Diamorphine. Esconde o próprio módulo (some da module
		// list e do /sys/module), esconde processo por um sinal mágico e eleva
		// privilégio por outro. É o rootkit de referência.
		//
		// CONTRATO por rota, e a severidade é do MECANISMO — o Diamorphine
		// clássico patcha a sys_call_table, NÃO usa ftrace:
		//   PISO (DEVE disparar)
		//     cross.hidden_pid   o PID escondido responde a stat direto e não à
		//                        listagem de /proc — vale qualquer que seja a
		//                        técnica de ocultação
		//   DEPENDE DA VERSÃO/KERNEL
		//     cross.module_view  dispara SE a versão deixar rastro no ftrace
		//                        (available_filter_functions) e some do /proc/modules
		//     kernel.ftrace_hook  SÓ se a versão hooka por ftrace. A que patcha a
		//                        sys_call_table direto NÃO aparece aqui — e, num
		//                        kernel 6.x com despacho por switch, esse patch é
		//                        no-op e a ocultação de getdents nem funciona,
		//                        mudando o quadro inteiro
		// Ou seja: ftrace_hook NÃO é piso; é sinal quando o mecanismo é ftrace. O
		// cenário real decide empiricamente o que sobra no kernel escolhido.
		// Quebra da CONFIANÇA: quando um destes dispara, a ausência dos outros
		// deixa de valer (invalidarAusencias).
		//
		// RECEITA: compilar o .ko contra o kernel do guest (Alpine LTS, como o
		// vm-matrix já faz para socknd/modhide), insmod dentro da VM, plantar um
		// processo, escondê-lo pelo sinal, e exigir os três checks acima.
		Untestable: "exige o LKM Diamorphine compilado e carregado; ocultação de " +
			"módulo/PID só é real vinda do kernel, e carregá-la na suíte Go " +
			"perderia o controle do ambiente. Provar no vm-matrix (make vm-matrix), " +
			"onde módulo que se esconde já é carregado em VM descartável.",
	})

	Register(Scenario{
		ID:   "RK2-reptile",
		Desc: "LKM por ftrace: esconde arquivo/dir/PID/porta e persiste, com trigger de rede",
		// github.com/f0rb1dd3n/Reptile. Hooks por ftrace, esconde arquivos por
		// prefixo, PIDs, portas, e traz persistência (o loader). Mais completo
		// que o Diamorphine, mesma família de mecanismo (ftrace).
		//
		// CONTRATO (piso — DEVE disparar):
		//   kernel.ftrace_hook  os hooks em enabled_functions são o mecanismo
		//   cross.module_view   se o módulo se esconde da module list
		//   persist.*           o loader/persistência do Reptile em disco
		// LACUNA possível: se a versão esconder a porta de /proc/net E do
		// SOCK_DIAG ao mesmo tempo, o cross.socket_view cega — mas o hook em
		// ftrace continua visível (é o duplo-hide que o vm-matrix já mede).
		//
		// RECEITA: idem RK1; a persistência do loader também sai na varredura de
		// disco (modo --root), sem precisar de VM.
		Untestable: "exige o LKM Reptile compilado e carregado num kernel casado; " +
			"mesma recusa do RK1. A PARTE de persistência em disco é analisável " +
			"por --root sobre uma imagem, sem carregar o módulo — vale um cenário " +
			"de imagem separado se/quando houver um rootfs com o loader plantado.",
	})

	// --- BOSS FIGHT: o adversário que ataca as TESTEMUNHAS do live scan. ---

	Register(Scenario{
		ID:   "RK3-singularity-full-stealth",
		Desc: "rootkit 6.x que falsifica /proc, /proc/net, module list, sysfs, taint, SOCK_DIAG, BPF, ftrace, audit",
		// github.com/gavz/Singularity_rootkit (kernels 6.x). É o principal
		// candidato a fazer a ferramenta dizer "não há nada": não esconde só
		// /proc, esconde de TODAS as fontes que a Aletheia cruza — /proc/net E
		// SOCK_DIAG, module list E sysfs E taint, BPF iterators, ferramentas de
		// eBPF, ftrace e audit.
		//
		// CONTRATO HONESTO — a Aletheia NÃO detecta o efeito quando todas as
		// evasões estão ativas, e o cenário existe para MEDIR isso, não para
		// alegar detecção:
		//   - O cross-view (a arma principal) cega: view A mente, view B mente
		//     igual, e não há divergência para achar. É o duplo-hide levado a
		//     TODAS as fontes.
		//   - A única salvação é a evasão INCOMPLETA: se o hook aparecer em
		//     enabled_functions, kernel.ftrace_hook o pega; se a module list
		//     divergir do ftrace, cross.module_view o pega. A versão full-stealth
		//     que também falsifica o ftrace derrota isso.
		//   - O que a ferramenta DEVE fazer mesmo perdendo: NÃO afirmar "limpo".
		//     A quebra de confiança por inconsistência de kernel deve rebaixar a
		//     cobertura — ausência de achado deixa de significar ausência.
		// O alvo NÃO é Expect de detecção: é ForbidOutput de qualquer alegação de
		// host íntegro + Expect da cobertura REBAIXADA. É o adversário que prova o
		// limite, não a força.
		//
		// PARCIALMENTE MEDIDO: a propriedade central — cega um eixo, é pego em
		// outro pela evasão incompleta, e NÃO alega host íntegro — já roda no
		// RK3-multivetor-cegueira-parcial (cases_ocultacao.go), com os PADRÕES de
		// evasão do Singularity carregados juntos (socknd+modhide+pidhide): ele
		// afirma ForbidOutput "RESULT: OK" + cobertura rebaixada, sem precisar do
		// rootkit real. O que SOBRA Untestable é só o extremo: a versão que
		// também falsifica o ftrace de forma consistente, onde não resta
		// divergência nenhuma e a ferramenta reportaria limpo — o limite que
		// exige o Singularity de verdade num kernel 6.x casado.
		Untestable: "os PADRÕES de evasão já são medidos no " +
			"RK3-multivetor-cegueira-parcial. Só o extremo full-stealth que " +
			"falsifica TAMBÉM o ftrace (sem divergência residual) exige o " +
			"Singularity real num kernel 6.x — aí o contrato é o LIMITE (reportar " +
			"limpo é o ponto cego documentado).",
	})

	// --- eBPF: atribuição parcial e lacuna FixMapa declarada. ---

	Register(Scenario{
		ID:   "RK4-triplecross",
		Desc: "rootkit eBPF multipropósito: stealth, injeção, hijack e C2 por vários tipos de programa/anexo",
		// github.com/h3xduck/TripleCross. Usa várias capacidades de eBPF —
		// XDP, tc, tracepoints, cgroup — para stealth, injeção e C2.
		//
		// CONTRATO (PARCIAL, por tipo de anexo — o valor é medir QUAL premissa
		// cada programa derrota):
		//   ATRIBUÍDO   XDP/tc/cgroup preso a interface/cgroup → a Aletheia o
		//               NOMEIA (RTM_GETLINK/GETTFILTER/BPF_PROG_QUERY), como o
		//               vm-matrix já prova para os anexos de rede.
		//   bpf_unowned programa órfão de fd/pin/link → CRÍTICO (não some).
		//   LACUNA      programa segurado por MAPA (sk_msg/sockmap/struct_ops) →
		//               FixMapa: lacuna DECLARADA, não atribuída (o vm-matrix já
		//               mede esse caminho com o plant sockmap).
		// Ou seja: TripleCross não é "detectado" ou "perdido" em bloco — cada
		// programa cai numa dessas três, e o cenário tem de dizer QUAL.
		//
		// RECEITA: carregar o TripleCross na VM e, para CADA programa BPF que ele
		// cria, casar contra o dump: atribuído, unowned-crítico ou FixMapa. O
		// arcabouço de medição por-programa já existe no vm-matrix.
		Untestable: "exige o TripleCross carregado; o contrato é por-PROGRAMA " +
			"(atribuído vs bpf_unowned vs FixMapa), não um veredito único. O " +
			"arcabouço para medir isso é o vm-matrix (atribuição de cgroup/tc/xdp " +
			"e a lacuna FixMapa do sockmap já provados lá).",
	})

	Register(Scenario{
		ID:   "RK5-ebpfkit",
		Desc: "rootkit eBPF com anexos e mapas variados para stealth e controle",
		// github.com/Gui774ume/ebpfkit. Como o TripleCross, vive por eBPF, com
		// ênfase em mapas e anexos diversos.
		//
		// CONTRATO: idêntico em ESPÍRITO ao RK4 — a pergunta é a atribuição por
		// programa. O interesse específico do ebpfkit é a dependência de MAPAS
		// para estado/controle: é o candidato mais forte a cair no FixMapa
		// (segurado por mapa → lacuna declarada), o gap que o RK4 também toca e
		// que o vm-matrix mede com sk_skb/sockmap.
		//
		// RECEITA: idem RK4.
		Untestable: "exige o ebpfkit carregado; contrato por-programa como o RK4, " +
			"com peso no caminho FixMapa (segurado por mapa). Medir no vm-matrix.",
	})

	Register(Scenario{
		ID:   "RK6-boopkit",
		Desc: "backdoor eBPF: RCE sobre TCP cru com gatilho de rede e ocultação de processo",
		// github.com/krisnova/boopkit. eBPF + RCE sobre TCP cru (pacote-gatilho)
		// + ocultação de processo. Mistura rede, BPF e hidden-process.
		//
		// CONTRATO (candidato a DETECÇÃO — vários ângulos):
		//   inventário BPF     o programa de filtro/gatilho aparece
		//   bpf_unowned        se órfão de fd/pin/link → CRÍTICO
		//   cross.hidden_pid   se esconde processo por divergência de /proc
		//   net/socket         o socket cru / comportamento de rede
		// A expectativa pela mecânica é BOA chance de pelo menos um disparar —
		// mas é previsão, e o cenário existe para CONFIRMAR contra o binário real,
		// não para escrever "detected" antes de rodar.
		//
		// RECEITA: carregar o boopkit na VM, disparar o pacote-gatilho, e exigir
		// pelo menos um dos ângulos acima; medir quais.
		Untestable: "exige o boopkit carregado e o pacote-gatilho disparado; a " +
			"expectativa é detecção por algum ângulo (bpf_unowned, hidden_pid, " +
			"socket cru), mas é previsão a confirmar no vm-matrix, não medição.",
	})
}
