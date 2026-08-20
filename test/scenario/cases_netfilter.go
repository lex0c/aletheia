//go:build scenarios

package scenario

// Backdoor de netfilter no kernel (magic-packet, forma Syslogk/Drovorub),
// MEDIDO contra kernel real.
//
// A pergunta que este cenário fecha: um hook de netfilter é visto pela
// ferramenta? A resposta honesta começa por um NÃO estrutural — o kernel NÃO
// expõe a lista de nf_hooks registrados a userspace (/proc/net/netfilter só tem
// nf_log). Não há como enumerá-los nativamente, então um "cross-view de nf_hook
// × ruleset" não é construível zero-dep.
//
// Mas o backdoor de netfilter tem de viver em algum lugar: um MÓDULO ou um
// programa BPF. E os dois já são cobertos. Quando é módulo — o caso do Syslogk,
// do Drovorub — o MÓDULO é o sinal, não o hook: se ele se esconde, o
// cross.module_view o delata pela função do hook que sobra em
// available_filter_functions (a mesma via do modhide). É isso que este cenário
// MEDE, com um nf_hook DE VERDADE registrado (nfhook.ko), fechando "a classe
// backdoor-de-netfilter está coberta?" com um sim medido, não afirmado.
//
// (O caso BPF é coberto pelos checks de bpf; o caso "regra nftables NFQUEUE" é o
// único gap distinto, e é alto FP — fica declarado, não construído às cegas.)
func init() {
	Register(Scenario{
		ID:   "NF1-netfilter-backdoor-oculto",
		Desc: "backdoor de netfilter que se esconde de /proc/modules é pego pelo cross.module_view via a função do hook no ftrace",
		Mode: VM,
		// O mesmo mecanismo do RK-cross-module-view, mas o módulo aqui registra
		// um nf_hook REAL: é a prova de que a classe netfilter mapeia para a
		// cobertura de módulo, não uma duplicata do modhide por acaso.
		Kernel:           "lts",
		ModulosOcultacao: true,
		Setup: `mkdir -p /sys/kernel/tracing
			mount -t tracefs tracefs /sys/kernel/tracing
			insmod /modulos/nfhook.ko esconder=1`,
		Expect: []Expect{
			{ID: "cross.module_view", Sev: "CRITICAL", Subject: "nfhook"},
			{ID: "cross.module_view", Evidence: "NÃO está em /proc/modules"},
		},
		ExpectOutput:     []string{"O KERNEL SE CONTRADISSE"},
		MustBeIncomplete: true,
		Exit:             2,
	})
}
