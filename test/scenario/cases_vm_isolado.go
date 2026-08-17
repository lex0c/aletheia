package scenario

// Situações que só uma VM responde com honestidade.
//
// Todas estas existiam como cenário de contêiner e dependiam de `--privileged`
// ou de `--cap-add`, e isso é uma concessão: um contêiner privilegiado é um
// ambiente que não se parece com o que se varre de verdade, e o runtime ainda
// mascara /sys por baixo.
//
// A VM não precisa de concessão nenhuma. Kernel próprio, root de verdade,
// nada mascarado — e o que ela mede é o que aconteceria num servidor.
//
//	G1  MAC rebaixado        /sys/fs/selinux não existe em contêiner nenhum
//	G2  hook de ftrace       tracefs de verdade, montado pelo próprio guest
//	G3  montagem que esconde bind sem privilégio emprestado

func init() {
	Register(Scenario{
		ID:   "G1-mac-rebaixado",
		Desc: "config pede enforcing e o kernel reporta permissivo: alguém rodou setenforce 0",
		// Nenhum contêiner tem selinuxfs — o runtime mascara /sys —, então este
		// check não era testável em lugar nenhum antes desta VM.
		//
		// O que ele procura é a CONTRADIÇÃO, não o estado: config em permissivo
		// é escolha declarada do administrador e não é achado. Nenhum sistema se
		// instala auto-contraditório, e a contradição não sobrevive a reboot —
		// é decisão recente por definição.
		Mode: VM,
		// A montagem é sobre /sys/fs, e não dentro dele: sysfs não aceita
		// `mkdir`, então criar /sys/fs/selinux direto falha com "operation not
		// permitted". Montar tmpfs POR CIMA de um diretório de sysfs funciona,
		// porque montar não escreve no filesystem de baixo.
		Setup: `mkdir -p /etc/selinux
			printf 'SELINUX=enforcing\nSELINUXTYPE=targeted\n' > /etc/selinux/config
			mount -t tmpfs tmpfs /sys/fs
			mkdir -p /sys/fs/selinux
			echo 0 > /sys/fs/selinux/enforce`,
		Expect: []Expect{
			{ID: "antiforense.mac_downgraded", Sev: "CRITICAL", Subject: "selinux"},
			{ID: "antiforense.mac_downgraded", Evidence: "DEPOIS do boot"},
			{ID: "antiforense.mac_downgraded", Evidence: "sem confinamento"},
		},
		Exit: 2,
	})

	Register(Scenario{
		ID:   "G2-mac-permissivo-declarado",
		Desc: "config PEDE permissivo: é escolha do administrador e não pode virar achado",
		// O outro lado, e ele importa mais.
		//
		// Metade dos servidores roda com SELinux permissivo de propósito. Se o
		// check acusasse o ESTADO em vez da contradição, ele falaria em todos
		// eles — e um check que fala sempre é um check que ninguém lê.
		Mode: VM,
		Setup: `mkdir -p /etc/selinux
			printf 'SELINUX=permissive\nSELINUXTYPE=targeted\n' > /etc/selinux/config
			mount -t tmpfs tmpfs /sys/fs
			mkdir -p /sys/fs/selinux
			echo 0 > /sys/fs/selinux/enforce`,
		Forbid: []string{"antiforense.mac_downgraded"},
		Exit:   -1,
	})

	Register(Scenario{
		ID:   "G3-hook-de-ftrace-em-vm",
		Desc: "hook de enumeração com tracefs montado pelo próprio guest, sem contêiner privilegiado",
		// O cenário D3 faz o mesmo dentro de um contêiner `--privileged`, o que
		// é uma concessão: contêiner privilegiado não se parece com o servidor
		// que se varre.
		//
		// Aqui o guest monta o tracefs porque é o kernel dele, e a leitura
		// acontece como aconteceria num host — inclusive a decisão de que
		// ausência de tracefs NÃO é lacuna, que só faz sentido onde ele PODE
		// existir.
		Mode: VM,
		Setup: `mkdir -p /sys/kernel/tracing
			mount -t tmpfs tmpfs /sys/kernel/tracing
			/helper ftrace /sys/kernel/tracing/enabled_functions __x64_sys_getdents64 diamorphine
			/helper ftrace /sys/kernel/tracing/enabled_functions tcp4_seq_show diamorphine`,
		Expect: []Expect{
			{ID: "kernel.ftrace_hook", Sev: "CRITICAL", Evidence: "esconde ARQUIVO"},
			{ID: "kernel.ftrace_hook", Evidence: "esconde CONEXÃO"},
			{ID: "kernel.ftrace_hook", Evidence: "NÃO é trampolim de eBPF"},
		},
		Exit: 2,
	})

	Register(Scenario{
		ID:   "G4-montagem-que-esconde-em-vm",
		Desc: "bind por cima de /etc num kernel próprio, sem privilégio emprestado de contêiner",
		// O D1 precisa de `--cap-add SYS_ADMIN` num contêiner. Aqui é só root
		// num kernel próprio, que é a situação real: quem já é root num
		// servidor monta o que quiser.
		Mode: VM,
		Setup: `mkdir -p /fake
			cp /etc/passwd /fake/passwd 2>/dev/null || true
			mount --bind /fake /etc`,
		Expect: []Expect{
			{ID: "kernel.mount_over_system", Sev: "CRITICAL", Subject: "/etc"},
			{ID: "kernel.mount_over_system", Evidence: "BIND de"},
		},
		Exit: 2,
	})
}
