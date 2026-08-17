package scenario

// Matriz de userland. O objetivo não é cobrir distro por distro, é provar que a
// ferramenta SONDA em vez de detectar: layouts diferentes de cron, systemd,
// base de pacotes e libc.
var (
	matriz  = []string{"debian:12", "alpine:3.20"}
	minimal = []string{"alpine:3.20"} // rápido, e sem glibc: prova o binário estático
)

func init() {
	// ---------------------------------------------------------------- negativos
	//
	// Valem tanto quanto os positivos. Um check que dispara em host limpo é
	// ruído que treina o operador a ignorar o relatório inteiro.

	Register(Scenario{
		ID:     "00-limpo",
		Desc:   "contêiner intocado não pode produzir achado nenhum",
		Images: matriz,
		Expect: nil,
		Forbid: []string{"proc.memfd_exec", "proc.exe_deleted", "proc.kthread_disguise"},
		Exit:   0,
	})

	Register(Scenario{
		ID:   "01-sem-root",
		Desc: "sem root a cobertura DEGRADA e o exit não pode ser 0",
		// É o invariante central da ferramenta: distinguir "não achei" de
		// "não consegui olhar". Antes da revisão, esta execução saía OK/0 com
		// 246 de 303 processos ilegíveis.
		Images:           matriz,
		User:             "1000",
		Plant:            `sleep 300 &`,
		Exit:             1,
		MustBeIncomplete: true,
	})

	Register(Scenario{
		ID:     "02-kthread-real",
		Desc:   "thread de kernel legítima não dispara: ela não tem exe",
		Images: minimal,
		Forbid: []string{"proc.kthread_disguise"},
		Exit:   0,
	})

	// ---------------------------------------------------------------- positivos

	Register(Scenario{
		ID:     "10-kthread-disguise",
		Desc:   "implante renomeado com exec -a para se passar por thread de kernel",
		Images: matriz,
		// Duas armadilhas de portabilidade que a matriz revelou:
		//   1. exec -a é builtin do BASH; debian usa dash e alpine usa busybox ash
		//   2. o /bin/sleep do Alpine É o busybox, que despacha pelo argv[0] —
		//      renomeá-lo faz ele procurar um applet inexistente e sair
		// O alvo precisa ser um binário próprio, estático e sem despacho por nome.
		Plant: `/helper argv0 "[kworker/9:2]" /helper sleep 300 &
			sleep 0.4`,
		Expect: []Expect{{ID: "proc.kthread_disguise", Sev: "CRITICAL"}},
		// Não pode confundir com os outros dois checks de exe.
		Forbid:         []string{"proc.memfd_exec"},
		Exit:           2,
		MustBeComplete: true,
	})

	Register(Scenario{
		ID:     "11-exe-apagado",
		Desc:   "binário apagado com o processo ainda rodando",
		Images: matriz,
		// Mesma razão do cenário acima: copiar o /bin/sleep do Alpine copia o
		// busybox inteiro, e invocá-lo como ".y" não resolve applet nenhum.
		Plant: `cp /helper /tmp/.y
			/tmp/.y sleep 300 &
			sleep 0.4
			rm -f /tmp/.y`,
		// WARN, não CRITICAL: é o que acontece em TODA atualização de pacote
		// com o serviço no ar. A severidade precisa refletir isso.
		Expect:         []Expect{{ID: "proc.exe_deleted", Sev: "WARN"}},
		Forbid:         []string{"proc.memfd_exec"},
		Exit:           1,
		MustBeComplete: true,
	})

	Register(Scenario{
		ID:   "12-pid1-nao-eh-isento",
		Desc: "PID 1 é avaliado como qualquer outro processo",
		// Regressão do pior achado da revisão: a versão anterior isentava toda
		// a cadeia de ancestrais, e como a caminhada terminava em 1, o PID 1
		// ficava fora de todo check em todo host — junto com o sshd que
		// costuma ser ancestral da sessão de IR.
		Images: minimal,
		Plant:  ``, // o próprio PID 1 do contêiner é o alvo
		Args:   []string{"-v"},
		Exit:   -1,
	})

	Register(Scenario{
		ID:   "13-memfd-fileless",
		Desc: "binário executado de memória anônima: nunca esteve em disco",
		// A forma que anula §8 (find), §5.4 (hash) e §24 (pacote) de uma vez:
		// não há caminho, não há inode, não há o que comparar. E matar o
		// processo destrói a única cópia existente.
		Images: matriz,
		Plant: `/helper memfd /helper sleep 300 &
			sleep 0.4`,
		Expect: []Expect{{ID: "proc.memfd_exec", Sev: "CRITICAL"}},
		// memfd tem check próprio: não pode ser contado também como exe apagado.
		Forbid:         []string{"proc.exe_deleted"},
		Exit:           2,
		MustBeComplete: true,
	})

	// ---------------------------------------------------------------- modo image

	Register(Scenario{
		ID:   "20-image-symlink-absoluto",
		Desc: "imagem com symlink absoluto não pode ler o host do analista",
		// Symlink absoluto é NORMAL em rootfs real (/etc/os-release →
		// /usr/lib/os-release). Antes da correção, varrer uma imagem imprimia
		// o hostname e a distro do ANALISTA atribuídos a ela.
		Images: minimal,
		Mode:   Image,
		Plant: `ln -sf /etc/hostname /etc/hostname.link
			rm -f /etc/os-release && ln -s /nao/existe/os-release /etc/os-release`,
		Exit: -1,
	})

	Register(Scenario{
		ID:     "21-image-sem-processo",
		Desc:   "imagem montada não tem processo: os checks de proc viram NÃO VERIFICADO",
		Images: minimal,
		Mode:   Image,
		// Zero processos numa imagem não é "host limpo" — é ausência de fonte,
		// e precisa aparecer como tal.
		Forbid:           []string{"proc.memfd_exec", "proc.exe_deleted", "proc.kthread_disguise"},
		MustBeIncomplete: true,
		Exit:             1,
	})

	// ------------------------------------------------------- fora do contêiner

	Register(Scenario{
		ID:   "90-kernel-antigo",
		Desc: "procfs de kernel 2.6.32 (campos ausentes em /proc/<pid>/status)",
		Untestable: "contêiner compartilha o kernel do host: uma imagem centos:6 testa o " +
			"LAYOUT de userland, não o procfs antigo. Exige VM.",
	})

	// ----------------------------------------------------------------- VM
	//
	// Kernel próprio. É o que contêiner não alcança, porque compartilha o do
	// host: opção de mount de /proc, sysctl, módulo, cgroup, eBPF.

	Register(Scenario{
		ID:   "30-hidepid-root",
		Desc: "com root, hidepid=2 não esconde nada: o implante é visto",
		Mode: VM,
		Setup: `adduser -D -u 1000 app
			/helper argv0 "[kworker/0:9]" /helper sleep 300 &
			sleep 0.4
			mount -o remount,hidepid=2 /proc`,
		Expect:         []Expect{{ID: "proc.kthread_disguise", Sev: "CRITICAL"}},
		Exit:           2,
		MustBeComplete: true,
	})

	Register(Scenario{
		ID:   "31-hidepid-sem-root",
		Desc: "sem root sob hidepid=2 o implante é INVISÍVEL — e a ferramenta precisa DIZER isso",
		// É o defeito que a revisão de código encontrou, no ambiente exato em
		// que ele se manifestava: a ferramenta via 4 de 310 processos e
		// imprimia "RESULT: OK, exit 0" com um implante CRITICAL bem ali.
		// A asserção é dupla e é o coração da suíte: o achado NÃO aparece
		// (nada a fazer, ele é mesmo invisível) E o veredito NÃO pode ser OK.
		Mode: VM,
		User: "app",
		Setup: `adduser -D -u 1000 app
			/helper argv0 "[kworker/0:9]" /helper sleep 300 &
			sleep 0.4
			mount -o remount,hidepid=2 /proc`,
		Forbid:           []string{"proc.kthread_disguise"},
		MustBeIncomplete: true,
		Exit:             1,
	})

	Register(Scenario{
		ID:   "92-userland-trojanizado",
		Desc: "ls/ss/ps substituídos não podem mudar o resultado da CLI",
		Untestable: "prova a decisão da SPEC 4 (binário estático, sem chamar binário do " +
			"host). Precisa de uma imagem com userland adulterado de propósito — " +
			"vale construir quando a fase 7 (integridade) existir.",
	})
}
