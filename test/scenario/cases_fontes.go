package scenario

// Três fontes que faltavam, vindas de ler osquery, tracee e velociraptor.
//
//	D1  montagem por cima      esconder sem tocar em arquivo nenhum
//	D2  força bruta que entrou o cruzamento entre wtmp e btmp
//	D3  hook de enumeração     COMO o kernel estaria mentindo
//
// O D3 tem um limite escrito: ele planta o CONTEÚDO que o kernel produziria,
// num tracefs falso, e exercita o parser e a decisão. Carregar um rootkit de
// verdade na suíte trocaria a garantia de um check pela perda de controle sobre
// o ambiente de teste — é a mesma linha que o cenário 91 traça.

func init() {
	Register(Scenario{
		ID:   "D1-montagem-que-esconde",
		Desc: "bind por cima de /etc: o conteúdo real continua no disco e some da visão de todo processo",
		// Ocultação sem rootkit nenhum. Não precisa de módulo, não precisa de
		// LD_PRELOAD, não cria arquivo — e some no reboot sem deixar rastro.
		//
		// A ferramenta lê o filesystem como qualquer processo, então ela TAMBÉM
		// é enganada pela montagem. O que ela pode fazer é notar a montagem, e
		// a tabela é a única fonte que ainda mostra as duas camadas.
		Images: []string{"debian:12"},
		Caps:   []string{"SYS_ADMIN"},
		Plant:  montagemQueEsconde,
		Expect: []Expect{
			{ID: "kernel.mount_over_system", Sev: "CRITICAL", Subject: "/etc"},
			{ID: "kernel.mount_over_system", Evidence: "BIND de"},
			// E o roteiro precisa dizer para NÃO desmontar antes de preservar.
			{ID: "kernel.mount_over_system", Evidence: "continua no disco"},
		},
		Exit: 2,
	})

	Register(Scenario{
		ID:   "D2-forca-bruta-que-entrou",
		Desc: "a mesma origem que falhou dezenas de vezes conseguiu entrar",
		// É o achado que nenhuma das duas fontes dá sozinha, e é por isso que
		// vale existir:
		//
		//	btmp cheio de falhas    ruído de internet, todo host exposto tem
		//	wtmp com uma entrada    o host funcionando
		//	as duas na MESMA origem como o invasor chegou, com hora e endereço
		//
		// A ferramenta citava o wtmp em dezenas de evidências — "confira contra
		// o wtmp" — e nunca o lia. O formato nunca justificou a omissão: é
		// registro binário de tamanho fixo.
		Images: matriz,
		Plant:  forcaBrutaQueEntrou,
		Expect: []Expect{
			{ID: "auth.bruteforce_success", Sev: "CRITICAL", Subject: "203.0.113.9"},
			{ID: "auth.bruteforce_success", Evidence: "e depois ENTROU"},
			// E o inventário, que fecha o loop que a ferramenta apontava.
			{ID: "auth.login_inventory", Sev: "MANUAL", Subject: "root"},
		},
		// A origem legítima do time NÃO pode virar achado: ela entrou sem
		// falhar antes.
		Exit: 2,
	})

	Register(Scenario{
		ID:   "D3-hook-de-enumeracao",
		Desc: "função de listagem de diretório interceptada no kernel: algo está sendo escondido",
		// Os checks de visão cruzada dizem que o kernel PODE estar mentindo.
		// Este diz COMO — e sem isso o operador sabe que há ocultação e não sabe
		// de quê, o que não orienta resposta nenhuma.
		//
		// O que separa rootkit de ferramenta de observação é o CALLBACK:
		// bpftrace e perf carregam programa em eBPF e aparecem como trampolim;
		// módulo nomeado interceptando `getdents64` é outra conversa.
		//
		// LIMITE: o conteúdo é plantado num tracefs falso. Isso exercita o
		// parser e a decisão contra o que o kernel produziria — carregar um
		// rootkit de verdade trocaria a garantia de um check pela perda de
		// controle sobre o ambiente de teste.
		Images: []string{"debian:12"},
		Caps:   []string{"SYS_ADMIN"},
		Plant:  hookDeEnumeracaoFalso,
		Expect: []Expect{
			{ID: "kernel.ftrace_hook", Sev: "CRITICAL"},
			{ID: "kernel.ftrace_hook", Evidence: "esconde ARQUIVO"},
			// O discriminador precisa aparecer: não é eBPF, é módulo.
			{ID: "kernel.ftrace_hook", Evidence: "NÃO é trampolim de eBPF"},
		},
		Exit: 2,
	})
}

// ---------------------------------------------------------------------------

const montagemQueEsconde = `
mkdir -p /fake
cp /etc/passwd /fake/passwd 2>/dev/null || true
mount --bind /fake /etc
`

// forcaBrutaQueEntrou planta as duas metades: as falhas e a entrada.
const forcaBrutaQueEntrou = `
mkdir -p /var/log

# 25 tentativas recusadas da mesma origem — é o ruído que todo host exposto tem
/helper utmp /var/log/btmp 7 root 203.0.113.9 25

# e uma entrada bem-sucedida da MESMA origem: é o cruzamento que dá o sinal
/helper utmp /var/log/wtmp 7 root 203.0.113.9 1

# mais uma entrada legítima, de outra origem e SEM falhas antes: ela não pode
# virar achado, e é o que impede o check de acusar todo login que existe
/helper utmp /var/log/wtmp 7 deploy 10.0.0.15 3
chmod 600 /var/log/btmp
`

// hookDeEnumeracaoFalso monta um tracefs de mentira e escreve nele o que o
// kernel escreveria.
const hookDeEnumeracaoFalso = `
mkdir -p /sys/kernel/tracing
mount -t tmpfs tmpfs /sys/kernel/tracing

# a forma do rootkit: módulo nomeado interceptando listagem de diretório
/helper ftrace /sys/kernel/tracing/enabled_functions __x64_sys_getdents64 diamorphine
/helper ftrace /sys/kernel/tracing/enabled_functions filldir64 diamorphine
`
