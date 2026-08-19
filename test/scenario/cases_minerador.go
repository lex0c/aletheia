package scenario

// O criptominerador falando com o POOL — o sinal de rede que faltava.
//
// Já há dois cenários vizinhos, e este existe pela lacuna EXATA entre eles:
//
//	81-minerador-oportunista   pega o processo (disfarce, tmpfs, rwx) e a VOLTA
//	                           (cron, unit), mas NÃO afirma a conexão de pool
//	86-c2-por-origem           pega o egresso sem dono, mas de um binário de
//	                           SISTEMA (/usr/local/sbin) — severidade AVISO, e
//	                           de propósito "bem-comportado" no resto
//
// O XMRig real não é nenhum dos dois isolados: é UM processo em tmpfs que se
// disfarça de thread de kernel E abre a conexão stratum para o pool. Essa
// composição aciona o `net.egress_unowned` no ramo CRÍTICO — o `peso` de
// diretório gravável por qualquer um —, que o 86 (binário de sistema, AVISO)
// nunca exercita, e liga o sinal de rede ao MESMO pid que já é anômalo pelo
// caminho e pelo nome. É a forma que um responder encontra de verdade.
//
// O `pool` fica FORA do host num incidente real. Aqui, sem rede (NoNetwork), um
// listener local segura a outra ponta para o retrato mostrar o socket
// ESTABELECIDO — é o mesmo artifício do 86. Esse listener sem dono numa porta
// pública é, ele próprio, um achado legítimo (`net.listener_unowned`), mas é
// consequência do NoNetwork e não o sinal que este cenário demonstra: por isso
// não está no Expect.

func init() {
	Register(Scenario{
		ID:        "99-minerador-fala-com-pool",
		Desc:      "criptominerador em tmpfs, disfarçado de kthread, abrindo a conexão stratum para o pool",
		Images:    minimal,
		Caps:      []string{"NET_ADMIN"},
		NoNetwork: true,
		Plant: `mkdir -p /etc/crontabs
			ip link set lo up
			ip addr add 203.0.113.77/32 dev lo

			# o "pool": um listener local que segura a conexão (ver comentário)
			/helper listen 203.0.113.77:5555 &
			sleep 0.4

			# o minerador: cai em tmpfs (volátil, gravável por todos), assume o
			# nome de uma thread de kernel, e fala com o pool — um processo, três
			# sinais
			cp /helper /tmp/.xmrig
			/helper argv0 "[kworker/0:0]" /tmp/.xmrig connect 203.0.113.77:5555 &
			sleep 0.6

			# a volta depois do reboot que apaga o /tmp
			printf '@reboot /tmp/.xmrig connect 203.0.113.77:5555\n* * * * * /tmp/.xmrig connect 203.0.113.77:5555\n' > /etc/crontabs/root
			chmod 600 /etc/crontabs/root
			sleep 0.2`,
		Expect: []Expect{
			// O disfarce: argv0 entre colchetes, exe resolvido em /tmp — um
			// kworker de verdade não tem exe.
			{ID: "proc.kthread_disguise", Sev: "CRITICAL", Evidence: "kworker"},
			// O caminho volátil, gravável por todos.
			{ID: "proc.suspicious_path", Sev: "WARN", Evidence: "/tmp/.xmrig"},
			// A conexão de pool, do MESMO processo: CRÍTICO porque a origem está
			// em diretório gravável por qualquer um — o ramo que o 86 (binário de
			// sistema, AVISO) não alcança.
			{ID: "net.egress_unowned", Sev: "CRITICAL", Evidence: "203.0.113.77:5555"},
			{ID: "net.egress_unowned", Evidence: "nenhuma lista de reputação"},
			// A volta que sobrevive ao reboot que apagou o /tmp.
			{ID: "persist.cron_frequent"},
		},
		// Origem e destino saem da MESMA tabela: sem descritor padrão sobre o
		// socket não há shell, e a saída para a internet não é um pivô interno.
		Forbid: []string{"correlate.revshell", "net.pivot"},
		Exit:   2,
	})
}
