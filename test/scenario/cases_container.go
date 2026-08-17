package scenario

// FRONTEIRA ENTRE CONTÊINER E HOST.
//
// Estes cenários rodam em VM porque a pergunta só existe num HOST. De dentro de
// um contêiner todo processo visível está do mesmo lado da fronteira, e a
// própria ferramenta declara isso e não afirma nada — o que é o comportamento
// certo, e torna o contêiner o lugar errado para medir.
//
// A origem foi um falso positivo medido: um binário sob
// /var/lib/docker/overlay2/…/usr/sbin/nginx saía como "nenhum pacote
// reivindica". Num servidor com trinta contêineres são trinta avisos, e
// contêiner é a norma em produção.
//
// A base de pacotes do host está CERTA em não reivindicar aquilo — ela nunca o
// entregou. A pergunta é que estava errada, e trocá-la transformou a fonte de
// ruído em fonte de sinal.

func init() {
	Register(Scenario{
		ID:   "M1-processo-de-container-nao-vira-aviso",
		Desc: "binário em camada de imagem, com cgroup de contêiner: é o normal",
		// O cenário do FALSO POSITIVO. O cgroup é montado à mão porque não há
		// docker dentro da VM — e o que a ferramenta lê é exatamente isto: o
		// caminho do cgroup, que o runtime escreve e o invasor não escolhe.
		Mode: VM,
		Setup: `mkdir -p /sys/fs/cgroup
			mount -t cgroup2 none /sys/fs/cgroup 2>/dev/null || true
			d=/var/lib/docker/overlay2/9f3c1a2b4d5e6f708192a3b4c5d6e7f8/diff/usr/sbin
			mkdir -p "$d"
			cp /helper "$d/nginx"
			"$d/nginx" sleep 90 &
			pid=$!
			cg=/sys/fs/cgroup/system.slice/docker-2549dd25988f0f64c491475e481d0cd12b4b9399c7be55d24e3b670a6f235ced.scope
			mkdir -p "$cg" && echo $pid > "$cg/cgroup.procs"
			sleep 0.4`,
		Expect: []Expect{
			// O inventário existe, e é ele que dá tamanho ao que saiu da
			// pergunta de propriedade.
			{ID: "proc.container_boundary", Sev: "INFO", Evidence: "docker=1"},
			{ID: "proc.container_boundary", Evidence: "não se aplica"},
		},
		// E o §24 NÃO pode acusar o nginx da imagem: era esse o falso positivo.
		ForbidOutput: []string{"overlay2"},
		Exit:         -1,
	})

	Register(Scenario{
		ID:   "M2-conteudo-de-imagem-executado-fora",
		Desc: "o MESMO binário, com o cgroup do host: alguém rodou fora do contêiner",
		// O par do M1, e a razão de não ter bastado suprimir. Plantio idêntico
		// menos UMA coisa — o processo não entra no cgroup do contêiner —, e a
		// conclusão inverte: um binário só chega àquele caminho dentro de uma
		// imagem, e rodá-lo com o cgroup do host não tem caminho legítimo comum.
		Mode: VM,
		Setup: `d=/var/lib/docker/overlay2/9f3c1a2b4d5e6f708192a3b4c5d6e7f8/diff/usr/sbin
			mkdir -p "$d"
			cp /helper "$d/nginx"
			"$d/nginx" sleep 90 &
			sleep 0.4`,
		Expect: []Expect{
			{ID: "proc.container_boundary", Sev: "CRITICAL"},
			{ID: "proc.container_boundary", Evidence: "FORA do"},
			{ID: "proc.container_boundary", Evidence: "cgroup"},
		},
		Exit: 2,
	})
}
