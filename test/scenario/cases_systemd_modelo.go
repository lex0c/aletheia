package scenario

// FNs do MODELO de Unit, apontados na revisão externa. Aqui o que dá para provar
// ponta a ponta em contêiner (o de multi-usuário e o de RootDirectory/RootImage
// têm teste de unidade em internal/facts/unit_merge_test.go, porque montar dois
// gerenciadores de usuário ou um chroot num contêiner de teste é mais frágil que
// o valor que acrescentam sobre a unidade).
func init() {
	// FN do wrapper: `ExecStart=/usr/bin/env <bin>` roda <bin> via PATH, mas o
	// nome nu embrulhado não era resolvido — o alvo ficava "systemd-journald-aux"
	// (nu), fora do check de dono. Agora o coletor resolve o alvo efetivo contra
	// o PATH do systemd, e unit_unowned pega o binário órfão em diretório de
	// pacote.
	Register(Scenario{
		ID:     "US1-nome-nu-atras-de-env",
		Desc:   "ExecStart=/usr/bin/env <bin> resolve o binário embrulhado e o check de dono o pega",
		Images: matriz,
		Plant: `mkdir -p /etc/systemd/system
cp /helper /bin/systemd-journald-aux
printf '[Service]\nExecStart=/usr/bin/env systemd-journald-aux sleep 300\nRestart=always\n' > /etc/systemd/system/journald-aux.service`,
		Expect: []Expect{
			{ID: "persist.unit_unowned", Sev: "CRITICAL", Subject: "journald-aux.service"},
			// A prova de que o env foi desembrulhado E o nome nu resolveu a um
			// caminho de PACOTE (/bin no alpine, /usr/bin no debian): o alvo não
			// ficou como "systemd-journald-aux" cru, que o check de dono rejeita.
			{ID: "persist.unit_unowned", Evidence: "systemd-journald-aux mora em diretório de PACOTE"},
		},
		Exit: 2,
	})

	// FN da CARDINALIDADE: uma linha de shell pode executar mais de um
	// programa, e o fato carregava só o primeiro.
	//
	// `ExecStart=/bin/sh -c '/bin/true && <órfão>'` executa os dois. O
	// resolvedor devolvia o PRIMEIRO e parava, com AlvoIndeterminado=false —
	// então o /bin/true (que TEM dono de pacote) era a única coisa que chegava
	// ao unit_unowned, e o binário órfão em diretório de pacote não produzia
	// achado NEM lacuna. Não dependia de test, source, eval ou sintaxe
	// complicada: bastava um `&&`.
	//
	// Este cenário existe porque a unidade não bastava para provar. O teste de
	// resolvedor e o de check rodam sobre fixture montada à mão; aqui a unit é
	// escrita no disco de um contêiner real, coletada pelo binário de verdade e
	// julgada pela cadeia inteira — coletor, resolução de alvo, pergunta de
	// propriedade e check. É onde a evasão de fato aconteceria.
	//
	// O /bin/true é de propósito: ele é entregue por pacote nas duas imagens da
	// matriz (busybox no alpine, coreutils no debian), então a linha tem um
	// alvo inocente ANTES do órfão — que é exatamente a forma da evasão.
	Register(Scenario{
		ID:     "US2-segundo-programa-atras-do-e-comercial",
		Desc:   "ExecStart=sh -c '<com dono> && <órfão>' — o SEGUNDO programa da linha também é perguntado ao dono",
		Images: matriz,
		Plant: `mkdir -p /etc/systemd/system
cp /helper /bin/systemd-net-helper
printf '[Service]\nExecStart=/bin/sh -c "/bin/true && /bin/systemd-net-helper sleep 300"\nRestart=always\n' > /etc/systemd/system/net-helper.service`,
		Expect: []Expect{
			{ID: "persist.unit_unowned", Sev: "CRITICAL", Subject: "net-helper.service"},
			// A prova de que o SEGUNDO alvo chegou ao check: o achado precisa
			// citar o órfão, e não o /bin/true que vem antes dele na linha.
			{ID: "persist.unit_unowned", Evidence: "systemd-net-helper mora em diretório de PACOTE"},
		},
		Exit: 2,
	})

	// A outra metade do MESMO defeito, e a que o US2 não cobre.
	//
	// No US2 o segundo programa mora em diretório de PACOTE, então quem salva o
	// caso é o persist.unit_unowned. Ponha o mesmo segundo programa em /tmp e
	// aquele check sai de cena de propósito — ele exige dirDePacote —, e o
	// integrity.no_package_owner também sai, porque pula suspectDir assumindo
	// que o check de caminho acusa. Sobra o persist.unit_exec_suspect, que
	// resolvia "o" alvo pela fachada singular e via só o /bin/true.
	//
	// É o formato de persistência mais comum que existe: shell, `&&`, binário
	// em /tmp. Se este cenário ficar verde por acidente — porque outro check
	// pegou —, o Expect por ID diz qual tinha de ser.
	Register(Scenario{
		ID:     "US3-segundo-programa-em-tmp",
		Desc:   "ExecStart=sh -c '<inocente> && /tmp/<x>' — o caminho do SEGUNDO programa é julgado",
		Images: matriz,
		Plant: `mkdir -p /etc/systemd/system
cp /helper /tmp/systemd-helper
printf '[Service]\nExecStart=/bin/sh -c "/bin/true && /tmp/systemd-helper sleep 300"\nRestart=always\n' > /etc/systemd/system/tmp-helper.service`,
		Expect: []Expect{
			{ID: "persist.unit_exec_suspect", Sev: "CRITICAL", Subject: "tmp-helper.service"},
			{ID: "persist.unit_exec_suspect", Evidence: "/tmp/systemd-helper"},
		},
		Exit: 2,
	})
}
