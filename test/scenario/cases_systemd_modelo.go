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
}
