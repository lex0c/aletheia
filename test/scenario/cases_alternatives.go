package scenario

// update-alternatives: o mecanismo padrão do Debian e do RHEL para escolher
// entre implementações — e um falso positivo CRÍTICO até ser tratado.
//
//	/usr/bin/java -> /etc/alternatives/java -> /usr/lib/jvm/…/bin/java
//
// O gerenciador de pacotes reivindica o alvo final e NUNCA os dois links: eles
// nascem no postinst, não são empacotados. Sem seguir a cadeia, /usr/bin/java
// saía como "nenhum pacote reivindica" — e em /usr/bin isso é crítico, porque
// tudo ali deveria vir de um pacote.
//
// ONDE ISTO FOI MEDIDO importa mais que o defeito: num servidor de CI montado
// por OUTRO agente, que não sabia que existia um detector nem o que ele procura.
// A matriz de imagens nunca pegou porque contêiner base quase não tem
// alternatives e nenhum deles é executado ou agendado — a pergunta de
// propriedade só é feita sobre o que roda. Aquela imagem tinha 101.
//
// O par abaixo trava as duas metades: a forma legítima não pode acusar, e o
// SEQUESTRO da mesma forma tem que continuar acusando.

func init() {
	Register(Scenario{
		ID:     "N1-alternatives-legitimo",
		Desc:   "cadeia do update-alternatives apontando para binário COM dono",
		Images: matriz,
		Plant: `alvo=/usr/bin/dash; [ -f "$alvo" ] || alvo=/bin/busybox
			mkdir -p /etc/alternatives /etc/systemd/system
			ln -sf "$alvo" /etc/alternatives/sh-alt
			ln -sf /etc/alternatives/sh-alt /usr/bin/sh-alt
			printf '[Service]\nExecStart=/usr/bin/sh-alt -c true\n' > /etc/systemd/system/alt.service`,
		// Nenhum dos dois links tem dono, e o alvo final tem. É a forma normal.
		ForbidOutput:   []string{"sh-alt"},
		MaxWarn:        0,
		Exit:           0,
		MustBeComplete: true,
	})

	Register(Scenario{
		ID:   "N2-alternatives-sequestrado",
		Desc: "a MESMA cadeia, apontando para lugar sem dono: continua achado",
		// A metade que impede a correção de virar cegueira. Seguir a cadeia não
		// pode afrouxar nada: link para /tmp segue sendo implante, e agora com
		// a cadeia disponível como evidência.
		Images: matriz,
		Plant: `mkdir -p /etc/alternatives /etc/systemd/system /tmp/.x
			cp /helper /tmp/.x/payload
			ln -sf /tmp/.x/payload /etc/alternatives/sh-alt
			ln -sf /etc/alternatives/sh-alt /usr/bin/sh-alt
			printf '[Service]\nExecStart=/usr/bin/sh-alt -c true\n' > /etc/systemd/system/alt.service`,
		Expect: []Expect{
			{ID: "integrity.no_package_owner", Sev: "CRITICAL", Subject: "/usr/bin/sh-alt"},
		},
		Exit:           2,
		MustBeComplete: true,
	})
}
