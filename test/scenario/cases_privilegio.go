package scenario

// Duas formas de retenção que uma varredura por MODO de arquivo não vê.
//
// Vieram de ler o que outras ferramentas do mesmo espaço já procuram: o
// osquery mantém uma tabela de atributos estendidos, e o velociraptor tem um
// artefato só para arquivos imutáveis, com a observação que resume o valor —
// "às vezes é um sinal forte".
//
//	C1  capability em xattr   o setuid moderno, e `find -perm -4000` não acha
//	C2  atributo imutável     o implante que resiste à própria limpeza

func init() {
	Register(Scenario{
		ID:   "C1-capability-em-xattr",
		Desc: "retenção de root por capability em atributo estendido, sem bit de setuid nenhum",
		// A varredura de SUID era a resposta desta ferramenta para "retenção de
		// root". Ela procurava BIT, e o bit é a metade que caiu em desuso.
		//
		// O /usr/bin/ping das distribuições atuais não tem setuid: o poder dele
		// vem de `cap_net_raw` num atributo estendido. Um invasor faz o mesmo
		// com `setcap cap_setuid+ep`, e o arquivo continua 755 aos olhos de
		// qualquer `ls`, `find -perm -4000` ou varredura por modo.
		//
		// O discriminador é o mesmo do setuid — nenhum pacote entregou isto —,
		// e é por isso que a forma nova coube no check existente em vez de
		// virar outro.
		Images: []string{"debian:12", "alpine:3.20"},
		Caps:   []string{"SETFCAP"},
		Plant:  capabilityEmXattr,
		Expect: []Expect{
			{ID: "persist.suid_unowned", Sev: "CRITICAL",
				Subject: "/usr/local/bin/.systemd-notify"},
			// A evidência precisa dizer a FORMA: quem lê o achado vai procurar
			// um bit que não existe.
			{ID: "persist.suid_unowned", Evidence: "SEM bit de setuid"},
			// E nomear a capability: cap_net_raw é um sniffer, cap_setuid é root.
			{ID: "persist.suid_unowned", Evidence: "capabilities no atributo estendido: setuid"},
			{ID: "persist.suid_unowned", Evidence: "bit EFETIVO"},
		},
		Exit: 2,
	})

	Register(Scenario{
		ID:   "C2-implante-imutavel",
		Desc: "implante travado com atributo imutável: a limpeza falha, e falha em silêncio",
		// O que este cenário protege NÃO é a detecção do arquivo — o §24 já o
		// pegava por não ter dono de pacote. É o ROTEIRO.
		//
		// Contra um arquivo imutável, `rm` e `chmod` devolvem "operação não
		// permitida" mesmo como root. Quem não conhece o atributo conclui que o
		// host está quebrado, e não que o implante está se defendendo — e o
		// roteiro que esta ferramenta imprime seria inteiramente inócuo.
		//
		// Por isso o primeiro passo do achado é `chattr -i`, antes de qualquer
		// remoção. É a única ordem em que o resto funciona.
		Images: []string{"debian:12", "alpine:3.20"},
		Caps:   []string{"LINUX_IMMUTABLE"},
		Plant:  implanteImutavel,
		Expect: []Expect{
			{ID: "integrity.immutable_flag", Sev: "CRITICAL",
				Subject: "/usr/local/sbin/.agent"},
			{ID: "integrity.immutable_flag", Evidence: "FALHA até isso ser feito"},
			// E o motivo de ser crítico e não aviso: travar o que a distribuição
			// não entregou é defesa de implante, não endurecimento.
			{ID: "integrity.immutable_flag", Evidence: "nenhum pacote reivindica"},
		},
		// O TÍTULO carrega o aviso na visão compacta, e é ele que o operador lê
		// antes de tentar remover.
		//
		// O `chattr -i` fica nos passos do achado e NÃO no bloco de ação do
		// topo, e isso é deliberado: aquele bloco é dos passos IRREVERSÍVEIS —
		// os que perdem prova para sempre se forem pulados. Ler um arquivo
		// imutável funciona, então a amostra não está em risco, e marcar este
		// achado como irreversível para ganhar posição no relatório seria
		// esvaziar o significado do campo que decide o que se preserva primeiro.
		ExpectOutput: []string{"a remoção falha até ele sair"},
		Exit:         2,
	})
}

// ---------------------------------------------------------------------------

// capabilityEmXattr planta o setuid moderno. O helper escreve o xattr direto
// porque a imagem de teste não traz o `setcap` do libcap.
const capabilityEmXattr = `
mkdir -p /usr/local/bin
cp /helper /usr/local/bin/.systemd-notify
chmod 755 /usr/local/bin/.systemd-notify

# 7 é CAP_SETUID. O modo continua 755: nenhuma varredura por bit vê isto.
/helper setcap /usr/local/bin/.systemd-notify 7
`

// implanteImutavel trava o arquivo contra a própria limpeza.
const implanteImutavel = `
mkdir -p /usr/local/sbin /etc/cron.d
cp /helper /usr/local/sbin/.agent
chmod 755 /usr/local/sbin/.agent
printf '@reboot root /usr/local/sbin/.agent sleep 3600\n' > /etc/cron.d/agent

# a partir daqui, nem root remove sem tirar o atributo
/helper immutable /usr/local/sbin/.agent
`
