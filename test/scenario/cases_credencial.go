package scenario

// A outra metade da história de SSH, e a categoria que faltava.
//
//	E1  chave privada sem senha   para onde este host CONSEGUE ir
//	E2  histórico desligado       anti-forense: a AUSÊNCIA deliberada de rastro
//	E3  known_hosts               para onde este host JÁ foi, e o raio da §23
//
// Os três vieram de ler o velociraptor, e todos fecham o mesmo padrão: fonte
// que a ferramenta MANDAVA olhar e nunca lia.

func init() {
	Register(Scenario{
		ID:   "E1-chave-privada-sem-senha",
		Desc: "chave SSH privada sem senha: credencial de movimento lateral largada aberta",
		// A ferramenta lia `authorized_keys` — quem ENTRA — e nada sobre o
		// caminho inverso. Sem senha, quem lê o arquivo já pode usar a chave:
		// não quebra nada, não abre sessão de teste, não deixa tentativa
		// registrada em lugar nenhum.
		//
		// As duas chaves deste cenário são REAIS, geradas pelo ssh-keygen. A
		// cifrada existe para provar o outro lado: uma chave protegida por
		// senha não pode sair como aviso, ou o check viraria "todo host que usa
		// SSH tem um problema".
		Images: matriz,
		Plant:  chavesPrivadas,
		Expect: []Expect{
			{ID: "cred.ssh_private_key", Sev: "WARN", Subject: "/root/.ssh/deploy_key"},
			{ID: "cred.ssh_private_key", Evidence: "SEM SENHA"},
			// A cifrada entra no inventário e NÃO como aviso.
			{ID: "cred.ssh_private_key", Sev: "MANUAL", Subject: "/root/.ssh/pessoal"},
			{ID: "cred.ssh_private_key", Evidence: "protegida por senha"},
		},
		Exit: 1,
	})

	Register(Scenario{
		ID:   "E2-historico-desligado",
		Desc: "histórico de shell apontado para /dev/null e desligado no rc: rastro apagado de propósito",
		// ANTI-FORENSE, categoria que nenhum outro check cobria. O achado não é
		// o implante: é a ausência DELIBERADA de rastro.
		//
		// Ninguém aponta .bash_history para /dev/null por acidente, e ninguém
		// escreve `unset HISTFILE` sem querer. Custa uma linha, e quem faz isso
		// está contando que alguém fosse procurar.
		Images: matriz,
		Plant:  historicoApagado,
		Expect: []Expect{
			{ID: "antiforense.shell_history", Sev: "CRITICAL",
				Subject: "/root/.bash_history"},
			{ID: "antiforense.shell_history", Evidence: "dispositivo nulo"},
			// E a forma que mora no arquivo de inicialização.
			{ID: "antiforense.shell_history", Sev: "WARN", Evidence: "sem onde gravar"},
		},
		// O roteiro precisa dizer onde procurar o que o histórico não guardou.
		ExpectOutput: []string{"rastro apagado de propósito"},
		Exit:         2,
	})

	Register(Scenario{
		ID:   "E3-alcance-do-host",
		Desc: "known_hosts: dezenas de evidências mandam procurar na frota, e esta diz em quais máquinas",
		// Não é achado — é o tamanho do problema. Um servidor de aplicação com
		// três destinos e um bastion com quatrocentos são incidentes de escalas
		// diferentes, e a diferença aparece aqui e em nenhum outro lugar.
		//
		// A entrada embaralhada entra de propósito: com HashKnownHosts o
		// destino não volta, e a ferramenta precisa dizer isso em vez de
		// fingir que a lista está completa.
		Images: matriz,
		Plant:  destinosConhecidos,
		Expect: []Expect{
			{ID: "cred.known_hosts", Sev: "MANUAL"},
			{ID: "cred.known_hosts", Evidence: "bastion.interno"},
			{ID: "cred.known_hosts", Evidence: "embaralhado"},
			{ID: "cred.known_hosts", Evidence: "runbook §23"},
		},
		Exit: -1,
	})
	Register(Scenario{
		ID:   "E6-credencial-em-arquivo",
		Desc: "credencial de nuvem e segredo de aplicação: até onde este host alcança",
		// É o que um invasor procura PRIMEIRO depois de entrar, e o que define
		// até onde ele vai a partir daqui. Uma chave de nuvem vale mais que
		// qualquer implante: com ela não é preciso voltar ao host.
		//
		// O cenário planta as duas metades de propósito. A permissão é a única
		// coisa objetiva que a ferramenta pode dizer, e é ela que separa o
		// inventário do aviso:
		//
		//	0644  o segredo deixou de depender da conta dona
		//	0600  é o desenho normal, e entra como inventário
		//
		// Se as duas saíssem iguais, o check viraria "todo servidor de aplicação
		// tem um problema" — e todo servidor de aplicação tem credencial.
		Images: matriz,
		Plant:  credenciaisEmArquivo,
		Expect: []Expect{
			{ID: "cred.secret_file", Sev: "WARN", Subject: "/root/.aws/credentials"},
			{ID: "cred.secret_file", Evidence: "LEGÍVEL por grupo ou por outros"},
			{ID: "cred.secret_file", Sev: "MANUAL", Subject: "/srv/app/.env"},
		},
		Exit: 1,
	})

	Register(Scenario{
		ID:   "E4-auditoria-desligada",
		Desc: "auditoria instalada e neutralizada com `-e 0`: a trilha some sem o arquivo sumir",
		// A pergunta que vem ANTES de todas numa resposta a incidente: este host
		// consegue dizer o que foi executado antes da varredura?
		//
		// O `-e 0` é a forma mais silenciosa de responder não. A configuração
		// continua no lugar, as regras continuam escritas, e nada é registrado —
		// quem só verifica se o arquivo existe não vê diferença nenhuma.
		//
		// O cenário planta a regra de execve JUNTO, de propósito: é o que prova
		// que o check olha o estado do subsistema e não a presença de regra.
		Images: matriz,
		Plant:  auditoriaDesligada,
		Expect: []Expect{
			{ID: "antiforense.audit_disabled", Sev: "CRITICAL",
				Subject: "auditoria desligada"},
			{ID: "antiforense.audit_disabled", Evidence: "quem só verificar se o arquivo existe"},
			// E o passo que impede destruir a própria evidência ao consertar.
			{ID: "antiforense.audit_disabled", Evidence: "NÃO religue antes de preservar"},
		},
		Exit: 2,
	})

	Register(Scenario{
		ID:   "E5-sem-auditoria-nao-eh-achado",
		Desc: "host sem auditoria não produz achado: é o estado da maioria dos servidores",
		// O outro lado, e ele importa mais que o primeiro.
		//
		// Auditoria não é padrão em quase nenhuma distribuição, e contêiner
		// nunca tem. Se "sem auditoria" produzisse linha, este check falaria em
		// praticamente todo host do mundo — e advertência que sai sempre é papel
		// de parede.
		//
		// Há também um limite de conhecimento: regra DELETADA e regra nunca
		// escrita são indistinguíveis em disco. Acusar sem poder separar as duas
		// seria acusar no escuro.
		Images: matriz,
		Plant:  "",
		Forbid: []string{"antiforense.audit_disabled"},
		Exit:   0,
	})
}

// auditoriaDesligada instala regra e desliga o subsistema.
const auditoriaDesligada = `
mkdir -p /etc/audit/rules.d
cat > /etc/audit/rules.d/audit.rules <<'FIM'
-a always,exit -F arch=b64 -S execve -k exec
-e 0
FIM
`

// ---------------------------------------------------------------------------

// chavesPrivadas planta duas chaves REAIS: uma sem senha e uma com.
const chavesPrivadas = `
mkdir -p /root/.ssh
cat > /root/.ssh/deploy_key <<'CHAVE'
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAKlbMkWN+4WnJuLfhyXdl5i1VnqO7eVL2ylTZYW5SomwAAAIjyYC208mAt
tAAAAAtzc2gtZWQyNTUxOQAAACAKlbMkWN+4WnJuLfhyXdl5i1VnqO7eVL2ylTZYW5Somw
AAAEBrbDoMoAuq7HZCajDx/3AQt4P6QM8Xgho0Ef+zdcWHiwqVsyRY37hacm4t+HJd2XmL
VWeo7t5UvbKVNlhblKibAAAABXRlc3Rl
-----END OPENSSH PRIVATE KEY-----
CHAVE
cat > /root/.ssh/pessoal <<'CHAVE'
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABBwe+jSOr
Ua1z1m/NVBajklAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAICiM3xxP6tHcJ7jd
U51SK5eI5/hbSoNcabBpaUKeWBZFAAAAkBczTN/lkJ60ZN6b2xgf1VzL9pdwyZthB41OBG
sEkLChgs+EIZxthAStpYEsYRpPugTpchB6k/MUOh+3c47/Xmg8nnlZt15c/8AzebAsSqQ6
OOlpDZNqS4S4Bf9+LASkOWaflPQx7nwySN7WyqH2jeMBAOGvYw28a+nugE+gd1yQXaUvbX
v/bMcTuNb8wErBvQ==
-----END OPENSSH PRIVATE KEY-----
CHAVE
chmod 600 /root/.ssh/deploy_key /root/.ssh/pessoal
`

// historicoApagado usa as duas formas mais baratas de anti-forense.
const historicoApagado = `
mkdir -p /root
ln -sf /dev/null /root/.bash_history
printf '\nunset HISTFILE\n' >> /root/.bashrc
`

// destinosConhecidos planta o alcance, com uma entrada embaralhada.
const destinosConhecidos = `
mkdir -p /root/.ssh
cat > /root/.ssh/known_hosts <<'FIM'
bastion.interno.corp ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExemploDoBastion
db01.interno.corp,10.0.0.31 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABExemploDoBanco
|1|F1E2D3C4B5A6978877665544332211AABBCCDD=|AABBCCDDEEFF00112233445566778899AA= ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExemploEmbaralhado
FIM
chmod 600 /root/.ssh/known_hosts
`

// credenciaisEmArquivo planta as duas permissões, que é o que separa aviso de
// inventário.
const credenciaisEmArquivo = `
mkdir -p /root/.aws /srv/app
printf '[default]\naws_access_key_id=AKIAEXEMPLO\naws_secret_access_key=exemplo\n' > /root/.aws/credentials
chmod 644 /root/.aws/credentials

printf 'DB_PASSWORD=exemplo\nAPI_TOKEN=exemplo\n' > /srv/app/.env
chmod 600 /srv/app/.env
`
