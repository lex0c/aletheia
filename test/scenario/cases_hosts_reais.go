package scenario

// Os três servidores de REFERÊNCIA (`make fixtures`).
//
// # Por que eles valem mais que qualquer cenário desta suíte
//
// Todo o resto daqui foi escrito por quem escreveu os checks, e o `ATTACK.md`
// registra esse limite: mais cenários provam principalmente que o autor
// continua pensando igual. Estas três máquinas não têm esse problema — foram
// montadas por quem NÃO conhecia a ferramenta, sem acesso ao repositório, com o
// pedido de parecer produção de verdade:
//
//	servidor-web    debian 12, nginx + gunicorn, deploy estilo Capistrano
//	servidor-db     rocky 9, PostgreSQL 16 com cluster de verdade, e a história
//	                suja de quem nasceu CentOS 7 com MariaDB
//	servidor-build  ubuntu 22.04, agente de build Jenkins, cheio de cache
//
// O experimento já pagou uma vez: foi ele que achou o falso positivo do
// `update-alternatives`, que a matriz inteira de contêineres não pegava.
//
// # O que estes cenários travam
//
// Duas coisas, e as duas são NEGATIVAS:
//
//	nenhum crítico    `Exit: 1` é a asserção. Um host de produção limpo não
//	                  pode fazer a frota parar
//	ruído medido      o teto veio da medição, não de opinião. Se um check novo
//	                  acrescentar um aviso aqui, a suíte quebra e alguém decide
//	                  se ele vale a atenção que custa
//
// A segunda rodada de medição — com o catálogo de hoje, 78 checks, contra as
// mesmas três máquinas — achou o segundo defeito: `%dba ALL=(postgres)
// NOPASSWD: ALL` saía como CRÍTICO dizendo "é root inteiro", e não é: vira o
// dono do banco, que é como um time de DBA recebe o serviço que administra.

func init() {
	Register(Scenario{
		ID:   "T1-servidor-web-de-producao",
		Desc: "nó de web real, arrumado e recém-reconstruído: nada de crítico, e o ruído tem teto",
		// O que sobra aqui é verdade e é caro em atenção: o venv da aplicação e
		// o agente de telemetria não vêm de pacote, o housekeeping roda de
		// poucos em poucos minutos, e três contas humanas têm chave e sudo.
		// Nada disso é ataque; tudo isso o operador precisa reconhecer uma vez.
		Images: []string{"servidor-web:test"},
		// As duas últimas fecham lacunas que a suíte não tinha: o web tem
		// rotação de log de VERDADE (.1, .2.gz, .3.gz com mtime antigo) e
		// diretório oculto de build em /tmp — os dois falsos positivos que
		// esses checks declaram e que ninguém provava que eles evitam.
		Forbid: []string{
			"proc.memfd_exec", "proc.exe_deleted", "correlate.revshell", "net.pivot",
			"antiforense.log_rotation_gap", "path.hidden_exec",
			// Duas negativas que só um host realista prova: conta bem formada
			// aparece em passwd E em shadow, e servidor de produção não tem
			// socket de captura aberto.
			//
			// O `proc.container_boundary` ficou DE FORA de propósito: rodando
			// dentro de um contêiner ele emite um INFO de escopo por desenho —
			// "aqui esta pergunta não existe" —, e proibi-lo seria proibir a
			// ferramenta de declarar o próprio alcance.
			"priv.account_no_shadow", "net.packet_socket",
		},
		MaxWarn:        11,
		Exit:           1,
		MustBeComplete: true,
	})

	Register(Scenario{
		ID:   "T2-servidor-de-banco-de-producao",
		Desc: "PostgreSQL 16 numa máquina com três migrações de história: o host mais sujo dos três",
		// É a máquina que mais tem lixo legítimo — resto de MariaDB, de 9.6, de
		// 13 — e mesmo assim precisa sair sem crítico. Foi ela que produziu o
		// falso positivo do runas de sudo.
		//
		// A cobertura é incompleta de propósito: é um host rpm, e a §24 declara
		// que ler a base do rpm exigiria cgo — que mataria o binário estático.
		Images: []string{"servidor-db:test"},
		Forbid: []string{
			"proc.memfd_exec", "correlate.revshell", "priv.uid_zero",
			"antiforense.log_rotation_gap", "path.hidden_exec",
			// Duas negativas que só um host realista prova: conta bem formada
			// aparece em passwd E em shadow, e servidor de produção não tem
			// socket de captura aberto.
			//
			// O `proc.container_boundary` ficou DE FORA de propósito: rodando
			// dentro de um contêiner ele emite um INFO de escopo por desenho —
			// "aqui esta pergunta não existe" —, e proibi-lo seria proibir a
			// ferramenta de declarar o próprio alcance.
			"priv.account_no_shadow", "net.packet_socket",
		},
		MaxWarn:          6,
		Exit:             1,
		MustBeIncomplete: true,
	})

	Register(Scenario{
		ID:   "T3-agente-de-build-de-producao",
		Desc: "runner de CI: chave privada, credencial de registro e grupo docker — tudo legítimo, tudo verdadeiro",
		// O papel que mais parece comprometido sem estar: um agente de CI tem
		// chave privada sem senha, token de registro em arquivo, grupo docker
		// (que é root por outro caminho) e binário próprio em /usr/local. A
		// ferramenta diz as quatro coisas, e as quatro estão certas — o teto
		// existe para que a quinta não entre sem alguém decidir.
		Images: []string{"servidor-build:test"},
		Forbid: []string{
			"proc.memfd_exec", "proc.exe_deleted", "correlate.revshell",
			"antiforense.log_rotation_gap", "path.hidden_exec",
			// Duas negativas que só um host realista prova: conta bem formada
			// aparece em passwd E em shadow, e servidor de produção não tem
			// socket de captura aberto.
			//
			// O `proc.container_boundary` ficou DE FORA de propósito: rodando
			// dentro de um contêiner ele emite um INFO de escopo por desenho —
			// "aqui esta pergunta não existe" —, e proibi-lo seria proibir a
			// ferramenta de declarar o próprio alcance.
			"priv.account_no_shadow", "net.packet_socket",
		},
		MaxWarn:        9,
		Exit:           1,
		MustBeComplete: true,
	})
}

// Os mesmos três servidores, varridos como ROOTFS DESLIGADO.
//
// É a prova que o par 84/85 faz para um plantio sintético, agora contra
// máquinas de produção reais — e ela vale mais aqui, porque o modo imagem é o
// caminho da §35.6: quando o userland do alvo não é confiável, monta-se o disco
// e varre-se DE FORA, onde o kernel é o do analista e ocultamento não acontece.
//
// A medição diz que os achados de DISCO são os mesmos — 11, 6 e 9 avisos, como
// ao vivo — e que o que muda é a COBERTURA: trinta checks viram NÃO VERIFICADO
// porque não há processo numa imagem montada. As duas metades precisam continuar
// verdadeiras: mesmo resultado, cobertura honesta sobre o que não dá para ver.
func init() {
	Register(Scenario{
		ID:     "T4-servidor-web-como-imagem",
		Desc:   "o nó de web varrido de fora, como rootfs desligado: os mesmos achados de disco, com a cobertura dizendo o que falta",
		Images: []string{"servidor-web:test"},
		Mode:   Image,
		Expect: []Expect{
			{ID: "integrity.no_package_owner", Sev: "WARN", Subject: "/opt/telemetry-agent/bin/telemetry-agent"},
		},
		Forbid: []string{"proc.memfd_exec", "correlate.revshell", "path.hidden_exec"},
		// O MESMO teto do T1: se o modo imagem passar a dizer mais ou menos que
		// o ao vivo sobre o mesmo disco, alguém precisa explicar por quê.
		MaxWarn:          11,
		MustBeIncomplete: true,
		Exit:             1,
	})

	Register(Scenario{
		ID:     "T5-servidor-de-banco-como-imagem",
		Desc:   "o banco varrido de fora: a regra de sudo continua aparecendo, e os checks de processo viram NÃO VERIFICADO",
		Images: []string{"servidor-db:test"},
		Mode:   Image,
		Expect: []Expect{
			{ID: "priv.sudo_nopasswd", Sev: "WARN", Subject: "%dba"},
		},
		Forbid:           []string{"proc.memfd_exec", "correlate.revshell", "path.hidden_exec"},
		MaxWarn:          6,
		MustBeIncomplete: true,
		Exit:             1,
	})

	Register(Scenario{
		ID:     "T6-agente-de-build-como-imagem",
		Desc:   "o runner de CI varrido de fora: chave privada e credencial de registro continuam visíveis no disco",
		Images: []string{"servidor-build:test"},
		Mode:   Image,
		Expect: []Expect{
			{ID: "cred.ssh_private_key", Sev: "WARN", Subject: "/var/lib/jenkins/.ssh/id_ed25519"},
		},
		Forbid:           []string{"proc.memfd_exec", "correlate.revshell", "path.hidden_exec"},
		MaxWarn:          9,
		MustBeIncomplete: true,
		Exit:             1,
	})
}
