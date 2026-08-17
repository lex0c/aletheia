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
		Images:         []string{"servidor-web:test"},
		Forbid:         []string{"proc.memfd_exec", "proc.exe_deleted", "correlate.revshell", "net.pivot"},
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
		Images:           []string{"servidor-db:test"},
		Forbid:           []string{"proc.memfd_exec", "correlate.revshell", "priv.uid_zero"},
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
		Images:         []string{"servidor-build:test"},
		Forbid:         []string{"proc.memfd_exec", "proc.exe_deleted", "correlate.revshell"},
		MaxWarn:        9,
		Exit:           1,
		MustBeComplete: true,
	})
}
