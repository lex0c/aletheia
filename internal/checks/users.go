package checks

import (
	"strconv"
	"strings"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

func init() {
	check.Register(uidZero)
	check.Register(semSenha)
	check.Register(contaDeServicoComShell)
	check.Register(grupoEquivalenteARoot)
	check.Register(sudoSemSenha)
	check.Register(doasSemSenha)
}

// uidZero — runbook §7.9.
//
// É o UID que define o poder, não o nome. O kernel só compara números:
// qualquer conta com uid 0 É root, chame-se `backup`, `systemd-net` ou `ftp`.
//
// Por isso a busca é por uid == 0 e não por "root" — procurar pelo nome acharia
// uma conta e perderia a outra, que é exatamente o ponto do disfarce.
var uidZero = check.Check{
	ID:       "priv.uid_zero",
	Ref:      "7.9",
	Title:    "conta com uid 0 além do root",
	Group:    "priv",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Wtf:      true,
	FalsePositives: []string{
		"algumas distribuições e appliances trazem uma segunda conta de uid 0 de " +
			"fábrica (`toor` no BSD e derivados, contas de fornecedor em " +
			"appliance). São poucas e conhecidas pelo nome",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		for i := range f.Accounts {
			a := &f.Accounts[i]
			if a.UID != 0 || a.Name == "root" {
				continue
			}
			ev := []string{
				a.Name + " tem uid 0 — para o kernel, é root",
				"shell=" + nz(a.Shell, "(nenhum)") + " home=" + nz(a.Home, "(nenhum)"),
				"auditoria por NOME de usuário não veria isto: só a comparação " +
					"numérica do uid",
			}
			if a.SemSenha {
				ev = append(ev, "e o campo de senha está VAZIO: login sem autenticação")
			}
			ev = append(ev, metaDeAcesso(f)...)

			fd := self.F(check.SevCritical, a.Name, "", ev...)
			fd.NextSteps = []string{
				"o ctime de /etc/passwd data a criação, mesmo que a conta pareça " +
					"antiga",
				"procure a mesma conta na frota: criação em vários hosts é campanha, " +
					"não incidente isolado",
			}
			r.Findings = append(r.Findings, fd)
		}
		r.Partial = append(r.Partial, f.PersistDenied["users"]...)
		return r
	},
}

// semSenha — runbook §7.9.
//
// Campo de senha vazio no shadow significa login SEM autenticação nenhuma. Não
// é senha fraca: é a ausência da pergunta.
var semSenha = check.Check{
	ID:       "priv.no_password",
	Ref:      "7.9",
	Title:    "conta com campo de senha vazio: entra sem autenticação",
	Group:    "priv",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Optional: env.CapRoot,
	Wtf:      true,
	FalsePositives: []string{
		"conta de sistema sem senha e sem shell não é porta de entrada por " +
			"senha — mas continua valendo para `su` a partir de root, e por isso " +
			"aparece com severidade menor",
		"sem root o /etc/shadow é ilegível, e 'nenhuma conta sem senha' passa a " +
			"ser desconhecimento em vez de resposta",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		for i := range f.Accounts {
			a := &f.Accounts[i]
			if !a.SemSenha {
				continue
			}
			temShell := shellDeVerdade(a.Shell)
			sev := check.SevWarn
			ev := []string{
				a.Name + " tem campo de senha VAZIO no /etc/shadow",
				"não é senha fraca: é a ausência da pergunta",
				"shell=" + nz(a.Shell, "(nenhum)") + " uid=" + strconv.Itoa(a.UID),
			}
			if temShell {
				sev = check.SevCritical
				ev = append(ev, "e tem shell de login: a conta é porta de entrada")
			} else {
				ev = append(ev, "sem shell de login — mas continua valendo para `su` "+
					"a partir de root")
			}
			ev = append(ev, metaDeAcesso(f)...)

			fd := self.F(sev, a.Name, "", ev...)
			fd.NextSteps = []string{
				"`passwd -l " + a.Name + "` tranca a conta sem removê-la",
				"o ctime de /etc/shadow data a alteração",
			}
			r.Findings = append(r.Findings, fd)
		}
		r.Partial = append(r.Partial, f.PersistDenied["users"]...)
		return r
	},
}

// contaDeServicoComShell — runbook §7.9.
//
// Conta de serviço que GANHOU shell é alteração deliberada: ela nasce com
// /usr/sbin/nologin, e alguém precisou editar o passwd para trocar isso.
var contaDeServicoComShell = check.Check{
	ID:       "priv.service_account_shell",
	Ref:      "7.9",
	Title:    "conta de serviço com shell de login",
	Group:    "priv",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Wtf:      true,
	FalsePositives: []string{
		"a fronteira de uid entre conta de sistema e conta de pessoa varia por " +
			"distribuição, e algumas contas de serviço legitimamente têm shell — " +
			"`postgres` e `git` são os exemplos clássicos, e ambos precisam dele",
		"em host de desenvolvimento, contas criadas à mão com uid baixo confundem " +
			"a heurística",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		for i := range f.Accounts {
			a := &f.Accounts[i]
			// Faixa de conta de SISTEMA, abaixo do primeiro uid de pessoa.
			if a.UID == 0 || a.UID >= 1000 || !shellDeVerdade(a.Shell) {
				continue
			}
			if contaDeServicoComShellLegitima[a.Name] {
				continue
			}
			ev := []string{
				a.Name + " é conta de sistema (uid " + strconv.Itoa(a.UID) +
					") e tem shell " + a.Shell,
				"conta de serviço nasce com nologin: trocar isso é edição deliberada " +
					"do /etc/passwd",
			}
			if a.SemSenha {
				ev = append(ev, "e o campo de senha está VAZIO")
			}
			ev = append(ev, metaDeAcesso(f)...)

			fd := self.F(check.SevWarn, a.Name, "", ev...)
			fd.NextSteps = []string{
				"compare com outro host da frota: a mesma conta com nologin lá " +
					"confirma a alteração aqui",
			}
			r.Findings = append(r.Findings, fd)
		}
		r.Partial = append(r.Partial, f.PersistDenied["users"]...)
		return r
	},
}

// grupoEquivalenteARoot — runbook §7.9.
//
// `docker`, `lxd` e `disk` equivalem a root: quem monta o filesystem do host
// num container lê e escreve tudo. É privilégio que não aparece em auditoria de
// sudo nem de uid.
var grupoEquivalenteARoot = check.Check{
	ID:       "priv.root_equivalent_group",
	Ref:      "7.9",
	Title:    "grupo que equivale a root tem membro",
	Group:    "priv",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Wtf:      true,
	FalsePositives: []string{
		"em estação de desenvolvimento e em host de CI, pertencer ao grupo " +
			"`docker` é rotina e proposital. O achado diz que a conta É root por " +
			"outro caminho — não que alguém a pôs ali indevidamente",
		"quem administra o host legitimamente costuma estar em `sudo` ou `wheel`; " +
			"o sinal é ter conta ali que ninguém reconhece",
		"o próprio root é ignorado como membro: ele já é root, e o Alpine entrega " +
			"`disk:x:6:root` de fábrica",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		for i := range f.Grupos {
			g := &f.Grupos[i]
			motivo, ok := grupoRoot[g.Name]
			if !ok {
				continue
			}
			// root num grupo equivalente a root não informa nada — e o Alpine
			// entrega `disk:x:6:root` de fábrica. Sem esta exclusão, todo
			// contêiner Alpine vira achado.
			var membros []string
			for _, m := range g.Members {
				if m != "root" && m != "" {
					membros = append(membros, m)
				}
			}
			if len(membros) == 0 {
				continue
			}
			ev := []string{
				g.Name + ": " + strings.Join(membros, " "),
				motivo,
			}
			ev = append(ev, metaDeAcesso(f)...)

			fd := self.F(check.SevWarn, g.Name, "", ev...)
			fd.NextSteps = []string{
				"confira cada membro com o time: privilégio por GRUPO não aparece " +
					"em auditoria de sudo nem de uid",
			}
			r.Findings = append(r.Findings, fd)
		}
		r.Partial = append(r.Partial, f.PersistDenied["users"]...)
		return r
	},
}

// grupoRoot são as associações que dão poder de root por outro caminho, com o
// MOTIVO — sem ele o operador não sabe por que se importar.
var grupoRoot = map[string]string{
	"docker": "quem pode falar com o docker monta o filesystem do host num " +
		"container e lê e escreve tudo: é root por outro caminho",
	"lxd": "mesmo caso do docker: o container monta o host",
	"disk": "acesso direto aos dispositivos de bloco: lê e escreve o filesystem " +
		"inteiro passando por cima de qualquer permissão",
	"shadow": "lê /etc/shadow: todos os hashes de senha do host",
}

// contaDeServicoComShellLegitima: shell aqui é parte do funcionamento, não
// alteração. Sem esta lista, todo host com PostgreSQL vira achado.
var contaDeServicoComShellLegitima = map[string]bool{
	"postgres": true, "git": true, "sync": true, "halt": true,
	"shutdown": true, "gitlab-runner": true, "jenkins": true,
}

func shellDeVerdade(s string) bool {
	if s == "" {
		return false
	}
	b := baseDe(s)
	return b != "nologin" && b != "false" && b != "sync" && b != "shutdown" && b != "halt"
}

// metaDeAcesso devolve as datas dos arquivos que decidem acesso. O ctime deles
// na janela do incidente é o que data a alteração (runbook §9).
func metaDeAcesso(f *facts.Facts) []string {
	var ev []string
	for _, m := range f.MetaAcesso {
		if m.Path == "/etc/passwd" || m.Path == "/etc/shadow" {
			ev = append(ev, m.Path+" modificado em "+m.ModUTC)
		}
	}
	return ev
}

// sudoSemSenha — runbook §7.9.
//
// Escalar para root sem responder nada. É o mecanismo de privilégio mais
// discreto que existe: não cria conta, não muda uid, não deixa processo — só
// uma linha num arquivo que ninguém abre depois de instalar a máquina.
//
// E é o caminho de MENOR atrito para quem já entrou com uma conta comum: a
// senha que ele não tem deixa de ser necessária.
//
// Duas formas, e a segunda quase não é conhecida:
//
//	NOPASSWD:        concede o comando sem pedir senha
//	!authenticate    desliga a pergunta de senha para o alvo inteiro
var sudoSemSenha = check.Check{
	ID:       "priv.sudo_nopasswd",
	Ref:      "7.9",
	Title:    "regra de sudo que escala sem pedir senha",
	Group:    "priv",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Optional: env.CapRoot,
	Wtf:      true,
	FalsePositives: []string{
		"automação legítima vive disto: Ansible, provisionamento em nuvem e " +
			"agente de CI precisam de sudo sem senha porque não há ninguém para " +
			"digitá-la. O `cloud-init` deixa NOPASSWD para o usuário padrão em " +
			"praticamente toda imagem de nuvem, e isso é de fábrica",
		"regra restrita a UM comando é desenho comum de menor privilégio, e sai " +
			"com severidade menor do que a que concede ALL — MAS só quando aquele " +
			"comando não devolve execução arbitrária: `NOPASSWD: /usr/bin/find` " +
			"sem argumento é root em um passo, e sai crítico (checks/primitiva.go)",
		"a tabela de primitivas tem ~110 nomes e o universo é maior. O comando " +
			"que ela NÃO reconhece não sai absolvido: o achado continua como aviso " +
			"e diz, em voz alta, que aquele binário não foi examinado — a " +
			"conferência é humana, e a tabela de referência é a GTFOBins",
		"conceder ALL como OUTRA CONTA não é root, e sai como aviso: " +
			"`%dba ALL=(postgres) NOPASSWD: ALL` é como um time de DBA recebe o " +
			"serviço que administra, e um servidor de banco real produziu " +
			"exatamente essa linha",
		"sem root o /etc/sudoers é ilegível, e a ausência de achado passa a ser " +
			"desconhecimento em vez de resposta — a cobertura diz qual dos dois",
		"REGRA DE OUTRO HOST não é achado deste host: sudoers distribuído por " +
			"configuração central manda o mesmo arquivo para a frota inteira, e " +
			"`ops db01=(root) NOPASSWD: ALL` não vale em web01. Elas saem juntas " +
			"num único INFO com a contagem. O que NÃO dá para resolver — " +
			"Host_Alias, netgroup, endereço de rede — mantém a severidade e sai " +
			"dito na evidência",
		"CURINGA em argumento sobe a severidade mesmo havendo literal depois " +
			"dele, e isso alcança regra de limpeza de log escrita de boa-fé " +
			"(`find /var/log -name *.gz -delete`). Não é conservadorismo gratuito: " +
			"o sudo compara os argumentos como UMA string e o `*` casa espaço, " +
			"então o confinamento não é demonstrável. A saída é fixar o argumento " +
			"sem curinga, ou usar a regex ancorada do sudo 1.9.10+",
		"a tag `NOEXEC:` REBAIXA o achado, e ela é a única do sudoers que " +
			"responde à primitiva. O freio depende de link dinâmico: binário " +
			"estático não é interceptado, e por isso o achado continua saindo " +
			"como aviso em vez de sumir",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		var deOutroHost []string
		for i := range f.Sudoers {
			s := &f.Sudoers[i]
			up := strings.ToUpper(s.Text)
			nopass := strings.Contains(up, "NOPASSWD")
			naoAutentica := strings.Contains(strings.ToLower(s.Text), "!authenticate")
			if !nopass && !naoAutentica {
				continue
			}

			quem := campoInicial(s.Text)
			// A LEITURA É DE PARSER, e não mais de `strings.Index` sobre a
			// linha. Runas, Host_List, tags e o `ALL` que é comando (contra o
			// `ALL` que é argumento) são posições da gramática, e respondê-las
			// por substring custou um crítico falso e três achados perdidos.
			// Ver sudoers.go.
			reg := parseRegraSudo(s.Text)
			var v vereditoSudo
			if reg.Ok {
				v = vereditoDaRegra(reg, naoAutentica, f.Host.Hostname, quem)
			}

			sev := check.SevWarn
			ev := []string{
				s.File + ":" + strconv.Itoa(s.Line) + " — " + s.Text,
			}
			if naoAutentica {
				ev = append(ev, "`!authenticate` desliga a pergunta de senha para o "+
					"alvo inteiro, e quase ninguém procura por essa forma")
			}
			switch {
			case v.Achou:
				sev = v.Sev
				ev = append(ev, v.Ev...)
				if v.Indeterminado {
					// Alias, netgroup ou endereço no Host_List. NÃO absolve: a
					// severidade é a mesma, e a evidência diz o que não foi
					// resolvido para quem lê poder resolver.
					ev = append(ev, "o Host_List desta regra (`"+v.Host+"`) NÃO foi "+
						"resolvido — há alias, netgroup ou endereço ali, e esta "+
						"ferramenta não os expande. A regra é tratada como se valesse "+
						"AQUI, porque não saber não é o mesmo que não valer")
				}
			case reg.Ok && v.Vistas > 0 && v.Vistas == v.OutroHost:
				// TODA a linha é de outro host, e nenhuma parte dela vale aqui.
				//
				// Sem esta leitura, um sudoers distribuído por configuração
				// central fazia a regra do banco sair CRITICAL em cada servidor
				// web da frota. A linha não some do relatório: vira UM achado
				// informativo no fim, com a contagem.
				deOutroHost = append(deOutroHost,
					s.File+":"+strconv.Itoa(s.Line)+" — "+s.Text+" (vale em `"+v.Host+"`)")
				continue
			case naoAutentica && defaultsGlobal(s.Text):
				// `Defaults !authenticate` SEM alvo desliga a senha para o host
				// inteiro — é NOPASSWD amplo escrito de outro jeito, e o coletor
				// guarda essa linha justamente por isso.
				sev = check.SevCritical
				ev = append(ev, "e é um `Defaults` SEM alvo: vale para TODO usuário "+
					"e TODO comando deste host — é NOPASSWD amplo escrito de outra "+
					"forma, não uma restrição")
			case naoAutentica:
				// Ramo de EVIDÊNCIA, e por isso ele é o último antes do default.
				//
				// Ele estava acima dos ramos de primitiva, e engolia todos eles:
				// uma regra que combinasse `!authenticate` com um comando
				// reconhecido perdia a única frase que diz o que aquele comando
				// concede.
				ev = append(ev, "o `!authenticate` está restrito a um alvo nomeado, "+
					"mas continua desligando a senha para ele")
			case ehDefinicaoDeAliasSudo(s.Text):
				// Definição de alias NOMEIA um conjunto e não concede nada:
				// quem concede é a User_Spec que cita o nome. Uma linha dessas
				// só chega até aqui quando o NOME do alias contém o texto
				// `NOPASSWD`, e emitir achado sobre ela seria acusar a
				// nomenclatura de alguém.
				continue
			default:
				// FALHA DE LEITURA, e ela sai dita. A linha tem `NOPASSWD` e o
				// parser não achou nela um comando sem senha: ou é sintaxe que
				// ele não representa, ou o único comando está negado. Chamar
				// isso de "nada aqui" seria a ferramenta transformando o próprio
				// limite em absolvição.
				ev = append(ev, "esta linha tem `NOPASSWD`, e o leitor de sudoers "+
					"desta ferramenta NÃO extraiu dela um comando concedido sem "+
					"senha — pode ser negação (`!`), pode ser sintaxe que ele não "+
					"representa. `sudo -l -U "+quem+"` resolve o que a regra concede "+
					"de fato")
			}
			if strings.HasPrefix(s.File, "/etc/sudoers.d/") {
				// Um arquivo novo em sudoers.d não altera nada existente: ele
				// ACRESCENTA, e por isso não aparece em diff do /etc/sudoers.
				ev = append(ev, "veio de um arquivo PRÓPRIO em sudoers.d: acrescenta "+
					"sem alterar o /etc/sudoers, e some de qualquer comparação que "+
					"olhe só o arquivo principal")
			}
			ev = append(ev, "alvo: "+quem)
			ev = append(ev, metaDeAcesso(f)...)

			fd := self.F(sev, quem, "", ev...)
			// O sujeito é o USUÁRIO, e o mesmo usuário costuma ter mais de uma
			// regra: sem discriminador, uma regra NOVA em sudoers.d herdava a
			// presença da antiga na baseline e saía sem a marca ✳NOVO. O texto
			// da regra é estável entre execuções; o número da linha não é.
			fd.Chave = s.Text
			fd.NextSteps = []string{
				"`sudo -l -U " + quem + "` mostra o que a regra concede de verdade, " +
					"já resolvendo alias e herança de grupo",
				"o ctime do arquivo data a inserção mesmo que o conteúdo pareça " +
					"antigo",
				"compare com outro host da frota: a mesma regra em vários é " +
					"provisionamento; em um só, é alteração",
			}
			r.Findings = append(r.Findings, fd)
		}
		if len(deOutroHost) > 0 {
			// INFO, e de propósito: o fato fica no relatório sem gastar o
			// crítico nem o exit code de um host onde a regra não vale.
			ev := append([]string{
				"o sudoers deste host declara " + strconv.Itoa(len(deOutroHost)) +
					" regra(s) sem senha cujo Host_List nomeia OUTRO host — elas " +
					"estão no arquivo e não valem aqui",
				"é o desenho normal de sudoers distribuído por configuração " +
					"central: o mesmo arquivo vai para a frota inteira e cada host " +
					"usa a parte dele",
				"o que confirma: `sudo -l` neste host não lista esses comandos",
			}, deOutroHost...)
			fd := self.F(check.SevInfo, "regras de outro host", "", ev...)
			fd.Chave = "host-alheio"
			r.Findings = append(r.Findings, fd)
		}
		r.Partial = append(r.Partial, f.PersistDenied["users"]...)
		return r
	},
}

// vereditoSudo é o resultado da leitura de UMA linha de sudoers: a pior spec
// sem senha que ela concede NESTE host, e o que sobrou de fora.
type vereditoSudo struct {
	Achou bool
	Sev   check.Severity
	Ev    []string

	// Vistas é quantas specs sem senha a linha tem; OutroHost, quantas delas
	// pertencem a um Host_List que não é este host. Iguais, a linha inteira é
	// de outra máquina.
	Vistas    int
	OutroHost int

	Indeterminado bool
	Host          string

	rank int
}

// rankDaSpec ordena o que a evidência cita quando duas specs pesam igual:
// `ALL` primeiro, depois shell, depois execução, escrita e leitura.
func rankDaSpec(sp specSudo) int {
	if sp.Tudo {
		return 0
	}
	switch sp.Cmd.Classe {
	case primShell:
		return 1
	case primExec:
		return 2
	case primEscrita:
		return 3
	case primLeitura:
		return 4
	}
	return 5
}

// vereditoDaRegra escolhe a PIOR spec sem senha da linha.
//
// Uma linha pode conceder vários comandos com tags diferentes —
// `NOPASSWD: /bin/true, PASSWD: /bin/ls, NOPASSWD: /usr/bin/find` são três
// decisões distintas na mesma linha. A leitura anterior cortava no último
// `NOPASSWD:` e olhava só o que vinha depois; esta olha todas e fica com a
// que pesa mais.
func vereditoDaRegra(reg regraSudo, semSenhaSempre bool, hostname, quem string) vereditoSudo {
	var v vereditoSudo
	for _, sp := range reg.Specs {
		if !sp.Nopasswd && !semSenhaSempre {
			continue
		}
		if sp.Negado {
			// `!/bin/su` TIRA da concessão em vez de conceder.
			continue
		}
		v.Vistas++
		apl, ondeH := aplicabilidadeSudo(sp.Hosts, hostname)
		if apl == sudoOutroHost {
			v.OutroHost++
			if v.Host == "" {
				v.Host = ondeH
			}
			continue
		}
		sev, ev := vereditoDoSpec(sp, quem)
		// Empate de severidade é decidido pela primitiva MAIS DIRETA: quando a
		// linha concede `find` e `bash` juntos, a evidência precisa citar o
		// shell. Era o que o `concedeExecucao` fazia com a ordem das classes, e
		// a ordem não podia se perder ao trocar de leitor.
		rank := rankDaSpec(sp)
		if !v.Achou || sev > v.Sev || (sev == v.Sev && rank < v.rank) {
			v.Achou, v.Sev, v.Ev, v.rank = true, sev, ev, rank
			v.Indeterminado, v.Host = apl == sudoIndeterminado, ondeH
		}
	}
	return v
}

// vereditoDoSpec é a escada inteira para UM Cmnd_Spec.
func vereditoDoSpec(sp specSudo, quem string) (check.Severity, []string) {
	c := sp.Cmd
	sev := check.SevWarn
	var ev []string
	switch {
	case sp.Tudo && sp.ComoRoot:
		sev = check.SevCritical
		ev = []string{"e a especificação de comando é ALL, como " + sp.RunasTexto +
			": é root inteiro, sem responder nada"}
	case sp.Tudo:
		// Conceder TUDO como outra conta não é root, e dizer que é seria
		// afirmar o que a regra não diz. Continua valendo olhar — quem usa vira
		// aquela conta sem senha —, mas é aviso.
		ev = []string{"a especificação de comando é ALL, mas como " + sp.RunasTexto +
			" — NÃO como root: quem usa a regra vira aquela conta sem responder " +
			"nada, que é como se entrega um serviço a um time"}
	case c.CaminhoAmplo:
		sev, ev = vereditoDeCaminhoAmplo(sp, quem)
	case sp.ComoRoot && c.Concede():
		// "restrita a UM comando" só é menor privilégio se aquele comando
		// não devolver execução arbitrária. `NOPASSWD: /bin/bash` como
		// root É root irrestrito — e `NOPASSWD: /usr/bin/find` também,
		// porque `find . -exec /bin/sh \;` é um passo, não uma exploração.
		sev = check.SevCritical
		ev = []string{
			"e o comando `" + c.Bin + "` " + c.Classe.frase() +
				" — como " + sp.RunasTexto + ", chamar isto de restrição é falso",
			c.notaDeArgumento(),
		}
	case c.Concede():
		// Mesmo poder, outra identidade: quem usar a regra executa o que
		// quiser COMO aquela conta. Não é root, e por isso é aviso.
		ev = []string{"e o comando `" + c.Bin + "` " + c.Classe.frase() +
			" — como " + sp.RunasTexto + ", e não como root"}
	case c.Classe == primLeitura && (!c.PresoPorArgumento || c.Curinga || c.RegexLarga):
		// Leitura arbitrária não é root no ato: entrega o /etc/shadow, e o hash
		// ainda precisa ser quebrado. Continua sendo aviso, e deixa de ser
		// chamado de menor privilégio.
		ev = []string{"e o comando `" + c.Bin + "` " + c.Classe.frase()}
		if !sp.ComoRoot {
			ev = append(ev, "e é como "+sp.RunasTexto+", não como root: o que ele lê "+
				"é o que aquela conta lê")
		}
		ev = append(ev, c.notaDeArgumento())
	case c.Classe != primNenhuma && c.PresoPorArgumento:
		// A tabela RECONHECE este binário, e o que segura a regra é o argumento
		// fixado. Dizer "não reconheço" aqui seria afirmar uma ignorância que
		// não existe — e esconder que o freio é uma string.
		ev = c.notaDePrisao()
	case ehAliasDeComando(c.Bin):
		// Alias não é binário: o que ele expande está em outra linha do
		// sudoers, e esta ferramenta não resolve alias.
		ev = []string{"restrita a comando nomeado pelo alias `" + c.Bin +
			"`: o que ele expande está em OUTRA linha do sudoers, e esta " +
			"ferramenta não resolve alias — `sudo -l -U " + quem + "` resolve, e " +
			"é ali que se vê o que a regra concede de fato"}
	default:
		// A frase anterior era "é desenho de menor privilégio", e ela AFIRMAVA
		// sobre um binário que a ferramenta não examinou. A tabela de primitivas
		// cobre ~110 nomes; o universo é maior, e não reconhecer não é o mesmo
		// que não haver.
		ev = []string{"restrita a comando nomeado (`" + nz(c.Bin, "?") +
			"`), que esta ferramenta NÃO reconhece como primitiva de escalada — " +
			"o que a regra concede depende do que aquele binário faz com " +
			"privilégio, e a tabela de referência do assunto é a GTFOBins"}
	}
	if sp.Noexec && sev == check.SevCritical && !sp.Tudo {
		// NOEXEC é a tag que de fato restringe: o sudo pré-carrega uma
		// biblioteca que intercepta a família exec, e o `-exec` do find, o `:!sh`
		// do vim e o `--to-command` do tar passam todos por ela. Manter CRITICAL
		// aqui seria ignorar a única tag do sudoers que responde à primitiva.
		sev = check.SevWarn
		ev = append(ev, "MAS a regra tem a tag `NOEXEC:`, e ela responde justamente "+
			"a esta primitiva: o sudo pré-carrega uma biblioteca que intercepta a "+
			"família `exec`, e é por ali que o escape passa")
		ev = append(ev, "o freio NÃO é absoluto: ele depende de link dinâmico. "+
			"Binário estático, ou que chame o syscall direto, não é interceptado")
	}
	return sev, ev
}

// vereditoDeCaminhoAmplo lê a regra cujo COMANDO é um diretório ou um curinga
// de caminho.
//
// `ops ALL=(root) NOPASSWD: /usr/bin/*` concede todo executável direto de
// /usr/bin — o que inclui `bash`, `find`, `python`, `vim`. A leitura anterior
// era por basename: o binário chamava-se `*`, a tabela não o reconhecia, e a
// evidência saía dizendo "esta ferramenta NÃO reconhece como primitiva de
// escalada" sobre uma regra que entrega root em um passo.
func vereditoDeCaminhoAmplo(sp specSudo, quem string) (check.Severity, []string) {
	c := sp.Cmd
	forma := "curinga"
	if strings.HasSuffix(c.Bin, "/") {
		forma = "diretório"
	}
	ev := []string{
		"o CAMINHO do comando é um " + forma + " (`" + c.Bin + "`) e não um " +
			"binário: a regra concede TODO executável que esse padrão alcança em `" +
			nz(c.DirDoCaminho, "/") + "`",
	}
	if !dirDeExecutaveisGerais[c.DirDoCaminho] {
		return check.SevWarn, append(ev,
			"esta ferramenta NÃO enumera o diretório: quantos executáveis o padrão "+
				"alcança, e o que cada um faz com privilégio, é a conferência que "+
				"sobra — `sudo -l -U "+quem+"` mostra o alcance efetivo")
	}
	ev = append(ev, "e `"+c.DirDoCaminho+"` é diretório de ferramentas do sistema: "+
		"dentro dele estão o shell, o interpretador e o `find`")
	if !sp.ComoRoot {
		return check.SevWarn, append(ev, "e é como "+sp.RunasTexto+", não como root")
	}
	return check.SevCritical, append(ev,
		"como root e sem senha, isto é `ALL` escrito de outra forma",
		"o `/` não é casado pelo curinga de caminho (sudoers(5)), então o alcance "+
			"é aquele diretório e não a árvore inteira — e o diretório já basta")
}

// defaultsGlobal diz se a linha é um `Defaults` sem alvo. O sudoers permite
// restringir com `Defaults:usuario`, `Defaults@host`, `Defaults>runas` e
// `Defaults!comando`; sem nenhum desses, a diretiva vale para o host inteiro.
func defaultsGlobal(texto string) bool {
	t := strings.TrimSpace(texto)
	if !strings.HasPrefix(strings.ToLower(t), "defaults") {
		return false
	}
	resto := t[len("defaults"):]
	if resto == "" {
		return false
	}
	switch resto[0] {
	case ':', '@', '>', '!':
		return false
	}
	return resto[0] == ' ' || resto[0] == '\t'
}

// campoInicial é o alvo da regra: usuário, %grupo ou Defaults:alvo.
// doas é o sudo do OpenBSD, e vem por padrão em Alpine e Arch. `permit nopass`
// é escalada SEM senha — o mesmo backdoor que o NOPASSWD do sudoers, num arquivo
// que quase ninguém audita porque o reflexo é procurar em /etc/sudoers.
//
//	permit nopass user             root sem senha para `user`, QUALQUER comando
//	permit nopass keepenv :wheel   idem para todo o grupo wheel
//	permit nopass user as postgres vira `postgres` sem senha — não é root
var doasSemSenha = check.Check{
	ID:       "priv.doas_nopasswd",
	Ref:      "7.9",
	Title:    "regra de doas que escala sem pedir senha",
	Group:    "priv",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Optional: env.CapRoot,
	Wtf:      true,
	FalsePositives: []string{
		"em Alpine e Arch o doas é o mecanismo NORMAL de escalada, e uma regra " +
			"`permit :wheel` (COM senha) é o desenho de fábrica — o sinal é o " +
			"`nopass`, não a existência da regra",
		"automação sem operador precisa de nopass pela mesma razão do sudo: não " +
			"há ninguém para digitar a senha. Um `permit nopass` restrito a UM " +
			"comando é menor privilégio, e sai com severidade menor — MAS só " +
			"quando aquele comando não devolve execução arbitrária, e um `cmd` " +
			"sem `args` aceita QUALQUER argumento",
		"conceder acesso como OUTRA conta (`as postgres`) não é root, e sai como " +
			"aviso — é como um time recebe o serviço que administra",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		for i := range f.Doas {
			d := &f.Doas[i]
			// `deny` restringe, não concede; e sem nopass a senha ainda é pedida.
			if !d.Permit || !d.NoPass {
				continue
			}
			// LAST-MATCH do doas: a ÚLTIMA regra que casa um pedido decide. Um
			// `permit nopass X` seguido de `deny X` NÃO concede nada — o deny é a
			// regra efetiva. Avaliar cada permit isolado gerava FP sobre uma regra
			// que a ordem já anulou.
			if !concedeNopassEfetivo(f.Doas, i) {
				continue
			}

			// alvo vazio = root (o padrão do doas). E comando vazio = QUALQUER
			// comando, que é o que torna a regra ampla.
			comoRoot := d.Alvo == "" || d.Alvo == "root"
			amplo := d.Comando == ""
			cmd := comandoDoDoas(d.Comando, d.TemArgs)

			ev := []string{
				d.File + ":" + strconv.Itoa(d.Line) + " — " + d.Text,
				"`permit nopass` concede escalada SEM pedir senha",
			}
			// Suporte a confdir (/etc/doas.d) é FEATURE DE BUILD do OpenDoas, não
			// universal. Numa build sem confdir, uma regra ali é inerte — a regra
			// EXISTE, mas pode não estar ativa, e isso não é inferível do disco.
			if strings.HasPrefix(d.File, "/etc/doas.d/") {
				ev = append(ev, "vem de /etc/doas.d — confira se este build do doas LÊ "+
					"confdir (é opção de compilação do OpenDoas): a regra existe, mas "+
					"pode estar inerte")
			}
			quem := d.Identidade
			if strings.HasPrefix(quem, ":") {
				ev = append(ev, "vale para todo o GRUPO "+quem[1:])
			}

			sev := check.SevWarn
			switch {
			case amplo && comoRoot:
				sev = check.SevCritical
				ev = append(ev, "e é root, QUALQUER comando, sem senha: é escalada "+
					"irrestrita para "+quem)
			case comoRoot && cmd.Concede():
				// "restrita a UM comando" só é menor privilégio se aquele comando
				// não devolver execução arbitrária. `cmd /bin/sh` como root É root
				// irrestrito, e `cmd /usr/bin/tar` também — a diferença entre os
				// dois é quantos caracteres o atacante digita, não o poder.
				sev = check.SevCritical
				ev = append(ev, "e o comando `"+d.Comando+"` "+cmd.Classe.frase()+
					": restringir a isto como root não restringe nada")
				ev = append(ev, cmd.notaDeArgumento())
			case comoRoot && cmd.Classe == primLeitura && !d.TemArgs:
				ev = append(ev, "e o comando `"+d.Comando+"` "+cmd.Classe.frase())
				ev = append(ev, cmd.notaDeArgumento())
			case comoRoot && cmd.Classe != primNenhuma:
				// Reconhecida e presa pelo `args`. Ver notaDePrisao.
				ev = append(ev, cmd.notaDePrisao()...)
			case comoRoot:
				ev = append(ev, "restrita ao comando `"+d.Comando+"`, que esta "+
					"ferramenta NÃO reconhece como primitiva de escalada — o que a "+
					"regra concede depende do que aquele binário faz com privilégio, "+
					"e a tabela de referência do assunto é a GTFOBins")
			default:
				ev = append(ev, "escala como `"+d.Alvo+"`, não root — quem usa vira "+
					"aquela conta sem senha")
			}

			fd := self.F(sev, quem, "", ev...)
			// Mesma razão do sudo: o sujeito é a identidade, e uma identidade
			// pode ter várias regras. Ver check.Finding.Chave.
			fd.Chave = d.Alvo + "|" + d.Comando
			fd.NextSteps = []string{
				"leia a regra: `permit nopass` sem `as` é root; com `cmd` é restrita",
				"se ninguém reconhecer a identidade liberada, remova a linha e " +
					"rotacione o acesso da conta",
			}
			r.Findings = append(r.Findings, fd)
		}
		r.Partial = append(r.Partial, f.PersistDenied["users"]...)
		return r
	},
}

func campoInicial(texto string) string {
	fs := strings.Fields(texto)
	if len(fs) == 0 {
		return "?"
	}
	if alvo, ok := strings.CutPrefix(fs[0], "Defaults:"); ok && alvo != "" {
		return alvo
	}
	return fs[0]
}

// concedeNopassEfetivo aplica o last-match do doas: a regra `permit nopass` no
// índice i só é a decisão efetiva se NENHUMA regra POSTERIOR de mesma identidade
// e escopo abrangente a sobrescrever. Uma regra posterior que casa e (a) nega ou
// (b) concede COM senha torna o nopass de i inerte.
func concedeNopassEfetivo(rs []facts.DoasRule, i int) bool {
	r := rs[i]
	for j := i + 1; j < len(rs); j++ {
		o := rs[j]
		if o.Identidade != r.Identidade {
			continue
		}
		// `o` cobre o pedido mais amplo de `r`? Alvo vazio = qualquer; comando
		// vazio = qualquer. Se `r` é amplo (comando vazio), só um `o` amplo cobre.
		cobreAlvo := o.Alvo == "" || o.Alvo == r.Alvo
		cobreCmd := o.Comando == "" || (r.Comando != "" && o.Comando == r.Comando)
		if !cobreAlvo || !cobreCmd {
			continue
		}
		// Uma regra posterior que casa DECIDE. Se ela nega ou pede senha, o
		// nopass de `r` deixou de ser o efetivo.
		if !o.Permit || !o.NoPass {
			return false
		}
	}
	return true
}
