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
					"antiga (runbook §9)",
				"procure a mesma conta na frota: criação em vários hosts é campanha, " +
					"não incidente isolado (runbook §23)",
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
				"o ctime de /etc/shadow data a alteração (runbook §9)",
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
					"confirma a alteração aqui (runbook §23)",
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
			"com severidade menor do que a que concede ALL",
		"conceder ALL como OUTRA CONTA não é root, e sai como aviso: " +
			"`%dba ALL=(postgres) NOPASSWD: ALL` é como um time de DBA recebe o " +
			"serviço que administra, e um servidor de banco real produziu " +
			"exatamente essa linha",
		"sem root o /etc/sudoers é ilegível, e a ausência de achado passa a ser " +
			"desconhecimento em vez de resposta — a cobertura diz qual dos dois",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		for i := range f.Sudoers {
			s := &f.Sudoers[i]
			up := strings.ToUpper(s.Text)
			nopass := strings.Contains(up, "NOPASSWD")
			naoAutentica := strings.Contains(strings.ToLower(s.Text), "!authenticate")
			if !nopass && !naoAutentica {
				continue
			}

			quem := campoInicial(s.Text)
			// ALL como especificação de comando concede QUALQUER comando; e o
			// runas diz como QUEM. As duas perguntas são diferentes, e confundi-las
			// custou um crítico contra um servidor de banco limpo.
			amplo := regraAmpla(s.Text)
			comoRoot, runas := viraRoot(s.Text)
			sev := check.SevWarn
			ev := []string{
				s.File + ":" + strconv.Itoa(s.Line) + " — " + s.Text,
			}
			if naoAutentica {
				ev = append(ev, "`!authenticate` desliga a pergunta de senha para o "+
					"alvo inteiro, e quase ninguém procura por essa forma")
			}
			switch {
			case amplo && comoRoot:
				sev = check.SevCritical
				ev = append(ev, "e a especificação de comando é ALL, como "+runas+
					": é root inteiro, sem responder nada")
			case amplo:
				// Conceder TUDO como outra conta não é root, e dizer que é seria
				// afirmar o que a regra não diz. Continua valendo olhar — quem
				// usa vira aquela conta sem senha —, mas é aviso.
				ev = append(ev, "a especificação de comando é ALL, mas como "+runas+
					" — NÃO como root: quem usa a regra vira aquela conta sem "+
					"responder nada, que é como se entrega um serviço a um time")
			case naoAutentica && defaultsGlobal(s.Text):
				// `Defaults !authenticate` SEM alvo desliga a senha para o host
				// inteiro — é NOPASSWD amplo escrito de outro jeito, e o coletor
				// guarda essa linha justamente por isso. Como ela não tem
				// `NOPASSWD:` nem `=`, regraAmpla varria a linha inteira, não
				// achava ALL, e o caso caía no `default` — que imprimia
				// "restrita a comando nomeado", contradizendo a evidência
				// anterior do próprio achado, com exit 1 em vez de 2.
				sev = check.SevCritical
				ev = append(ev, "e é um `Defaults` SEM alvo: vale para TODO usuário "+
					"e TODO comando deste host — é NOPASSWD amplo escrito de outra "+
					"forma, não uma restrição")
			case naoAutentica:
				ev = append(ev, "o `!authenticate` está restrito a um alvo nomeado, "+
					"mas continua desligando a senha para ele")
			default:
				ev = append(ev, "restrita a comando nomeado — é desenho de menor "+
					"privilégio, e vale conferir só se ninguém reconhecer a regra")
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
			fd.NextSteps = []string{
				"`sudo -l -U " + quem + "` mostra o que a regra concede de verdade, " +
					"já resolvendo alias e herança de grupo",
				"o ctime do arquivo data a inserção mesmo que o conteúdo pareça " +
					"antigo (runbook §9)",
				"compare com outro host da frota: a mesma regra em vários é " +
					"provisionamento; em um só, é alteração (runbook §23)",
			}
			r.Findings = append(r.Findings, fd)
		}
		r.Partial = append(r.Partial, f.PersistDenied["users"]...)
		return r
	},
}

// viraRoot lê o RUNAS da regra — o `(...)` depois do `=` — e diz se ela leva a
// root, junto do texto para a evidência citar.
//
// Foi a metade que faltava, e a falta produziu um CRÍTICO contra um servidor de
// banco perfeitamente normal:
//
//	%dba    ALL=(postgres) NOPASSWD: ALL
//
// A ferramenta dizia "é root inteiro". Não é: vira `postgres`, que é como um
// time de DBA recebe o serviço que administra. Root sem senha e serviço sem
// senha são achados diferentes, e chamá-los de iguais gasta o crítico — que é a
// severidade que faz a frota parar.
//
// Ausência de runas é root: é o padrão do sudo, e escrever `ALL=NOPASSWD: ALL`
// concede root do mesmo jeito.
func viraRoot(texto string) (bool, string) {
	i := strings.Index(texto, "(")
	j := strings.Index(texto, ")")
	if i < 0 || j < i {
		return true, "root (padrão do sudo, sem runas declarado)"
	}
	dentro := texto[i+1 : j]
	// O runas tem duas metades: usuários antes do `:`, grupos depois. Root
	// entra pela primeira.
	usuarios, _, _ := strings.Cut(dentro, ":")
	for _, campo := range strings.FieldsFunc(usuarios, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t'
	}) {
		c := strings.TrimSpace(campo)
		if c == "root" || c == "ALL" || c == "#0" {
			return true, c
		}
	}
	return false, strings.TrimSpace(dentro)
}

// regraAmpla diz se a regra concede QUALQUER comando. É o que separa "root
// inteiro sem senha" de "pode reiniciar o nginx sem senha".
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

func regraAmpla(texto string) bool {
	// A especificação de comando é o que vem depois do último `=` ou dos
	// dois-pontos do NOPASSWD.
	corte := texto
	if i := indiceSemCaixa(texto, "NOPASSWD:"); i >= 0 {
		corte = texto[i+len("NOPASSWD:"):]
	} else if i := strings.LastIndex(texto, "="); i >= 0 {
		corte = texto[i+1:]
	}
	for _, campo := range strings.FieldsFunc(corte, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t'
	}) {
		if strings.TrimSpace(campo) == "ALL" {
			return true
		}
	}
	return false
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
			"comando é menor privilégio, e sai com severidade menor",
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

			// alvo vazio = root (o padrão do doas). E comando vazio = QUALQUER
			// comando, que é o que torna a regra ampla.
			comoRoot := d.Alvo == "" || d.Alvo == "root"
			amplo := d.Comando == ""

			ev := []string{
				d.File + ":" + strconv.Itoa(d.Line) + " — " + d.Text,
				"`permit nopass` concede escalada SEM pedir senha",
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
			case comoRoot && ehShellOuInterp(d.Comando):
				// "restrita a UM comando" só é menor privilégio se aquele comando
				// não for um shell. `cmd /bin/sh` como root É root irrestrito: o
				// alvo executa qualquer coisa a partir dali. Não é a GTFOBins
				// inteira — é a classe direta de interpretador.
				sev = check.SevCritical
				ev = append(ev, "e o comando é um SHELL/interpretador ("+d.Comando+"): "+
					"restringir a `sh` como root não restringe nada — é root irrestrito")
			case comoRoot:
				ev = append(ev, "restrita ao comando `"+d.Comando+"` — menor privilégio, "+
					"vale conferir se ninguém reconhece a regra")
			default:
				ev = append(ev, "escala como `"+d.Alvo+"`, não root — quem usa vira "+
					"aquela conta sem senha")
			}

			fd := self.F(sev, quem, "", ev...)
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

// indiceSemCaixa acha a última ocorrência ignorando maiúsculas, devolvendo o
// índice na string ORIGINAL.
//
// A versão anterior indexava `strings.ToUpper(texto)` e fatiava `texto`. Em
// ASCII os dois coincidem, mas ToUpper muda o tamanho em bytes de alguns
// caracteres (o `ı` turco vira `I`, de dois bytes para um) — e aí o corte cai
// no lugar errado e a severidade sai trocada. É improvável num sudoers e é
// barato de não deixar acontecer.
func indiceSemCaixa(texto, alvo string) int {
	for i := len(texto) - len(alvo); i >= 0; i-- {
		if strings.EqualFold(texto[i:i+len(alvo)], alvo) {
			return i
		}
	}
	return -1
}

// ehShellOuInterp diz se o comando é um shell ou interpretador direto. Reusa o
// mesmo conjunto do classificador de pipe (systemd.go) — a lista de coisas que,
// recebendo argumento, executam qualquer coisa. Pega o primeiro token porque a
// regra de doas pode citar `cmd /bin/sh args ...`.
func ehShellOuInterp(cmd string) bool {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return false
	}
	campos := strings.Fields(cmd)
	return interpretadoresDePipe[baseDe(campos[0])]
}
