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
