package checks

import (
	"strconv"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

func init() { check.Register(contaSemShadow) }

// contaSemShadow — runbook §7.9.
//
// O jeito clássico de criar acesso permanente cabe numa linha:
//
//	echo 'backdoor:x:0:0::/root:/bin/bash' >> /etc/passwd
//
// E ela deixa um rastro estrutural que quem a escreve quase sempre esquece: o
// `useradd` escreve em `/etc/passwd` E em `/etc/shadow`, sempre. Uma conta que
// existe só no primeiro nunca passou por ele.
//
// Medido nas quatro distribuições da matriz — Debian 12, Alpine, CentOS 7 e
// Ubuntu 14.04: os dois arquivos batem exatamente, conta por conta. Divergência
// aqui não é variação de distribuição.
//
// É a mesma forma dos checks de visão cruzada: duas fontes para o mesmo fato, e
// o achado mora na divergência.
var contaSemShadow = check.Check{
	ID:       "priv.account_no_shadow",
	Ref:      "7.9",
	Title:    "conta existe no passwd e não no shadow: não passou pelo useradd",
	Group:    "priv",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Optional: env.CapRoot,
	Wtf:      true,
	FalsePositives: []string{
		"provisionamento que escreve /etc/passwd por template — imagem de nuvem, " +
			"Ansible com `lineinfile`, contêiner construído à mão — produz " +
			"exatamente esta forma legitimamente",
		"appliance e sistema embarcado às vezes não usam shadow nenhum, e aí o " +
			"arquivo inteiro está ausente: sem shadow legível o check não forma " +
			"achado, e a cobertura diz isso",
		"NIS, LDAP e outros diretórios centrais respondem por contas que não " +
			"estão em nenhum dos dois arquivos — mas essas também não aparecem no " +
			"passwd local, então não caem aqui",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		for i := range f.Accounts {
			a := &f.Accounts[i]
			if !a.SemShadow {
				continue
			}

			ev := []string{
				a.Name + " está no /etc/passwd e não tem entrada no /etc/shadow",
				"o `useradd` escreve nos DOIS, sempre: uma conta só no primeiro " +
					"nunca passou por ele",
				"uid=" + strconv.Itoa(a.UID) + " shell=" + nz(a.Shell, "(nenhum)") +
					" home=" + nz(a.Home, "(nenhum)"),
			}

			// uid 0 já tem check próprio, e a soma das duas coisas é a linha
			// inteira do backdoor clássico.
			sev := check.SevWarn
			if a.UID == 0 {
				sev = check.SevCritical
				ev = append(ev, "e tem uid 0: é a linha exata do acesso permanente "+
					"mais antigo que existe, acrescentada com um `echo`")
			} else if shellDeVerdade(a.Shell) {
				sev = check.SevCritical
				ev = append(ev, "e tem shell de login: a conta é porta de entrada")
			}
			ev = append(ev, metaDeAcesso(f)...)

			fd := self.F(sev, a.Name, "", ev...)
			fd.NextSteps = []string{
				"`getent shadow " + a.Name + "` confirma a ausência já resolvendo " +
					"diretório central, se houver",
				"o ctime de /etc/passwd data a inserção, mesmo que a conta pareça " +
					"antiga",
				"procure a mesma conta na frota: em vários hosts é provisionamento, " +
					"num só é incidente",
			}
			r.Findings = append(r.Findings, fd)
		}
		r.Partial = append(r.Partial, f.PersistDenied["users"]...)
		return r
	},
}
