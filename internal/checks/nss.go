package checks

import (
	"strings"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

func init() {
	check.Register(nssModuleSemDono)
}

// nssModuleSemDono — runbook §7.8, ATT&CK T1556.
//
// O /etc/nsswitch.conf mapeia cada resolução de nome (passwd, hosts, shadow)
// para bibliotecas `libnss_<fonte>.so.2` que o glibc carrega e EXECUTA dentro de
// QUALQUER processo que resolva um nome — login, sshd, cron, o próprio `id`. Um
// módulo plantado ali roda em toda resolução, inclusive de daemon root, sem
// deixar processo, porta nem agendamento.
//
// O sinal é o mesmo do serviço-backdoor: a fonte referencia uma biblioteca que
// NENHUM pacote entregou. nss-systemd vem do systemd, sss do sssd, mdns do
// avahi — todos com dono. O `libnss_impl.so.2` do atacante, não. Não é o NOME
// da fonte que decide (há dezenas de módulos legítimos): é a propriedade.
var nssModuleSemDono = check.Check{
	ID:       "persist.nss_module",
	Ref:      "7.8",
	Title:    "módulo NSS carregado em toda resolução de nome que nenhum pacote entregou",
	Group:    "persist",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Wtf:      true,
	FalsePositives: []string{
		"há dezenas de módulos NSS legítimos — nss-systemd, sss, ldap, winbind, " +
			"mdns do avahi, o do libvirt. TODOS vêm de pacote, e é isso que os " +
			"separa: o achado é a biblioteca SEM dono, não a fonte com nome " +
			"desconhecido",
		"módulo NSS compilado à mão (raro) aparece como sem dono — mas em host " +
			"normal nenhum módulo NSS é órfão, e essa raridade é o que dá valor",
		"sem a base de pacotes legível a pergunta de propriedade não se faz, e o " +
			"achado não se forma — vira lacuna declarada, não silêncio",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		semDono := caminhosSemDono(f)
		if len(semDono) == 0 {
			r.Partial = append(r.Partial, f.PersistDenied["pkg"]...)
			r.Partial = append(r.Partial, f.PersistDenied["nss"]...)
			return r
		}
		for i := range f.NSSModules {
			m := &f.NSSModules[i]
			if m.Path == "" || !semDono[m.Path] {
				continue
			}
			ev := []string{
				"a fonte `" + m.Fonte + "` do nsswitch.conf carrega " + m.Path,
				"esse arquivo está num diretório de biblioteca e NENHUM pacote o " +
					"reivindica (base: " + f.Pkg.Kind + "): módulo NSS que ninguém entregou",
				"resolve para os serviços: " + strings.Join(m.Servicos, ", ") +
					" — o código roda em CADA resolução desses, inclusive por daemon root",
			}
			fd := self.F(check.SevCritical, "libnss_"+m.Fonte, "", ev...)
			fd.NextSteps = []string{
				"preserve " + m.Path + " antes de qualquer coisa (runbook §6)",
				"remova a fonte `" + m.Fonte + "` do /etc/nsswitch.conf — enquanto " +
					"ela estiver lá, toda resolução recarrega o módulo",
				"a lib é carregada por PROCESSOS JÁ EM EXECUÇÃO: reinicie os daemons " +
					"que resolvem nome (sshd, cron) depois de remover",
			}
			r.Findings = append(r.Findings, fd)
		}
		r.Partial = append(r.Partial, f.PersistDenied["nss"]...)
		return r
	},
}
