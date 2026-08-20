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
		// O mecanismo é do glibc. No musl (Alpine) o nsswitch.conf é IGNORADO, e
		// afirmar "roda em toda resolução" seria falso. Só o glibc — ou o
		// desconhecido, onde a presença de nsswitch.conf + libnss_ já é padrão
		// glibc — sustenta a afirmação; no musl vira nota, não acusação.
		if f.Host.Libc == "musl" {
			if len(f.NSSModules) > 0 {
				r.Partial = append(r.Partial, "há fontes no /etc/nsswitch.conf, mas a "+
					"libc é musl: ela IGNORA o nsswitch, então nenhum libnss_ é carregado "+
					"por ele — a via NSS-glibc não se aplica a este host")
			}
			return r
		}
		semDono := caminhosSemDono(f)
		if len(semDono) == 0 {
			r.Partial = append(r.Partial, f.PersistDenied["pkg"]...)
			r.Partial = append(r.Partial, f.PersistDenied["nss"]...)
			return r
		}
		for i := range f.NSSModules {
			m := &f.NSSModules[i]
			// Dispara sobre QUALQUER candidato sem dono. Com shadowing (uma cópia
			// legítima e um implante), o loader escolhe pelo ld.so.cache — que
			// esta ferramenta ainda não lê —, então o candidato órfão não pode
			// ser descartado por existir uma cópia com dono ao lado.
			var orfaos []string
			for _, p := range m.Paths {
				if semDono[p] {
					orfaos = append(orfaos, p)
				}
			}
			if len(orfaos) == 0 {
				continue
			}
			ev := []string{
				"a fonte `" + m.Fonte + "` do nsswitch.conf carrega " + strings.Join(orfaos, ", "),
				"esse arquivo está num diretório de biblioteca e NENHUM pacote o " +
					"reivindica (base: " + f.Pkg.Kind + "): módulo NSS que ninguém entregou",
				"resolve para os serviços: " + strings.Join(m.Servicos, ", ") +
					" — o código roda em CADA resolução desses, inclusive por daemon root",
			}
			if len(m.Paths) > len(orfaos) {
				// Há também uma cópia COM dono: shadowing. Qual carrega depende do
				// ld.so.cache (ainda não lido) — a ambiguidade fica dita.
				ev = append(ev, "ATENÇÃO: existe também uma cópia COM dono de pacote "+
					"para esta fonte — qual o loader carrega depende do ld.so.cache, "+
					"não do primeiro diretório; trate a órfã como possivelmente ativa")
			}
			fd := self.F(check.SevCritical, "libnss_"+m.Fonte, "", ev...)
			fd.NextSteps = []string{
				"preserve " + strings.Join(orfaos, ", ") + " antes de qualquer coisa",
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
