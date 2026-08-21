package checks

import (
	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

func init() { check.Register(macRebaixado) }

// macRebaixado — runbook §21.
//
// Desligar o controle de acesso obrigatório é passo comum depois de entrar: com
// SELinux em permissivo o implante roda sem confinamento, e nada é negado nem
// registrado.
//
// O que este check NÃO faz é acusar MAC inativo. **Estado de fábrica não é
// ataque**: metade dos servidores roda com SELinux permissivo de propósito, e
// há distribuição que entrega 158 perfis de AppArmor com o módulo desligado.
// Um check assim acusaria todos eles, e viraria ruído no primeiro dia.
//
// O que é objetivo é a CONTRADIÇÃO entre duas fontes:
//
//	/etc/selinux/config      diz o que o administrador QUIS
//	/sys/fs/selinux/enforce  diz o que está valendo AGORA
//
// Nenhum sistema se instala em estado auto-contraditório. Config pedindo
// enforcing com o kernel em permissivo significa `setenforce 0` depois do boot
// — e isso não sobrevive a um reboot, o que o torna decisão RECENTE por
// definição.
//
// É a mesma forma dos checks de visão cruzada: duas fontes para o mesmo fato, e
// o achado mora na divergência.
var macRebaixado = check.Check{
	ID:       "antiforense.mac_downgraded",
	Ref:      "34.9",
	Title:    "SELinux configurado para enforcing e rodando em permissivo",
	Group:    "priv",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive,
	Requires: env.CapFilesystem,
	Optional: env.CapRoot,
	Wtf:      true,
	FalsePositives: []string{
		"DIAGNÓSTICO usa exatamente isto: `setenforce 0` é a primeira coisa que " +
			"se faz para descobrir se o SELinux é a causa de um problema, e " +
			"esquecer de religar é comum. O que separa é quem fez e quando — " +
			"pergunta para o time, não para a ferramenta",
		"config em `permissive` ou `disabled` NÃO é achado: é escolha declarada " +
			"do administrador, e a maioria dos servidores está assim",
		"contêiner não tem selinuxfs próprio, e a ausência dele ali é o runtime " +
			"mascarando — não SELinux desligado",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		m := &f.MAC

		// A lacuna do coletor vem PRIMEIRO, antes de qualquer saída.
		//
		// O coletor grava f.Partial["mac"] quando /etc/selinux/config ou
		// /sys/fs/selinux/enforce não abrem, e nenhum check lia a chave. Com
		// isso o `return` logo abaixo juntava duas coisas diferentes — "o
		// administrador escolheu permissive" e "não consegui ler o config" — e
		// as duas saíam como cobertura COMPLETA. O mesmo valia com config
		// legível pedindo enforcing e /sys ilegível: Ativo=="" não casa nenhum
		// case do switch, e o check terminava em silêncio.
		r.Partial = append(r.Partial, f.Partial["mac"]...)

		// Sem config não há o que contradizer, e config que já pede permissivo
		// ou disabled é escolha declarada.
		if m.Configurado != "enforcing" {
			return r
		}

		switch {
		case m.Ativo == "0":
			fd := self.F(check.SevCritical, "selinux", "",
				"/etc/selinux/config pede `enforcing` e o kernel reporta permissivo",
				"nenhum sistema se instala assim: a contradição significa que alguém "+
					"rodou `setenforce 0` DEPOIS do boot",
				"e isso não sobrevive a um reboot — é decisão recente por definição, "+
					"e a janela dela é o tempo desde o último boot",
				"com o SELinux em permissivo nada é negado nem registrado: o que "+
					"rodou desde então rodou sem confinamento",
			)
			fd.Irreversible = true
			fd.NextSteps = []string{
				"`ausearch -m AVC` mostra o que TERIA sido negado desde o boot, e é " +
					"onde o implante aparece",
				"NÃO religue antes de preservar: `setenforce 1` muda o estado e pode " +
					"matar o que se quer observar",
				"o uptime do host delimita a janela: a mudança é posterior a ele",
			}
			r.Findings = append(r.Findings, fd)

		case !m.FSPresente:
			// Sem selinuxfs a contradição existe, mas a explicação inocente
			// também: contêiner e `selinux=0` na linha de comando do kernel.
			fd := self.F(check.SevWarn, "selinux", "",
				"/etc/selinux/config pede `enforcing` e não há selinuxfs montado",
				"ou o SELinux foi desligado na linha de comando do kernel — o que "+
					"sobrevive a reboot e é mudança persistente —, ou isto é um "+
					"contêiner, cujo runtime mascara /sys",
				"as duas explicações são plausíveis, e só o cabeçalho desta varredura "+
					"diz qual delas se aplica",
			)
			fd.NextSteps = []string{
				"confira `selinux=0` ou `enforcing=0` na linha de comando do kernel " +
					"(/proc/cmdline)",
			}
			r.Findings = append(r.Findings, fd)
		}
		return r
	},
}
