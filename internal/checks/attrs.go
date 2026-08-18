package checks

import (
	"strings"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

func init() { check.Register(arquivoImutavel) }

// arquivoImutavel — runbook §7.11, §19.
//
// O `chattr +i` trava o arquivo contra alteração e remoção, e nem root passa
// por cima sem tirar o atributo antes. Um invasor que faz isso compra duas
// coisas, e a segunda é a que interessa a esta ferramenta:
//
//	o implante resiste à limpeza
//	e a limpeza FALHA EM SILÊNCIO para quem não conhece o atributo
//
// O roteiro que a própria aletheia imprime manda remover a persistência e tirar
// o bit de privilégio. Contra um arquivo imutável, esses comandos devolvem
// "operação não permitida" — como root — e quem não sabe do atributo conclui
// que o host está quebrado, não que está defendido.
//
// Por isso o primeiro passo deste achado é `chattr -i`, antes de qualquer
// remoção: sem ele, todo o resto do roteiro é inócuo.
var arquivoImutavel = check.Check{
	ID:       "integrity.immutable_flag",
	Ref:      "21",
	Title:    "arquivo travado por atributo de inode: a remoção falha até ele sair",
	Group:    "integrity",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Wtf:      true,
	FalsePositives: []string{
		"ENDURECIMENTO LEGÍTIMO usa exatamente isto: guia de hardening manda " +
			"`chattr +i` em /etc/passwd, /etc/shadow, /etc/resolv.conf e nos " +
			"arquivos de configuração que ninguém deveria alterar. Num host " +
			"endurecido de propósito, esses aparecem e estão certos",
		"`+a` em arquivo de LOG é a forma recomendada de impedir que rastro seja " +
			"apagado — ali o atributo é defesa, não ataque. Em binário é o contrário",
		"alguns instaladores e gerenciadores de configuração marcam arquivo " +
			"próprio como imutável para evitar edição acidental",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		semDono := caminhosSemDono(f)

		for i := range f.Atributos {
			a := &f.Atributos[i]
			if !a.Imutavel && !a.SoAnexa {
				continue // nodump sozinho não trava nada
			}

			quais := []string{}
			if a.Imutavel {
				quais = append(quais, "imutável (+i)")
			}
			if a.SoAnexa {
				quais = append(quais, "só-anexa (+a)")
			}

			ev := []string{
				a.Path + " está " + strings.Join(quais, " e "),
				"nem root altera ou remove sem tirar o atributo antes: qualquer " +
					"passo de limpeza sobre este arquivo FALHA até isso ser feito",
			}

			// O peso vem de o arquivo ser algo que ninguém empacotou. Config de
			// sistema travada é endurecimento; binário sem dono travado é
			// implante que se defende.
			sev := check.SevWarn
			if semDono[a.Path] {
				sev = check.SevCritical
				ev = append(ev, "e nenhum pacote reivindica este arquivo: travar o "+
					"que a distribuição não entregou é defesa de implante, não "+
					"endurecimento de sistema")
			} else {
				ev = append(ev, "o arquivo tem dono de pacote — guia de endurecimento "+
					"manda travar /etc/passwd e /etc/shadow assim, e ali o atributo "+
					"é defesa")
			}
			if motivo := arquivoComPoder(f, a.Path); motivo != "" {
				sev = check.SevCritical
				ev = append(ev, motivo)
			}

			fd := self.F(sev, a.Path, "", ev...)
			fd.NextSteps = []string{
				// PRIMEIRO passo, e a ordem é o ponto do check: sem isto, o resto
				// do roteiro devolve "operação não permitida" e parece defeito.
				"sudo chattr -i -a " + a.Path + "   # ANTES de qualquer remoção: sem isto o resto falha",
				"sudo cp " + a.Path + " \"$IR/\"   # a amostra, antes de qualquer coisa (runbook §6)",
				"`lsattr` no diretório inteiro: quem trava um arquivo costuma travar mais de um",
			}
			r.Findings = append(r.Findings, fd)
		}
		return r
	},
}
