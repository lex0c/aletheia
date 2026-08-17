package checks

import (
	"strings"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

func init() { check.Register(baseDePacotesAdulterada) }

// baseDePacotesAdulterada — runbook §24.
//
// ESTE CHECK PROTEGE A DEFESA PRINCIPAL DA FERRAMENTA.
//
// Cinco checks se apoiam em "nenhum pacote reivindica este binário": o §24, os
// dois de rede por origem, o SUID e o alvo de gatilho. Todos caem juntos com
// uma linha, e ela não exige construir pacote nenhum:
//
//	echo /usr/local/sbin/implante >> /var/lib/dpkg/info/coreutils.list
//
// A lista do dpkg é texto puro e gravável por root. Quem já é root para
// instalar o implante já é root para escrever nela — e foi medido: com essa
// linha, um implante SUID com unit de systemd e cron `@reboot` saía com
// "RESULT: OK, nenhum indicador coberto disparou".
//
// O que chama atenção é ONDE a reivindicação cai. A FHS reserva /usr/local ao
// administrador local, e a política do Debian proíbe que um pacote escreva ali.
//
// MAS A PREMISSA FORTE É FALSA, e foi medido: o Manjaro entrega
// `lightdm-settings` e `xflock4` em /usr/local/bin, empacotados. "Distribuição
// nenhuma instala ali" é política do Debian, não regra universal — a versão
// anterior deste comentário afirmava isso e rendeu três críticos num host limpo.
//
// Então a reivindicação sozinha é AVISO. Ela vira crítica quando está fazendo
// trabalho: o arquivo tem bit setuid, ou algum mecanismo de persistência aponta
// para ele. Aí a linha na base não é o hábito da distribuição — é o que faz o
// implante desaparecer da pergunta de propriedade.
var baseDePacotesAdulterada = check.Check{
	ID:       "integrity.pkgdb_tampered",
	Ref:      "24",
	Title:    "a base de pacotes reivindica arquivo onde distribuição nenhuma instala",
	Group:    "integrity",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Wtf:      true,
	FalsePositives: []string{
		"DISTRIBUIÇÃO DE VERDADE FAZ ISSO: o Manjaro entrega lightdm-settings e " +
			"xflock4 em /usr/local/bin, empacotados. A regra é política do Debian, " +
			"não da FHS inteira — por isso a reivindicação sozinha é aviso, e só " +
			"vira crítica quando o arquivo também é setuid ou está persistido",
		"pacote CONSTRUÍDO NA CASA instala em /usr/local com frequência, e o " +
			"time reconhece o pacote pelo nome",
		"alguns pacotes de terceiro (fora do repositório da distribuição) " +
			"instalam em /opt e criam links em /usr/local. /opt NÃO entra nesta " +
			"lista justamente por isso",
		"LIMITE: isto detecta a adulteração GROSSEIRA, que é a que se faz com " +
			"um `echo`. Quem construir um pacote de verdade, instalando em " +
			"/usr/bin, não aparece aqui — e derrota os cinco checks que dependem " +
			"de propriedade. Fechar isso exige verificar ASSINATURA do pacote",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		for i := range f.PkgEstranho {
			c := &f.PkgEstranho[i]
			ev := []string{
				c.Path,
				"declarado como pertencente a um pacote em " + c.File,
				"a FHS reserva /usr/local ao administrador local, e a lista do " +
					"gerenciador é texto puro e gravável por root — acrescentar uma " +
					"linha é como se derrota a pergunta 'que pacote entregou este " +
					"binário', da qual cinco checks desta ferramenta dependem",
			}
			// A reivindicação sozinha pode ser o hábito da distribuição. Ela vira
			// crítica quando está FAZENDO TRABALHO: escondendo um binário que tem
			// poder ou que alguém persistiu.
			sev := check.SevWarn
			if motivo := reivindicacaoComPoder(f, c.Path); motivo != "" {
				sev = check.SevCritical
				ev = append(ev, motivo)
			} else {
				ev = append(ev, "nenhum mecanismo de persistência aponta para este "+
					"arquivo e ele não tem bit setuid — pode ser o hábito da "+
					"distribuição, que existe (o Manjaro empacota em /usr/local)")
			}
			fd := self.F(sev, c.Path, "", ev...)
			fd.Irreversible = true
			fd.NextSteps = []string{
				"trate TODA resposta de propriedade deste host como não confiável: " +
					"a base foi editada, e é ela que responde por cinco checks",
				"`dpkg -V` e o md5sums do pacote citado dizem se o resto da base " +
					"também foi mexido",
				"o ctime de " + c.File + " data a edição (runbook §9)",
				"sudo cp " + c.Path + " \"$IR/\"   # a amostra, antes de qualquer coisa (runbook §6)",
			}
			r.Findings = append(r.Findings, fd)
		}
		r.Partial = append(r.Partial, f.PersistDenied["pkg"]...)
		return r
	},
}

// reivindicacaoComPoder diz se a linha estranha está escondendo algo que
// importa. É o que separa o hábito da distribuição da adulteração.
func reivindicacaoComPoder(f *facts.Facts, p string) string {
	for i := range f.Suid {
		if f.Suid[i].Path == p {
			return "e o arquivo tem bit SETUID: a linha na base está escondendo " +
				"um binário que dá privilégio"
		}
	}
	for i := range f.Units {
		for _, ex := range f.Units[i].Exec {
			if strings.HasPrefix(ex.Cmd, p) {
				return "e uma unit de systemd (" + f.Units[i].Name + ") executa este " +
					"arquivo: a linha na base está escondendo um alvo de persistência"
			}
		}
	}
	for i := range f.Cron {
		if strings.HasPrefix(f.Cron[i].Cmd, p) {
			return "e um agendamento (" + f.Cron[i].File + ") executa este arquivo: " +
				"a linha na base está escondendo um alvo de persistência"
		}
	}
	return ""
}
