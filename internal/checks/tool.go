package checks

import (
	"strconv"
	"strings"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
	"github.com/lex0c/aletheia/internal/tools"
)

func init() {
	check.Register(toolArtifact)
	check.Register(toolBinary)
}

// maxOndeporFamilia limita as ocorrências LISTADAS, não as contadas: vinte
// workers de rclone são um fato, e o número precisa aparecer.
const maxOndeporFamilia = 6

// O que estes dois checks são, e o que eles NÃO são.
//
// Eles reconhecem ferramenta pelo NOME — config em disco, nome de executável.
// Isso é o atalho da §5.10: o nome diz o que a ferramenta SABE FAZER, e isso
// redireciona a resposta inteira antes de qualquer engenharia reversa.
//
// Mas reconhecer pelo nome é trivial de burlar: renomear o binário derrota os
// dois. Por isso eles NÃO são a detecção primária — são o acelerador. Quem pega
// o implante renomeado é o check ESTRUTURAL, que olha a forma e não o nome:
//
//	correlate.revshell     fd 0,1,2 no mesmo socket
//	net.pivot              saída externa + saída interna
//	proc.kthread_disguise  cmdline vazio com exe existente
//	persist.unit_dropin    alguém acrescentou execução a uma unit alheia
//
// O cenário 71 existe justamente para provar isso: lá o binário se chama
// `systemd-netlinkd`, nenhum destes dois dispara, e o que sobrevive é o check
// de forma. Confundir as duas coisas levaria a "melhorar" a ferramenta
// engordando a lista de nomes — que é a estratégia que envelhece pior.

// toolArtifact — runbook §5.10, rota "nome de config".
//
// É a rota de maior alcance, e a única que funciona em IMAGEM MONTADA: a
// maioria dos implantes não usa variável de ambiente, usa arquivo de config —
// e disco é legível de fora, onde o kernel é o do analista (§35.6).
var toolArtifact = check.Check{
	ID:       "tool.artifact",
	Ref:      "5.10",
	Title:    "config de ferramenta conhecida presente em disco",
	Group:    "app",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Wtf:      true,
	FalsePositives: []string{
		"TODAS as famílias do catálogo são ferramentas legítimas de uso duplo. " +
			"tailscale, rclone, cloudflared e RMM rodam em produção por bons " +
			"motivos — o achado diz que a CAPACIDADE está presente, não que houve " +
			"abuso. Capacidade não é prova de uso (runbook §5.10)",
		"config órfã sobrevive à desinstalação: o diretório pode ser resto de " +
			"algo removido meses atrás. A data de modificação separa os dois casos",
		"reconhecer pelo NOME é trivial de burlar — renomear o binário derrota " +
			"este check. Ele é atalho, não detecção: quem pega o implante " +
			"renomeado é o check estrutural",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		porFamilia := map[string][]facts.ToolArtifact{}
		var ordem []string
		for _, a := range f.ToolArtifacts {
			if _, ok := porFamilia[a.Family]; !ok {
				ordem = append(ordem, a.Family)
			}
			porFamilia[a.Family] = append(porFamilia[a.Family], a)
		}

		for _, nome := range ordem {
			fam, ok := familyByName(nome)
			if !ok {
				continue
			}
			var caminhos []string
			for _, a := range porFamilia[nome] {
				caminhos = append(caminhos, a.Path)
			}
			ev := []string{
				"artefato em disco: " + strings.Join(caminhos, " · "),
				"assinatura de: " + fam.Name,
				fam.Nota,
			}
			fd := self.F(sevDoRisco(fam.Risk), nome, "", ev...)
			fd.NextSteps = []string{
				"LEIA a config: o destino, a conta e a chave estão nela, e valem " +
					"como IOC de frota melhor que hash (runbook §23)",
				"confirme com o time se alguém instalou isto de propósito antes de " +
					"tratar como achado",
			}
			r.Findings = append(r.Findings, fd)
		}
		// append e não atribuição: a atribuição aliasa o slice do Facts, e o
		// Facts é compartilhado por todos os checks.
		r.Partial = append(r.Partial, f.PersistDenied["artifact"]...)
		return r
	},
}

// toolBinary — runbook §5.10.
//
// O nome do executável, olhado em dois lugares que se complementam: o processo
// vivo e o `Exec=` das units. O segundo funciona em imagem montada e cobre o
// caso em que a ferramenta não está rodando AGORA mas roda no próximo boot.
var toolBinary = check.Check{
	ID:       "tool.binary",
	Ref:      "5.10",
	Title:    "executável de ferramenta conhecida em execução ou agendado",
	Group:    "app",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Optional: env.CapRoot,
	Wtf:      true,
	FalsePositives: []string{
		"as famílias são legítimas: um host que roda tailscale ou faz backup com " +
			"rclone dispara aqui todo dia, e está certo. O achado muda o ESCOPO da " +
			"investigação, não o veredito",
		"renomear o binário derrota este check por completo. Ele é o atalho da " +
			"§5.10, não a detecção — o implante renomeado é pego pela FORMA " +
			"(fd, direção, disfarce), não pelo nome",
		"sem root o exe de processo alheio é ilegível, e só a rota de unit responde",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		var ilegivel int

		// Uma linha por família, não uma por processo: cinco workers de rclone
		// são um fato, não cinco.
		type achado struct {
			onde  []string
			total int
			fam   tools.Family
		}
		porFamilia := map[string]*achado{}
		var ordem []string

		add := func(fam tools.Family, onde string) {
			a, ok := porFamilia[fam.Name]
			if !ok {
				a = &achado{fam: fam}
				porFamilia[fam.Name] = a
				ordem = append(ordem, fam.Name)
			}
			a.total++
			if len(a.onde) < maxOndeporFamilia {
				a.onde = append(a.onde, onde)
			}
		}

		for i := range f.Processes {
			p := &f.Processes[i]
			if p.Self || p.Vanished {
				continue
			}
			if p.ExeDenied {
				ilegivel++
				continue
			}
			if fam, ok := familyByBin(base(p.Exe)); ok {
				add(fam, "processo pid="+strconv.Itoa(p.PID)+" exe="+p.Exe)
			}
		}
		for i := range f.Units {
			u := &f.Units[i]
			for _, ex := range u.Exec {
				bin := strings.TrimLeft(firstToken(ex.Cmd), "-@+!:")
				if fam, ok := familyByBin(base(bin)); ok {
					add(fam, "unit "+u.Name+" ("+ex.Key+"="+bin+")")
				}
			}
		}

		for _, nome := range ordem {
			a := porFamilia[nome]
			ev := append([]string{
				"assinatura de: " + a.fam.Name,
				a.fam.Nota,
			}, a.onde...)
			if a.total > len(a.onde) {
				// Corte silencioso é a regra que o resto do código não quebra:
				// quem lê precisa saber que havia mais.
				ev = append(ev, "… e mais "+strconv.Itoa(a.total-len(a.onde))+
					" ocorrências não listadas")
			}
			fd := self.F(sevDoRisco(a.fam.Risk), nome, "", ev...)
			fd.NextSteps = []string{
				"a §5.10 com o nome em mãos muda a PRIORIDADE do resto da resposta",
				"se ninguém instalou isto, o próximo passo é a persistência (runbook §7), " +
					"não o processo",
			}
			r.Findings = append(r.Findings, fd)
		}
		if ilegivel > 0 {
			r.Partial = append(r.Partial, strconv.Itoa(ilegivel)+
				" processos com exe ilegível não foram avaliados")
		}
		// A rota de unit depende de ter conseguido LER as árvores de unit.
		r.Partial = append(r.Partial, f.PersistDenied["unit"]...)
		return r
	},
}

func familyByName(n string) (tools.Family, bool) {
	for _, f := range tools.All {
		if f.Name == n {
			return f, true
		}
	}
	return tools.Family{}, false
}

func familyByBin(bin string) (tools.Family, bool) {
	if bin == "" {
		return tools.Family{}, false
	}
	for _, f := range tools.All {
		for _, b := range f.Bins {
			if b == bin {
				return f, true
			}
		}
		// Sufixo variável: o Explorer do runZero se instala como
		// `runzero-agent-<uuid>`, e o uuid muda a cada organização. Casar só
		// nome inteiro passaria direto por ele em toda instalação real.
		for _, pre := range f.BinsPrefixo {
			if len(bin) > len(pre) && strings.HasPrefix(bin, pre) {
				return f, true
			}
		}
	}
	return tools.Family{}, false
}

func base(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}
