package checks

import (
	"sort"
	"strconv"
	"strings"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

func init() { check.Register(fronteiraDeContainer) }

// fronteiraDeContainer — runbook §24, §3.5.
//
// Este check nasceu de um FALSO POSITIVO, e é o que sobrou depois de corrigi-lo.
//
// A pergunta central da ferramenta — "que pacote entregou este binário?" — não
// tem resposta útil para processo de contêiner: o host vê o exe dele dentro da
// camada de imagem, e a base de pacotes está certa em não reivindicar. Medido,
// um servidor com trinta contêineres produzia trinta avisos.
//
// Suprimir seria a resposta errada: escape de contêiner é real, e camada de
// imagem é exatamente onde um invasor gosta de estar. Então em vez de calar,
// pergunta-se OUTRA coisa — e aí duas fontes passam a poder se contradizer, que
// é a forma de sinal que esta ferramenta prefere:
//
//	cgroup diz contêiner + exe em camada de imagem   normal, e sai da pergunta
//	                                                 de propriedade do host
//	cgroup diz HOST      + exe em camada de imagem   ALGUÉM EXECUTOU CONTEÚDO
//	                                                 DE IMAGEM FORA DO CONTÊINER
//	cgroup diz contêiner + exe fora de toda camada   o processo alcança o
//	                                                 filesystem do host
//
// O segundo é o achado forte. Um binário só chega a `/var/lib/docker/overlay2/`
// dentro de uma imagem; executá-lo com o cgroup do host significa que alguém
// pegou conteúdo de imagem e rodou fora dela, e não há caminho legítimo comum
// para isso.
var fronteiraDeContainer = check.Check{
	ID:       "proc.container_boundary",
	Ref:      "38.1",
	Title:    "processo cruza a fronteira entre contêiner e host",
	Group:    "proc",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive,
	Requires: env.CapProcfs,
	Optional: env.CapRoot,
	Wtf:      true,
	FalsePositives: []string{
		"FERRAMENTA DE DEPURAÇÃO cruza a fronteira por desenho: `nsenter`, " +
			"`docker exec` com o binário montado de fora, e depurador anexado a " +
			"processo de contêiner aparecem exatamente com esta forma",
		"MONTAGEM DE VOLUME faz um processo de contêiner executar binário que " +
			"não está em camada nenhuma — é a forma normal de rodar uma " +
			"aplicação montada do host, e é comum em desenvolvimento",
		"runtime de contêiner rodando de caminho não-padrão, ou storage-driver " +
			"configurado fora do diretório de fábrica, desloca a árvore inteira " +
			"e faz a comparação perder o referencial",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result

		// De DENTRO de um contêiner não há fronteira a cruzar: todo processo
		// visível está do mesmo lado dela.
		//
		// Isto é INFO e não lacuna de cobertura, e a distinção custou uma
		// regressão para ficar clara. Marcar parcial fazia TODA varredura feita
		// dentro de contêiner sair incompleta e com exit 1 — inclusive a de um
		// contêiner perfeitamente limpo.
		//
		// A regra desta ferramenta é que "não consegui olhar" nunca pode sair
		// como "não encontrei". Aqui não é nenhum dos dois: é "não há o que
		// olhar DENTRO DO ESCOPO desta execução". Uma varredura feita dentro de
		// um contêiner fala sobre aquele contêiner, e dentro dele a pergunta
		// não existe — nada se perde. Reivindicar lacuna seria inventar uma.
		if f.Host.EmContainer {
			r.Findings = append(r.Findings, self.F(check.SevInfo, "escopo", "",
				"a varredura está DENTRO de um contêiner, e fala sobre ele",
				"a fronteira contêiner/host não é visível daqui: todo processo que "+
					"aparece está do mesmo lado dela",
				"as perguntas sobre o KERNEL — módulo carregado sem arquivo, marca "+
					"de taint, programa eBPF — são sobre o host: o contêiner "+
					"compartilha o kernel dele, e daqui elas não têm resposta",
				"para perguntar sobre o HOST, rode a ferramenta no host",
			))
			return r
		}

		var forasteiros, vazados []*facts.Process
		emContainer := 0
		for i := range f.Processes {
			p := &f.Processes[i]
			if p.Self || p.Vanished || p.Exe == "" || p.ExeDeleted || p.ExeMemfd {
				continue
			}
			naCamada := facts.EmCamadaDeImagem(p.Exe)
			switch {
			case p.Container == "" && naCamada:
				forasteiros = append(forasteiros, p)
			case p.Container != "" && !naCamada:
				emContainer++
				vazados = append(vazados, p)
			case p.Container != "":
				emContainer++
			}
		}

		// O CASO FORTE: conteúdo de imagem executado fora do contêiner.
		for _, p := range forasteiros {
			fd := self.F(check.SevCritical, "pid="+strconv.Itoa(p.PID), "",
				"exe="+p.Exe,
				"o binário está dentro do armazenamento de um runtime de contêiner, "+
					"e o cgroup deste processo é do HOST: ele foi executado FORA do "+
					"contêiner a que a imagem pertence",
				"cgroup="+cgroupCurto(p.Cgroup),
				"um binário só chega ali dentro de uma imagem; rodá-lo com o cgroup "+
					"do host não tem caminho legítimo comum",
			)
			fd.NextSteps = []string{
				"sudo cp " + p.Exe + " \"$IR/\"   # a amostra, antes de qualquer coisa (runbook §6)",
				"`docker ps -a --no-trunc` e cruze o hash do caminho com a imagem de origem",
				"quem tem acesso ao socket do docker tem root no host (runbook §7.9): " +
					"confira o grupo `docker` antes de concluir que houve escape",
			}
			r.Findings = append(r.Findings, fd)
		}

		// O caso fraco, e é INFORMATIVO: volume montado é a forma normal disto.
		if len(vazados) > 0 {
			sort.Slice(vazados, func(i, j int) bool { return vazados[i].PID < vazados[j].PID })
			var ex []string
			for _, p := range vazados {
				if len(ex) >= 5 {
					ex = append(ex, "…")
					break
				}
				ex = append(ex, "pid="+strconv.Itoa(p.PID)+" "+p.Exe)
			}
			fd := self.F(check.SevInfo, strconv.Itoa(len(vazados))+" processos", "",
				"processo de contêiner executando binário que não está em camada de imagem",
				strings.Join(ex, " · "),
				"a causa comum é VOLUME MONTADO do host, que é o jeito normal de rodar "+
					"aplicação em desenvolvimento — vira pergunta quando o alvo é "+
					"binário de sistema em vez de código de aplicação",
			)
			r.Findings = append(r.Findings, fd)
		}

		// E o inventário, que é o que dá tamanho ao que ficou de fora da
		// pergunta de propriedade. Sem esta linha, "cobertura completa" com
		// trinta processos não perguntados seria meia verdade.
		if emContainer > 0 {
			r.Findings = append(r.Findings, self.F(check.SevInfo,
				strconv.Itoa(emContainer)+" processos", "",
				"processos de contêiner neste host, por runtime: "+resumoDeRuntimes(f),
				"o binário deles vem de camada de imagem, e a pergunta \"que pacote do "+
					"host entregou isto?\" não se aplica — por isso eles ficam FORA "+
					"do §24, e a exclusão está declarada na cobertura",
				"para varrer o que roda DENTRO deles, aponte a ferramenta para a imagem: "+
					"`aletheia scan --root` sobre o rootfs exportado (runbook §35.6)",
			))
		}
		return r
	},
}

func resumoDeRuntimes(f *facts.Facts) string {
	n := map[string]int{}
	for i := range f.Processes {
		if rt := f.Processes[i].Container; rt != "" {
			n[rt]++
		}
	}
	var rts []string
	for rt := range n {
		rts = append(rts, rt)
	}
	sort.Strings(rts)
	var out []string
	for _, rt := range rts {
		out = append(out, rt+"="+strconv.Itoa(n[rt]))
	}
	return strings.Join(out, " ")
}

// cgroupCurto encurta o caminho para caber na evidência sem perder o que
// identifica.
func cgroupCurto(cg string) string {
	if len(cg) <= 72 {
		return cg
	}
	return cg[:36] + "…" + cg[len(cg)-32:]
}
