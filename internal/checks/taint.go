package checks

import (
	"strconv"
	"strings"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

func init() { check.Register(taintSemDono) }

// taintSemDono — runbook §35.3.
//
// # A propriedade que faz este check existir
//
// O taint do kernel é MONOTÔNICO: só se acrescenta bit, nunca se remove.
// Escrever em /proc/sys/kernel/tainted faz OR com o valor atual, e nem o root
// limpa sem reiniciar. Um módulo que se carrega, suja o kernel e depois se
// desencadeia da lista para sumir deixa o bit para trás — e o bit fica.
//
// Quase nada mais nesta ferramenta tem essa propriedade. Log se apaga, arquivo
// se remove, processo termina, histórico se desliga; cada um desses tem um
// check de anti-forense justamente porque some. O bit de taint não some.
//
// # E o achado não é o estado
//
// Kernel sujo é o normal: driver de vídeo, VirtualBox, qualquer coisa vinda de
// DKMS. Medido num desktop real — Manjaro com nvidia —, bits 12 e 13 ligados e
// quatro módulos exibindo as duas letras. Acusar o estado acusaria esse host,
// e não há nada errado com ele.
//
// O achado é a ATRIBUIÇÃO que falta: o kernel registra que um módulo fez algo,
// e nenhum módulo carregado admite ter feito. Ou ele foi removido depois — que
// é o que se faz para não deixar rastro —, ou ele continua lá e não aparece na
// lista, que é a definição de rootkit.
var taintSemDono = check.Check{
	ID:       "kernel.taint_unexplained",
	Ref:      "35.3",
	Title:    "o kernel registra um módulo que nenhum módulo carregado admite",
	Group:    "kernel",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive,
	Requires: env.CapProcfs,
	Optional: env.CapRoot,
	Wtf:      true,
	FalsePositives: []string{
		"MÓDULO CARREGADO E DESCARREGADO no mesmo boot deixa exatamente esta " +
			"forma, e existe legitimamente: instalador que testa um driver, " +
			"DKMS reconstruindo depois de atualizar o kernel, VirtualBox que " +
			"descarrega os módulos ao fechar",
		"quando o módulo AINDA ESTÁ carregado a marca tem dono e não vira " +
			"achado — foi assim que um desktop com nvidia (bits O e E ligados, " +
			"quatro módulos assumindo) saiu limpo",
		"qualquer root pode SUJAR o taint escrevendo no /proc/sys/kernel/tainted, " +
			"e ninguém pode limpar. Dá para fabricar este achado; não dá para " +
			"apagá-lo",
		"varredura de DENTRO de contêiner: o kernel é do host, e a marca não é " +
			"deste contêiner. Nesse caso o achado sai como INFO",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		if !f.Taint.Lido {
			r.Partial = append(r.Partial, f.Partial["taint"]...)
			return r
		}
		if !f.Taint.ListaLida {
			// Sem a lista de módulos não existe atribuição, e sem atribuição
			// este check não tem pergunta: acusar aqui seria acusar todo host
			// com driver de vídeo.
			r.Partial = append(r.Partial, f.Partial["taint"]...)
			return r
		}

		// De dentro de um contêiner o kernel é do host: dá para LER a marca e
		// não dá para agir sobre ela. Dizer é obrigação; acusar seria atribuir
		// ao contêiner uma propriedade que não é dele.
		rebaixa := f.Host.EmContainer

		if sem := facts.TaintSemDono(f.Taint.Bits, f.Taint.Modulos); len(sem) > 0 {
			var letras []string
			var motivos []string
			forcado := false
			for _, m := range sem {
				letras = append(letras, string(m.Letra))
				motivos = append(motivos, string(m.Letra)+": "+m.Significado)
				if m.Letra == 'F' {
					forcado = true
				}
			}

			sev := check.SevWarn
			if forcado {
				// Carregar módulo à força passa por cima da checagem de versão
				// do kernel, e a maioria das distribuições nem compila essa
				// opção. Quem faz isso está contornando uma recusa.
				sev = check.SevCritical
			}
			if rebaixa {
				sev = check.SevInfo
			}

			ev := append([]string{
				"o kernel está marcado com " + strings.Join(letras, "") +
					" e nenhum dos " + strconv.Itoa(len(f.Taint.Modulos)) +
					" módulo(s) carregado(s) com marca assume essa(s) letra(s)",
			}, motivos...)
			ev = append(ev,
				"a marca não pode ser apagada sem reiniciar: ela é prova de que "+
					"aconteceu, mesmo que o módulo já não esteja mais lá",
				"módulos que assumem alguma marca agora: "+nz(listaModulos(f.Taint.Modulos), "nenhum"))
			if rebaixa {
				ev = append(ev, "esta varredura roda DENTRO de um contêiner, e o kernel "+
					"é o do host: a marca é real e não é deste contêiner — varra o host")
			}

			fd := self.F(sev, "taint "+strings.Join(letras, ""), "", ev...)
			fd.NextSteps = []string{
				"`dmesg | grep -iE 'module verification failed|loading out-of-tree|" +
					"module .* tainted'` nomeia o módulo, enquanto o buffer o tiver",
				"compare a lista de módulos com a de um host irmão do mesmo papel",
				"procure o arquivo do módulo fora do lugar: /tmp, /dev/shm, " +
					"/var/tmp e o home de quem tem sudo",
			}
			r.Findings = append(r.Findings, fd)
		}

		// Remoção FORÇADA é caso próprio: nenhum módulo pode admiti-la, porque
		// quem a sofreu não está mais carregado. Exige CONFIG_MODULE_FORCE_UNLOAD,
		// que a maioria das distribuições não compila — quando o bit aparece,
		// alguém rodou `rmmod -f` num kernel preparado para isso.
		if facts.TaintTem(f.Taint.Bits, 'R') {
			sev := check.SevWarn
			if rebaixa {
				sev = check.SevInfo
			}
			fd := self.F(sev, "taint R", "", []string{
				"R: " + facts.SignificadoDeTaint('R'),
				"remover módulo à força exige uma opção de kernel que a maioria " +
					"das distribuições não compila, e ignora a contagem de uso: é " +
					"o que se faz para tirar da lista o que estava carregado",
				"a marca continua depois que o módulo some — é ela que denuncia " +
					"a remoção",
			}...)
			fd.NextSteps = []string{
				"`dmesg | grep -i rmmod` e o histórico de shell de quem tem sudo",
			}
			r.Findings = append(r.Findings, fd)
		}

		// O kernel ter MORRIDO não é achado por si: driver com defeito produz
		// oops. Mas exploit de kernel que falha produz exatamente isto, e a
		// data do oops ao lado da janela do incidente muda a leitura.
		if facts.TaintTem(f.Taint.Bits, 'D') {
			r.Findings = append(r.Findings, self.F(check.SevInfo, "taint D", "", []string{
				"D: " + facts.SignificadoDeTaint('D'),
				"driver com defeito produz oops, e é a causa comum — mas exploit " +
					"de kernel que FALHA produz a mesma marca",
				"`dmesg` ou o journal do boot mostram a pilha e o instante",
			}...))
		}
		return r
	},
}

func listaModulos(ms []facts.ModuloTaint) string {
	var out []string
	for i, m := range ms {
		if i >= 8 {
			out = append(out, "…")
			break
		}
		out = append(out, m.Nome+"("+m.Letras+")")
	}
	return strings.Join(out, " · ")
}
