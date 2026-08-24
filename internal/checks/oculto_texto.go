package checks

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

func init() { check.Register(textoOculto) }

// textoOculto — runbook §13 (anti-forense).
//
// A pergunta é uma só, e ela é sobre a LEITURA e não sobre a execução:
//
//	o que o operador lê é o que está ali?
//
// Duas formas, com o mesmo propósito e alvos diferentes:
//
//	NO CAMINHO   um caractere INVISÍVEL no nome faz dois arquivos se lerem
//	             iguais. `index<U+200D>.php` ao lado de `index.php` é
//	             indistinguível em qualquer terminal, em qualquer `ls`, em
//	             qualquer captura de tela de post-mortem. Quem remover "o
//	             webshell" remove o arquivo errado.
//
//	NO CONTEÚDO  uma sequência de escape de terminal faz o `cat` mostrar
//	             menos do que o arquivo tem. Um `\x1b[2J` no meio de um
//	             `.bashrc` limpa a tela e deixa visível só a última linha —
//	             que o invasor escreve parecendo um cabeçalho gerado.
//
// # Por que isto é um check, e não só uma sanitização de saída
//
// O relatório já escapa esses caracteres na impressão (report/sanitize.go), e
// isso protege a saída DESTA ferramenta. Não protege o operador, que passa o
// dia inteiro no `ls`, no `cat` e no `grep` — e é ali que a decisão é tomada.
//
// A ferramenta ver e não DIZER seria o pior dos dois mundos: ela teria a
// informação e a gastaria em não ser enganada sozinha.
//
// # Por que a superfície é estreita de propósito
//
// A varredura não caminha filesystem atrás de nome esquisito. Ela olha o
// conjunto que os coletores JÁ trouxeram — o que executa, o que algum gatilho
// dispara, o que carrega privilégio, o código servido. É a mesma escolha do
// coletor de propriedade: a pergunta útil não é "todo arquivo do host", é "o
// que está no caminho da execução".
var textoOculto = check.Check{
	ID:       "antiforense.hidden_text",
	Ref:      "13",
	Title:    "caractere invisível ou sequência de escape: o que se lê não é o que está lá",
	Group:    "persist",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Wtf:      true,
	FalsePositives: []string{
		"NOME COM ACENTO, CJK OU EMOJI NÃO DISPARA, e a distinção é o check " +
			"inteiro: o que conta é caractere de FORMATAÇÃO invisível (categoria " +
			"Cf do Unicode — zero-width, joiner, marca de direção) e caractere de " +
			"controle. `relatório-2026.php` e `文档.py` são nomes legítimos e " +
			"passam",
		"CR ISOLADO em arquivo de configuração acontece por acidente: um arquivo " +
			"editado no Windows e copiado para o host tem `\\r\\n` em toda linha. " +
			"O fim de linha `\\r\\n` é IGNORADO de propósito; o que dispara é o CR " +
			"no MEIO da linha, que não é fim de linha nenhum",
		"gerador de saída colorida que escreve seu próprio log pode deixar " +
			"sequência ANSI num arquivo. Ela quase nunca cai em arquivo que o " +
			"sistema EXECUTA, que é o único conjunto olhado aqui",
		"a superfície é o que os coletores já trouxeram — o que executa, o que " +
			"um gatilho dispara, o que carrega privilégio, o código servido. Um " +
			"arquivo de dados com nome enganoso, fora desse conjunto, NÃO é " +
			"procurado",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		visto := map[string]bool{}

		// METADE UM: o NOME.
		for _, c := range caminhosNoCaminhoDaExecucao(f) {
			if visto[c.path] {
				continue
			}
			runas := invisiveisEm(c.path)
			if len(runas) == 0 {
				continue
			}
			visto[c.path] = true

			ev := []string{
				"o caminho tem caractere invisível: " + strings.Join(runas, " "),
				"forma escapada: " + escapar(c.path),
				"em qualquer `ls`, `cat` ou captura de tela ele se lê como um nome " +
					"comum — a diferença não tem como aparecer",
				"origem: " + c.onde,
			}
			sev := check.SevWarn
			// O GÊMEO é o que fecha a intenção. Um nome invisível sozinho é
			// esquisito; um nome invisível AO LADO do arquivo com o nome limpo
			// é o disfarce montado, e quem remover "o webshell" remove o outro.
			if limpo := semInvisiveis(c.path); limpo != c.path && e.Exists(limpo) {
				sev = check.SevCritical
				ev = append(ev, "e EXISTE um arquivo com o nome limpo ao lado: "+limpo+
					" — são dois arquivos que se leem iguais, e é para isso que o "+
					"caractere está ali")
			}
			fd := self.F(sev, escapar(c.path), "", ev...)
			fd.Irreversible = true
			fd.NextSteps = []string{
				"`ls -b` e `ls --quoting-style=escape` mostram o nome como ele é",
				"`find <dir> -name '*' -print0 | xxd` desambigua os dois no byte",
				"copie o arquivo pelo INODE (`find -inum`), não pelo nome: colar o " +
					"nome do relatório pega o gêmeo errado",
			}
			r.Findings = append(r.Findings, fd)
		}

		// METADE DOIS: o CONTEÚDO de um arquivo que EXECUTA.
		for i := range f.Triggers {
			t := &f.Triggers[i]
			if t.EscapeN == 0 {
				continue
			}
			fd := self.F(check.SevCritical, t.File, "",
				t.File+":"+strconv.Itoa(t.EscapeN)+" tem sequência de escape de terminal",
				"num arquivo que EXECUTA ("+t.When+"), e não num log: quem der `cat` "+
					"vê MENOS do que o arquivo tem",
				"a forma conhecida é `# $(clear)` seguido de uma linha que parece "+
					"cabeçalho gerado: o escape limpa a tela e só a última linha "+
					"sobra à vista",
				"o `less`, o `vim` e o `cat -v` mostram tudo — o reflexo de quem "+
					"investiga é o `cat`, que é justamente o que ela engana",
			)
			fd.Quando, fd.QuandoFonte = t.ModUTC, "mtime do arquivo"
			fd.Irreversible = true
			fd.NextSteps = []string{
				"`cat -v " + check.Arg(t.File) + "` — o -v torna o escape visível",
				"leia o arquivo INTEIRO com o -v: o que o escape esconde está acima " +
					"da linha citada, não abaixo",
			}
			r.Findings = append(r.Findings, fd)
		}

		// A cobertura deste check é a UNIÃO das coberturas dos coletores que
		// formam o universo de caminhos. Declarar só duas delas diria "olhei
		// tudo" sobre uma varredura de SUID truncada ou um /etc/cron.d que
		// ninguém conseguiu listar — e um nome enganoso que ficou fora sairia
		// como ausência em vez de desconhecimento.
		for _, k := range []string{"startup", "codigo", "suid", "pkg", "cron", "unit"} {
			r.Partial = append(r.Partial, f.PersistDenied[k]...)
		}
		return r
	},
}

// caminhoOlhado é um caminho do conjunto avaliado, com de onde ele veio — a
// origem entra na evidência porque "há um nome invisível no host" e "há um nome
// invisível no ExecStart de uma unit" mandam o operador para lugares
// diferentes.
type caminhoOlhado struct{ path, onde string }

// caminhosNoCaminhoDaExecucao é a superfície, e ela é DERIVADA: nada aqui
// caminha filesystem. São os conjuntos que os coletores já trouxeram.
func caminhosNoCaminhoDaExecucao(f *facts.Facts) []caminhoOlhado {
	var out []caminhoOlhado
	add := func(p, onde string) {
		if p != "" {
			out = append(out, caminhoOlhado{p, onde})
		}
	}
	for i := range f.Processes {
		add(f.Processes[i].Exe, "executável de um processo em execução")
	}
	for i := range f.Ownership {
		add(f.Ownership[i].Path, "binário que roda ou que um gatilho executa")
	}
	for i := range f.Suid {
		add(f.Suid[i].Path, "arquivo que carrega privilégio")
	}
	for i := range f.Triggers {
		add(f.Triggers[i].File, "arquivo de gatilho ("+f.Triggers[i].When+")")
	}
	for i := range f.AlvosDeRoot {
		add(f.AlvosDeRoot[i].Caminho, "caminho que algo executa como root")
	}
	// Cron e unit entram DIRETO, e não só pela via de f.AlvosDeRoot, porque
	// aquele coletor tem duas condições que este check não pode herdar: ele
	// exige que a propriedade da árvore seja aferível (um rootfs extraído por
	// usuário comum o desliga inteiro) e a pergunta de propriedade exige base
	// de pacotes legível (num host rpm ela não é). Nas duas situações o
	// universo de caminhos ficava VAZIO — e vazio aqui é o falso "nenhum nome
	// enganoso", justamente num modo de análise (imagem montada) em que este
	// check é dos poucos que ainda valem.
	for i := range f.Cron {
		add(primeiroToken(f.Cron[i].Cmd), "comando agendado no cron ("+
			f.Cron[i].File+")")
	}
	for i := range f.Units {
		for _, ex := range f.Units[i].Exec {
			if len(ex.Targets) == 0 {
				add(primeiroToken(ex.Cmd), "unit "+f.Units[i].Name+" ("+ex.Key+")")
				continue
			}
			for _, t := range ex.Targets {
				add(t, "unit "+f.Units[i].Name+" ("+ex.Key+")")
			}
		}
	}
	for i := range f.CodigoSuspeito {
		add(f.CodigoSuspeito[i].Path, "código servido")
	}
	for i := range f.ConfigWeb {
		add(f.ConfigWeb[i].Path, "configuração do servidor web")
	}
	return out
}

// invisivel diz se a rune muda o que se LÊ sem ser lida. São duas famílias:
// formatação (Cf — zero-width, joiner, marca de direção) e controle.
//
// Acento, CJK e emoji NÃO entram, e essa é a linha inteira do check: nome com
// caractere de outra língua é nome legítimo, e acusá-lo seria acusar o mundo.
func invisivel(r rune) bool {
	return unicode.Is(unicode.Cf, r) || r < 0x20 || r == 0x7f
}

// invisiveisEm devolve os pontos de código invisíveis do caminho, nomeados.
func invisiveisEm(p string) []string {
	var out []string
	visto := map[rune]bool{}
	for _, r := range p {
		if !invisivel(r) || visto[r] {
			continue
		}
		visto[r] = true
		out = append(out, "U+"+strings.ToUpper(strconv.FormatInt(int64(r), 16))+
			nomeDoInvisivel(r))
	}
	return out
}

func nomeDoInvisivel(r rune) string {
	switch r {
	case 0x200b:
		return " (espaço de largura zero)"
	case 0x200c:
		return " (não-juntador de largura zero)"
	case 0x200d:
		return " (juntador de largura zero)"
	case 0x200e, 0x200f:
		return " (marca de direção)"
	case 0x202a, 0x202b, 0x202c, 0x202d, 0x202e:
		return " (sobreposição de direção: REORDENA o que o humano lê)"
	case 0xfeff:
		return " (marca de ordem de byte no meio do nome)"
	case 0x00ad:
		return " (hífen suave)"
	case 0x0a:
		return " (quebra de linha DENTRO do nome)"
	case 0x09:
		return " (tabulação dentro do nome)"
	}
	return ""
}

func semInvisiveis(p string) string {
	return strings.Map(func(r rune) rune {
		if invisivel(r) {
			return -1
		}
		return r
	}, p)
}

// escapar é a forma imprimível do caminho. O relatório já sanitiza na saída,
// mas o SUJEITO do achado precisa ser estável e comparável — a baseline compara
// strings, e um sujeito com byte invisível casa consigo mesmo e com mais nada.
//
// A forma é `<U+XXXX>`, com DELIMITADOR, e por isso ela não tem o problema de
// largura que o `\uXXXX` do report/sanitize.go teve: os sinais de maior e
// menor fecham a sequência, então cinco dígitos (as TAG characters de
// U+E0020) são tão inequívocos quanto quatro.
func escapar(p string) string {
	var b strings.Builder
	for _, r := range p {
		if invisivel(r) {
			fmt.Fprintf(&b, "<U+%04X>", r)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
