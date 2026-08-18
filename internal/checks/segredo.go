package checks

import (
	"sort"
	"strconv"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

func init() { check.Register(credencialEmArquivo) }

// credencialEmArquivo — runbook §23.
//
// É o que um invasor procura PRIMEIRO depois de entrar, e o que define até onde
// ele vai a partir daqui. Uma chave de nuvem no home do usuário de deploy vale
// mais que qualquer implante: com ela não é preciso voltar ao host.
//
// O achado é INVENTÁRIO, pelo mesmo motivo do `known_hosts`: a ferramenta não
// sabe quais credenciais são esperadas, e toda aplicação tem alguma. Julgar
// produziria falso positivo em cada host que serve alguma coisa.
//
// O que ela diz com precisão é o alcance — e uma coisa objetiva a mais:
// permissão que deixa OUTROS lerem um arquivo de segredo é fato, não opinião. A
// partir dali o segredo não depende mais da conta dona, e qualquer processo do
// host o alcança.
//
// E o conteúdo NÃO é lido, deliberadamente. Carregar segredo para dentro da
// memória da ferramenta — e daí para dentro de um relatório que vai para um
// ticket — cria exposição em vez de reduzir.
var credencialEmArquivo = check.Check{
	ID:       "cred.secret_file",
	Ref:      "12.3",
	Title:    "credencial em arquivo: até onde este host alcança",
	Group:    "priv",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Optional: env.CapRoot,
	Wtf:      false, // é alcance, não incêndio
	FalsePositives: []string{
		"não é achado: é o raio de alcance, para dimensionar a §23. Servidor de " +
			"aplicação TEM credencial de aplicação — é assim que ele funciona",
		"permissão frouxa tem explicação legítima quando o arquivo é lido por " +
			"vários serviços do mesmo host, e o desenho previu isso",
		"sem root, o home de outros usuários é ilegível e as credenciais deles " +
			"não aparecem — a cobertura diz quando foi esse o caso",
		"o CONTEÚDO não é lido: a ferramenta não sabe se a credencial é válida, " +
			"nem para onde ela dá acesso. Isso é trabalho de quem opera",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		if len(f.Segredos) == 0 {
			return r
		}

		// Ordem estável e agrupada por conta: o operador reconhece contas.
		idx := make([]int, len(f.Segredos))
		for i := range idx {
			idx[i] = i
		}
		sort.Slice(idx, func(a, b int) bool {
			return f.Segredos[idx[a]].Path < f.Segredos[idx[b]].Path
		})

		for _, i := range idx {
			s := &f.Segredos[i]
			ev := []string{
				s.Path + " — " + s.Tipo,
				"modo " + s.Modo,
			}
			sev := check.SevManual
			if s.Aberto {
				// Isto é objetivo: a partir daqui o segredo não depende mais da
				// conta dona, e qualquer processo do host o alcança.
				sev = check.SevWarn
				ev = append(ev, "e é LEGÍVEL por grupo ou por outros: o segredo deixou "+
					"de depender da conta dona, e qualquer processo do host o alcança")
			}
			if s.ModUTC != "" {
				ev = append(ev, "modificada em "+s.ModUTC)
			}
			ev = append(ev, "o alcance dela é o que um invasor herda ao chegar aqui "+
				"(runbook §23)")

			fd := self.F(sev, s.Path, "", ev...)
			fd.NextSteps = []string{
				"se o host for tratado como comprometido, esta credencial também é: " +
					"rotacione antes de reconectar qualquer coisa",
				"o registro de uso da nuvem diz se ela foi USADA de outro lugar, e é " +
					"a única fonte que responde isso (runbook §10.4)",
			}
			r.Findings = append(r.Findings, fd)
		}

		// Uma linha de resumo vale mais que a lista para dimensionar: é o
		// número que separa um servidor de aplicação de um host de automação
		// com acesso a tudo.
		if abertos := contaAbertos(f.Segredos); abertos > 0 {
			r.Findings[0].Evidence = append(r.Findings[0].Evidence,
				strconv.Itoa(abertos)+" de "+strconv.Itoa(len(f.Segredos))+
					" credenciais estão legíveis além da conta dona")
		}
		r.Partial = append(r.Partial, f.PersistDenied["ssh"]...)
		return r
	},
}

func contaAbertos(ss []facts.Segredo) int {
	var n int
	for i := range ss {
		if ss[i].Aberto {
			n++
		}
	}
	return n
}
