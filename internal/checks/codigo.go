package checks

import (
	"strconv"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

func init() { check.Register(codigoBackdoor) }

// codigoBackdoor — runbook §24, §16.
//
// A peneira de webshell. Um sink de execução aplicado a entrada de request —
// `echo \`$_REQUEST[0]\“, `eval($_POST[x])`, `system($_GET[cmd])` — é o padrão
// de maior sinal que existe em código servido: nenhum framework faz isso, e é a
// linha exata que um invasor acrescenta a um arquivo que já roda.
//
// A postura é a mesma do resto da ferramenta, e o check a diz em voz alta:
// PENEIRA, NÃO PROVA. Pega o webshell comum — a maioria dos reais é copiada de
// padrão conhecido — e erra o ofuscado a fundo, porque `ev`.`al` e cadeia de
// `chr()` derrotam regex. Um achado diz "leia este trecho", e o que dá peso não
// é o padrão sozinho: é o cruzamento com "este arquivo MUDOU", que sai do mtime.
//
// Por isso a data acompanha cada achado: um padrão num arquivo alterado na
// janela do incidente é outra conversa, e a janela do relatório o traz à tona.
var codigoBackdoor = check.Check{
	ID:       "app.code_backdoor",
	Ref:      "24",
	Title:    "padrão de backdoor em código servido (PHP/JS/Python)",
	Group:    "app",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Wtf:      true,
	FalsePositives: []string{
		"framework e template usam eval, base64_decode e system legitimamente — " +
			"por isso um sink SEM entrada de request sai como aviso (leia), não " +
			"como crítico. O crítico exige a co-ocorrência sink+entrada, que " +
			"quase não tem uso legítimo",
		"é PENEIRA, não prova: pega o webshell comum e ERRA o ofuscado a fundo " +
			"(`ev`.`al`, chr() em cadeia, decodificação empilhada). Um match é " +
			"'leia este trecho', não veredito",
		"árvore de dependência (vendor, node_modules) NÃO é varrida — o custo " +
			"de I/O é proibitivo e ela está em quase todo host —, então um shell " +
			"escondido ali passa. É limite conhecido, não lacuna do host; se " +
			"suspeitar, varra a árvore com um scan direcionado. Payload acima de " +
			"2 MB também fica de fora, e esse SIM a cobertura declara",
		"reconhecer por padrão é trivial de burlar. O que separa backdoor de " +
			"uso legítimo é o arquivo ter MUDADO — cruze com o mtime e com o " +
			"git",
		"três construções REBAIXAM de crítico para aviso, e cada uma é um " +
			"buraco declarado: (a) entrada presa a uma allowlist literal " +
			"(`switch` de `case` literais, `in_array` de lista fixa) — se a " +
			"lista incluir algo perigoso, o crítico não sai; (b) contaminação e " +
			"sink em FUNÇÕES diferentes do mesmo arquivo PHP, que é coincidência " +
			"de nome e não fluxo — a não ser por `global`/`use`, que o motor " +
			"segue; (c) crase dentro de string, que em PHP é aspa de " +
			"identificador de banco, não shell_exec. Fluxo por sessão, banco ou " +
			"variável de outro arquivo NÃO é seguido em caso nenhum",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		for i := range f.CodigoSuspeito {
			cs := &f.CodigoSuspeito[i]

			// A severidade do arquivo é a do seu match mais forte.
			maxTier := 0
			for _, m := range cs.Matches {
				if m.Tier > maxTier {
					maxTier = m.Tier
				}
			}
			// Tier 1 sozinho — um eval, um pickle.loads — aparece legitimamente
			// em quase todo código, e sai como INFO: observação para quem audita
			// a fundo (-vv), não alarme. Só a co-ocorrência sink+entrada (tier 2)
			// é crítica. Foi medido: num host de dev, tier 1 rendia 50 avisos e
			// zero deles era backdoor.
			sev := check.SevInfo
			if maxTier >= 2 {
				sev = check.SevCritical
			}

			// A evidência é só o SINAL: os matches, com linha e trecho. O título
			// já diz o que é, a severidade sai no marcador, e a caveat (PENEIRA)
			// e a guia (→) saem no bloco FP e nos próximos-passos — uma vez por
			// check, não repetidas em cada achado. O tier sai no rótulo do match
			// (um tier-1 diz "dispatch, não execução arbitrária" ali mesmo).
			var ev []string
			mostrados := cs.Matches
			if len(mostrados) > 6 {
				mostrados = mostrados[:6]
			}
			for _, m := range mostrados {
				ev = append(ev, cs.Path+":"+strconv.Itoa(m.Linha)+" — "+m.Regra+
					"\n      "+m.Trecho)
			}
			if len(cs.Matches) > len(mostrados) {
				ev = append(ev, "e mais "+strconv.Itoa(len(cs.Matches)-len(mostrados))+
					" linha(s) no mesmo arquivo")
			}

			fd := self.F(sev, cs.Path, "", ev...)
			if cs.ModUTC != "" {
				fd.Quando, fd.QuandoFonte = cs.ModUTC, "mtime do arquivo de código"
			}
			fd.NextSteps = []string{
				"leia o trecho: um sink sobre $_GET/$_POST/req/request roda o que o " +
					"atacante enviar",
				"o ctime do arquivo data quando a linha entrou, mesmo que o resto " +
					"pareça antigo",
				"se o diretório é um repo git, `git log -p -- " + check.Arg(cs.Path) +
					"` mostra o commit que a acrescentou — e `git diff` o que não foi " +
					"commitado",
				"procure o mesmo padrão nos outros hosts da frota: num só é " +
					"comprometimento, em vários pode ser código legítimo esquisito",
			}
			r.Findings = append(r.Findings, fd)
		}
		r.Partial = append(r.Partial, f.PersistDenied["codigo"]...)
		return r
	},
}
