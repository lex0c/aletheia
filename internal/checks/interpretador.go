package checks

import (
	"sort"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

func init() { check.Register(hookDeInterpretador) }

// hookDeInterpretador — runbook §7.8, §7.6.
//
// O LD_PRELOAD de quem não é ELF.
//
// Esta ferramenta trata `/etc/ld.so.preload` e `LD_PRELOAD` como QUEBRA DE
// CONFIANÇA, e com razão: o loader injeta biblioteca em todo processo dinâmico,
// e a partir dali nenhum binário do host vale como prova. O que ela não fazia
// era a mesma pergunta a python, node, perl, ruby, java e bash — que têm o
// mesmo mecanismo, com outros nomes.
//
// A lacuna veio de um corpus externo (atomic-red-team), e foi de enquadramento:
// quem escreveu os checks e quem escreveu os cenários eram a mesma pessoa,
// olhando para o mesmo lado.
//
// O peso vem de DUAS perguntas, e nenhuma delas é o nome da variável:
//
//	ONDE foi definida    /etc/environment vale para toda sessão do host;
//	                     Environment= de unit vale para um serviço; environ de
//	                     processo vale para aquele processo
//	PARA ONDE aponta     alvo em diretório gravável por qualquer um, ou que
//	                     nenhum pacote reivindica, é outra conversa
var hookDeInterpretador = check.Check{
	ID:       "persist.interpreter_hook",
	Ref:      "7.8",
	Title:    "variável faz um interpretador carregar código de terceiro",
	Group:    "persist",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Optional: env.CapRoot,
	Wtf:      true,
	FalsePositives: []string{
		"AMBIENTE DE DESENVOLVIMENTO usa quase todas legitimamente: PYTHONPATH " +
			"apontando para o projeto, NODE_OPTIONS com --max-old-space-size, " +
			"PERL5LIB de um deploy com biblioteca própria. Em máquina de " +
			"desenvolvedor isto é rotina, e em servidor de produção é pergunta",
		"JAVA_TOOL_OPTIONS com `-javaagent` é a forma DOCUMENTADA de instalar " +
			"APM e instrumentação — Datadog, New Relic e OpenTelemetry usam " +
			"exatamente isto. O que separa é quem entregou o agente",
		"gerenciador de versão de linguagem (pyenv, nvm, rbenv) escreve essas " +
			"variáveis no perfil do usuário por desenho",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		if len(f.HooksInterp) == 0 {
			return r
		}
		semDono := caminhosSemDono(f)

		// Agrupado por FONTE: três variáveis no mesmo /etc/environment são uma
		// história, não três.
		porFonte := map[string][]facts.HookInterp{}
		var ordem []string
		for _, h := range f.HooksInterp {
			if _, visto := porFonte[h.Fonte]; !visto {
				ordem = append(ordem, h.Fonte)
			}
			porFonte[h.Fonte] = append(porFonte[h.Fonte], h)
		}
		sort.Strings(ordem)

		for _, fonte := range ordem {
			hs := porFonte[fonte]
			sort.Slice(hs, func(i, j int) bool { return hs[i].Key < hs[j].Key })

			var ev []string
			global := false
			pior := check.SevWarn
			for _, h := range hs {
				linha := h.Key + "=" + h.Value
				if h.Value == "" {
					linha = h.Key + " (valor não legível)"
				}
				ev = append(ev, linha+" — "+facts.MotivoDoHook(h.Key))
				if h.Global {
					global = true
				}
				// O alvo é o que decide. Um caminho que ninguém empacotou, ou
				// que mora em diretório gravável por qualquer um, não é
				// configuração de deploy.
				for _, alvo := range facts.CaminhosDoValor(h.Value) {
					if semDono[alvo] {
						pior = check.SevCritical
						ev = append(ev, "e aponta para "+alvo+", que nenhum pacote reivindica")
						continue
					}
					if _, gravavel := suspectDir(alvo); gravavel {
						pior = check.SevCritical
						ev = append(ev, "e aponta para "+alvo+", em diretório gravável por qualquer um")
					}
				}
			}

			if global {
				pior = check.SevCritical
				ev = append(ev, "e está em arquivo lido a cada sessão: vale para TODO "+
					"processo daquele interpretador no host, não para um serviço só")
			}

			fd := self.F(pior, fonte, "", ev...)
			fd.NextSteps = []string{
				"leia o ALVO antes de remover a variável: é ele que executa, e é a amostra",
				"`grep -rn " + hs[0].Key + " /etc /home` — quem define uma costuma definir mais de uma",
				"em servidor de produção, pergunte que deploy precisa disto: a resposta " +
					"costuma ser nenhuma",
			}
			r.Findings = append(r.Findings, fd)
		}
		return r
	},
}
