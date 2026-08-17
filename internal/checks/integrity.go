package checks

import (
	"strings"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

func init() { check.Register(semDonoDePacote) }

// semDonoDePacote — runbook §24.
//
// O discriminador que faltava, e o que ele resolve:
//
// Uma cadeia de invasão completa saía `RESULT: OK` porque cada peça, isolada,
// parecia legítima — payload em `/usr/local/sbin` com nome de serviço do
// systemd, unit habilitada com comando limpo, cron apontando para o mesmo
// binário. Nenhum check de CAMINHO dispara ali, porque o caminho é de sistema.
//
// A pergunta que separa é outra: ALGUM pacote reivindica este arquivo? Serviço
// legítimo vem de pacote. O que não vem, alguém pôs à mão — e "alguém" precisa
// ter nome.
//
// A severidade sai do DIRETÓRIO, e a diferença é real:
//
//	/usr/bin, /sbin, /usr/lib   território do gerenciador de pacotes. Binário
//	                            sem dono ali é anomalia forte
//	/usr/local, /opt            existem PARA software fora do pacote. Sem dono
//	                            ali é a norma, e o sinal vem da correlação com
//	                            persistência (correlate.persistence_redundant)
var semDonoDePacote = check.Check{
	ID:       "integrity.no_package_owner",
	Ref:      "24",
	Title:    "binário em execução ou agendado que nenhum pacote reivindica",
	Group:    "integrity",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Optional: env.CapRoot,
	Wtf:      true,
	FalsePositives: []string{
		"/usr/local e /opt existem PARA software instalado fora do gerenciador " +
			"de pacotes: runtime de linguagem, agente de fornecedor, binário " +
			"compilado no próprio host. Sai como aviso justamente por isso — em " +
			"servidor de produção cada um deles tem dono e motivo",
		"software instalado por outro gerenciador (snap, flatpak, pip, npm, cargo) " +
			"não aparece na base do sistema e cai aqui legitimamente",
		"a pergunta é feita só sobre o que está RODANDO ou AGENDADO. Um binário " +
			"largado em disco e nunca executado não entra — isso é a §8, e ela " +
			"exige varredura de filesystem",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result

		for i := range f.Ownership {
			o := &f.Ownership[i]
			if o.Owned {
				continue
			}
			// Caminho gravável já tem check próprio (§8): contar o mesmo
			// binário duas vezes infla a triagem sem acrescentar informação.
			if _, gravavel := suspectDir(o.Path); gravavel {
				continue
			}

			sev := check.SevWarn
			nota := "está em diretório de instalação manual (/usr/local, /opt): " +
				"sem dono ali é a norma, e o que dá sinal é ele também estar " +
				"persistido — veja correlate.persistence_redundant"
			if dirDePacote(o.Path) {
				sev = check.SevCritical
				nota = "está em diretório do GERENCIADOR DE PACOTES: tudo ali " +
					"deveria vir de um pacote, e este arquivo não vem de nenhum"
			}

			ev := []string{
				o.Path,
				"nenhum pacote reivindica este arquivo (base: " + f.Pkg.Kind + ")",
				nota,
				"visto em: " + strings.Join(o.Onde, " · "),
			}

			fd := self.F(sev, o.Path, "", ev...)
			fd.Irreversible = true
			fd.NextSteps = []string{
				"pergunte QUEM instalou antes de tratar como achado: instalação " +
					"manual legítima é comum",
				"sudo cp " + o.Path + " \"$IR/\"   # a amostra, antes de qualquer coisa (runbook §6)",
				"com o binário em mãos, a §5.10 diz a FAMÍLIA — e o nome muda a " +
					"prioridade do resto da resposta",
			}
			r.Findings = append(r.Findings, fd)
		}

		// "Não pude perguntar" nunca pode sair igual a "ninguém reclamou".
		r.Partial = append(r.Partial, f.PersistDenied["pkg"]...)
		return r
	},
}

// dirDePacote são as árvores que pertencem ao gerenciador de pacotes. O que
// está fora delas — /usr/local, /opt — é território de instalação manual, e o
// runbook trata os dois de forma diferente por bons motivos.
func dirDePacote(p string) bool {
	for _, d := range []string{
		"/bin/", "/sbin/", "/lib/", "/lib64/",
		"/usr/bin/", "/usr/sbin/", "/usr/lib/", "/usr/lib64/", "/usr/libexec/",
		"/usr/share/",
	} {
		if strings.HasPrefix(p, d) {
			return true
		}
	}
	return false
}
