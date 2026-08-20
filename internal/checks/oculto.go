package checks

import (
	"sort"
	"strconv"
	"strings"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

func init() { check.Register(execEmDiretorioOculto) }

// execEmDiretorioOculto — runbook §8.
//
// Fecha um limite que estava escrito, em voz alta, no check de propriedade:
//
//	"um binário largado em disco e nunca executado não entra — isso é a §8,
//	 e ela exige varredura de filesystem"
//
// A varredura existe desde o check de privilégio, e percorre exatamente as
// árvores onde isto importa. O que faltava era olhar para o que ela já passava
// na frente.
//
// Diretório oculto SOZINHO é ruído: `.X11-unix`, `.ICE-unix` e `.font-unix` vêm
// de fábrica em qualquer desktop. Medido num host real, nenhum deles contém
// executável — e é esse cruzamento, não o nome, que separa o normal do resto.
//
// A restrição às árvores temporárias é o que torna o check utilizável: home de
// usuário é cheio de diretório oculto com executável dentro — `.local/bin`,
// `.cargo/bin`, `.nvm` — e tudo aquilo é legítimo. Em `/tmp` não é.
var execEmDiretorioOculto = check.Check{
	ID:       "path.hidden_exec",
	Ref:      "8",
	Title:    "executável escondido em diretório com ponto, sob árvore temporária",
	Group:    "integrity",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Wtf:      true,
	FalsePositives: []string{
		"instalador e sistema de build usam /tmp com diretório oculto por " +
			"conveniência, e alguns deixam script executável lá dentro. É o " +
			"falso positivo esperado, e ele some sozinho na próxima limpeza do " +
			"/tmp — o que um implante não faz",
		"sessão gráfica cria `.X11-unix`, `.ICE-unix` e `.font-unix`, e os três " +
			"guardam SOCKET e não executável: não caem aqui",
		"o achado é sobre o que está PARADO em disco. Se aquilo estiver rodando, " +
			"outros checks já falam por outro caminho, e a correlação junta os dois",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		if len(f.ExecOculto) == 0 {
			r.Partial = append(r.Partial, f.PersistDenied["suid"]...)
			return r
		}

		// Agrupado por DIRETÓRIO: cinco arquivos dentro de um esconderijo são
		// um esconderijo, não cinco achados.
		porDir := map[string][]string{}
		for _, p := range f.ExecOculto {
			// LastIndex devolve -1 quando não há barra, e `p[:-1]` é pânico —
			// que o motor converte em "o check falhou", perdendo o check
			// INTEIRO. Sem barra, o diretório é o próprio ponto corrente.
			i := strings.LastIndex(p, "/")
			if i < 0 {
				porDir["."] = append(porDir["."], p)
				continue
			}
			porDir[p[:i]] = append(porDir[p[:i]], p[i+1:])
		}

		dirs := make([]string, 0, len(porDir))
		for d := range porDir {
			dirs = append(dirs, d)
		}
		sort.Strings(dirs)

		for _, d := range dirs {
			arqs := porDir[d]
			sort.Strings(arqs)
			mostra := arqs
			if len(mostra) > 6 {
				mostra = append(mostra[:6:6], "…")
			}

			ev := []string{
				d + " tem " + strconv.Itoa(len(arqs)) + " executável(is): " +
					strings.Join(mostra, " "),
				"diretório com ponto não aparece num `ls` comum, e árvore " +
					"temporária é gravável por qualquer um: as duas coisas juntas " +
					"são escolha, não acaso",
				"o achado é sobre o que está PARADO em disco — nada aqui precisa " +
					"estar em execução para importar",
			}

			fd := self.F(check.SevWarn, d, "", ev...)
			fd.Irreversible = true
			fd.NextSteps = []string{
				"sudo cp -a " + check.Arg(d) + " \"$IR/\"   # o diretório inteiro, antes de qualquer coisa",
				"o ctime do diretório data a criação do esconderijo",
				"o conteúdo some no próximo boot se for tmpfs: preservar agora é a " +
					"única chance",
			}
			r.Findings = append(r.Findings, fd)
		}
		r.Partial = append(r.Partial, f.PersistDenied["suid"]...)
		return r
	},
}
