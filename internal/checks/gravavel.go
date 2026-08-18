package checks

import (
	"strconv"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

func init() { check.Register(rootExecutaGravavel) }

// rootExecutaGravavel — runbook §36.4.
//
// # A rota mais comum, e a que menos gente enxerga
//
// O runbook chama de "a rota mais comum na prática — e a mais fácil de
// corrigir". Não é bug de software, é permissão: um script citado num cron de
// root, com dono `deploy`, É root para quem for `deploy`. Sem exploit, sem
// vulnerabilidade, sem nada para estudar — basta editar o arquivo e esperar o
// próximo minuto.
//
// A ferramenta já sabia quem executa o quê (cron, unit, gatilho) e já sabia
// olhar modo de arquivo (SUID, §25). O que faltava era CRUZAR as duas coisas, e
// é o cruzamento que produz o achado.
//
// # Quatro formas, e a mais comum não é a óbvia
//
//	dono não é root         o dono reescreve quando quiser. É a que mais aparece
//	grupo grava             e o grupo não é o do root
//	todos gravam            o caso óbvio, e o mais raro em host de verdade
//	o arquivo NÃO EXISTE    e o diretório é gravável: quem criar primeiro ganha
//
// A última é a mais silenciosa: um `ExecStartPre=` apontando para um script que
// alguém removeu deixa a vaga aberta, e nada no host reclama.
var rootExecutaGravavel = check.Check{
	ID:       "priv.root_runs_writable",
	Ref:      "36.4",
	Title:    "root executa um arquivo que outra pessoa pode reescrever",
	Group:    "priv",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	// Sem root, /root e os crontabs de outros usuários não são lidos: a lista
	// de coisas que root executa sai menor, e a cobertura precisa dizer isso.
	Optional: env.CapRoot,
	Wtf:      true,
	FalsePositives: []string{
		"DEPLOY COM DONO DE APLICAÇÃO é a forma legítima mais comum: o time " +
			"publica em /opt/app com dono `app`, e uma unit de sistema roda " +
			"aquilo. Continua sendo escalada — quem tiver a conta `app` vira " +
			"root —, mas foi assim de propósito, e a correção é de permissão",
		"o dono não-root pode ser uma conta SEM login (nologin, sem senha): a " +
			"rota existe, mas exige antes comprometer aquele serviço",
		"diretório com sticky bit (/tmp) permite criar e não permite substituir " +
			"o arquivo de outro dono — a nota diz quando é esse o caso",
		"DIRETÓRIO fica de fora: `run-parts /etc/cron.daily` executa o que estiver " +
			"lá dentro, e um diretório de deploy com dono da aplicação é a norma " +
			"em qualquer servidor — a rota existe, e acusá-la produziria ruído em " +
			"série. O que este check afirma é sobre ARQUIVO",
		"a leitura é do que está ESCRITO na linha de comando: PATH hijack e " +
			"wildcard injection (as duas outras rotas da §36.4) não aparecem " +
			"aqui, porque exigiriam adivinhar o PATH de um processo que ainda " +
			"não existe",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		for i := range f.AlvosDeRoot {
			a := &f.AlvosDeRoot[i]
			quem := a.QuemGrava()
			if quem == "" {
				continue
			}

			// A severidade separa "o dono é outra conta" de "qualquer um
			// escreve". A segunda não precisa de nenhum passo anterior: um
			// usuário sem privilégio nenhum já vira root no próximo minuto.
			sev := check.SevWarn
			if a.Existe && a.Modo&0o002 != 0 && !a.DirSticky {
				sev = check.SevCritical
			}

			ev := []string{
				quem,
				a.Origem + " em " + a.Onde + " manda executar isto COMO ROOT",
			}
			if a.Existe {
				ev = append(ev, "modo="+modoOctal(a.Modo)+" uid="+numero(a.UID)+
					" gid="+numero(a.GID))
			} else {
				ev = append(ev, "o caminho não existe agora: a execução falha "+
					"em silêncio até alguém criar o arquivo")
			}
			if a.DirGravavel() {
				d := "e o diretório também é gravável por quem não é root"
				if a.DirSticky {
					d += " — com sticky bit, então dá para criar, não para substituir o alheio"
				}
				ev = append(ev, d)
			}
			ev = append(ev, "não é vulnerabilidade de software: é permissão, e a "+
				"correção é dono root:root com modo 755 (runbook §36.4)")

			fd := self.F(sev, a.Caminho, "", ev...)
			fd.Ator = a.Caminho
			fd.NextSteps = []string{
				"quem é o dono, e ele deveria ser: stat -c '%U %G %a' " + a.Caminho,
				"sudo chown root:root " + a.Caminho + " && sudo chmod 755 " + a.Caminho,
				"o mesmo vale para o DIRETÓRIO e para tudo que o script chamar sem " +
					"caminho absoluto (runbook §36.4)",
			}
			r.Findings = append(r.Findings, fd)
		}
		// A lacuna vem do coletor: sem propriedade confiável, ele não coleta e
		// diz por quê. Repassar é o que transforma "nenhum achado" em "não deu
		// para perguntar".
		r.Partial = append(r.Partial, f.Partial["gravavel"]...)
		r.Partial = append(r.Partial, f.PersistDenied["cron"]...)
		return r
	},
}

func modoOctal(m uint32) string {
	s := "0"
	for i := 2; i >= 0; i-- {
		s += string(rune('0' + (m>>(uint(i)*3))&7))
	}
	return s
}

func numero(n int) string {
	if n < 0 {
		return "?"
	}
	return strconv.Itoa(n)
}
