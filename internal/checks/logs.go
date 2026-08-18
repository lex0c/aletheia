package checks

import (
	"sort"
	"strconv"
	"strings"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

func init() {
	check.Register(rotacaoComBuraco)
	check.Register(sessaoSemRegistro)
}

// rotacaoComBuraco — runbook §21.
//
// Apagar log é das primeiras coisas que se faz depois de entrar, e das mais
// difíceis de acusar sem errar. A tentação é reportar arquivo VAZIO, e ela
// morre na primeira medição: numa debian:12 recém-criada, `wtmp`, `btmp`,
// `faillog` e `lastlog` estão TODOS com zero bytes. Vazio é o estado normal de
// sistema novo.
//
// O que resta é estrutural. O logrotate produz sequência CONTÍGUA e apaga o
// mais ANTIGO quando passa do limite — nunca o do meio. Então:
//
//	auth.log, auth.log.1, auth.log.3.gz     falta o .2, e ninguém o rotacionou
//	                                        para fora: alguém o removeu
//
// Não depende de julgar se um arquivo deveria ter conteúdo, e é por isso que
// funciona em host novo e em host de dez anos igual.
var rotacaoComBuraco = check.Check{
	ID:       "antiforense.log_rotation_gap",
	Ref:      "10",
	Title:    "falta uma geração no meio da rotação de log: alguém removeu",
	Group:    "persist",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Optional: env.CapRoot,
	Wtf:      true,
	FalsePositives: []string{
		"MUDANÇA DE CONFIGURAÇÃO produz buraco legítimo: baixar o `rotate` do " +
			"logrotate de 8 para 4 deixa gerações antigas órfãs, e mexer no " +
			"`compress` troca `.1` por `.1.gz` no meio da série",
		"log movido à mão para análise — o que se faz durante uma resposta a " +
			"incidente — deixa exatamente esta forma. Quem varre um host DEPOIS " +
			"de outra pessoa ter trabalhado nele vê o rastro dela",
		"aplicação que rotaciona o próprio log com esquema diferente do " +
			"logrotate (numeração invertida, data no nome) pode aparecer aqui",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		buracos := f.BuracosNaRotacao()
		if len(buracos) == 0 {
			return r
		}

		bases := make([]string, 0, len(buracos))
		for b := range buracos {
			bases = append(bases, b)
		}
		sort.Strings(bases)

		for _, base := range bases {
			faltam := buracos[base]
			var txt []string
			for _, g := range faltam {
				txt = append(txt, strconv.Itoa(g))
			}

			// Quantas presentes, para o operador ver a série inteira.
			var presentes []string
			for i := range f.Logs {
				if f.Logs[i].Base == base {
					presentes = append(presentes, baseDe(f.Logs[i].Path))
				}
			}

			ev := []string{
				base + ": falta a geração " + strings.Join(txt, ", "),
				"presentes: " + strings.Join(presentes, " "),
				"o logrotate apaga o mais ANTIGO quando passa do limite, nunca o do " +
					"meio — uma série com buraco no meio não vem de rotação",
			}
			// Log de autenticação é o primeiro que se apaga, e o mais caro de
			// perder: é ele que datava a entrada.
			if logDeAutenticacao(base) {
				ev = append(ev, "e é log de AUTENTICAÇÃO: é o que datava a entrada, "+
					"e o primeiro que se apaga")
			}

			sev := check.SevWarn
			if logDeAutenticacao(base) {
				sev = check.SevCritical
			}
			fd := self.F(sev, base, "", ev...)
			fd.Irreversible = true
			fd.NextSteps = []string{
				"o que estava naquela geração não volta daqui: procure no servidor " +
					"de log central, se houver (runbook §21)",
				"o ctime do diretório /var/log data a remoção (runbook §9)",
				"confirme com o time se alguém moveu log à mão durante a resposta — " +
					"isso produz a mesma forma",
			}
			r.Findings = append(r.Findings, fd)
		}
		return r
	},
}

// sessaoSemRegistro — runbook §21, §13.
//
// Duas coisas que não podem ser verdade ao mesmo tempo:
//
//	há sessão ABERTA agora          /run/utmp tem entrada viva
//	e o histórico de login vazio    /var/log/wtmp não tem registro nenhum
//
// Uma sessão aberta foi aberta em algum momento, e abrir sessão escreve nos
// dois arquivos. Se o segundo está vazio, ele foi zerado depois — e é o
// primeiro arquivo que se apaga, porque é o que data a entrada.
//
// O cruzamento é o que torna isto utilizável: `wtmp` vazio SOZINHO é o estado
// de toda instalação nova, e acusá-lo seria acusar todo contêiner do mundo.
var sessaoSemRegistro = check.Check{
	ID:       "antiforense.wtmp_cleared",
	Ref:      "12",
	Title:    "há sessão aberta e nenhum registro de login: o histórico foi zerado",
	Group:    "persist",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive,
	Requires: env.CapFilesystem,
	Optional: env.CapRoot,
	Wtf:      true,
	FalsePositives: []string{
		"ROTAÇÃO DO WTMP existe e é configurada em várias distribuições: logo " +
			"depois dela o arquivo vivo está vazio com sessão aberta, " +
			"legitimamente. O `wtmp.1` ao lado é o que separa os dois casos, e " +
			"por isso ele é procurado antes",
		"contêiner que herda /run do host, ou que monta wtmp de fora, pode " +
			"apresentar as duas metades sem relação entre si",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result

		var abertas, historico int
		var quem []string
		for i := range f.Logins {
			l := &f.Logins[i]
			if l.Falhou || l.Tipo != facts.TipoLoginUsuario {
				continue
			}
			if l.Agora {
				abertas++
				quem = append(quem, l.User)
				continue
			}
			historico++
		}
		if abertas == 0 || historico > 0 {
			return r
		}

		// A ROTAÇÃO produz exatamente esta forma, e por isso é procurada antes
		// de acusar: com um wtmp.1 ao lado, o arquivo vivo estar vazio é o
		// funcionamento normal do logrotate.
		for i := range f.Logs {
			if strings.Contains(f.Logs[i].Base, "wtmp") && f.Logs[i].Geracao > 0 {
				return r
			}
		}

		sort.Strings(quem)
		fd := self.F(check.SevCritical, "wtmp", "",
			strconv.Itoa(abertas)+" sessão(ões) aberta(s) agora ("+
				strings.Join(quem, " ")+") e NENHUM registro de login no histórico",
			"abrir sessão escreve nos dois arquivos: se o histórico está vazio, "+
				"ele foi zerado depois que a sessão abriu",
			"não há wtmp rotacionado ao lado, então isto não é o logrotate",
			"é o primeiro arquivo que se apaga, porque é o que datava a entrada",
		)
		fd.Irreversible = true
		fd.NextSteps = []string{
			"as sessões abertas AGORA são a única fonte que sobrou: registre " +
				"usuário, terminal e origem antes de qualquer coisa (runbook §13)",
			"o ctime de /var/log/wtmp data o zeramento (runbook §9)",
			"procure o mesmo horário no journal e no log da aplicação: apagar um " +
				"arquivo não apaga os outros",
		}
		r.Findings = append(r.Findings, fd)
		return r
	},
}

// logDeAutenticacao reconhece os logs que datam ENTRADA. Perder uma geração
// deles custa mais que perder qualquer outra: é o que responde "quando".
func logDeAutenticacao(base string) bool {
	n := baseDe(base)
	for _, a := range []string{"auth.log", "secure", "wtmp", "btmp", "lastlog", "sulog"} {
		if n == a {
			return true
		}
	}
	return false
}
