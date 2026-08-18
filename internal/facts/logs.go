package facts

import (
	"sort"
	"strconv"
	"strings"

	"github.com/lex0c/aletheia/internal/env"
)

// Logs do sistema (runbook §21).
//
// Apagar log é das primeiras coisas que se faz depois de entrar, e das mais
// difíceis de acusar sem errar. A tentação é reportar arquivo VAZIO — e ela
// morre na primeira medição: numa debian:12 recém-criada, `wtmp`, `btmp`,
// `faillog` e `lastlog` estão TODOS com zero bytes. Vazio é o estado normal de
// sistema novo, e um check baseado nisso acusaria toda instalação limpa.
//
// O que sobra é estrutural, e são duas coisas:
//
//	buraco na rotação   logrotate produz sequência CONTÍGUA. Ele apaga o mais
//	                    ANTIGO quando passa do limite, nunca o do meio — então
//	                    x.1 e x.3 existirem sem x.2 é remoção manual
//	sessão sem registro alguém está logado AGORA e o histórico de login está
//	                    vazio: as duas coisas não podem ser verdade juntas
//
// Nenhuma das duas depende de julgar se um arquivo "deveria" ter conteúdo.

// ArquivoDeLog descreve um arquivo em /var/log.
type ArquivoDeLog struct {
	Path string `json:"path"`
	// Base é o nome sem o sufixo de rotação: `auth.log.2.gz` vira `auth.log`.
	Base string `json:"base"`
	// Geracao é o número da rotação; zero é o arquivo vivo.
	Geracao int   `json:"generation"`
	Tamanho int64 `json:"size"`
}

const maxLogDirs = 200

func collectLogs(f *Facts, e *env.Env) {
	var anda func(dir string, prof int)
	visitados := 0
	anda = func(dir string, prof int) {
		if prof > 3 || visitados > maxLogDirs {
			return
		}
		visitados++
		for _, ent := range e.ReadDirNames(dir) {
			p := dir + "/" + ent
			if e.IsDir(p) {
				anda(p, prof+1)
				continue
			}
			fi, err := e.Lstat(p)
			if err != nil || !fi.Mode().IsRegular() {
				continue
			}
			base, ger := separaRotacao(ent)
			f.Logs = append(f.Logs, ArquivoDeLog{
				Path: p, Base: dir + "/" + base, Geracao: ger, Tamanho: fi.Size(),
			})
		}
	}
	if e.IsDir("/var/log") {
		anda("/var/log", 0)
	}
	sort.Slice(f.Logs, func(i, j int) bool {
		if f.Logs[i].Base != f.Logs[j].Base {
			return f.Logs[i].Base < f.Logs[j].Base
		}
		return f.Logs[i].Geracao < f.Logs[j].Geracao
	})
}

// separaRotacao devolve o nome vivo e o número da geração.
//
// As formas que o logrotate produz:
//
//	auth.log        geração 0, o arquivo vivo
//	auth.log.1      geração 1
//	auth.log.2.gz   geração 2, comprimida
//
// O `.gz` sai antes do número: sem isso `auth.log.2.gz` viraria base própria e
// a sequência nunca teria buraco nenhum, porque cada geração seria um arquivo
// diferente.
// maxGeracoes é o teto de gerações que uma série de rotação pode ter. O
// logrotate mais generoso guarda algumas dezenas; acima disso o número veio do
// nome do arquivo, não da realidade.
const maxGeracoes = 400

func separaRotacao(nome string) (string, int) {
	n := nome
	for _, suf := range []string{".gz", ".xz", ".bz2", ".zst"} {
		n = strings.TrimSuffix(n, suf)
	}
	i := strings.LastIndex(n, ".")
	if i <= 0 {
		return n, 0
	}
	ger, err := strconv.Atoi(n[i+1:])
	if err != nil || ger <= 0 {
		return n, 0
	}
	return n[:i], ger
}

// BuracosNaRotacao devolve as sequências com geração faltando NO MEIO.
//
// O logrotate apaga o mais ANTIGO quando passa do limite configurado, então uma
// sequência normal é um prefixo contíguo: 0,1,2,3. Faltar o fim é rotação
// funcionando; faltar o meio é alguém tendo removido um arquivo.
func (f *Facts) BuracosNaRotacao() map[string][]int {
	porBase := map[string][]int{}
	for i := range f.Logs {
		l := &f.Logs[i]
		porBase[l.Base] = append(porBase[l.Base], l.Geracao)
	}

	out := map[string][]int{}
	for base, gers := range porBase {
		sort.Ints(gers)
		maior := gers[len(gers)-1]
		if maior == 0 {
			continue
		}
		tem := map[int]bool{}
		for _, g := range gers {
			tem[g] = true
		}
		// Do 1 até o maior presente: o que faltar no meio foi removido. A
		// geração 0 não entra — um arquivo vivo ausente é outra história, e
		// distribuição nenhuma garante que ele exista.
		// TETO: `maior` sai de um Atoi do sufixo de um NOME DE ARQUIVO, e um
		// `touch /var/log/x.500000000` derrubava o processo por falta de
		// memória — exit 2, que a frota lê como comprometimento. Rotação de
		// verdade não passa de algumas dezenas de gerações.
		if maior > maxGeracoes {
			continue
		}
		var faltam []int
		for g := 1; g < maior; g++ {
			if !tem[g] {
				faltam = append(faltam, g)
			}
		}
		if len(faltam) > 0 {
			out[base] = faltam
		}
	}
	return out
}
