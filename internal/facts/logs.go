package facts

import (
	"errors"
	"io/fs"
	"os"
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
	Geracao int `json:"generation"`
	// Datada diz que a rotação foi identificada pelo SUFIXO DE DATA do
	// logrotate (`dateext`, que produz `wtmp-20260801`) e não por contador.
	//
	// A distinção precisa viajar no dump porque as duas formas respondem
	// perguntas diferentes. Para "existe rotacionado ao lado?" — a guarda que
	// separa logrotate de antiforense — as duas servem igual, e era só isso
	// que faltava para o wtmp_cleared parar de acusar a família RHEL inteira.
	// Para "falta uma geração NO MEIO?" não servem: contador tem sucessor
	// definido, data não. Sem este campo, a série datada entrava no cálculo de
	// buraco como um monte de bases distintas com geração 0 e saía sem buraco
	// nenhum — silêncio com cara de resposta.
	Datada  bool  `json:"date_suffix,omitempty"`
	Tamanho int64 `json:"size"`
}

const maxLogDirs = 200

// maxLogArquivosInventario é o teto de ARQUIVOS do inventário, e ele existe
// porque maxLogDirs não era teto nenhum.
//
// Duzentos diretórios sem teto de arquivo é ilimitado: a lista de /var/log é
// escrita por quem tem root no alvo, e o threat model deste coletor É esse — o
// comentário de alvosDeLog já cita `touch /var/log/auth.log.{1..3000}` como
// caso medido. Meio milhão de arquivos vazios produzia meio milhão de
// ArquivoDeLog, meio milhão de entradas no dump e um milhão de syscalls, e o
// único teto da família agia DEPOIS de tudo isso, cortando a saída em 500.
//
// Vinte mil é uma ordem de grandeza acima de qualquer /var/log real e limita o
// que o inventário pode custar antes de qualquer decisão: 20 mil registros são
// cerca de 1 MB de fatos.
//
// Quando ele morde, o conjunto que sobrevive é o que a ordem do readdir
// entregou primeiro — arbitrário, e declarado como tal. Num host que NÃO o
// atinge, e é todo host real, o conjunto é o mesmo de sempre e a saída continua
// ordenada no fim: o drift não vê diferença.
const maxLogArquivosInventario = 20_000

func collectLogs(f *Facts, e *env.Env) {
	var anda func(dir string, prof int)
	visitados := 0
	truncou := false
	estourouArquivos := false
	expirou := false
	var ilegiveis []string
	var cortados []string

	anda = func(dir string, prof int) {
		if visitados > maxLogDirs {
			truncou = true
			return
		}
		if prof > 3 {
			return
		}
		visitados++

		// EM LOTES, e não ReadDirNamesErr.
		//
		// A versão anterior materializava o diretório inteiro — nomes, e depois
		// um ArquivoDeLog por nome — para só então algum teto agir. Contra um
		// diretório inflado de propósito, o teto que age depois da alocação
		// protege o tamanho da saída e não o custo de chegar nela.
		var subdirs []string
		err := e.ReadDirBatch(dir, func(ent fs.DirEntry) error {
			if len(f.Logs) >= maxLogArquivosInventario {
				estourouArquivos = true
				return env.ErrPararDeListar
			}
			if e.WalkExpired() {
				expirou = true
				return env.ErrPararDeListar
			}
			p := dir + "/" + ent.Name()

			// UM Lstat, e não um Stat mais um Lstat.
			//
			// A versão anterior perguntava e.IsDir(p) e DEPOIS e.Lstat(p): duas
			// syscalls por entrada, num laço cujo tamanho o alvo escolhe. O
			// Lstat responde as duas perguntas, e o Stat só volta a ser
			// necessário no caso raro em que a entrada é um symlink — que
			// continua sendo seguido, porque deixar de segui-lo mudaria o que
			// esta função enxerga.
			fi, err := e.Lstat(p)
			if err != nil {
				return nil
			}
			switch {
			case fi.IsDir():
				subdirs = append(subdirs, p)
			case fi.Mode()&os.ModeSymlink != 0:
				if e.IsDir(p) {
					subdirs = append(subdirs, p)
				}
			case fi.Mode().IsRegular():
				base, ger, datada := separaRotacao(ent.Name())
				f.Logs = append(f.Logs, ArquivoDeLog{
					Path: p, Base: dir + "/" + base, Geracao: ger,
					Datada: datada, Tamanho: fi.Size(),
				})
			}
			return nil
		})
		switch {
		case errors.Is(err, env.ErrDiretorioCortado):
			// O teto do próprio env mordeu antes do nosso: o diretório tem mais
			// de cem mil entradas. É lacuna pelo mesmo motivo que um diretório
			// ilegível é, e não pode virar "não havia mais nada ali".
			cortados = append(cortados, dir)
		case env.EhLacuna(err):
			// antiforense.log_rotation_gap e wtmp_cleared perguntam se alguém
			// APAGOU registro. Diretório de log ilegível produzia a mesma
			// observação — "não há log ali" — que apagar tudo.
			ilegiveis = append(ilegiveis, dir)
			return
		}
		// A recursão sai FORA do laço de listagem: descer com o descritor do
		// pai ainda aberto multiplica descritores pela profundidade, e o
		// diretório de log de um alvo pode ser fundo.
		//
		// E ela não acontece depois de o orçamento estourar: descer para
		// reencontrar o mesmo teto na primeira entrada de cada subdiretório
		// gasta o teto de DIRETÓRIOS sem inventariar nada.
		if estourouArquivos || expirou {
			return
		}
		for _, sub := range subdirs {
			anda(sub, prof+1)
		}
	}
	if e.IsDir("/var/log") {
		anda("/var/log", 0)
	}
	if n := len(ilegiveis); n > 0 {
		f.partial("logs", strconv.Itoa(n)+" diretório(s) de log não puderam ser "+
			"listados: o que há neles NÃO entrou no inventário, e buraco de rotação "+
			"não pode ser distinguido de diretório ilegível — "+amostraDe(ilegiveis))
	}
	if n := len(cortados); n > 0 {
		f.partial("logs", strconv.Itoa(n)+" diretório(s) de log passaram de "+
			strconv.Itoa(env.MaxEntradasPorDiretorio)+" entradas e foram lidos só "+
			"até ali: um diretório inflado é a forma barata de esconder um arquivo "+
			"entre cem mil — "+amostraDe(cortados))
	}
	if estourouArquivos {
		f.partial("logs", "o inventário parou em "+strconv.Itoa(maxLogArquivosInventario)+
			" arquivos: o que estiver além NÃO foi inventariado, e a seleção que "+
			"sobrou é a que o readdir entregou primeiro, não a mais recente")
	}
	if expirou {
		f.partial("logs", "a varredura de log parou pelo teto de TEMPO: o "+
			"inventário está incompleto, e buraco de rotação não pôde ser "+
			"distinguido de diretório não visitado")
	}
	if truncou {
		// O inventário de log alimenta o buraco de rotação (§10), e "nenhum
		// buraco" com a varredura cortada é a mesma frase que "não olhei". Sete
		// dos nove tetos desta coleta já declaravam; este e o de bibliotecas
		// mapeadas eram os dois que cortavam calados.
		f.partial("logs", "a varredura de diretórios de log parou em "+
			strconv.Itoa(maxLogDirs)+": o que estiver além NÃO foi inventariado, "+
			"e buraco de rotação lá dentro não pôde ser visto")
	}
	// A ORDEM PRECISA SER TOTAL, e (base, geração) não é.
	//
	// Toda rotação DATADA é geração 1, então `secure-20260801`,
	// `secure-20260810` e `secure-20260820` empatam nas duas chaves — e
	// sort.Slice não é estável. Enquanto a entrada vinha de ReadDir, que
	// ordenava por nome, o empate era desfeito do mesmo jeito toda vez. A
	// leitura em LOTES entrega na ordem do readdir, que muda a cada arquivo
	// criado no diretório, e aí o desempate passou a variar entre execuções.
	//
	// Isso vaza: antiforense.log_rotation_gap monta a evidência "presentes: ..."
	// percorrendo f.Logs, e uma evidência que muda de ordem sozinha faz o drift
	// acusar mudança onde não houve — sobre o host que ninguém tocou.
	sort.Slice(f.Logs, func(i, j int) bool {
		a, b := f.Logs[i], f.Logs[j]
		if a.Base != b.Base {
			return a.Base < b.Base
		}
		if a.Geracao != b.Geracao {
			return a.Geracao < b.Geracao
		}
		return a.Path < b.Path
	})
}

// amostraDe corta a lista para a mensagem: uma lacuna com duzentos caminhos
// dentro não é lida por ninguém.
func amostraDe(xs []string) string {
	if len(xs) > 3 {
		xs = xs[:3]
	}
	return strings.Join(xs, ", ")
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

// separaDataExt reconhece o sufixo de DATA do logrotate.
//
// `dateext` produz `<base>-YYYYMMDD` e é o padrão de fábrica da família RHEL:
// está no /etc/logrotate.conf do RHEL, Rocky, Alma, CentOS e Fedora. O parser
// só entendia contador, então `wtmp-20260801` virava base própria com geração
// zero — e a guarda que procura "tem rotacionado ao lado?" nunca casava. O
// efeito era um CRITICAL irreversível de antiforense.wtmp_cleared em qualquer
// jump host RHEL que rotacionasse o wtmp com sessão aberta, acusando o operador
// de ter limpado o histórico de login. Reproduz sem root.
//
// A validação é estreita de propósito: oito dígitos, e uma data plausível. Um
// `app-20250` ou um `backup-12345678` não viram rotação — inventar geração a
// partir de qualquer número atrás de um traço trocaria um falso positivo por
// outro.
func separaDataExt(n string) (string, bool) {
	i := strings.LastIndex(n, "-")
	if i <= 0 || len(n)-i-1 != 8 {
		return n, false
	}
	d := n[i+1:]
	for j := 0; j < len(d); j++ {
		if d[j] < '0' || d[j] > '9' {
			return n, false
		}
	}
	ano, _ := strconv.Atoi(d[:4])
	mes, _ := strconv.Atoi(d[4:6])
	dia, _ := strconv.Atoi(d[6:8])
	if ano < 1990 || ano > 2200 || mes < 1 || mes > 12 || dia < 1 || dia > 31 {
		return n, false
	}
	return n[:i], true
}

func separaRotacao(nome string) (string, int, bool) {
	n := nome
	for _, suf := range []string{".gz", ".xz", ".bz2", ".zst"} {
		n = strings.TrimSuffix(n, suf)
	}
	if base, ok := separaDataExt(n); ok {
		// Geração 1 é convenção: a série datada não tem ordinal, e o que os
		// consumidores perguntam por este número é "existe rotacionado?" — que
		// é verdade. Quem precisa da diferença lê Datada.
		return base, 1, true
	}
	i := strings.LastIndex(n, ".")
	if i <= 0 {
		return n, 0, false
	}
	ger, err := strconv.Atoi(n[i+1:])
	if err != nil || ger <= 0 {
		return n, 0, false
	}
	return n[:i], ger, false
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
		if l.Datada {
			continue // ver SeriesDatadas
		}
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
		//
		// TETO: `maior` sai de um Atoi do sufixo de um NOME DE ARQUIVO, e um
		// `touch /var/log/x.500000000` derrubava o processo por falta de
		// memória — exit 2, que a frota lê como comprometimento. Rotação de
		// verdade não passa de algumas dezenas de gerações.
		//
		// O teto DESCARTA A GERAÇÃO ABSURDA, e não a série.
		//
		// Antes ele fazia `continue` sobre a base inteira, e isso entregava ao
		// atacante um jeito barato de desligar o check: um `touch
		// /var/log/auth.log.401` ao lado de auth.log.1 e auth.log.3 fazia o
		// buraco REAL da geração 2 — a semana que ele apagou — deixar de ser
		// procurado. A defesa contra o custo virava a ferramenta de quem ela
		// devia pegar.
		if maior > maxGeracoes {
			var reais []int
			var absurdas int
			for _, g := range gers {
				if g <= maxGeracoes {
					reais = append(reais, g)
					continue
				}
				absurdas++
			}
			f.partial("logs", base+": "+strconv.Itoa(absurdas)+" arquivo(s) com "+
				"sufixo de geração acima de "+strconv.Itoa(maxGeracoes)+
				" foram DESCARTADOS da análise de rotação (rotação de verdade não "+
				"passa de algumas dezenas): o número saiu do nome do arquivo, que "+
				"o host escolhe")
			if len(reais) == 0 {
				continue
			}
			gers = reais
			maior = gers[len(gers)-1]
			if maior == 0 {
				continue
			}
			tem = map[int]bool{}
			for _, g := range gers {
				tem[g] = true
			}
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

// SeriesDatadas devolve as bases cuja rotação usa SUFIXO DE DATA.
//
// Elas ficam fora do BuracosNaRotacao, e a razão é que o método não se aplica —
// não que não haja o que achar. Um contador tem sucessor definido: entre o 1 e o
// 3, o 2 existiu e sumiu. Uma data não tem: entre `secure-20260801` e
// `secure-20260815` pode faltar uma semana apagada, ou o logrotate pode
// simplesmente não ter rodado ali (é o que `minsize` faz, e é o padrão do wtmp
// no RHEL). Derivar buraco de aritmética de datas trocaria um falso limpo por um
// falso positivo, e num check de antiforense o falso positivo custa a confiança
// no relatório inteiro.
//
// Então o que a ferramenta pode dizer com honestidade é: aqui eu não olhei por
// este método. Quem consome isto declara lacuna — o silêncio anterior afirmava
// cobertura completa sobre a família RHEL inteira, onde `dateext` é o padrão de
// fábrica, e a deleção que é pega no Debian era invisível no Rocky.
func (f *Facts) SeriesDatadas() []string {
	visto := map[string]bool{}
	var out []string
	for i := range f.Logs {
		if !f.Logs[i].Datada || visto[f.Logs[i].Base] {
			continue
		}
		visto[f.Logs[i].Base] = true
		out = append(out, f.Logs[i].Base)
	}
	sort.Strings(out)
	return out
}
