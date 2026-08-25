package facts

import (
	"bufio"
	"compress/gzip"
	"io"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lex0c/aletheia/internal/env"
)

// A leitura dos logs, e os tetos que a tornam segura (runbook §10).
//
// # Os tetos são de DUAS naturezas, e só uma é ajustável
//
// A janela e a quantidade de arquivos SELECIONADOS são escolha do operador: o
// `--logs-all` abre as duas. Bytes, linhas, eventos e descompressão NÃO são
// ajustáveis por ninguém, porque quem escolhe o conteúdo do /var/log de um host
// comprometido é o adversário:
//
//	touch /var/log/x{000001..999999}   um milhão de arquivos, custo zero
//	um .gz de 40 KB                    descomprime para 40 GB se assim for feito
//	uma linha de 8 GB                  sem newline, e o leitor acumula tudo
//
// Nenhum deles pode derrubar a varredura: um processo morto por falta de
// memória sai com status 2, que o contrato desta ferramenta define como
// "CRITICAL, indicador de alta confiança" — um defeito nosso faria a automação
// de frota marcar o host como comprometido.
//
// E todo teto que morde é DECLARADO com o nome dele. Truncar em silêncio diria
// "não achei" sobre o que não foi lido.

const (
	// maxLogArquivosPadrao é a SELEÇÃO normal; maxLogArquivosHard é o limite que
	// nem o --logs-all ultrapassa.
	maxLogArquivosPadrao = 40
	maxLogArquivosHard   = 500

	// maxLogBytesArquivo é quanto se lê de UM arquivo. Num auth.log de 300 MB,
	// os 8 MB da cauda são as horas mais recentes — e é a diferença entre eles e
	// o arquivo inteiro que o CobertoDesde existe para não esconder.
	maxLogBytesArquivo = 8 << 20
	// maxLogBytesTotal conta bytes JÁ DESCOMPRIMIDOS entregues ao parser, e é
	// decrementado DURANTE a leitura — não ao fim de cada arquivo. Ao fim,
	// cem .gz pequenos poderiam custar cem vezes o teto de descompressão antes
	// de o total ser consultado uma única vez.
	maxLogBytesTotal = 128 << 20

	maxLogLinhasArquivo = 200000
	maxEventosLog       = 5000
	// maxDescompactado é o teto por arquivo comprimido. O tamanho em disco é
	// escolhido por quem escreve o arquivo, e a razão entre ele e o conteúdo
	// também. Mesmo raciocínio do mtree do pacman em integrity.go.
	maxDescompactado = 64 << 20

	// cabecaDeLog é o pedaço do INÍCIO que se lê de um arquivo grande, e serve a
	// uma pergunta só: qual é a primeira data dele. É ela que responde onde a
	// geração anterior termina, e o buraco de rotação sai da comparação entre as
	// duas. Não é cobertura — ver LeituraDescontinua.
	cabecaDeLog = 64 << 10

	janelaPadraoDeLog = 7 * 24 * time.Hour
)

// familiasDeLog mapeia a PERGUNTA para os arquivos que a respondem em cada
// distribuição.
//
// Um mesmo caminho aparece em famílias diferentes de propósito: no Alpine o
// busybox syslogd manda tudo para /var/log/messages, e no RHEL o `messages`
// carrega sistema e kernel enquanto a autenticação vai para o `secure`. O
// arquivo é lido UMA vez e serve as famílias que o reivindicam.
var familiasDeLog = map[string][]string{
	"auth": {"/var/log/auth.log", "/var/log/secure", "/var/log/messages"},
	// ATENÇÃO ao /var/log/messages em `auth`: ele só vale quando NÃO há fonte
	// dedicada. Ver authComFonteDedicada.
	"syslog": {"/var/log/syslog", "/var/log/messages"},
	"kern":   {"/var/log/kern.log", "/var/log/messages"},
	"cron":   {"/var/log/cron.log", "/var/log/cron"},
	"audit":  {"/var/log/audit/audit.log"},
}

// orcamento é o custo COMPARTILHADO entre todos os arquivos desta coleta.
type orcamento struct {
	bytes int64
	// eventos é o que RESTA do teto, e ele é decrementado DURANTE a extração de
	// cada arquivo — não depois. Antes, leFonteDeLog montava os eventos do
	// arquivo INTEIRO e o chamador cortava em 5000: o dump saía limitado e a
	// alocação que o teto existe para impedir já tinha acontecido, sobre um
	// arquivo cujo conteúdo o adversário escolhe.
	eventos  int
	arquivos int
	estourou map[string]bool
}

func (o *orcamento) marca(teto string) { o.estourou[teto] = true }

// collectEventosDeLog é o coletor. Roda depois de collectLogs: o inventário de
// rotação dele é o que diz quais gerações existem ao lado de cada arquivo vivo.
func collectEventosDeLog(f *Facts, e *env.Env) {
	if e.SemLogs {
		// Desligado NÃO é lacuna: é escolha declarada de quem rodou. Emitir
		// Partial aqui poria uma lacuna permanente em todo `wtf`.
		f.LogEstado = LogDesativado
		return
	}

	loc, suposto := fusoDoAlvo(f, e)
	f.FusoDoAlvoLido = !suposto

	// NÃO HÁ MAIS JANELA TEMPORAL NA COLETA, e a razão é que toda forma dela
	// acabava decidindo NÃO ABRIR um arquivo a partir de um número que o alvo
	// escreve.
	//
	// A primeira versão comparava o mtime — metadado do host suspeito. A
	// segunda comparava o CONTEÚDO já lido, e parecia segura: só parava de abrir
	// gerações mais antigas depois de ler uma que terminava antes do horizonte.
	// Ela tinha três defeitos, e dois deles nem precisam de atacante:
	//
	//	dateext        toda rotação por DATA é geração 1, e a ordenação
	//	               secundária é por caminho — `secure-20260801` vem ANTES de
	//	               `secure-20260820`. A primeira examinada é a MAIS ANTIGA, e
	//	               parar ali pula justamente as mais novas. É o padrão de
	//	               fábrica da família RHEL
	//	série          uma família tem VÁRIAS séries de rotação: `auth` cobre
	//	               auth.log, secure e messages. Um `messages.1` velho fazia
	//	               `secure.1` não ser aberto, e um não é geração anterior do
	//	               outro
	//	ano inferido   o CobertoAte do syslog tradicional carrega ano deduzido da
	//	               âncora, que no rotacionado é o mtime. O mtime saiu da porta
	//	               da frente e voltava por esta
	//
	// O custo passa a ser controlado só pelos TETOS — arquivos, bytes, linhas,
	// eventos —, que são números da ferramenta. Trocar uma otimização de I/O por
	// uma semântica defensável é o negócio certo numa ferramenta cuja tese é
	// dizer "não olhei" em vez de "não aconteceu".
	f.LogJanelaTudo = e.LogsTudo

	tetoArquivos := maxLogArquivosPadrao
	if e.LogsTudo {
		tetoArquivos = maxLogArquivosHard
	}
	orc := &orcamento{bytes: maxLogBytesTotal, eventos: maxEventosLog, estourou: map[string]bool{}}
	parcialPorAcesso := false

	alvos, inacessiveis, descartados := alvosDeLog(f, e)
	if descartados > 0 {
		// O TETO RÍGIDO VALE SOBRE O QUE É CONSIDERADO, e não só sobre o que é
		// lido. Medido: um `touch -t 202001010000 /var/log/auth.log.{1..3000}`
		// põe 3001 fontes no dump — as 3000 velhas nem são abertas (ficam fora
		// da janela), e ainda assim cada uma vira uma entrada serializada. A
		// lista de arquivos de /var/log é escolhida pelo adversário, e nenhuma
		// lista que ele escolhe pode crescer sem limite dentro do artefato.
		//
		// O corte fica com as gerações MAIS NOVAS, que é onde mora o que
		// interessa numa triagem.
		f.partial("logeventos", strconv.Itoa(descartados)+" arquivo(s) de log "+
			"ficaram FORA da seleção pelo teto rígido de "+strconv.Itoa(maxLogArquivosHard)+
			": as gerações mais antigas não foram nem consideradas, e o que houver "+
			"nelas não pode ser afirmado nem negado")
		parcialPorAcesso = true
	}
	// FONTE QUE EXISTE E NÃO PÔDE SER VISTA é lacuna, e nunca escopo.
	//
	// Medido neste host: /var/log/audit é 0700 root. Sem root, o diretório não
	// LISTA, o audit.log não entra no inventário, e a coleta concluía "não há log
	// em texto neste host" — uma afirmação sobre um arquivo que ninguém
	// conseguiu olhar. É a mesma equivalência que a ferramenta recusa em todo
	// lugar, entrando por um caminho que só aparece sem privilégio.
	for _, ina := range inacessiveis {
		f.FontesDeLog = append(f.FontesDeLog, FonteDeLog{
			Path: ina.path, Familias: ina.familias, Estado: FonteIlegivel,
			Lacuna: ina.motivo,
		})
		f.partial("logeventos", ina.motivo)
		parcialPorAcesso = true
	}
	if len(alvos) == 0 && !parcialPorAcesso {
		// FORA DE ESCOPO, e não lacuna. Debian 12 e Fedora não instalam rsyslog:
		// não existe auth.log nem secure, e o journal é binário. Declarar lacuna
		// aqui derrubaria a cobertura de metade da frota para sempre — e uma
		// lacuna que nunca fecha deixa de ser lida. A pergunta não cabe neste
		// host; quem diz isso é logs.source_coverage, em INFO.
		f.LogEstado = LogForaDeEscopo
		return
	}

	visto := map[string]string{} // impressão do evento -> arquivo onde apareceu
	parcial := parcialPorAcesso
	parouEm, motivoDaParada := -1, ""
	for idx, a := range alvos {
		// TETO GLOBAL PARA A SELEÇÃO, e o que sobra NÃO some.
		//
		// Sair do laço sem registrar os alvos restantes fazia a família deles
		// sumir de FontesDeLog — e escopoDaFamilia decide que uma família existe
		// consultando exatamente isso. Um audit.log que esgotasse o orçamento
		// antes do auth.log tirava os checks de auth do DENOMINADOR, com a frase
		// "este host não tem log em TEXTO" sobre um arquivo que a coleta apenas
		// não alcançou. É a confusão entre escopo e lacuna que o resto do projeto
		// recusa — e aqui ela entrava por um `break`.
		switch {
		case orc.arquivos >= tetoArquivos:
			motivoDaParada = "o teto de " + strconv.Itoa(tetoArquivos) + " arquivos de log"
		case orc.bytes <= 0:
			motivoDaParada = "o teto de " + strconv.Itoa(maxLogBytesTotal>>20) + " MB de log lidos"
		case orc.eventos <= 0:
			motivoDaParada = "o teto de " + strconv.Itoa(maxEventosLog) + " eventos de log"
		case e.WalkExpired():
			motivoDaParada = "o teto de TEMPO da varredura"
		}
		if motivoDaParada != "" {
			parouEm = idx
			orc.marca(strings.TrimPrefix(motivoDaParada, "o teto "))
			break
		}
		orc.arquivos++

		// A ÂNCORA DO ANO, e ela não pode ser o mtime no arquivo VIVO.
		//
		// O arquivo vivo é o que está sendo escrito AGORA: a última linha dele é,
		// por definição, recente. Ancorar no mtime deixava o adversário escolher
		// o ano das linhas com um `touch -d '2025-08-24'` — e um ano a menos
		// empurra o achado para fora de `--since 7d`, onde o relatório passa a
		// mostrar só a contagem dele. O gate de abertura já foi corrigido; esta é
		// a segunda porta da mesma casa.
		//
		// Para o ROTACIONADO o mtime continua sendo a melhor pista que existe:
		// ele não é mais escrito, e a coleta não tem outra referência.
		ancora := a.mod
		if a.geracao == 0 {
			ancora = e.Now
		}
		ctx := contextoDeTempo{Loc: loc, Suposto: suposto, Ancora: ancora, Agora: e.Now}
		fonte, evs := leFonteDeLog(f, e, a, ctx, orc)
		// Lacuna num arquivo LIDO — capacidade do parser, montagem incompleta do
		// audit — também é coleta parcial. Sem isto, o fato de RESUMO dizia
		// `collected` enquanto o fato detalhado carregava a lacuna: dois fatos da
		// mesma coleta se contradizendo.
		if fonte.Estado != FonteLida || fonte.Lacuna != "" {
			parcial = true
		}
		for i := range evs {
			ev := evs[i]
			// DEDUPE ENTRE ARQUIVOS, nunca dentro do mesmo. Conforme a
			// configuração do rsyslog, a mesma mensagem do sshd cai em auth.log
			// E em syslog. Já duas linhas idênticas DENTRO de um arquivo são
			// duas ocorrências de verdade — num arranque de força bruta a
			// quarenta tentativas por segundo elas são idênticas mesmo, e
			// colapsá-las apagaria a campanha.
			imp := impressaoDeEvento(&ev)
			if onde, ja := visto[imp]; ja && onde != ev.File {
				continue
			}
			visto[imp] = ev.File
			f.EventosDeLog = append(f.EventosDeLog, ev)
			fonte.EventosGerados++
		}
		f.FontesDeLog = append(f.FontesDeLog, fonte)
	}

	if parouEm >= 0 {
		for _, a := range alvos[parouEm:] {
			f.FontesDeLog = append(f.FontesDeLog, FonteDeLog{
				Path: a.path, Familias: a.familias, Estado: FonteNaoLida,
				Lacuna: a.path + " NÃO foi visitado: a coleta parou antes dele por " +
					motivoDaParada + ". O arquivo existe, e nada pode ser afirmado " +
					"sobre o que há nele",
			})
		}
		parcial = true
	}

	for teto := range orc.estourou {
		parcial = true
		f.partial("logeventos", "a leitura de log parou no teto "+teto+
			": o que estiver além NÃO foi lido, e ausência de evento ali não pode "+
			"ser afirmada")
	}
	// COMPLETUDE POR FONTE, e não pelo estado global da coleta.
	//
	// Derivar os dois de `parcial` faria um audit.log ilegível derrubar o fato do
	// log em TEXTO, que pode ter sido lido inteiro — é exatamente o vazamento que
	// a catraca de completude existe para pegar, e que já custou três defeitos
	// nesta base (LoaderPathCompleto, ModuleConfigCompleto, HelpersLidos). Cada
	// fato responde pela SUA fonte.
	f.LogTextoCompleto = completaNasFamiliasDeTexto(f)
	f.AuditLogCompleto = completaNaFamilia(f, "audit")
	f.LogJanelaEfetiva = janelaEfetiva(f)
	if parcial {
		f.LogEstado = LogParcial
		return
	}
	f.LogEstado = LogColetado
}

// alvoDeLog é um arquivo escolhido para leitura.
type alvoDeLog struct {
	path     string
	familias []string
	geracao  int
	mod      time.Time
	tam      int64
	gz       bool
}

// alvosDeLog escolhe o que abrir, e em que ORDEM.
//
// A ordem é por GERAÇÃO, e não por família: primeiro os arquivos vivos de todas
// elas, depois as primeiras rotações, e assim por diante. Ler família por
// família faria o orçamento acabar dentro da primeira, e o audit.log — que é a
// fonte de maior valor — nunca seria aberto num host cujo /var/log é grande.
// fonteInacessivel é o arquivo que EXISTE (ou cujo diretório existe) e não pôde
// ser visto. Ele não vira alvo, e não pode virar silêncio.
type fonteInacessivel struct {
	path     string
	familias []string
	motivo   string
}

func alvosDeLog(f *Facts, e *env.Env) ([]alvoDeLog, []fonteInacessivel, int) {
	porPath := map[string]*alvoDeLog{}
	var ordem []string

	// O inventário de collectLogs já separou base e geração, inclusive o sufixo
	// de data do RHEL. Reusá-lo evita uma segunda caminhada e evita divergir
	// dele — duas leituras do mesmo diretório com regras diferentes é como
	// nasce o falso negativo que ninguém encontra.
	for fam, caminhos := range familiasDeLog {
		for _, vivo := range caminhos {
			for i := range f.Logs {
				l := &f.Logs[i]
				if l.Base != vivo {
					continue
				}
				a := porPath[l.Path]
				if a == nil {
					fi, err := e.Lstat(l.Path)
					if err != nil || !fi.Mode().IsRegular() {
						continue
					}
					a = &alvoDeLog{
						path: l.Path, geracao: l.Geracao, mod: fi.ModTime().UTC(),
						tam: fi.Size(), gz: comprimido(l.Path),
					}
					porPath[l.Path] = a
					ordem = append(ordem, l.Path)
				}
				if !contemString(a.familias, fam) {
					a.familias = append(a.familias, fam)
				}
			}
		}
	}

	// O INVENTÁRIO PODE NÃO TER ENXERGADO O ARQUIVO, e a razão mais comum não é
	// ele faltar: é o diretório não listar. /var/log/audit é 0700 root em toda
	// distribuição que instala auditd, então sem root o caminho inteiro some do
	// inventário — e sumir do inventário não é a mesma coisa que não existir.
	var inacessiveis []fonteInacessivel
	for fam, caminhos := range familiasDeLog {
		for _, vivo := range caminhos {
			if porPath[vivo] != nil {
				continue
			}
			fi, err := e.Lstat(vivo)
			if err != nil {
				if env.EhLacuna(err) {
					inacessiveis = append(inacessiveis, fonteInacessivel{
						path: vivo, familias: []string{fam},
						motivo: vivo + " não pôde ser examinado (" + env.MotivoDoErro(err) +
							"): ele pode existir e conter eventos, e nada pode ser " +
							"afirmado sobre o que os logs deste host registraram — " +
							"não confunda com o host que não TEM log em texto",
					})
				}
				continue
			}
			if !fi.Mode().IsRegular() {
				// NÃO É ARQUIVO COMUM, e sumir daqui em silêncio é o defeito:
				// um /var/log/auth.log trocado por fifo, por symlink para
				// /dev/null ou por diretório sai do inventário (que filtra
				// regular) E sairia daqui — a família ficaria sem fonte nenhuma,
				// e a coleta concluiria "este host não tem log em texto".
				//
				// É a versão de log do que o HistoricoShell.Desviado já
				// reconhece para o histórico de shell: apontar o arquivo para o
				// vazio é a forma mais barata de anti-forense que existe, e ela
				// não pode virar escopo.
				inacessiveis = append(inacessiveis, fonteInacessivel{
					path: vivo, familias: []string{fam},
					motivo: vivo + " existe e NÃO é arquivo comum (" + tipoDeObjeto(fi.Mode()) +
						"): o conteúdo dele não foi lido, e um log apontado para " +
						"outro lugar é anti-forense barato — isto NÃO é o mesmo que " +
						"o host não ter log em texto",
				})
				continue
			}
			// Existe, é arquivo comum, e o inventário não o trouxe (diretório
			// sem permissão de LISTAR, mas com permissão de atravessar). Entra
			// como alvo: se a leitura falhar, a lacuna sai de lá.
			a := &alvoDeLog{
				path: vivo, geracao: 0, mod: fi.ModTime().UTC(),
				tam: fi.Size(), familias: []string{fam},
			}
			porPath[vivo] = a
			ordem = append(ordem, vivo)
		}
	}

	// ORDEM ESTÁVEL entre execuções: `familiasDeLog` é um mapa, e a ordem de
	// iteração dele varia. Sem isto, duas coletas do MESMO host produzem
	// listas de lacuna em ordens diferentes — e é justamente saída contra saída
	// que o drift compara.
	sort.Slice(inacessiveis, func(i, j int) bool { return inacessiveis[i].path < inacessiveis[j].path })

	// "ARQUIVO QUE PODE CONTER AUTENTICAÇÃO EM ALGUMA DISTRO" não é o mesmo que
	// "fonte autoritativa de autenticação NESTE host".
	//
	// No RHEL a autenticação vai para `secure` e o `messages` recebe o resto; no
	// Alpine o busybox manda tudo para `messages`. Classificar `messages` como
	// `auth` sempre fazia CoberturaLog("auth") usar o intervalo dele como
	// cobertura de autenticação num host onde autenticação não passa por ali —
	// e cobertura é justamente a afirmação de que "se tivesse acontecido, eu
	// teria visto".
	//
	// Quando existe fonte dedicada, o messages sai da família `auth`. Ele
	// continua sendo lido e continua produzindo evento de auth se uma linha
	// aparecer lá — o que muda é ele deixar de servir de autoridade de ausência.
	if dedicada := temFonteDedicadaDeAuth(porPath); dedicada {
		if a := porPath["/var/log/messages"]; a != nil {
			a.familias = semFamilia(a.familias, "auth")
		}
	}

	out := make([]alvoDeLog, 0, len(ordem))
	for _, p := range ordem {
		a := porPath[p]
		sort.Strings(a.familias)
		out = append(out, *a)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].geracao != out[j].geracao {
			return out[i].geracao < out[j].geracao
		}
		return out[i].path < out[j].path
	})
	descartados := 0
	if len(out) > maxLogArquivosHard {
		descartados = len(out) - maxLogArquivosHard
		out = out[:maxLogArquivosHard]
	}
	return out, inacessiveis, descartados
}

// temFonteDedicadaDeAuth olha as SÉRIES, e não só os arquivos vivos: um host que
// só tem `auth.log.1` continua tendo fonte dedicada de autenticação.
func temFonteDedicadaDeAuth(porPath map[string]*alvoDeLog) bool {
	for p := range porPath {
		if strings.HasPrefix(p, "/var/log/auth.log") || strings.HasPrefix(p, "/var/log/secure") {
			return true
		}
	}
	return false
}

func semFamilia(familias []string, fora string) []string {
	out := familias[:0]
	for _, f := range familias {
		if f != fora {
			out = append(out, f)
		}
	}
	return out
}

func comprimido(p string) bool {
	for _, suf := range []string{".gz", ".xz", ".bz2", ".zst"} {
		if strings.HasSuffix(p, suf) {
			return true
		}
	}
	return false
}

func contemString(hay []string, s string) bool {
	for _, h := range hay {
		if h == s {
			return true
		}
	}
	return false
}

// leFonteDeLog lê UM arquivo e devolve os eventos mais a observabilidade dele.
func leFonteDeLog(f *Facts, e *env.Env, a alvoDeLog, ctx contextoDeTempo, orc *orcamento) (FonteDeLog, []EventoDeLog) {
	fonte := FonteDeLog{Path: a.path, Familias: a.familias, Estado: FonteLida}

	if a.gz && !strings.HasSuffix(a.path, ".gz") {
		// xz, bz2 e zst exigiriam dependência externa, e este binário não tem
		// nenhuma. É ESCOPO declarado: o arquivo existe e não foi lido.
		fonte.Estado = FonteFormatoNaoLido
		anota(f, &fonte, a.path+" está comprimido num formato que este binário não "+
			"descompacta (só gzip): o conteúdo dele NÃO foi lido")
		return fonte, nil
	}

	cabeca, corpo, err := abreConteudoDeLog(e, a, orc, &fonte)
	if err != nil {
		fonte.Estado = FonteIlegivel
		if env.EhLacuna(err) {
			// É AQUI que mora a diferença entre lacuna e escopo. O arquivo
			// EXISTE e não pôde ser lido: a pergunta cabe neste host e ficou sem
			// resposta. O auth.log é 0640 root:adm em Debian por desenho — sem
			// root, ou sem estar no grupo adm, esta é a resposta honesta.
			anota(f, &fonte, a.path+" não pôde ser lido ("+env.MotivoDoErro(err)+
				"): os eventos dele NÃO foram examinados, e ausência de evento "+
				"neste intervalo não pode ser afirmada")
		}
		return fonte, nil
	}

	// A CABEÇA data a rotação e NÃO é cobertura: entre ela e a cauda há um miolo
	// que ninguém leu. Ver LeituraDescontinua.
	if cabeca != "" {
		fonte.PrimeiroAt = primeiraDataDe(cabeca, a, ctx)
	}

	auditd := contemString(a.familias, "audit")
	var evs []EventoDeLog
	var mont *montadorDeAudit
	if auditd {
		mont = novoMontadorDeAudit()
	}

	nLinha := 0
	br := bufio.NewReaderSize(strings.NewReader(corpo), 64<<10)
	for {
		linha, err := br.ReadString('\n')
		if linha == "" && err != nil {
			break
		}
		nLinha++
		// O TETO DE EVENTOS PARA A EXTRAÇÃO AQUI, e não depois de o arquivo
		// inteiro virar objeto.
		//
		// E parar aqui também interrompe a COBERTURA: continuar lendo carimbos
		// depois de deixar de extrair afirmaria que aquele trecho foi observado
		// — quando, dali em diante, evento nenhum seria detectado. É o mesmo
		// erro que a cobertura por evento cometia, pelo outro lado.
		if orc.eventos <= 0 {
			fonte.Estado = FonteTruncada
			fonte.CorteNoFim = true
			fonte.Lacuna = a.path + ": a extração parou no teto de " +
				strconv.Itoa(maxEventosLog) + " eventos — o resto do arquivo NÃO foi " +
				"examinado, e a cobertura acima não o alcança"
			orc.marca("de " + strconv.Itoa(maxEventosLog) + " eventos de log")
			break
		}
		if nLinha > maxLogLinhasArquivo {
			fonte.Estado = FonteTruncada
			fonte.CorteNoFim = true
			fonte.Lacuna = a.path + ": a leitura parou no teto de " +
				strconv.Itoa(maxLogLinhasArquivo) + " linhas — o resto do arquivo NÃO foi examinado"
			orc.marca("de " + strconv.Itoa(maxLogLinhasArquivo) + " linhas por arquivo")
			break
		}
		linha = strings.TrimRight(linha, "\r\n")
		fonte.LinhasLidas++

		if auditd {
			r, ok := parseRegistroAudit(linha)
			if !ok {
				if err != nil {
					break
				}
				continue
			}
			fonte.LinhasParseadas++
			// COBERTURA = OBSERVAÇÃO: qualquer registro com epoch válido diz
			// que este trecho do arquivo foi lido, mesmo que o montador não
			// produza evento a partir dele.
			// O epoch do auditd é UTC por construção: nada é inferido.
			if t, ok := instanteDeEpoch(strconv.FormatFloat(r.Epoch, 'f', 3, 64)); ok {
				marcaCobertura(&fonte, Carimbo{At: utc(t)})
			}
			// O DENOMINADOR do audit.log são os tipos que o montador promete
			// consumir, e não toda linha com envelope válido.
			//
			// Contar tudo como reconhecido — que era o que este laço fazia —
			// tornava a medição de capacidade VACUA para o audit: um arquivo
			// inteiro de tipos desconhecidos saía com razão perfeita de
			// reconhecimento, que é a mesma cegueira que o estado
			// `naoReconhecida` foi criado para acusar no syslog.
			if tiposDeAuditConsumidos[r.Tipo] {
				fonte.LinhasCandidatas++
				fonte.LinhasReconhecidas++
			}
			r.Linha = nLinha
			// O LOTE, e não só o evento: fechaVelhos pode encerrar muitos grupos
			// de uma vez quando o fluxo dá um salto de tempo, e o teto era
			// conferido só no TOPO da iteração seguinte. Com cinco mil grupos
			// incompletos expirando juntos, o orçamento ficava negativo e o
			// retrato saía acima do teto que ele promete.
			for _, ev := range mont.Alimenta(r) {
				if orc.eventos <= 0 {
					estourouEvento(&fonte, a.path, orc)
					break
				}
				evs = append(evs, comOrigem(ev, a.path))
				orc.eventos--
			}
			if err != nil || orc.eventos <= 0 {
				break
			}
			continue
		}

		ev, res, carimbo := parseLinhaSyslog(linha, ctx)
		// COBERTURA = OBSERVAÇÃO, e não achado. Uma linha
		// `Connection closed by 1.2.3.4` foi lida, parseada e datada — ela só
		// não interessa como evento. Derivar o intervalo dos EVENTOS afirmaria
		// que o arquivo foi visto apenas onde apareceu algo interessante, e é
		// sobre esse intervalo que o antiforense.log_time_gap diz "N dias sem
		// UMA linha de autenticação". Num arquivo cheio de linhas de rotina e
		// com um único evento, aquela frase seria falsa.
		marcaCobertura(&fonte, carimbo)
		switch res {
		case linhaNaoParseada:
		case linhaNaoCandidata, linhaNaoMedida:
			fonte.LinhasParseadas++
		case linhaNaoReconhecida:
			// DENOMINADOR sem numerador: é a única linha que faz a razão cair, e
			// é ela que denuncia formato diferente do esperado.
			fonte.LinhasParseadas++
			fonte.LinhasCandidatas++
		case linhaReconhecidaSemEvento:
			fonte.LinhasParseadas++
			fonte.LinhasCandidatas++
			fonte.LinhasReconhecidas++
		case linhaEvento:
			fonte.LinhasParseadas++
			fonte.LinhasCandidatas++
			fonte.LinhasReconhecidas++
			ev.Line = nLinha
			evs = append(evs, comOrigem(ev, a.path))
			orc.eventos--
		}
		if err != nil {
			break
		}
	}
	if mont != nil {
		// O QUE SOBRA NO MONTADOR também passa pelo orçamento. Com a
		// finalização por terminador e por tempo, o que sobra aqui é a última
		// janela de dois segundos do arquivo — mas o teto é promessa, e promessa
		// com exceção não é teto.
		for _, ev := range mont.Fecha() {
			if orc.eventos <= 0 {
				estourouEvento(&fonte, a.path, orc)
				break
			}
			evs = append(evs, comOrigem(ev, a.path))
			orc.eventos--
		}
		if mont.FechadosPorTeto > 0 {
			anota(f, &fonte, a.path+": "+strconv.Itoa(mont.FechadosPorTeto)+
				" evento(s) de auditoria foram montados ANTES de o arquivo dizer que "+
				"terminaram (teto de "+strconv.Itoa(maxGruposAuditAbertos)+" eventos "+
				"em aberto): o caminho de alguns pode ter ficado sem o registro PATH "+
				"que o resolveria")
		}
	}

	if fonte.UltimoAt == "" {
		fonte.UltimoAt = fonte.CobertoAte
	}
	if fonte.PrimeiroAt == "" {
		fonte.PrimeiroAt = fonte.CobertoDesde
	}

	declaraCapacidadeDoParser(f, &fonte)
	return fonte, evs
}

// marcaCobertura alarga o intervalo OBSERVADO deste arquivo.
//
// Ela é chamada por LINHA DATADA, e não por evento — ver o comentário no laço.
func marcaCobertura(fonte *FonteDeLog, c Carimbo) {
	if c.At == "" {
		return
	}
	if fonte.CobertoDesde == "" || c.At < fonte.CobertoDesde {
		fonte.CobertoDesde = c.At
	}
	if c.At > fonte.CobertoAte {
		fonte.CobertoAte = c.At
	}
	// A CONFIANÇA é da cobertura, e basta uma linha inferida para o intervalo
	// inteiro deixar de ser exato: não há como dizer qual ponta veio de onde.
	fonte.CoberturaAnoInferido = fonte.CoberturaAnoInferido || c.AnoInferido
	fonte.CoberturaFusoInferido = fonte.CoberturaFusoInferido || c.FusoInferido
}

// estourouEvento marca o arquivo em que o teto de eventos mordeu. A lacuna fica
// no arquivo — é ela que faz o check da família degradar — e o teto vai para o
// orçamento, que é quem reporta a coleta inteira.
func estourouEvento(fonte *FonteDeLog, path string, orc *orcamento) {
	fonte.Estado = FonteTruncada
	fonte.CorteNoFim = true
	if fonte.Lacuna == "" {
		fonte.Lacuna = path + ": a extração parou no teto de " +
			strconv.Itoa(maxEventosLog) + " eventos — o resto do arquivo NÃO foi " +
			"examinado, e a cobertura acima não o alcança"
	}
	orc.marca("de " + strconv.Itoa(maxEventosLog) + " eventos de log")
}

func comOrigem(ev EventoDeLog, path string) EventoDeLog {
	ev.File = path
	return ev
}

// declaraCapacidadeDoParser é a defesa contra o falso "limpo" mais convincente
// que existe: o parser não entende o formato deste host, a coleta termina com
// SUCESSO, e a lista de eventos sai vazia.
//
// A razão é reconhecidas/CANDIDATAS, e nunca reconhecidas/linhas. Um
// /var/log/messages saudável é 99% postgres, docker e aplicação — medir contra o
// total diria que todo host tem parser quebrado, e a lacuna apareceria em toda
// varredura limpa até ninguém mais a ler.
func declaraCapacidadeDoParser(f *Facts, fonte *FonteDeLog) {
	if fonte.LinhasLidas > 0 && fonte.LinhasParseadas == 0 {
		anota(f, fonte, fonte.Path+": "+strconv.Itoa(fonte.LinhasLidas)+
			" linha(s) lidas e NENHUMA no formato syslog esperado — este arquivo "+
			"não é do formato que este parser conhece, e 'nenhum evento' não pode "+
			"ser afirmado sobre ele")
		return
	}
	const minCandidatasParaMedir = 50
	if fonte.LinhasCandidatas < minCandidatasParaMedir {
		return
	}
	if fonte.LinhasReconhecidas*5 >= fonte.LinhasCandidatas {
		return
	}
	anota(f, fonte, fonte.Path+": de "+strconv.Itoa(fonte.LinhasCandidatas)+
		" linha(s) dos produtores que este parser promete entender, só "+
		strconv.Itoa(fonte.LinhasReconhecidas)+" foram compreendidas — o formato "+
		"deste host difere do esperado, e a ausência de evento pode ser do parser, "+
		"não do host")
}

// anota registra a lacuna nos DOIS lugares: no arquivo, para o check degradar
// pela família de que depende, e no mapa global, para o relatório de coleta.
//
// Os dois são necessários e respondem perguntas diferentes: "esta pergunta
// ficou sem resposta?" é por família; "o que esta coleta não conseguiu ler?" é
// da execução inteira.
func anota(f *Facts, fonte *FonteDeLog, motivo string) {
	if fonte.Lacuna == "" {
		fonte.Lacuna = motivo
	}
	f.partial("logeventos", motivo)
}

// abreConteudoDeLog devolve a CABEÇA (quando houve corte) e o CORPO a parsear.
//
// A escolha da ponta é o ponto: num arquivo VIVO grande, o que interessa é a
// CAUDA — as horas mais recentes. Num rotacionado comprimido não há como pular
// para o fim sem descomprimir tudo, então lê-se do começo, com teto, e o corte
// sai declarado no outro lado.
func abreConteudoDeLog(e *env.Env, a alvoDeLog, orc *orcamento, fonte *FonteDeLog) (string, string, error) {
	teto := int64(maxLogBytesArquivo)
	if orc.bytes < teto {
		teto = orc.bytes
	}

	if a.gz {
		fh, err := e.Open(a.path)
		if err != nil {
			return "", "", err
		}
		defer fh.Close()
		zr, err := gzip.NewReader(fh)
		if err != nil {
			return "", "", err
		}
		defer zr.Close()
		tetoZ := int64(maxDescompactado)
		if teto < tetoZ {
			tetoZ = teto
		}
		b, err := io.ReadAll(io.LimitReader(zr, tetoZ+1))
		if err != nil {
			return "", "", err
		}
		if int64(len(b)) > tetoZ {
			b = b[:tetoZ]
			fonte.Estado = FonteTruncada
			fonte.CorteNoFim = true
			fonte.Lacuna = a.path + ": a descompressão parou em " +
				strconv.FormatInt(tetoZ>>20, 10) + " MB — o resto do arquivo NÃO foi examinado"
			// O teto ANUNCIADO tem de ser o APLICADO. `tetoZ` é o menor entre a
			// descompressão máxima e o que sobrou do orçamento por arquivo —
			// dizer "64 MB" enquanto se parou em 8 MB é um relatório forense
			// afirmando um limite que não foi o limite.
			orc.marca("de leitura por arquivo comprimido (" +
				strconv.FormatInt(tetoZ>>20, 10) + " MB descomprimidos)")
		}
		orc.bytes -= int64(len(b))
		fonte.BytesLidos = int64(len(b))
		return "", string(b), nil
	}

	fh, err := e.OpenFD(a.path)
	if err != nil {
		return "", "", err
	}
	defer fh.Close()

	if a.tam <= teto {
		b, err := io.ReadAll(io.LimitReader(fh, teto))
		if err != nil {
			return "", "", err
		}
		orc.bytes -= int64(len(b))
		fonte.BytesLidos = int64(len(b))
		return "", string(b), nil
	}

	// Arquivo maior que o teto: cabeça para datar a rotação, cauda para os
	// eventos, e o miolo declarado como NÃO LIDO.
	cab := make([]byte, cabecaDeLog)
	n, _ := io.ReadFull(fh, cab)
	cab = cab[:n]

	if _, err := fh.Seek(a.tam-teto, io.SeekStart); err != nil {
		return "", "", err
	}
	b, err := io.ReadAll(io.LimitReader(fh, teto))
	if err != nil {
		return "", "", err
	}
	// A primeira linha da cauda começa no meio de outra: descartá-la evita
	// parsear meia linha como se fosse inteira.
	if i := strings.IndexByte(string(b), '\n'); i >= 0 {
		b = b[i+1:]
	}
	orc.bytes -= int64(len(b)) + int64(n)
	fonte.BytesLidos = int64(len(b)) + int64(n)
	fonte.CorteNoInicio = true
	fonte.LeituraDescontinua = true
	fonte.Estado = FonteTruncada
	fonte.Lacuna = a.path + ": maior que o teto por arquivo — só a CAUDA foi lida, e o " +
		"miolo entre a cabeça e ela NÃO foi observado"
	return string(cab), string(b), nil
}

// primeiraDataDe devolve o carimbo da primeira linha datável da cabeça.
func primeiraDataDe(cabeca string, a alvoDeLog, ctx contextoDeTempo) string {
	for _, linha := range strings.Split(cabeca, "\n") {
		if contemString(a.familias, "audit") {
			if r, ok := parseRegistroAudit(linha); ok {
				if t, ok := instanteDeEpoch(strconv.FormatFloat(r.Epoch, 'f', 3, 64)); ok {
					return utc(t)
				}
			}
			continue
		}
		if env, ok := separaEnvelope(linha, ctx); ok && env.Quando != "" {
			return env.Quando
		}
	}
	return ""
}

// impressaoDeEvento é a identidade usada só para o dedupe ENTRE arquivos. Não é
// serializada: é derivada, e guardá-la faria dois fatos precisarem concordar.
func impressaoDeEvento(ev *EventoDeLog) string {
	return strings.Join([]string{
		ev.At, ev.Kind, ev.Process, strconv.Itoa(ev.PID), ev.User, ev.RemoteIP,
		strings.Join(ev.Alvos, "\x00"), ev.Trecho,
	}, "\x01")
}

// familiasDeTexto são as que passam pelo parser de syslog. O auditd tem formato
// próprio, coletor próprio dentro do mesmo laço, e fato de completude próprio.
var familiasDeTexto = []string{"auth", "syslog", "kern", "cron"}

// completaNasFamiliasDeTexto responde pelas quatro juntas porque elas
// compartilham o parser e, em várias distribuições, o próprio ARQUIVO: no
// Alpine, /var/log/messages é as três primeiras ao mesmo tempo. Separá-las em
// quatro fatos seria fingir uma independência que o disco não tem.
func completaNasFamiliasDeTexto(f *Facts) bool {
	achou := false
	for i := range f.FontesDeLog {
		s := &f.FontesDeLog[i]
		daTexto := false
		for _, fam := range familiasDeTexto {
			if ehDaFamilia(s, fam) {
				daTexto = true
				break
			}
		}
		if !daTexto {
			continue
		}
		achou = true
		if s.Estado != FonteLida {
			return false
		}
	}
	return achou
}

// completaNaFamilia diz se TODOS os arquivos daquela família foram lidos
// inteiros. É o fato de completude por FONTE, e existe pela mesma razão que
// PasswdLido e ShadowLido são dois: um audit.log ilegível não pode suprimir a
// comparação de um auth.log perfeitamente lido.
func completaNaFamilia(f *Facts, familia string) bool {
	achou := false
	for i := range f.FontesDeLog {
		if !ehDaFamilia(&f.FontesDeLog[i], familia) {
			continue
		}
		achou = true
		if f.FontesDeLog[i].Estado != FonteLida {
			return false
		}
	}
	return achou
}

// janelaEfetiva é o horizonte mais CONSERVADOR entre as famílias lidas.
//
// Conservador porque ele vai para o rodapé, e o rodapé fala com quem pediu
// `--since 30d`: dizer o alcance da família mais funda esconderia que outra
// família só alcançou oito horas. A autoridade de um CHECK, ainda assim, é
// CoberturaLog(família) — um número global não sabe de qual pergunta se trata.
func janelaEfetiva(f *Facts) string {
	pior := ""
	for fam := range familiasDeLog {
		c := f.CoberturaLog(fam)
		if c.ContinuoDesde == "" {
			continue
		}
		if pior == "" || c.ContinuoDesde > pior {
			pior = c.ContinuoDesde
		}
	}
	return pior
}

// tipoDeObjeto nomeia o que está no lugar do arquivo. O nome importa: "fifo" e
// "link" mandam o operador para investigações diferentes.
func tipoDeObjeto(m fs.FileMode) string {
	switch {
	case m&fs.ModeSymlink != 0:
		return "link simbólico"
	case m.IsDir():
		return "diretório"
	case m&fs.ModeNamedPipe != 0:
		return "fifo"
	case m&fs.ModeSocket != 0:
		return "socket"
	case m&fs.ModeDevice != 0:
		return "dispositivo"
	}
	return m.String()
}
