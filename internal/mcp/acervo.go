package mcp

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/dump"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

// O acervo: os retratos que ESTE processo pode abrir, fixados no lançamento.
//
// # Por que nenhuma tool recebe caminho de arquivo
//
// A tentação óbvia era `snapshot.compare(antes.json, depois.json)`. Ela destrói
// o significado de `--snapshot`: dump.Carregar abre com os.Open no filesystem
// DO ANALISTA, então uma tool que aceita caminho entrega ao modelo uma
// primitiva de leitura arbitrária na estação de quem investiga — e, de brinde,
// um DoS de 512 MiB por chamada (o teto do MaxDump).
//
// Aqui o operador declara no lançamento tudo que o processo poderá abrir, e as
// tools falam por ID. Um ID que não está no acervo é erro, não uma abertura.

// Retrato é um dump carregado, com o ambiente DA COLETA reconstruído.
type Retrato struct {
	ID     string
	Rotulo string // host · data — nunca o caminho local
	Dump   *dump.Dump
	Env    *env.Env
	Fatos  *facts.Facts
	Fonte  env.Source

	// Digest é o sha256 COMPLETO dos bytes que foram interpretados. O ID é um
	// prefixo dele, para caber num handle; a identidade guardada é a inteira.
	Digest string

	// Soma é o que o sidecar .sha256 respondeu sobre este arquivo.
	//
	// O `collect` escreve `<dump>.sha256` ao lado do artefato, e `analyze` e
	// `drift` o CONFEREM antes de concluir qualquer coisa. O servidor MCP era o
	// único caminho de carga que pulava a verificação — e ele é justamente o
	// que entrega o retrato a um modelo, com um bloco de procedência que
	// afirma cadeia de custódia inteira.
	Soma EstadoDaSoma

	// O relatório é memoizado porque o retrato é IMUTÁVEL: rodar o catálogo
	// inteiro sobre os mesmos fatos com o mesmo ambiente é determinístico, e
	// quatro tools precisam dele (findings.list, finding.get, coverage.get,
	// findings.correlate). Sem isto, uma investigação de trinta chamadas roda
	// os checks trinta vezes sobre bytes que não mudaram.
	umaVez sync.Once
	rel    *check.Report
}

// Relatorio roda o catálogo COMPLETO sobre este retrato, uma vez.
//
// A seleção é `Selection{}` — o catálogo inteiro —, que é exatamente o que
// `aletheia analyze` sem flags seleciona. É essa igualdade que faz a catraca de
// paridade valer alguma coisa: se a seleção divergir, os dois lados passam a
// medir coisas diferentes e o teste que os compara vira decoração.
func (r *Retrato) Relatorio() *check.Report {
	r.umaVez.Do(func() {
		// O sync.Once ENVENENA em caso de pânico: ele marca a execução como
		// feita mesmo quando o corpo não terminou, e toda chamada seguinte
		// devolveria `rel` nil — o defeito viraria um nil deref em
		// ObservabilidadeDeRelatorio, longe da causa.
		//
		// check.Run protege cada CHECK com runGuarded, mas a cauda dele
		// (Index, resolverAtores, marcarDrift, invalidarAusencias) roda solta,
		// e ela lê fatos de um artefato que só foi validado por versão de
		// esquema.
		//
		// A saída é a resposta honesta desta ferramenta: o catálogo inteiro
		// NÃO VERIFICADO, com o motivo. Nunca nil, e nunca "nada encontrado".
		defer func() {
			if rec := recover(); rec != nil {
				r.rel = relatorioQueFalhou(fmt.Sprint(rec))
			}
		}()
		r.rel = check.Run(check.Select(check.Selection{}), r.Fatos, r.Env)
	})
	return r.rel
}

// relatorioQueFalhou é o rodapé de uma análise que não pôde acontecer.
//
// Ele existe para que a falha atravesse o protocolo com a MESMA forma de todo o
// resto: veredito INCOMPLETE, catálogo em not_checked, motivo escrito. Um erro
// de transporte diria "a chamada falhou"; isto diz "não foi possível olhar",
// que é a distinção que a ferramenta inteira mantém.
func relatorioQueFalhou(causa string) *check.Report {
	todos := check.Select(check.Selection{})
	rel := &check.Report{Coverage: check.Coverage{Total: len(todos)}}
	for _, c := range todos {
		rel.Coverage.NotChecked = append(rel.Coverage.NotChecked, check.NotChecked{
			ID: c.ID, Ref: c.Ref, Title: c.Title,
			Reason: "a análise deste retrato falhou durante a execução (" + causa +
				"): DEFEITO DA FERRAMENTA, e não afirmação sobre o host",
			Manual: []string{"analise o retrato pelo CLI: aletheia analyze <arquivo>"},
		})
	}
	return rel
}

// Escopo é o quanto ESTE retrato leu, e ele sai dos próprios fatos.
//
// Guardá-lo num campo à parte seria uma segunda verdade sobre a mesma coisa, e
// as duas divergem no dia em que alguém montar um Retrato por outro caminho.
// `Facts.Volatil` é o que o motor de checks já consulta para recusar conclusão;
// é ele que manda aqui também.
func (r *Retrato) Escopo() Escopo {
	if r.Fatos != nil && r.Fatos.Volatil {
		return EscopoVolatil
	}
	return EscopoCompleto
}

// Procedencia é a deste retrato, já montada.
func (r *Retrato) Procedencia() Procedencia {
	return ProcedenciaDeDump(r.ID, r.Dump, r.Soma.String(), string(r.Escopo()))
}

// EstadoDaSoma é a resposta do sidecar .sha256.
//
// Três estados e não dois: "não havia sidecar" (dump de outra versão, ou vindo
// de stdout) é diferente de "confere" e MUITO diferente de "não confere", e
// achatá-los faria a ausência de verificação parecer verificação.
//
// E os nomes dizem SIDECAR, não checksum: o `collect` é explícito quanto a
// isso — a soma não AUTENTICA o dump, porque quem altera um altera o outro. Os
// dois saem do mesmo host e viajam no mesmo pendrive. `sidecar_matches` afirma
// só que o arquivo não mudou desde que a soma foi escrita; a cadeia de custódia
// de verdade é o número que o operador registrou fora do host.
type EstadoDaSoma uint8

const (
	SomaAusente EstadoDaSoma = iota
	SomaConfere
	SomaDivergente
	// SomaNaoSeAplica é a captura ao vivo: ela nunca foi escrita em disco, então
	// não há sidecar a conferir. É diferente de "ausente", que é um arquivo cuja
	// integridade NÃO pôde ser verificada — aqui não há o que verificar, e
	// achatar os dois faria a captura parecer degradada.
	SomaNaoSeAplica
)

func (e EstadoDaSoma) String() string {
	switch e {
	case SomaConfere:
		return "sidecar_matches"
	case SomaDivergente:
		return "sidecar_mismatch"
	case SomaNaoSeAplica:
		return "sidecar_not_applicable"
	}
	return "sidecar_absent"
}

// conferirSidecar compara o hash já calculado com o que a coleta escreveu.
//
// O teto de leitura é o mesmo raciocínio do dump.MaxDump aplicado ao sidecar:
// ele veio do mesmo pendrive e do mesmo host, e "tamanho é entrada não
// confiável" vale para ele também. 64 bytes de hex mais um nome é tudo que o
// formato admite.
func conferirSidecar(caminho, obtido string) EstadoDaSoma {
	// Pela MESMA porta do dump: o sidecar vem do mesmo host e do mesmo
	// pendrive, e um `mkfifo dump.json.sha256` penduraria o lançamento do
	// servidor exatamente como o do dump penduraria.
	fh, err := dump.AbrirArtefato(caminho + ".sha256")
	if err != nil {
		return SomaAusente
	}
	defer fh.Close()
	b, err := io.ReadAll(io.LimitReader(fh, 8<<10))
	if err != nil {
		return SomaAusente
	}
	campos := strings.Fields(string(b))
	if len(campos) == 0 {
		return SomaAusente
	}
	if campos[0] == obtido {
		return SomaConfere
	}
	return SomaDivergente
}

// Acervo guarda os retratos por ID, na ordem em que o operador os declarou.
type Acervo struct {
	mu    sync.RWMutex
	ordem []string
	por   map[string]*Retrato

	// Teto limita quantos retratos vivem ao mesmo tempo. Zero = sem teto, que é
	// o modo snapshot: ali o operador declarou os arquivos no lançamento, e
	// limitar o que ele mesmo pediu não protege ninguém.
	Teto int
}

func NovoAcervo() *Acervo { return &Acervo{por: map[string]*Retrato{}} }

// LarguraDoID é quantos hex do digest entram no handle.
//
// 32 hex = 128 bits. Eram 12 hex — 48 bits —, e o acervo tratava colisão de ID
// como "mesmo conteúdo" sem conferir o resto. Vinte caracteres a mais num
// identificador que o modelo copia automaticamente não custam nada.
const LarguraDoID = 32

// ErrRetratoDesconhecido é a resposta a um handle que este servidor não conhece.
//
// Ele é DIFERENTE de "arquivo não encontrado" de propósito: o modelo não está
// pedindo um arquivo, está citando um handle, e a distinção impede que a
// mensagem de erro vire um oráculo sobre o disco do analista.
//
// A frase é NEUTRA quanto ao modo. Ela dizia "não declarado no lançamento", que
// é verdade em snapshot e falso em live — ali o retrato é cunhado em execução, e
// mandar o operador conferir o lançamento o manda para o lugar errado. O que
// muda por modo é a DICA, e ela vive em retratoDe.
var ErrRetratoDesconhecido = errors.New("snapshot_id desconhecido neste servidor")

// Carregar lê um dump do disco e o registra.
//
// O ID vem do HASH DO CONTEÚDO, e não do caminho. Duas razões:
//
//	reprodutível   reiniciar o servidor com os mesmos arquivos devolve os
//	               mesmos IDs, e uma investigação retomada continua citando
//	               as mesmas evidências
//	não vaza       o caminho no disco do analista (/home/ana/casos/acme-2026/…)
//	               não tem por que chegar ao modelo, e o rótulo legível sai do
//	               PRÓPRIO dump: o host e a data da coleta
func (a *Acervo) Carregar(caminho string) (*Retrato, error) {
	if caminho == "-" {
		// A entrada padrão é o CANAL DO PROTOCOLO. Ler o dump dali comeria as
		// mensagens do cliente, e o servidor ficaria mudo sem nenhum erro que
		// explicasse por quê.
		return nil, errors.New("--snapshot - não é possível: a entrada padrão é o transporte MCP")
	}
	// UMA leitura, limitada, com o digest dos MESMOS bytes.
	//
	// Antes eram duas aberturas independentes do mesmo caminho — uma para
	// hashear, outra para interpretar — e entre elas cabia a troca do arquivo.
	// O resultado é o pior possível num servidor que deixa uma IA CITAR
	// evidência: o snapshot_id identifica o conteúdo A e os fatos servidos são
	// o B, e a citação aponta para bytes que ninguém analisou.
	d, digest, err := dump.CarregarComDigest(caminho)
	if err != nil {
		return nil, err
	}
	// Ambiente DA COLETA, nunca do analista. dump.Env(nil) é explícito quanto a
	// isso: nenhuma capacidade é sondada aqui, senão uma análise rodando como
	// root declararia cobertura que a coleta nunca teve.
	e, err := d.Env(nil)
	if err != nil {
		return nil, err
	}
	// Sem o índice, ProcessByPID e a busca por inode voltam a ser lineares
	// dentro de laços sobre processos — e todo dossiê de alvo passa por elas.
	d.Facts.Index()

	fonte, _ := env.SourceDeNome(d.Ambiente.Source)
	r := &Retrato{
		ID:     "snap-" + digest[:LarguraDoID],
		Digest: digest,
		Rotulo: rotuloDe(d),
		Dump:   d, Env: e, Fatos: d.Facts, Fonte: fonte,
		Soma: conferirSidecar(caminho, digest),
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if ja, existe := a.por[r.ID]; existe {
		// Mesmo ID: confere o DIGEST INTEIRO antes de tratar como o mesmo
		// retrato.
		//
		// Antes o prefixo bastava, e ele tinha 48 bits. Para colisão acidental
		// entre dois ou dez snapshots isso é irrelevante; para conteúdo
		// ESCOLHIDO, não — e o efeito era silencioso: o segundo arquivo era
		// descartado e o servidor respondia sobre o primeiro, com o handle que
		// o operador acha que aponta para o outro. Não há motivo para economizar
		// caracteres num handle que o modelo copia sozinho.
		if ja.Digest == r.Digest {
			return ja, nil
		}
		return nil, fmt.Errorf(
			"dois artefatos DIFERENTES com o mesmo prefixo de digest (%s): "+
				"%s… e %s…. Isto não acontece por acaso — trate os dois arquivos "+
				"como suspeitos", r.ID, ja.Digest[:24], r.Digest[:24])
	}
	a.por[r.ID] = r
	a.ordem = append(a.ordem, r.ID)
	return r, nil
}

// Escopo é o QUANTO uma captura ao vivo lê.
type Escopo string

const (
	// EscopoVolatil lê /proc e sockets, e mais nada. Nove vezes mais barato
	// que a completa (164ms contra ~1,5s, medido em watch.go) — e é o que pega
	// processo efêmero e beacon curto.
	//
	// Ele NÃO sustenta check nenhum: o motor recusa rodar sobre fatos voláteis,
	// porque um check de unit encontraria zero units e reportaria "nada
	// encontrado" onde o certo é "não olhei". A recusa vira o catálogo inteiro
	// em not_checked, com motivo — que é a resposta honesta, e não um defeito.
	EscopoVolatil Escopo = "volatile"
	// EscopoCompleto é a varredura inteira: a única que sustenta findings.
	EscopoCompleto Escopo = "complete"
)

// Capturar tira um retrato AGORA e o registra.
//
// # Por que ela passa por dump.De
//
// A coleta ao vivo produz um Facts CRU — com argv inteiro, com o .bashrc do
// usuário, com o histórico de shell. As tools deste servidor declaram
// DadosRedigidosNaOrigem, que promete "não contém segredo em claro", e servir
// aquele Facts direto tornaria a promessa falsa outra vez, pela porta nova.
//
// Em vez de abrir um segundo caminho de redação, a captura ATRAVESSA o mesmo:
// dump.De aplica a redação profunda, carimba o artefato com a versão da
// política, e monta a procedência. O retrato ao vivo passa a ser literalmente o
// mesmo artefato de um `collect` — só que nunca escrito em disco.
//
// O custo é uma cópia profunda do Facts por captura, que é exatamente o que o
// `collect` já paga na escrita.
func (a *Acervo) Capturar(e *env.Env, escopo Escopo) (*Retrato, error) {
	// O TETO VEM ANTES DA COLETA.
	//
	// Ele era conferido no fim, na hora de registrar — depois de facts.Collect
	// ter varrido o filesystem inteiro, de dump.De ter feito a cópia profunda e
	// do índice ter sido montado. Uma captura que ia ser recusada já tinha
	// pagado tudo isso, no host investigado, e um agente em laço fazia o alvo
	// varrer o disco repetidas vezes para receber erro.
	//
	// O teto existe justamente para não gastar aquilo ali. Conferi-lo depois o
	// tornava uma trava sobre a memória e nenhuma sobre o custo.
	if err := a.vagaLivre(); err != nil {
		return nil, err
	}

	var f *facts.Facts
	switch escopo {
	case EscopoVolatil:
		if e.Source != env.SourceLive {
			return nil, errors.New("escopo volátil só existe sobre host vivo: ele lê " +
				"/proc e sockets, e uma imagem montada não tem nenhum dos dois")
		}
		f = facts.CollectVolatile(e)
		// O passwd é a única coisa de disco que a resposta barata precisa: sem
		// ele o censo imprime "uid 1000" onde o operador espera "node". É o
		// mesmo par que o `info` usa.
		f.Accounts = facts.NomesDeUsuario(e)
	case EscopoCompleto:
		f = facts.Collect(e)
	default:
		return nil, fmt.Errorf("escopo desconhecido: %s", escopo)
	}

	d := dump.De(e, f)
	d.Facts.Index()

	// O ENV É CONGELADO, e a captura é a ÚLTIMA operação que toca o alvo.
	//
	// O Retrato guardava o Env VIVO da aquisição — com o descritor da raiz
	// travada aberto, em modo imagem — e o passava para check.Run em toda
	// chamada de findings.list. Os checks são função pura sobre Facts hoje,
	// então nada relia; mas a porta ficava aberta: um check novo que chamasse
	// `e.ReadFile` faria uma consulta a um retrato ANTIGO ler o estado ATUAL, e
	// a invariante do servidor quebraria sem uma linha mudar aqui dentro.
	//
	// dump.Env(nil) reconstrói o ambiente DA COLETA a partir do artefato — sem
	// raiz, sem descritor, sem sondar nada. É exatamente o que o modo snapshot
	// já usa, e agora os dois convergem na mesma estrutura.
	congelado, err := d.Env(nil)
	if err != nil {
		e.Close()
		return nil, err
	}
	// A captura assume a POSSE do Env vivo e sempre o fecha. Fechá-lo em quem
	// chama deixava o descritor aberto no caminho de pânico, que rodarProtegido
	// recupera lá em cima — e em modo imagem cada captura segura um os.Root.
	e.Close()

	fonte := e.Source
	id, err := idDeCaptura()
	if err != nil {
		e.Close()
		return nil, err
	}
	r := &Retrato{
		ID: id, Rotulo: rotuloDe(d),
		Dump: d, Env: congelado, Fatos: d.Facts, Fonte: fonte,
		Soma: SomaNaoSeAplica,
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	// Conferido DE NOVO sob o lock: entre a primeira conferência e aqui houve
	// uma coleta inteira, e o Acervo é público — nada garante que ninguém
	// registrou no meio. A primeira verificação é sobre o CUSTO, esta é sobre a
	// invariante.
	if a.Teto > 0 && len(a.ordem) >= a.Teto {
		return nil, erroDeTeto(a.Teto)
	}
	a.por[r.ID] = r
	a.ordem = append(a.ordem, r.ID)
	return r, nil
}

// vagaLivre recusa antes de qualquer trabalho.
func (a *Acervo) vagaLivre() error {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.Teto > 0 && len(a.ordem) >= a.Teto {
		return erroDeTeto(a.Teto)
	}
	return nil
}

func erroDeTeto(teto int) error {
	return fmt.Errorf("teto de %d retratos vivos alcançado: libere um com "+
		"snapshot.release antes de capturar outro. O teto existe porque cada "+
		"retrato segura os fatos INTEIROS na memória deste processo, e ele roda "+
		"no host investigado", teto)
}

// idDeCaptura mint um handle para retrato ao vivo.
//
// O prefixo `live-` está no PRÓPRIO id, e não num campo ao lado, porque a
// diferença importa e um campo se perde: o id de um retrato carregado é o hash
// do CONTEÚDO — reproduzível, verificável contra uma cópia salva —, e o de uma
// captura não pode ser, porque ela nunca virou bytes em disco. Ver quem é quem
// olhando o handle é melhor que ter de perguntar.
func idDeCaptura() (string, error) {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("não foi possível cunhar o handle da captura: %w", err)
	}
	return "snap-live-" + hex.EncodeToString(b[:]), nil
}

// Liberar descarta um retrato e a memória dele.
func (a *Acervo) Liberar(id string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	r, ok := a.por[id]
	if !ok {
		return fmt.Errorf("%w: %s", ErrRetratoDesconhecido, id)
	}
	// A raiz travada de uma captura de IMAGEM é um descritor aberto, e cada
	// captura abre o seu. Sem isto, capturar em laço vaza descritor até o
	// processo bater no RLIMIT_NOFILE — no host investigado.
	if r.Env != nil {
		r.Env.Close()
	}
	delete(a.por, id)
	for i, x := range a.ordem {
		if x == id {
			a.ordem = append(a.ordem[:i], a.ordem[i+1:]...)
			break
		}
	}
	return nil
}

// Retrato busca por ID.
func (a *Acervo) Retrato(id string) (*Retrato, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	r, ok := a.por[id]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrRetratoDesconhecido, id)
	}
	return r, nil
}

// Todos devolve os retratos na ordem declarada.
func (a *Acervo) Todos() []*Retrato {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]*Retrato, 0, len(a.ordem))
	for _, id := range a.ordem {
		out = append(out, a.por[id])
	}
	return out
}

// Unico devolve o retrato quando há exatamente um.
//
// Existe para que a tool não exija `snapshot_id` no caso comum de um dump só —
// exigir o handle ali seria burocracia sem ganho, porque não há ambiguidade a
// resolver. Com dois ou mais, o handle passa a ser obrigatório: escolher um
// "padrão" faria o modelo receber resposta sobre o retrato errado sem nunca
// saber que havia outro.
func (a *Acervo) Unico() (*Retrato, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if len(a.ordem) != 1 {
		return nil, false
	}
	return a.por[a.ordem[0]], true
}

func (a *Acervo) Vazio() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.ordem) == 0
}

// Fontes é a união do que os retratos declaram. Decide quais tools existem:
// um acervo só de imagens não tem o que responder sobre processo.
func (a *Acervo) Fontes() env.Source {
	a.mu.RLock()
	defer a.mu.RUnlock()
	var s env.Source
	for _, id := range a.ordem {
		s |= a.por[id].Fonte
	}
	return s
}

func rotuloDe(d *dump.Dump) string {
	host := "host-desconhecido"
	if d.Facts != nil && d.Facts.Host.Hostname != "" {
		host = d.Facts.Host.Hostname
	}
	quando := d.Ambiente.CollectedAt
	if quando == "" {
		quando = "sem data"
	}
	return host + " · " + quando
}
