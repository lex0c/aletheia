package mcp

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
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

// Procedencia é a deste retrato, já montada.
func (r *Retrato) Procedencia() Procedencia {
	return ProcedenciaDeDump(r.ID, r.Dump, r.Soma.String())
}

// EstadoDaSoma é a resposta do sidecar .sha256.
//
// Três estados e não dois: "não havia sidecar" (dump de outra versão, ou vindo
// de stdout) é diferente de "confere" e MUITO diferente de "não confere", e
// achatá-los faria a ausência de verificação parecer verificação.
type EstadoDaSoma uint8

const (
	SomaAusente EstadoDaSoma = iota
	SomaConfere
	SomaDivergente
)

func (e EstadoDaSoma) String() string {
	switch e {
	case SomaConfere:
		return "checksum_verified"
	case SomaDivergente:
		return "checksum_mismatch"
	}
	return "checksum_absent"
}

// conferirSidecar compara o hash já calculado com o que a coleta escreveu.
//
// O teto de leitura é o mesmo raciocínio do dump.MaxDump aplicado ao sidecar:
// ele veio do mesmo pendrive e do mesmo host, e "tamanho é entrada não
// confiável" vale para ele também. 64 bytes de hex mais um nome é tudo que o
// formato admite.
func conferirSidecar(caminho, obtido string) EstadoDaSoma {
	fh, err := os.Open(caminho + ".sha256")
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
}

func NovoAcervo() *Acervo { return &Acervo{por: map[string]*Retrato{}} }

// ErrRetratoDesconhecido é a resposta a um ID que não foi declarado no
// lançamento. Ele é DIFERENTE de "arquivo não encontrado" de propósito: o
// modelo não está pedindo um arquivo, está citando um handle, e a distinção
// impede que a mensagem de erro vire um oráculo sobre o disco do analista.
var ErrRetratoDesconhecido = errors.New("snapshot_id não declarado no lançamento deste servidor")

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
	soma, err := somaDoArquivo(caminho)
	if err != nil {
		return nil, err
	}
	d, err := dump.Carregar(caminho)
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
		ID:     "snap-" + soma[:12],
		Rotulo: rotuloDe(d),
		Dump:   d, Env: e, Fatos: d.Facts, Fonte: fonte,
		Soma: conferirSidecar(caminho, soma),
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if ja, existe := a.por[r.ID]; existe {
		// Mesmo conteúdo declarado duas vezes: não é erro do operador, e
		// inventar um segundo ID para os mesmos bytes faria snapshot.compare
		// comparar um retrato com ele mesmo achando que são dois.
		return ja, nil
	}
	a.por[r.ID] = r
	a.ordem = append(a.ordem, r.ID)
	return r, nil
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

// somaDoArquivo calcula o sha256 em FLUXO.
//
// Em fluxo e não com ReadFile: um dump pode ter centenas de megabytes (o teto
// do dump.MaxDump é 512 MiB), e carregá-lo inteiro só para hashear duplicaria o
// pico de memória do carregamento que vem logo em seguida. É o mesmo motivo
// pelo qual env.Open existe ao lado de env.ReadFile.
func somaDoArquivo(caminho string) (string, error) {
	fh, err := os.Open(caminho)
	if err != nil {
		return "", err
	}
	defer fh.Close()
	h := sha256.New()
	if _, err := io.Copy(h, fh); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
