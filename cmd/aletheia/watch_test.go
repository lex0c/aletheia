package main

import (
	"bytes"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lex0c/aletheia/internal/check"
)

// A regra da SPEC 7.9 vale para o `watch` como vale para o `scan`: zero exige
// achado nenhum E cobertura completa. Ela faltava aqui — uma vigília de oito
// horas que nunca conseguiu ler /proc de ninguém terminava com exit 0, que é a
// ferramenta dizendo "olhei a noite toda e não vi nada" sobre uma noite em que
// ela não olhou.
func TestVigiaCegaNaoSaiZero(t *testing.T) {
	casos := []struct {
		nome string
		w    vigia
		quer int
	}{
		{"noite limpa e cobertura completa", vigia{}, 0},
		{"cobertura falhou em algum ciclo", vigia{coberturaFalhou: true}, 1},
		{"aviso vale mais que lacuna", vigia{pior: check.SevWarn}, 1},
		{"crítico vence tudo", vigia{pior: check.SevCritical, coberturaFalhou: true}, 2},
	}
	for _, c := range casos {
		if got := c.w.exit(); got != c.quer {
			t.Errorf("%s: exit = %d, queria %d", c.nome, got, c.quer)
		}
	}
}

// O ERRO NO PRIMEIRO JSONL TAMBÉM QUEBRA O JSONL.
//
// Havia dois caminhos de escrita e só um marcava. O relatório inicial — o ciclo
// 0, que é o retrato inteiro — imprimia o erro no stderr e seguia com
// jsonQuebrado em false. A sequência que sai disso é a pior possível: a
// primeira escrita falha, o arquivo já nasce truncado, as seguintes funcionam,
// nada mais falha, e a vigília termina com exit 0 — "olhei a noite toda e não
// vi nada" sobre um registro que a ferramenta SABE estar incompleto.
func TestErroNoJSONLInicialAfetaOExit(t *testing.T) {
	w := &vigia{jsonW: arquivoFechado(t)}
	w.emiteJSON(&check.Report{}, &facts.Facts{}, &env.Env{})

	if !w.jsonQuebrado {
		t.Fatal("o erro do relatório inicial não marcou o JSONL como quebrado")
	}
	if got := w.exit(); got != 1 {
		t.Errorf("exit = %d, quer 1: um JSONL truncado com exit 0 é a ferramenta "+
			"afirmando completude sobre um arquivo que ela sabe estar incompleto", got)
	}
}

// E OS DOIS CAMINHOS PASSAM PELO MESMO PONTO.
//
// Sem isto, o conserto seria só a linha que faltava, e o próximo caminho de
// escrita nasceria com o mesmo defeito.
func TestOsDoisCaminhosDeJSONMarcamIgual(t *testing.T) {
	inc := &vigia{jsonW: arquivoFechado(t)}
	inc.escreveJSON(map[string]string{"event": "novo"})
	if !inc.jsonQuebrado {
		t.Error("o caminho incremental não marcou")
	}

	ini := &vigia{jsonW: arquivoFechado(t)}
	ini.emiteJSON(&check.Report{}, &facts.Facts{}, &env.Env{})
	if !ini.jsonQuebrado {
		t.Error("o caminho inicial não marcou")
	}
}

// arquivoFechado devolve um descritor cuja escrita falha, que é o que a
// partição cheia às 03:00 produz.
func arquivoFechado(t *testing.T) *os.File {
	t.Helper()
	fh, err := os.CreateTemp(t.TempDir(), "jsonl")
	if err != nil {
		t.Fatal(err)
	}
	fh.Close()
	return fh
}

// O ESTADO DA VIGÍLIA TEM TETO, E O TETO VIRA LACUNA.
//
// `visto` guarda tudo que já apareceu alguma vez e `eventos` guardava toda
// transição. Numa vigília que `--for 0` deixa indefinida, um host que produz
// identidade nova continuamente — /tmp/x-1, /tmp/x-2, ... — fazia os dois
// crescerem enquanto o comando estivesse ligado, no comando cujo caso de uso é
// justamente ficar horas ligado.
//
// O teto NÃO é um LRU de propósito: descartar a identidade mais antiga faria a
// pergunta "isto é novo?" voltar a ser respondida — com "sim", sobre algo que a
// vigília já tinha visto e esqueceu. Um teto que transforma a resposta certa em
// resposta errada é pior que um teto que recusa a responder.
func TestEstadoDaVigiliaEhLimitado(t *testing.T) {
	w := &vigia{humano: io.Discard, visto: map[string]check.Finding{}, eventos: novoRegistro()}

	// Enche o conjunto até o teto. Tudo cabe, e nada é declarado.
	for i := 0; i < maxIdentidadesVigiadas; i++ {
		if !w.lembra("k"+strconv.Itoa(i), check.Finding{}) {
			t.Fatalf("recusou a identidade %d, abaixo do teto de %d", i, maxIdentidadesVigiadas)
		}
	}
	if w.estadoEsgotado {
		t.Fatal("declarou esgotamento no teto exato, sem ter recusado nada")
	}
	if got := w.exit(); got != 0 {
		t.Errorf("exit = %d antes de esgotar", got)
	}

	// A próxima identidade NOVA não cabe.
	if w.lembra("nova", check.Finding{}) {
		t.Fatal("aceitou acima do teto")
	}
	if !w.estadoEsgotado {
		t.Fatal("recusou e não declarou")
	}
	if len(w.visto) != maxIdentidadesVigiadas {
		t.Errorf("o conjunto cresceu para %d", len(w.visto))
	}

	// Uma identidade JÁ CONHECIDA continua sendo atualizada: ela não faz o
	// conjunto crescer, e recusá-la desligaria a vigília do que já se sabe.
	if !w.lembra("k0", check.Finding{Title: "mudou"}) {
		t.Error("recusou uma identidade que já estava no conjunto")
	}
	if w.visto["k0"].Title != "mudou" {
		t.Error("a identidade conhecida não foi atualizada")
	}

	// E o esgotamento não pode terminar em zero: o comando existe para
	// responder "o que MUDOU", e ele deixou de conseguir responder isso.
	if got := w.exit(); got != 1 {
		t.Errorf("exit = %d com estado esgotado, quer 1: terminar em zero seria "+
			"dizer \"nada mudou\" quando a resposta honesta é \"não sei mais dizer\"", got)
	}
}

// O RESUMO NÃO GUARDA UMA LINHA POR TRANSIÇÃO.
//
// O evento já FOI emitido quando aconteceu, no humano e no JSONL. Guardá-lo de
// novo só servia ao resumo, e o resumo não fica melhor com dez mil linhas.
func TestResumoGuardaContagemExataEExemplosLimitados(t *testing.T) {
	r := novoRegistro()
	const n = maxExemplosPorTipo * 3
	for i := 0; i < n; i++ {
		r.anota("novo", "linha "+strconv.Itoa(i))
	}
	if r.total["novo"] != n {
		t.Errorf("a contagem tem de ser EXATA: %d de %d", r.total["novo"], n)
	}
	if len(r.exemplos["novo"]) != maxExemplosPorTipo {
		t.Errorf("guardou %d exemplos, teto é %d", len(r.exemplos["novo"]), maxExemplosPorTipo)
	}
	if r.vazio() {
		t.Error("vazio() com eventos anotados")
	}
	vazio := novoRegistro()
	if !vazio.vazio() {
		t.Error("um registro novo não está vazio")
	}
}

// E O RESUMO DIZ QUANTAS FICARAM DE FORA.
//
// Sem isso o tamanho da lista é lido como o tamanho do que aconteceu, que é a
// mesma classe de mentira que um teto silencioso comete.
func TestResumoDeclaraOQueNaoListou(t *testing.T) {
	var buf bytes.Buffer
	w := &vigia{humano: &buf, visto: map[string]check.Finding{}, eventos: novoRegistro(),
		am: &amostrador{}}
	for i := 0; i < maxExemplosPorTipo+37; i++ {
		w.eventos.anota("novo", "  linha "+strconv.Itoa(i))
	}
	w.resumo(time.Minute, "concluído")

	out := buf.String()
	if !strings.Contains(out, strconv.Itoa(maxExemplosPorTipo+37)) {
		t.Errorf("a contagem total não aparece:\n%s", out)
	}
	if !strings.Contains(out, "e mais 37 não listada") {
		t.Errorf("não disse quantas ficaram de fora:\n%s", out)
	}
}

// A IDENTIDADE QUE NÃO COUBE NÃO PODE "SUMIR".
//
// Ela entra em `presente` — foi vista no ciclo anterior — e NÃO entra em
// `visto`, porque o teto a recusou. O laço de desaparecimento lia o mapa e
// emitia uma linha com o achado ZERO: sem título, sem referência, sem assunto.
//
// E não é cosmético: dizer que algo sumiu é uma afirmação sobre ele ter estado
// lá, e é essa afirmação que o esgotamento tirou.
func TestIdentidadeNaoClassificadaNaoVira(t *testing.T) {
	var buf bytes.Buffer
	w := &vigia{humano: &buf, visto: map[string]check.Finding{}, eventos: novoRegistro(),
		presente: map[string]bool{"fantasma": true}}

	// "fantasma" está em presente e não em visto: é a identidade que o teto
	// recusou no ciclo anterior.
	atual := map[string]bool{}
	for k := range w.presente {
		if atual[k] {
			continue
		}
		fd, conhecida := w.visto[k]
		if !conhecida {
			w.naoClassificadas++
			continue
		}
		w.registra(evento{Kind: "sumiu", Fd: fd, Quando: time.Now()})
	}

	if w.eventos.total["sumiu"] != 0 {
		t.Errorf("emitiu %d evento(s) de desaparecimento sobre uma identidade "+
			"que nunca foi registrada", w.eventos.total["sumiu"])
	}
	if w.naoClassificadas != 1 {
		t.Errorf("naoClassificadas = %d, quer 1", w.naoClassificadas)
	}
	if strings.Contains(buf.String(), "－") {
		t.Errorf("imprimiu uma linha de desaparecimento vazia:\n%s", buf.String())
	}
}
