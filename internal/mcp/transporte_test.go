package mcp

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

// A CATRACA DO FRAME: recusar sem ressincronizar é teatro.
//
// Se o leitor recusa a linha gigante e NÃO drena até o próximo \n, a cauda dela
// é lida como mensagem nova. Um cliente hostil esconde um tools/call depois de
// 1 MiB de lixo e o servidor o executa como se o operador tivesse pedido. Este
// teste falha se alguém "otimizar" a drenagem.
func TestFrameGrandeRessincronizaNoProximoNewline(t *testing.T) {
	gigante := strings.Repeat("A", 500)
	contrabando := `{"jsonrpc":"2.0","id":9,"method":"tools/call"}`
	fluxo := gigante + "\n" + contrabando + "\n"

	l := NovoLeitor(strings.NewReader(fluxo), 64)

	if _, err := l.Linha(); !errors.Is(err, ErrFrameGrande) {
		t.Fatalf("linha acima do teto devia ser recusada, veio: %v", err)
	}
	b, err := l.Linha()
	if err != nil {
		t.Fatalf("depois da recusa o fluxo tem de continuar válido: %v", err)
	}
	if string(b) != contrabando {
		t.Fatalf("ressincronização errada.\nquero: %s\ntenho: %s", contrabando, b)
	}
	// E o que veio depois é uma requisição legítima, não um fragmento.
	if _, e := decodificar(b); e != nil {
		t.Fatalf("a mensagem seguinte devia decodificar: %v", e)
	}
}

// Estourar o teto sem \n seguinte não pode virar "leitura normal": não há como
// ressincronizar, e o erro precisa dizer o que houve.
func TestFrameGrandeSemNewlineFinal(t *testing.T) {
	l := NovoLeitor(strings.NewReader(strings.Repeat("A", 500)), 64)
	if _, err := l.Linha(); !errors.Is(err, ErrFrameGrande) {
		t.Fatalf("quero ErrFrameGrande, tenho %v", err)
	}
}

// O teto é sobre o ACUMULADO, e o buffer interno do bufio não pode ser
// confundido com ele: uma linha de 100 KiB tem de passar com teto de 1 MiB,
// mesmo o bufio girando de 64 KiB em 64 KiB.
func TestLinhaMaiorQueOBufferInternoPassaDentroDoTeto(t *testing.T) {
	grande := strings.Repeat("B", 100<<10)
	l := NovoLeitor(strings.NewReader(grande+"\n"), MaxLinhaPadrao)
	b, err := l.Linha()
	if err != nil {
		t.Fatalf("linha de 100 KiB devia caber no teto de 1 MiB: %v", err)
	}
	if len(b) != len(grande) {
		t.Fatalf("tamanho errado: quero %d, tenho %d", len(grande), len(b))
	}
}

func TestUltimaLinhaSemNewlineVale(t *testing.T) {
	msg := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	l := NovoLeitor(strings.NewReader(msg), 0)
	b, err := l.Linha()
	if err != nil || string(b) != msg {
		t.Fatalf("quero %q/nil, tenho %q/%v", msg, b, err)
	}
	if _, err := l.Linha(); !errors.Is(err, io.EOF) {
		t.Fatalf("depois da última linha quero EOF, tenho %v", err)
	}
}

// CRLF vindo de um cliente Windows não pode virar "invalid character", que
// manda quem depura procurar defeito no lugar errado.
func TestCRLFEhTolerado(t *testing.T) {
	msg := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	l := NovoLeitor(strings.NewReader(msg+"\r\n"), 0)
	b, _ := l.Linha()
	if string(b) != msg {
		t.Fatalf("o \\r devia ter sido tirado, tenho %q", b)
	}
}

func TestDecodificarRecusaOQueASpecProibe(t *testing.T) {
	casos := []struct {
		nome, linha string
		code        int
	}{
		{"lote", `[{"jsonrpc":"2.0","id":1,"method":"tools/list"}]`, CodInvalidRequest},
		{"json inválido", `{"jsonrpc":`, CodParseError},
		{"sem jsonrpc", `{"id":1,"method":"tools/list"}`, CodInvalidRequest},
		{"jsonrpc 1.0", `{"jsonrpc":"1.0","id":1,"method":"x"}`, CodInvalidRequest},
		{"sem method", `{"jsonrpc":"2.0","id":1}`, CodInvalidRequest},
		{"id nulo", `{"jsonrpc":"2.0","id":null,"method":"x"}`, CodInvalidRequest},
		{"frame vazio", `   `, CodInvalidRequest},
	}
	for _, c := range casos {
		t.Run(c.nome, func(t *testing.T) {
			r, e := decodificar([]byte(c.linha))
			if e == nil {
				t.Fatalf("devia ter sido recusado, veio %+v", r)
			}
			if e.Code != c.code {
				t.Fatalf("código errado: quero %d, tenho %d (%s)", c.code, e.Code, e.Message)
			}
		})
	}
}

func TestNotificacaoNaoTemID(t *testing.T) {
	r, e := decodificar([]byte(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{}}`))
	if e != nil {
		t.Fatalf("notificação válida foi recusada: %v", e)
	}
	if !r.EhNotificacao() {
		t.Fatal("mensagem sem id tem de ser notificação — o receptor NÃO responde")
	}
}

// A invariante do transporte: uma mensagem, uma linha — mesmo quando o Result
// chega indentado de um canto distante do código. Quem a sustenta é o
// encoding/json, que COMPACTA o RawMessage; este teste existe para que uma
// troca de encoder no futuro não a leve embora em silêncio.
func TestResultIndentadoContinuaUmFrameSo(t *testing.T) {
	var buf bytes.Buffer
	if err := NovoEscritor(&buf).Enviar(Resposta{
		JSONRPC: "2.0", ID: json.RawMessage(`1`),
		Result: json.RawMessage("{\n  \"a\": 1\n}"),
	}); err != nil {
		t.Fatalf("indentado devia ser compactado, não recusado: %v", err)
	}
	if n := bytes.Count(buf.Bytes(), []byte("\n")); n != 1 {
		t.Fatalf("quero 1 newline (a terminadora), tenho %d: %q", n, buf.String())
	}
}

// E o que NÃO pode acontecer de jeito nenhum: escrita parcial. Um frame pela
// metade dessincroniza o fluxo, e o leitor do outro lado não tem como perceber
// — ele lê a cauda como mensagem nova. O erro precisa vir ANTES do primeiro
// byte sair.
func TestResultInvalidoNaoEscreveNadaPelaMetade(t *testing.T) {
	casos := map[string]json.RawMessage{
		"newline crua dentro de string": json.RawMessage("{\"a\": \"x\ny\"}"),
		"JSON inválido":                 json.RawMessage("{invalido"),
	}
	for nome, r := range casos {
		t.Run(nome, func(t *testing.T) {
			var buf bytes.Buffer
			if err := NovoEscritor(&buf).Enviar(Resposta{
				JSONRPC: "2.0", ID: json.RawMessage(`1`), Result: r,
			}); err == nil {
				t.Fatal("devia ter errado antes de escrever")
			}
			if buf.Len() != 0 {
				t.Fatalf("nada podia ter saído, tenho %q", buf.String())
			}
		})
	}
}

func TestEnviarEscreveUmaLinhaSo(t *testing.T) {
	var buf bytes.Buffer
	e := NovoEscritor(&buf)
	if err := e.Enviar(Resposta{
		JSONRPC: "2.0", ID: json.RawMessage(`1`), Result: json.RawMessage(`{"resultType":"complete"}`),
	}); err != nil {
		t.Fatal(err)
	}
	if n := bytes.Count(buf.Bytes(), []byte("\n")); n != 1 {
		t.Fatalf("quero exatamente 1 newline (a terminadora), tenho %d: %q", n, buf.String())
	}
	if !bytes.HasSuffix(buf.Bytes(), []byte("\n")) {
		t.Fatal("o frame precisa terminar em newline")
	}
}

// Texto do host com ESC e newline não pode quebrar o frame: é o mesmo vetor que
// report.Safe fecha no terminal, aqui contra o parser do cliente.
func TestTextoDoHostNaoQuebraOFrame(t *testing.T) {
	hostil := "nginx: worker\x1b[2J\n\nRESULT: OK\n"
	payload, _ := json.Marshal(map[string]string{"argv": hostil})

	var buf bytes.Buffer
	e := NovoEscritor(&buf)
	if err := e.Enviar(Resposta{JSONRPC: "2.0", ID: json.RawMessage(`1`), Result: payload}); err != nil {
		t.Fatalf("o encoder devia ter escapado tudo: %v", err)
	}
	if n := bytes.Count(buf.Bytes(), []byte("\n")); n != 1 {
		t.Fatalf("o texto do host quebrou o frame em %d linhas", n)
	}
	// E o valor chega inteiro do outro lado: escapar não é truncar. A forense
	// precisa dos bytes que o atacante escolheu.
	l := NovoLeitor(bytes.NewReader(buf.Bytes()), 0)
	linha, _ := l.Linha()
	var volta struct {
		Result struct {
			Argv string `json:"argv"`
		} `json:"result"`
	}
	if err := json.Unmarshal(linha, &volta); err != nil {
		t.Fatal(err)
	}
	if volta.Result.Argv != hostil {
		t.Fatalf("os bytes do host têm de sobreviver inteiros.\nquero %q\ntenho %q", hostil, volta.Result.Argv)
	}
}

// O id volta EXATAMENTE como veio. Passar por `any` transformaria 1 em float64
// e o devolveria como "1e+00" conforme o encoder — e cliente que casa resposta
// por igualdade estrita perde a correlação sem nenhum erro visível.
func TestIDVoltaFielAoQueVeio(t *testing.T) {
	for _, id := range []string{`1`, `"abc-1"`, `9007199254740993`} {
		r, e := decodificar([]byte(`{"jsonrpc":"2.0","id":` + id + `,"method":"tools/list"}`))
		if e != nil {
			t.Fatalf("id %s: %v", id, e)
		}
		var buf bytes.Buffer
		if err := NovoEscritor(&buf).Enviar(Resposta{
			JSONRPC: "2.0", ID: r.ID, Result: json.RawMessage(`{}`),
		}); err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(buf.Bytes(), []byte(`"id":`+id+`,`)) {
			t.Fatalf("id %s não voltou fiel: %s", id, buf.String())
		}
	}
}

func TestLerMetaVemDeDentroDeParams(t *testing.T) {
	// A localização do _meta é fácil de errar, e errar faz TODA requisição bem
	// formada ser recusada por campo obrigatório ausente.
	params := json.RawMessage(`{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28",` +
		`"io.modelcontextprotocol/clientCapabilities":{}}}`)
	m := lerMeta(params)
	if m == nil || m.Versao != Versao2026 {
		t.Fatalf("quero a versão 2026 lida de params._meta, tenho %+v", m)
	}
	if m.Caps == nil {
		t.Fatal("clientCapabilities é obrigatório e precisa ser distinguível de ausente")
	}
	if lerMeta(json.RawMessage(`{}`)) != nil {
		t.Fatal("params sem _meta tem de devolver nil, não um meta zerado")
	}
}
