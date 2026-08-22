package mcp

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// A TRANSCRIÇÃO DOURADA: o laço inteiro, sobre o fio.
//
// Todas as outras catracas deste pacote chamam função — `selar`, `chamarTool`,
// `decodificar`. Nenhuma atravessa `Servir`, que é onde as três coisas se
// juntam: ler o frame, decidir a era, escrever a resposta. Um defeito ali
// (ressincronização perdida, id trocado, resposta a notificação, era decidida
// pela requisição errada) passa por todos os testes de unidade.
//
// # Por que a saída dourada é a FORMA, e não o conteúdo
//
// A tentação é gravar as respostas inteiras. Elas mudam a cada check novo, a
// cada campo de cobertura, a cada tool — e um dourado que quebra a cada commit
// de produto vira um `-update` reflexo, que é o mesmo que não ter teste.
//
// O que este arquivo trava é o CONTRATO DE PROTOCOLO: quem respondeu, com que
// id, com que chaves de topo, com que código de erro, e quem NÃO respondeu.
// Isso é exatamente "deriva de protocolo", e é estável contra mudança de
// produto.
//
//	go test ./internal/mcp -run TestTranscricaoDourada -update

var atualizarDourada = flag.Bool("update", false, "reescreve a transcrição dourada")

const caminhoDourado = "testdata/transcricao.txt"

func TestTranscricaoDourada(t *testing.T) {
	entrada, err := os.ReadFile(caminhoDourado)
	if err != nil {
		t.Fatalf("%v — gere com: go test ./internal/mcp -run TestTranscricaoDourada -update", err)
	}

	var pedidos []string
	for _, ln := range strings.Split(string(entrada), "\n") {
		if strings.HasPrefix(ln, "> ") {
			pedidos = append(pedidos, expandir(strings.TrimPrefix(ln, "> ")))
		}
	}
	if len(pedidos) == 0 {
		t.Fatal("a transcrição não tem requisição nenhuma")
	}

	s, _ := servidorDeTeste(t, fatosDeTeste())
	var saida bytes.Buffer
	if err := s.Servir(strings.NewReader(strings.Join(pedidos, "\n")+"\n"), &saida); err != nil {
		t.Fatal(err)
	}

	novo := montarDourada(t, pedidos, saida.Bytes())
	if *atualizarDourada {
		if err := os.WriteFile(caminhoDourado, []byte(novo), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	if string(entrada) != novo {
		t.Errorf("a transcrição divergiu — o CONTRATO DE PROTOCOLO mudou.\n\n"+
			"Se foi de propósito, confira linha a linha e regrave:\n"+
			"    go test ./internal/mcp -run TestTranscricaoDourada -update\n\n"+
			"tenho:\n%s\nquero:\n%s", novo, entrada)
	}
}

// montarDourada monta o documento: cada requisição seguida da FORMA da resposta.
//
// # Por que LOCKSTEP, e não correlação por id
//
// A primeira versão indexava as respostas por id e, para notificação, escrevia
// "(sem resposta)" direto — sem conferir que resposta nenhuma tinha vindo.
// Medido: removendo o `continue` que trata notificação no laço do servidor, o
// dourado continuava passando. Uma asserção que não pode falhar, no arquivo que
// existe justamente para pegar deriva de protocolo.
//
// O laço é sequencial, então as respostas saem na ordem das requisições. Andar
// em lockstep afirma três coisas de uma vez: que cada requisição foi respondida
// UMA vez, que notificação NÃO consome resposta, e que o id que voltou é o que
// foi enviado. Se uma notificação passar a responder, o passo desanda e todo id
// seguinte diverge — alto, e não em silêncio.
func montarDourada(t *testing.T, pedidos []string, saida []byte) string {
	t.Helper()

	type resposta struct{ id, forma string }
	var respostas []resposta
	for _, ln := range strings.Split(strings.TrimSpace(string(saida)), "\n") {
		if ln == "" {
			continue
		}
		var m map[string]json.RawMessage
		if err := json.Unmarshal([]byte(ln), &m); err != nil {
			t.Fatalf("resposta que não é JSON: %q", ln)
		}
		id := "null"
		if b, ok := m["id"]; ok {
			id = strings.TrimSpace(string(b))
		}
		respostas = append(respostas, resposta{id, formaDaResposta(t, m)})
	}

	var b strings.Builder
	b.WriteString(cabecalhoDourado)
	k := 0
	for _, p := range pedidos {
		b.WriteString("> " + encolher(p) + "\n")
		id := idDoPedido(p)
		if id == "" {
			// Notificação: NÃO consome resposta. Se o servidor tiver respondido,
			// o lockstep desanda daqui para a frente.
			b.WriteString("< (sem resposta — notificação)\n\n")
			continue
		}
		if k >= len(respostas) {
			b.WriteString("< (SEM RESPOSTA)\n\n")
			continue
		}
		r := respostas[k]
		k++
		linha := r.forma
		// O id que voltou tem de ser o que foi enviado. O frame que não pôde ser
		// lido responde `null`, e é o único caso legítimo.
		if r.id != id && !(r.id == "null" && idIlegivel(p)) {
			linha += "   <<< ID DIVERGENTE: enviei " + id + ", voltou " + r.id
		}
		b.WriteString("< " + linha + "\n\n")
	}
	if k < len(respostas) {
		b.WriteString("# SOBRARAM " + strconv.Itoa(len(respostas)-k) +
			" RESPOSTA(S) SEM REQUISIÇÃO — alguma notificação foi respondida\n")
	}
	return b.String()
}

// idIlegivel diz que o id não pôde ser USADO — o único caso em que a spec
// permite responder com id nulo.
//
// # Por que ele precisou ficar mais preciso
//
// A versão anterior só reconhecia "documento não abriu" e "id null", então
// marcava ID DIVERGENTE para id `true`, `{}` e `[]` — que são recusados de
// propósito, porque não servem para correlacionar, e para os quais `null` é a
// resposta CERTA. Três acusações falsas.
//
// E elas custaram caro. Havia uma QUARTA linha de ID DIVERGENTE no arquivo, e
// essa era real: o servidor descartava o id de toda requisição recusada por
// validação, e a de id 14 voltava como null. Eu li as quatro, vi três que sabia
// serem esperadas, e li a quarta como mais uma. Um detector que produz ruído
// aceito treina quem o lê a ignorar o sinal — e o sinal aqui era um defeito de
// protocolo que uma revisão externa acabou tendo de apontar.
func idIlegivel(p string) bool {
	var m map[string]json.RawMessage
	if json.Unmarshal([]byte(p), &m) != nil {
		return true // o documento não abriu
	}
	b, ok := m["id"]
	if !ok {
		return true
	}
	t := strings.TrimSpace(string(b))
	if t == "null" || t == "" {
		return true
	}
	// String ou número servem para correlacionar; o resto foi lido e recusado,
	// e para ele `null` é a resposta certa.
	return !(t[0] == '"' || t[0] == '-' || (t[0] >= '0' && t[0] <= '9'))
}

// formaDaResposta reduz a resposta ao que é contrato de protocolo.
func formaDaResposta(t *testing.T, m map[string]json.RawMessage) string {
	t.Helper()
	if e, ok := m["error"]; ok {
		var er struct {
			Code int `json:"code"`
		}
		if err := json.Unmarshal(e, &er); err != nil {
			t.Fatal(err)
		}
		return "erro " + strconv.Itoa(er.Code)
	}
	res, ok := m["result"]
	if !ok {
		return "(sem result nem error)"
	}
	var corpo map[string]json.RawMessage
	if err := json.Unmarshal(res, &corpo); err != nil {
		t.Fatal(err)
	}
	chaves := make([]string, 0, len(corpo))
	for k := range corpo {
		chaves = append(chaves, k)
	}
	sort.Strings(chaves)
	return "ok " + strings.Join(chaves, ",")
}

// MarcadorLongo é o único desvio de "o arquivo é a entrada literal": um valor
// de 5000 caracteres, para exercitar o teto de argumento textual, encheria a
// transcrição de ruído e a tornaria ilegível — que é o oposto do que um
// documento dourado serve. Ele é expandido na leitura.
const MarcadorLongo = "__TEXTO_ACIMA_DO_TETO__"

func expandir(p string) string {
	return strings.ReplaceAll(p, MarcadorLongo, strings.Repeat("a", MaxTexto+1))
}

func encolher(p string) string {
	return strings.ReplaceAll(p, strings.Repeat("a", MaxTexto+1), MarcadorLongo)
}

// idDoPedido devolve o id como TEXTO, ou vazio para notificação.
func idDoPedido(p string) string {
	var m map[string]json.RawMessage
	if json.Unmarshal([]byte(p), &m) != nil {
		return "null"
	}
	b, ok := m["id"]
	if !ok {
		return ""
	}
	return strings.TrimSpace(string(b))
}

const cabecalhoDourado = `# TRANSCRIÇÃO DOURADA — o contrato de protocolo do servidor MCP.
#
# GERADO. Não edite à mão:
#     go test ./internal/mcp -run TestTranscricaoDourada -update
#
# "> " é a requisição, uma por linha, como ela entra no stdin — com um único
# desvio: __TEXTO_ACIMA_DO_TETO__ é expandido para 4097 caracteres na leitura,
# porque colar o valor inteiro aqui tornaria o documento ilegível.
# "< " é a FORMA da resposta: as chaves de topo do result, ou o código do erro.
#
# A forma, e não o conteúdo: as respostas mudam a cada check novo e a cada tool,
# e um dourado que quebra a cada commit de produto vira um -update reflexo. O
# que este arquivo trava é quem respondeu, com que id, com que chaves e com que
# código — que é o que "deriva de protocolo" quer dizer.

`

// E o caminho do arquivo, para o -update saber criar o diretório.
var _ = filepath.Join
