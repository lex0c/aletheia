package mcp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"sync"
)

// O transporte stdio: uma mensagem JSON-RPC por linha, delimitada por \n, sem
// newline embutida. stdout é EXCLUSIVAMENTE protocolo; stderr é
// exclusivamente diagnóstico e auditoria.
//
// # Por que isto é código de segurança
//
// O teto de frame ANTES do json.Unmarshal não é ideia nova neste repositório:
// é a terceira instância do mesmo raciocínio, e as duas primeiras foram
// escritas depois de um defeito real.
//
//	env.MaxLeitura   um arquivo esparso de 8 GB (truncate -s 8G, zero byte de
//	                 disco, sem privilégio nenhum) derruba a varredura por OOM
//	                 — e o runtime aborta com status 2, que o contrato desta
//	                 ferramenta define como "CRITICAL: alta confiança"
//	dump.MaxDump     "sem teto, um arquivo gigante estoura a memória do
//	                 analisador por OOM antes de qualquer erro controlado"
//
// Um servidor MCP que pode estar rodando como root não pode aceitar uma linha
// de 4 GB e descobrir o limite depois de já tê-la alocado.

// MaxLinhaPadrao é o teto de UM frame de entrada.
//
// Folgado para o que este servidor recebe de propósito: a maior requisição real
// é um tools/call com um punhado de argumentos escalares. Um cliente que
// precisar de mais que isto está fazendo outra coisa.
const MaxLinhaPadrao int64 = 1 << 20 // 1 MiB

var (
	// ErrFrameGrande é RECUSA, não falha de leitura: o fluxo continua válido e
	// sincronizado, e a próxima chamada devolve a mensagem seguinte.
	ErrFrameGrande = errors.New("frame acima do teto: RECUSADO sem ser alocado")
)

// Leitor entrega um frame por chamada.
type Leitor struct {
	r   *bufio.Reader
	max int64
}

// NovoLeitor monta o leitor. `max <= 0` usa o padrão.
func NovoLeitor(r io.Reader, max int64) *Leitor {
	if max <= 0 {
		max = MaxLinhaPadrao
	}
	// O buffer do bufio é pequeno de propósito: ele NÃO é o teto. Quem limita é
	// `max`, contado sobre o acumulado; o bufio só decide de quantos em quantos
	// bytes o laço gira.
	return &Leitor{r: bufio.NewReaderSize(r, 64<<10), max: max}
}

// Linha devolve o próximo frame, sem o \n final.
//
// # A ressincronização, que é o ponto todo
//
// Ao estourar o teto, não basta recusar: é preciso DRENAR até o próximo \n
// antes de retomar. Sem isso, a cauda da linha gigante é lida como uma
// mensagem nova — e um cliente hostil (ou um proxy defeituoso) contrabandeia
// uma chamada que o operador nunca autorizou, escondida depois de 1 MiB de
// lixo. O teto sozinho vira teatro; o teto mais a drenagem é a defesa.
//
// A drenagem NÃO acumula: os bytes descartados nunca chegam a ficar na memória
// ao mesmo tempo, que é a razão de existir do teto.
func (l *Leitor) Linha() ([]byte, error) {
	var buf []byte
	estourou := false
	for {
		parte, err := l.r.ReadSlice('\n')

		// A verificação vem ANTES do append: somar primeiro e conferir depois
		// já teria alocado o que o teto existe para não alocar.
		if !estourou && int64(len(buf))+int64(len(parte)) > l.max {
			estourou = true
			buf = nil // devolve o que já foi acumulado; daqui em diante só se drena
		}
		if !estourou {
			// ReadSlice devolve uma fatia do buffer INTERNO, que a próxima
			// chamada reescreve. O append copia, e é por isso que ele é
			// obrigatório aqui e não uma conveniência.
			buf = append(buf, parte...)
		}

		switch {
		case errors.Is(err, bufio.ErrBufferFull):
			continue // a linha é maior que o buffer do bufio; segue montando ou drenando
		case err != nil:
			if estourou {
				// Estourou E acabou o fluxo: não há próximo \n para ressincronizar,
				// e o erro de frame é o que descreve o que aconteceu.
				return nil, ErrFrameGrande
			}
			if len(buf) > 0 {
				// Última linha sem \n final. Vale como frame; o EOF chega na
				// próxima chamada.
				return trimCR(buf), nil
			}
			return nil, err
		case estourou:
			return nil, ErrFrameGrande
		default:
			return trimCR(buf[:len(buf)-1]), nil // sem o \n
		}
	}
}

// trimCR tolera CRLF. Um cliente em Windows, ou um pipe que passou por uma
// ferramenta que converte, entrega \r\n — e o \r sobrando faz o json.Unmarshal
// falhar com "invalid character", que manda quem depura procurar o defeito no
// lugar errado.
func trimCR(b []byte) []byte {
	if n := len(b); n > 0 && b[n-1] == '\r' {
		return b[:n-1]
	}
	return b
}

// Escritor serializa uma mensagem por linha.
type Escritor struct {
	mu sync.Mutex
	w  *bufio.Writer
}

func NovoEscritor(w io.Writer) *Escritor {
	return &Escritor{w: bufio.NewWriterSize(w, 64<<10)}
}

// Enviar escreve UMA mensagem e dá flush.
//
// O flush por mensagem não é desperdício: o cliente está bloqueado esperando a
// resposta desta requisição, e um buffer segurando bytes vira um deadlock que
// se parece com lentidão.
//
// # A invariante "uma mensagem, uma linha", e quem a sustenta
//
// `Resposta.Result` é json.RawMessage — bytes JÁ serializados por outra camada
// —, então a pergunta óbvia é se uma newline pode escapar por ali e partir o
// frame em dois. Medido contra o runtime, nos três caminhos que existem:
//
//	RawMessage indentado        json.Marshal COMPACTA, e a newline some
//	newline crua dentro de str  Marshal ERRA — JSON não a permite
//	RawMessage inválido         Marshal ERRA
//
// Quem sustenta a invariante é o encoding/json. Nos dois casos de erro o que
// importa é QUANDO ele acontece: antes de qualquer byte sair. Uma escrita
// parcial dessincronizaria o fluxo, e é o defeito que o leitor do outro lado
// não tem como perceber — ele leria a cauda como mensagem nova.
//
// Aqui havia uma conferência de newline no buffer serializado. Ela foi tirada
// porque NÃO TINHA COMO DISPARAR: todo caminho passa pelo Marshal, e os três
// acima o provam. É o mesmo motivo pelo qual cross.thread_count saiu do mapa de
// kernelBreakers — um contrato listado que não podia ser exercido. Guarda que
// nenhum teste alcança é pior que guarda nenhuma: ela promete uma defesa que
// ninguém verifica.
func (e *Escritor) Enviar(v any) error {
	b, err := semEscapeHTML(v)
	if err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, err := e.w.Write(b); err != nil {
		return err
	}
	if err := e.w.WriteByte('\n'); err != nil {
		return err
	}
	return e.w.Flush()
}

// semEscapeHTML serializa sem transformar <, > e & em \u003c, \u003e e \u0026.
//
// O padrão do encoding/json escapa os três — herança de quem embute JSON em
// HTML —, e isso quebrava a única promessa que o envelope faz sobre o id: que
// ele volta BYTE A BYTE. Um id `"req<7>"` voltava `"req\u003c7\u003e"`. O
// valor JSON é igual, então quem desserializa não vê nada; quem correlaciona
// por bytes — que é exatamente o cliente que o comentário do Requisicao.ID diz
// estar protegendo — perde a correlação sem erro nenhum.
//
// Verificado contra o runtime: inteiro grande e não-ASCII já atravessavam
// intactos; só os três caracteres de HTML quebravam.
func semEscapeHTML(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	// O Encode acrescenta uma newline; o frame põe a dele.
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// decodificar transforma um frame em requisição, ou no erro que o cliente
// precisa ver.
//
// Recusa em voz alta o que a spec proíbe, em vez de tentar interpretar:
//
//	batch      a 2025-06-18 removeu batch do protocolo. Aceitá-lo "por
//	           tolerância" abriria um caminho de execução paralelo, com
//	           correlação de id própria, que nenhum teste cobre
//	id nulo    a spec diz textualmente que o id NÃO pode ser null — e null é
//	           indistinguível de ausente depois do Unmarshal, então uma
//	           requisição viraria notificação e ficaria sem resposta
//
// A requisição volta MESMO NA RECUSA, quando o id pôde ser lido.
//
// A spec JSON-RPC é literal: a resposta de erro leva o MESMO id da requisição,
// e só usa `null` quando o id NÃO PÔDE SER DETECTADO. A versão anterior
// devolvia nil junto do erro em toda validação — e o `jsonrpc` errado, o
// `method` ausente e o lote têm o id perfeitamente legível, já desserializado
// pela linha acima.
//
// O efeito é do lado do cliente, e é mudo: ele correlaciona por id, tem a
// requisição 14 pendente, e a recusa dela chega num envelope `null` que ele não
// casa com nada. A 14 fica esperando até o timeout dele.
//
// A DENÚNCIA ESTAVA ESCRITA. O montador da transcrição dourada compara o id
// enviado com o que voltou e imprime "ID DIVERGENTE" — e o arquivo tem quatro
// dessas, gravadas por mim, lidas por mim, e aceitas como se fossem o esperado.
// Escrever o detector não adianta se a saída dele não é lida como acusação.
func decodificar(linha []byte) (*Requisicao, *ErroRPC) {
	corte := bytes.TrimLeft(linha, " \t\r\n")
	if len(corte) == 0 {
		return nil, erro(CodInvalidRequest, "frame vazio")
	}
	if corte[0] == '[' {
		// Lote: a spec proíbe, e o id de dentro dele não é o id DESTA mensagem —
		// não há um só id a devolver. `null` é a resposta certa aqui.
		return nil, erro(CodInvalidRequest,
			"lote (batch) JSON-RPC não é suportado: foi removido do MCP na 2025-06-18 — "+
				"envie uma mensagem por linha")
	}
	var r Requisicao
	if err := json.Unmarshal(corte, &r); err != nil {
		// Aqui o id realmente não pôde ser detectado: o documento não abriu.
		return nil, erro(CodParseError, "JSON inválido")
	}
	if er := conferirTipoDoID(r.ID); er != nil {
		// Id de tipo inválido: ele foi LIDO e não serve para correlacionar.
		// Devolvê-lo seria ecoar um `true` como se fosse handle.
		return nil, er
	}
	if r.JSONRPC != "2.0" {
		return &r, erro(CodInvalidRequest, `campo "jsonrpc" ausente ou diferente de "2.0"`)
	}
	if r.Method == "" {
		return &r, erro(CodInvalidRequest, `campo "method" ausente`)
	}
	return &r, nil
}

// conferirTipoDoID recusa o que a spec não admite.
//
// Ela diz: o id é string OU número, e NÃO pode ser null. A versão anterior deste
// código dizia isso no comentário e conferia só o null — então `true`, `{}` e
// `[]` entravam, e o servidor os ecoava de volta como se fossem ids legítimos.
//
// A conferência é sobre o PRIMEIRO TOKEN dos bytes crus, e não sobre um valor
// decodificado, porque o id é devolvido byte a byte de propósito: passá-lo por
// `any` transformaria o inteiro 9007199254740993 num float64 e o devolveria
// arredondado, e cliente que casa resposta por igualdade estrita perderia a
// correlação sem nenhum erro visível.
func conferirTipoDoID(id json.RawMessage) *ErroRPC {
	b := bytes.TrimSpace(id)
	if len(b) == 0 {
		return nil // notificação: a ausência é legítima
	}
	switch c := b[0]; {
	case c == '"':
		return nil // string
	case c == '-' || (c >= '0' && c <= '9'):
		return nil // número
	}
	return erro(CodInvalidRequest,
		"id de tipo inválido: a spec admite string ou número, e mais nada — "+
			"null se confunde com notificação, e objeto ou booleano não são "+
			"correlacionáveis")
}
