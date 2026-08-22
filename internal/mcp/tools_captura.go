package mcp

import (
	"encoding/json"
	"time"

	"github.com/lex0c/aletheia/internal/env"
)

// A aquisição: as duas únicas tools que fazem o host ser LIDO.
//
// Todo o resto deste servidor responde de memória sobre um retrato imutável.
// Estas duas são a fronteira, e é por isso que elas só existem nos modos de
// aquisição — em ModoSnapshot nenhuma leitura do host acontece, e ter aqui uma
// tool capaz de provocá-la contradiria a promessa daquele modo.

var toolSnapshotCapture = Ferramenta{
	Dados:  DadosRedigidosNaOrigem,
	Nome:   "snapshot.capture",
	Titulo: "Tirar um retrato do host AGORA",
	Descricao: "Lê o host e cunha um snapshot_id. Todas as outras tools respondem " +
		"sobre um retrato, nunca sobre o estado do momento — é isso que impede uma " +
		"investigação de trinta chamadas de misturar quatro instantes diferentes, e " +
		"de perguntar sobre um pid que já morreu (ou pior, que já foi reciclado).\n\n" +
		"scope=volatile lê /proc e sockets, e é ~9x mais barato: é o que pega " +
		"processo efêmero. Ele NÃO sustenta achado — findings.list sobre um retrato " +
		"volátil devolve zero achados COM o catálogo inteiro em not_checked, porque " +
		"um check de unit encontraria zero units e diria 'nada encontrado' onde o " +
		"certo é 'não olhei'.\n\n" +
		"scope=complete é a varredura inteira, e a única que sustenta findings. " +
		"Ela custa segundos no host investigado e, enquanto roda, este servidor não " +
		"responde outra chamada — inclusive um cancelamento, que só é notado depois. " +
		"É o limite real: os coletores não são interrompíveis.",
	Entrada: json.RawMessage(`{"type":"object","additionalProperties":false,
"properties":{
 "scope":{"type":"string","enum":["volatile","complete"],"default":"complete",
  "description":"volatile: /proc e sockets, barato, NAO sustenta achado. complete: varredura inteira, custa segundos no host."}}}`),
	Saida: esquemaEnvelope(`{"type":"object","required":["snapshot_id","scope"],
"properties":{
 "snapshot_id":{"type":"string","description":"o handle. O prefixo snap-live- diz que ele NAO é hash de conteudo: uma captura nunca virou bytes em disco, entao nao ha o que verificar depois."},
 "label":{"type":"string"},
 "scope":{"type":"string"},
 "supports_findings":{"type":"boolean","description":"false num retrato volatil: findings.list ali devolve zero achados com o catalogo inteiro em not_checked"}}}`, false),
	Modos: []Modo{ModoLive, ModoImagem},
	Rodar: func(s *Servidor, args json.RawMessage) (any, *ErroRPC) {
		var a struct {
			Escopo string `json:"scope,omitempty"`
		}
		if er := decodificarArgs(args, &a); er != nil {
			return nil, er
		}
		escopo := Escopo(a.Escopo)
		if a.Escopo == "" {
			escopo = EscopoCompleto
		}
		if escopo != EscopoVolatil && escopo != EscopoCompleto {
			return nil, erro(CodInvalidParams,
				`scope desconhecido: use "volatile" ou "complete"`)
		}
		if s.adquirir == nil {
			return nil, erro(CodInternalError, "este servidor não tem aquisição")
		}
		e, err := s.adquirir()
		if err != nil {
			return nil, erro(CodInternalError, "não foi possível sondar o ambiente: "+
				err.Error())
		}
		// O ORÇAMENTO, no único mecanismo que existe para ele: um teto
		// cooperativo na varredura de filesystem. Ela para no prazo e DECLARA o
		// que não examinou — a lacuna entra na cobertura, e não vira "nada
		// encontrado". Não interrompe a coleta no meio, e a descrição da tool
		// diz isso em vez de fingir.
		if escopo == EscopoCompleto && s.pol.Budget > 0 {
			e.WalkDeadline = time.Now().Add(s.pol.Budget)
		}
		r, err := s.acervo.Capturar(e, escopo)
		if err != nil {
			e.Close()
			return nil, erro(CodInvalidParams, err.Error())
		}
		return envelopar(r, ObservabilidadeDeFatos(r.Fatos), map[string]any{
			"snapshot_id": r.ID, "label": r.Rotulo, "scope": string(escopo),
			"supports_findings": escopo == EscopoCompleto,
		}), nil
	},
}

var toolSnapshotRelease = Ferramenta{
	Dados:  DadosDoMotor,
	Nome:   "snapshot.release",
	Titulo: "Descartar um retrato",
	Descricao: "Libera a memória de um retrato capturado. Cada um segura os fatos " +
		"INTEIROS deste host na memória de um processo que roda NO host investigado " +
		"— e a ferramenta promete passar pouco recurso ali. Libere o que já não vai " +
		"citar.",
	Entrada: json.RawMessage(`{"type":"object","additionalProperties":false,
"required":["snapshot_id"],
"properties":{"snapshot_id":{"type":"string"}}}`),
	Saida: json.RawMessage(`{"type":"object","required":["released"],
"properties":{"released":{"type":"string"},"remaining":{"type":"integer"}}}`),
	Modos: []Modo{ModoLive, ModoImagem},
	Rodar: func(s *Servidor, args json.RawMessage) (any, *ErroRPC) {
		var a argsSnapshot
		if er := decodificarArgs(args, &a); er != nil {
			return nil, er
		}
		if a.SnapshotID == "" {
			return nil, erro(CodInvalidParams, `snapshot.release exige "snapshot_id"`)
		}
		if err := s.acervo.Liberar(a.SnapshotID); err != nil {
			return nil, erro(CodInvalidParams, err.Error())
		}
		return map[string]any{
			"released": a.SnapshotID, "remaining": len(s.acervo.Todos()),
		}, nil
	},
}

// Aquisicao monta o ambiente de uma captura.
//
// Ela vem de FORA do pacote porque é decisão de linha de comando: a versão do
// binário, o --root, e a recusa de autoload de módulo. `internal/mcp` não
// deveria conhecer nenhuma das três.
type Aquisicao func() (*env.Env, error)
