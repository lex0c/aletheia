// Package mcp serve o Aletheia a um agente pelo Model Context Protocol, sobre
// stdio.
//
// A regra que vale para todo este pacote, e que nenhuma tool pode contornar:
//
//	O servidor concede OBSERVAÇÃO, não EXECUÇÃO. Dado do host é entrada
//	adversária. Privilégio é herdado, nunca adquirido. Evidência ausente
//	nunca é ausência de evidência.
//
// Nenhuma tool inicia conexão de rede, resolve nome, executa comando ou
// modifica o host. As interfaces LOCAIS de kernel que os coletores já usam —
// Netlink de diagnóstico, bpf(2), /proc, /sys, tracefs — continuam permitidas
// sob a política do Aletheia, sem autoload de módulo.
//
// # Por que o protocolo é escrito à mão
//
// O projeto não tem dependência Go externa (não há bloco `require` no go.mod
// nem go.sum), e a build reprodutível depende disso. O escopo aqui é pequeno o
// bastante para pagar: stdio, só tools, sem prompts, resources, HTTP, auth,
// sampling ou elicitation. O que ele NÃO é é código de conveniência — o parser
// lê bytes de um cliente e o servidor pode estar rodando como root, então o
// framing é tratado como código de segurança (ver transporte.go).
package mcp

import (
	"encoding/json"
	"fmt"
)

// As versões que este servidor fala.
//
// A primeira é a atual; as outras existem porque cliente real demora a migrar,
// e um servidor que só fala a versão nova não serve para o operador que está no
// meio de um incidente com o cliente que ele tem instalado.
const (
	Versao2026 = "2026-07-28"
	Versao2025 = "2025-11-25"
	Versao0625 = "2025-06-18"
)

// VersoesSuportadas é o que vai no `supportedVersions` do server/discover e no
// `data.supported` do erro de versão. Ordem: preferida primeiro.
var VersoesSuportadas = []string{Versao2026, Versao2025, Versao0625}

// Era é o formato de fio, e não a versão.
//
// A distinção existe porque a 2026-07-28 mudou a FORMA da resposta: todo
// resultado passou a carregar `resultType`, e as listas passaram a carregar
// `ttlMs`/`cacheScope`. Mandar esses campos para um cliente de 2025 é entregar
// um documento que ele lê torto — e mandar uma resposta de 2025 para um cliente
// de 2026 é omitir campo obrigatório. O encoder é POR ERA, e a era é derivada
// da versão que a requisição declarou, nunca de um padrão do servidor.
type Era uint8

const (
	// EraLegado: 2025-11-25 e antes. Handshake por `initialize`, resultado sem
	// `resultType`.
	EraLegado Era = iota
	// EraModerna: 2026-07-28. Sem handshake; versão e capabilities por
	// requisição, em `params._meta`.
	EraModerna
)

func (e Era) String() string {
	if e == EraModerna {
		return "2026"
	}
	return "2025"
}

// EraDaVersao mapeia versão declarada para formato de fio. Versão desconhecida
// devolve false: o chamador responde UnsupportedProtocolVersion em vez de
// adivinhar, porque adivinhar produz um documento que o cliente aceita e lê
// errado — falha silenciosa, que é a pior forma de falha num canal que carrega
// conclusão sobre host comprometido.
func EraDaVersao(v string) (Era, bool) {
	switch v {
	case Versao2026:
		return EraModerna, true
	case Versao2025, Versao0625:
		return EraLegado, true
	}
	return EraLegado, false
}

// As chaves reservadas de `_meta`. Ficam como constantes porque errar uma letra
// aqui não quebra nada visivelmente: o campo simplesmente não é encontrado, e o
// servidor passa a recusar requisição bem formada por "falta protocolVersion".
const (
	MetaVersao       = "io.modelcontextprotocol/protocolVersion"
	MetaCapsCliente  = "io.modelcontextprotocol/clientCapabilities"
	MetaInfoCliente  = "io.modelcontextprotocol/clientInfo"
	MetaInfoServidor = "io.modelcontextprotocol/serverInfo"
)

// Códigos de erro.
//
// A faixa -32020..-32099 é EXCLUSIVA da especificação: emitir código próprio
// dali é proibido. Os erros desta ferramenta que não têm código na spec usam
// -32602 (parâmetro inválido), que é o que a spec manda para requisição
// malformada.
const (
	CodParseError     = -32700
	CodInvalidRequest = -32600
	CodMethodNotFound = -32601
	CodInvalidParams  = -32602
	CodInternalError  = -32603

	// CodVersaoNaoSuportada é para versão PRESENTE e desconhecida. Campo
	// AUSENTE é outra coisa: a spec classifica requisição sem campo obrigatório
	// como malformada, e manda -32602. Confundir os dois faz o cliente tentar
	// renegociar versão quando o problema era outro.
	CodVersaoNaoSuportada = -32022
)

// Requisicao é uma mensagem JSON-RPC vinda do cliente.
//
// O ID é RawMessage e não `any` por uma razão de fidelidade: a resposta precisa
// devolver o MESMO id, e passar por `any` transformaria o inteiro 1 no float64
// 1 e o devolveria como `1` ou `1e+00` conforme o humor do encoder. Cliente que
// casa resposta por igualdade estrita de JSON perderia a correlação.
type Requisicao struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// EhNotificacao: sem id. A spec é explícita — notificação NÃO tem id, e o
// receptor NÃO responde.
func (r *Requisicao) EhNotificacao() bool { return len(r.ID) == 0 }

// Resposta é o envelope de sucesso. `Result` já vem serializado para que o
// encoder por era possa montá-lo com ou sem `resultType` sem duplicar tipo.
type Resposta struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result"`
}

// RespostaErro é o envelope de falha.
type RespostaErro struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Error   *ErroRPC        `json:"error"`
}

// ErroRPC é o erro JSON-RPC. `Data` carrega o que o cliente precisa para se
// recuperar — a lista de versões suportadas, o nome da capability que faltou —
// e NUNCA texto vindo do host.
type ErroRPC struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func (e *ErroRPC) Error() string { return fmt.Sprintf("jsonrpc %d: %s", e.Code, e.Message) }

func erro(code int, msg string) *ErroRPC { return &ErroRPC{Code: code, Message: msg} }

func erroComDados(code int, msg string, data any) *ErroRPC {
	return &ErroRPC{Code: code, Message: msg, Data: data}
}

// Implementacao é o par nome/versão que os dois lados usam para se identificar.
// A spec é enfática: é auto-declarado, não verificado, e NÃO pode ser base de
// decisão de segurança. Aqui ele serve ao log e ao relatório, nada mais.
type Implementacao struct {
	Nome   string `json:"name"`
	Versao string `json:"version"`
}

// meta é o `_meta` de dentro de `params`.
//
// A localização importa e é fácil de errar: a 2026-07-28 diz que a requisição
// carrega versão e capabilities em `_meta`, e o exemplo normativo do
// server/discover põe esse `_meta` DENTRO de `params` — não no topo da
// mensagem. Ler do lugar errado faz toda requisição bem formada ser recusada
// por campo obrigatório ausente.
type meta struct {
	Versao string          `json:"io.modelcontextprotocol/protocolVersion"`
	Caps   json.RawMessage `json:"io.modelcontextprotocol/clientCapabilities"`
	Info   *Implementacao  `json:"io.modelcontextprotocol/clientInfo"`
}

type paramsComMeta struct {
	Meta *meta `json:"_meta"`
}

// lerMeta extrai o `_meta` de params. Params ausente ou ilegível não é erro
// aqui — quem decide o que fazer com a falta é o chamador, que sabe se a
// requisição é de era legada (onde a ausência é NORMAL).
func lerMeta(params json.RawMessage) *meta {
	if len(params) == 0 {
		return nil
	}
	var p paramsComMeta
	if err := json.Unmarshal(params, &p); err != nil {
		return nil
	}
	return p.Meta
}
