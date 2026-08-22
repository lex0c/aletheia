package mcp

import (
	"encoding/json"

	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/info"
)

// As tools de ALVO: um processo, um endereço, uma porta, um arquivo.
//
// Todas delegam a internal/info, que é o núcleo de investigação do projeto e já
// tem a propriedade que importa aqui: ele RESPONDE sem concluir. Não há
// severidade, não há veredito — quem conclui é o scan, que traz os falsos
// positivos junto. Essa separação é do domínio, e é a mesma que separa achado
// do motor de hipótese do modelo.
//
// Nenhuma linha de lógica de investigação mora neste arquivo. Se uma pergunta
// nova precisar de lógica, ela nasce em internal/info e é servida aqui — do
// contrário o CLI e o MCP passam a responder coisas diferentes sobre o mesmo
// retrato.

// dossieDeAlvo é a cola comum: resolve o retrato, chama o info, envelopa.
func dossieDeAlvo(s *Servidor, id string, fontes env.Source,
	fn func(r *Retrato) *info.Dossie) (any, *ErroRPC) {

	r, er := s.retratoComFonte(id, fontes)
	if er != nil {
		return nil, er
	}
	return envelopar(r, ObservabilidadeDeFatos(r.Fatos), fn(r)), nil
}

// ------------------------------------------------------------ process.census

var toolProcessCensus = Ferramenta{
	Dados:  DadosRedigidosNaOrigem,
	Nome:   "process.census",
	Titulo: "Quem roda o quê, e contra que teto",
	Descricao: "O censo de processos por usuário, com as tarefas (processos + " +
		"threads) comparadas ao RLIMIT_NPROC de cada uid — o número que explica " +
		"'Resource temporarily unavailable' em su, fork e execve. Nomeia as " +
		"repetições que têm forma conhecida: cron sobreposto, pool, respawn.",
	Entrada: entradaSnapshot(""),
	Fontes:  env.SourceLive,
	Saida:   esquemaEnvelope(`{"type":"object"}`, false),
	Rodar: func(s *Servidor, args json.RawMessage) (any, *ErroRPC) {
		var a argsSnapshot
		if er := decodificarArgs(args, &a); er != nil {
			return nil, er
		}
		r, er := s.retratoComFonte(a.SnapshotID, env.SourceLive)
		if er != nil {
			return nil, er
		}
		return envelopar(r, ObservabilidadeDeFatos(r.Fatos), info.Censo(r.Fatos)), nil
	},
}

// --------------------------------------------------------------- process.get

var toolProcessGet = Ferramenta{
	Dados:  DadosRedigidosNaOrigem,
	Nome:   "process.get",
	Titulo: "O dossiê de um processo",
	Descricao: "Identidade, linhagem, rede, descritores e sinais de um PID. A " +
		"primeira pergunta é se ele É o que diz ser: comm e argv[0] o processo " +
		"escolhe, o executável é o kernel que diz. O PID é válido DENTRO deste " +
		"retrato — nada é relido, então não há reuso de PID a temer. " +
		"found:false não é erro: é resposta.",
	Entrada: entradaSnapshotExigindo([]string{"pid"},
		`"pid":{"type":"integer","minimum":1}`),
	Fontes: env.SourceLive,
	Saida:  esquemaEnvelope(esquemaDossie, false),
	Rodar: func(s *Servidor, args json.RawMessage) (any, *ErroRPC) {
		var a struct {
			argsSnapshot
			// PONTEIRO, para separar "não veio" de "veio zero". Com `int`, um
			// process.get{} decodificava para 0 e o servidor respondia,
			// confiante, sobre o pid 0 — found:false, com o sinal "ele pode ter
			// terminado, ou nunca ter existido". Ausência da PERGUNTA virando
			// resposta sobre um alvo que ninguém pediu, no servidor que existe
			// para não confundir as duas coisas.
			PID *int `json:"pid"`
		}
		if er := decodificarArgs(args, &a); er != nil {
			return nil, er
		}
		if a.PID == nil || *a.PID < 1 {
			return nil, erro(CodInvalidParams,
				`process.get exige "pid" — um inteiro positivo`)
		}
		return dossieDeAlvo(s, a.SnapshotID, env.SourceLive, func(r *Retrato) *info.Dossie {
			return info.Processo(r.Fatos, *a.PID)
		})
	},
}

// -------------------------------------------------------------- process.tree

var toolProcessTree = Ferramenta{
	Dados:  DadosRedigidosNaOrigem,
	Nome:   "process.tree",
	Titulo: "A árvore de um processo",
	Descricao: "Ancestrais até o init e descendentes de um PID, na estrutura em que " +
		"a linhagem se lê. O pai é o vetor de entrada: um shell sob um servidor web " +
		"conta uma história que a lista plana esconde. Sem pid, devolve as raízes " +
		"da árvore visível neste retrato.",
	Entrada: entradaSnapshot(
		`"pid":{"type":"integer","minimum":0},
"depth":{"type":"integer","minimum":1,"maximum":16,"default":4,"description":"profundidade de descendentes"}`),
	Fontes: env.SourceLive,
	Saida: esquemaEnvelope(`{"type":"object","required":["found","truncated"],
"properties":{
 "target":{"type":"integer"},
 "found":{"type":"boolean"},
 "ancestors":{"type":"array","items":{"type":"object"},"description":"do PAI ate a raiz, nessa ordem"},
 "node":{"type":"object","description":"o alvo, com children aninhado"},
 "roots":{"type":"array","items":{"type":"object"},"description":"a resposta quando nenhum pid foi pedido"},
 "signals":{"type":"array","items":{"type":"string"},"description":"orfao de ciclo, corte por profundidade — leia antes de concluir que a arvore esta inteira"},
 "truncated":{"type":"boolean"}}}`, false),
	Rodar: func(s *Servidor, args json.RawMessage) (any, *ErroRPC) {
		var a struct {
			argsSnapshot
			PID  int `json:"pid"`
			Prof int `json:"depth,omitempty"`
		}
		if er := decodificarArgs(args, &a); er != nil {
			return nil, er
		}
		if a.PID < 0 {
			return nil, erro(CodInvalidParams, "pid inválido")
		}
		r, er := s.retratoComFonte(a.SnapshotID, env.SourceLive)
		if er != nil {
			return nil, er
		}
		arv := info.Arvore(r.Fatos, a.PID, a.Prof)
		obs := ObservabilidadeDeFatos(r.Fatos)
		// A truncagem da ÁRVORE é truncagem da RESPOSTA, e observability é onde
		// o modelo a procura. Sem esta linha os dois campos discordavam: o
		// dossiê dizia truncated:true e o envelope, false.
		obs.Truncado = arv.Truncado
		if arv.Truncado {
			obs.MotivoTruncagem = "a árvore foi cortada: veja data.signals e " +
				"children_omitted para saber onde"
		}
		return envelopar(r, obs, arv), nil
	},
}

// ---------------------------------------------------------------- net.census

var toolNetCensus = Ferramenta{
	Dados:  DadosRedigidosNaOrigem,
	Nome:   "net.census",
	Titulo: "O que este host expõe, e com quem ele fala",
	Descricao: "Censo de rede: escutas (com o bind, para separar loopback de " +
		"exposto), quem fala para fora agrupado pelo executável real, quem conectou " +
		"aqui, e os tetos contra os quais a contagem de conexões significa algo. " +
		"without_owner conta os sockets cujo processo não pôde ser identificado — " +
		"eles existem do mesmo jeito.",
	Entrada: entradaSnapshot(""),
	Fontes:  env.SourceLive,
	Saida:   esquemaEnvelope(`{"type":"object"}`, false),
	Rodar: func(s *Servidor, args json.RawMessage) (any, *ErroRPC) {
		var a argsSnapshot
		if er := decodificarArgs(args, &a); er != nil {
			return nil, er
		}
		r, er := s.retratoComFonte(a.SnapshotID, env.SourceLive)
		if er != nil {
			return nil, er
		}
		return envelopar(r, ObservabilidadeDeFatos(r.Fatos), info.CensoDaRede(r.Fatos)), nil
	},
}

// -------------------------------------------------------------------- net.ip

var toolNetIP = Ferramenta{
	Dados:  DadosRedigidosNaOrigem,
	Nome:   "net.ip",
	Titulo: "O que este endereço tem a ver com este host",
	Descricao: "Conexões, quem fala com ele, e também o DISCO: /etc/hosts (um nome " +
		"apontado para lá não passa por DNS), resolv.conf e known_hosts (o host JÁ " +
		"se conectou lá — é alcance lateral). Ausência aqui não fecha a questão: " +
		"conexão de vida curta não aparece num retrato único.",
	Entrada: entradaSnapshotExigindo([]string{"address"},
		`"address":{"type":"string","maxLength":4096}`),
	Fontes: env.SourceLive,
	Saida:  esquemaEnvelope(esquemaDossie, false),
	Rodar: func(s *Servidor, args json.RawMessage) (any, *ErroRPC) {
		var a struct {
			argsSnapshot
			Endereco string `json:"address"`
		}
		if er := decodificarArgs(args, &a); er != nil {
			return nil, er
		}
		if er := validarTexto("address", a.Endereco); er != nil {
			return nil, er
		}
		if a.Endereco == "" {
			return nil, erro(CodInvalidParams, `net.ip exige "address"`)
		}
		return dossieDeAlvo(s, a.SnapshotID, env.SourceLive, func(r *Retrato) *info.Dossie {
			return info.IP(r.Fatos, a.Endereco)
		})
	},
}

// ------------------------------------------------------------------ net.port

var toolNetPort = Ferramenta{
	Dados:  DadosRedigidosNaOrigem,
	Nome:   "net.port",
	Titulo: "Quem abriu esta porta, e quem usa",
	Descricao: "Quem escuta, com que exposição e sob que pacote, e as conexões " +
		"estabelecidas. Ninguém escutando NESTE retrato não é o mesmo que a porta " +
		"estar fechada no firewall.",
	Entrada: entradaSnapshotExigindo([]string{"port"},
		`"port":{"type":"integer","minimum":0,"maximum":65535}`),
	Fontes: env.SourceLive,
	Saida:  esquemaEnvelope(esquemaDossie, false),
	Rodar: func(s *Servidor, args json.RawMessage) (any, *ErroRPC) {
		var a struct {
			argsSnapshot
			// Ponteiro pela mesma razão do pid: a porta 0 é um valor legítimo de
			// se perguntar, e indistinguível da pergunta que não veio.
			Porta *int `json:"port"`
		}
		if er := decodificarArgs(args, &a); er != nil {
			return nil, er
		}
		if a.Porta == nil {
			return nil, erro(CodInvalidParams, `net.port exige "port"`)
		}
		if *a.Porta < 0 || *a.Porta > 65535 {
			return nil, erro(CodInvalidParams, "port fora do intervalo 0..65535")
		}
		return dossieDeAlvo(s, a.SnapshotID, env.SourceLive, func(r *Retrato) *info.Dossie {
			return info.Porta(r.Fatos, *a.Porta)
		})
	},
}

// -------------------------------------------------------------- file.inspect

var toolFileInspect = Ferramenta{
	Dados:  DadosRedigidosNaOrigem,
	Nome:   "file.inspect",
	Titulo: "De onde veio este arquivo, e quem mexe nele",
	Descricao: "Procedência (que pacote o entregou, se o hash confere), poder (setuid, " +
		"capabilities em xattr, atributo imutável), quem manda executá-lo (cron, " +
		"unit) e se o root o executa. NÃO lê o conteúdo: isto responde sobre o " +
		"arquivo a partir do que a coleta já examinou. Um caminho que não aparece " +
		"em nada NÃO significa que ele não existe — significa que nada nesta " +
		"varredura o referencia.",
	Entrada: entradaSnapshotExigindo([]string{"path"},
		`"path":{"type":"string","maxLength":4096}`),
	Saida: esquemaEnvelope(esquemaDossie, false),
	Rodar: func(s *Servidor, args json.RawMessage) (any, *ErroRPC) {
		var a struct {
			argsSnapshot
			Caminho string `json:"path"`
		}
		if er := decodificarArgs(args, &a); er != nil {
			return nil, er
		}
		if er := validarTexto("path", a.Caminho); er != nil {
			return nil, er
		}
		if a.Caminho == "" {
			return nil, erro(CodInvalidParams, `file.inspect exige "path"`)
		}
		return dossieDeAlvo(s, a.SnapshotID, 0, func(r *Retrato) *info.Dossie {
			return info.Arquivo(r.Fatos, a.Caminho)
		})
	},
}
