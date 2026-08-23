package mcp

import (
	"encoding/json"
	"strconv"

	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

// crossview.get — as testemunhas do kernel sobre si mesmo.
//
// # Por que ela existe
//
// `coverage.get` publica `kernel_trust_broken` como um booleano, e um booleano
// não sustenta investigação: o modelo lê "true" e não tem como perguntar QUAIS
// visões discordaram, POR QUANTO, e até onde cada uma olhou. O detalhe estava no
// Facts desde sempre — CrossView é o campo mais consumido pelos checks — e
// nenhuma tool o alcançava. Ele só chegava ao modelo quando um achado o citava.
//
// E é justamente o fato que decide o valor de todo o resto: quando duas visões
// do MESMO kernel discordam, nenhuma ausência de achado vale como resposta. Um
// campo que governa a leitura da execução inteira precisa ser perguntável.
//
// # A forma da resposta, e por que ela não é um despejo
//
// Quatro eixos, e cada um é UM PAR de testemunhas com um estado entre elas.
//
// O par é a unidade porque o estado é uma relação, e relação não tem três
// pontas: /proc/modules e /sys/module se conferem por um motivo, o ftrace e
// /proc/modules por outro, e as duas comparações falham separado. Enquanto elas
// dividiam um eixo, o "agree" de uma carregava de graça a afirmação da outra —
// e no host onde isto foi escrito a segunda nunca chegou a acontecer, porque
// ler available_filter_functions exige root.
//
// O estado tem TRÊS valores, não dois:
//
//	agree          as duas olharam e concordam
//	disagree       as duas olharam e discordam — o kernel mentiu para uma
//	not_compared   a segunda não respondeu: não há comparação, e "nenhum
//	               oculto" aqui não significa nada
//
// O terceiro é o que um booleano apaga. "Nenhum socket oculto" com o netlink
// indisponível é a mesma frase de "nenhum socket oculto" com as duas visões
// batendo, e as duas conclusões são opostas.
//
// O ALCANCE viaja junto pelo mesmo motivo: "nenhum PID oculto até 4.194.304" e
// "nenhum PID oculto até 65.536" são afirmações diferentes, e a segunda quase
// não é afirmação nenhuma.
//
// As LISTAS de testemunha não são devolvidas — os nomes dos módulos que as duas
// interfaces mostram em comum são centenas, e não respondem a pergunta desta
// tool. O que sai é a contagem de cada testemunha e a DIVERGÊNCIA inteira, que
// é pequena por natureza e é o achado.
var toolCrossView = Ferramenta{
	Anotacoes: SomenteLeitura,
	Dados:     DadosRedigidosNaOrigem,
	// Live: o cross-view compara interfaces de um kernel EM EXECUÇÃO. Numa
	// imagem montada não há /proc, e as testemunhas não existem.
	Fontes: env.SourceLive,
	// A coleta volátil não roda o cross-view. Responder ali produziria
	// "nenhuma divergência" sobre comparação que ninguém fez.
	EscopoMin: EscopoCompleto,
	Nome:      "crossview.get",
	Titulo:    "O kernel concorda consigo mesmo?",
	Descricao: "Compara as visões INDEPENDENTES que o kernel dá de si em quatro " +
		"pares de testemunhas: processos (listagem de /proc contra sondagem por " +
		"sinal), sockets (/proc/net contra NETLINK_INET_DIAG), módulos " +
		"(/proc/modules contra /sys/module) e módulos pelo ftrace (o registro de " +
		"funções rastreáveis contra /proc/modules — o par que pega o módulo que " +
		"se DESENCADEIA das listas).\n\n" +
		"Leia ANTES de concluir qualquer coisa a partir de uma ausência. Quando " +
		"duas visões do MESMO kernel discordam, o kernel mentiu para uma delas — " +
		"e a partir daí nenhum 'não encontrei' deste host vale como prova. Os " +
		"achados continuam valendo; as ausências, não.\n\n" +
		"Cada eixo tem TRÊS estados, e o terceiro é o que um booleano apaga: " +
		"agree, disagree e not_compared. 'Nenhum socket oculto' com o netlink " +
		"indisponível é a mesma frase de 'nenhum socket oculto' com as duas " +
		"visões batendo, e as conclusões são opostas.\n\n" +
		"O ALCANCE vem junto: 'nenhum PID oculto até 4.194.304' e 'até 65.536' " +
		"são afirmações diferentes.",
	Entrada: entradaSnapshot(""),
	Saida: esquemaEnvelope(`{"type":"object","required":["trust_broken","axes"],
"properties":{
 "declared_gaps":{"type":"array","items":{"type":"string"},
  "description":"o que a propria comparacao declarou nao ter conseguido fazer. Um eixo em not_compared diz QUE nao houve comparacao; isto costuma dizer POR QUE. É o recorte de observability.collector_gaps deste coletor, e nao uma segunda contagem"},
 "trust_broken":{"type":"boolean","description":"true quando ALGUM eixo diverge. A partir daqui, ausencia de achado neste host NAO vale como prova — os achados continuam valendo"},
 "meaning":{"type":"string","description":"o que este estado significa para o resto da investigacao, em prosa"},
 "axes":{"type":"array","items":{"type":"object",
  "required":["axis","state","meaning"],
  "properties":{
   "axis":{"type":"string","enum":["processes","sockets","modules","modules_ftrace"]},
   "state":{"type":"string","enum":["agree","disagree","not_compared"],
    "description":"agree: as duas testemunhas olharam e concordam. disagree: olharam e DISCORDAM. not_compared: a segunda nao respondeu, e aqui 'nada oculto' nao significa nada"},
   "witnesses":{"type":"array","items":{"type":"object",
    "properties":{
     "name":{"type":"string"},
     "count":{"type":"integer","description":"quantos objetos esta testemunha viu"},
     "reach":{"type":"integer","description":"ate onde ela olhou, quando o alcance é limitado"},
     "read":{"type":"boolean"},
     "truncated":{"type":"boolean"},
     "reason":{"type":"string","description":"por que ela nao respondeu, quando nao respondeu"}}}},
   "divergences":{"type":"array","items":{"type":"object"},
    "description":"o que uma testemunha viu e a outra negou. Pequeno por natureza: é o achado"},
   "note":{"type":"string","description":"o que a comparacao deste eixo NAO cobre. Leia antes de tratar 'agree' como varredura completa"},
   "meaning":{"type":"string"}}}}}}`, false),
	Rodar: func(s *Servidor, args json.RawMessage) (any, *ErroRPC) {
		var a struct {
			SnapshotID string `json:"snapshot_id,omitempty"`
		}
		if er := decodificarArgs(args, &a); er != nil {
			return nil, er
		}
		r, er := s.retratoComFonte(a.SnapshotID, env.SourceLive, EscopoCompleto)
		if er != nil {
			return nil, er
		}
		c := &r.Fatos.Cross
		eixos := []map[string]any{
			eixoDeProcessos(r.Fatos),
			eixoDeSockets(c),
			eixoDeModulos(c),
			eixoDeFtrace(c),
		}
		quebrada := false
		for _, e := range eixos {
			if e["state"] == "disagree" {
				quebrada = true
			}
		}
		dados := map[string]any{
			"trust_broken": quebrada,
			"axes":         eixos,
			"meaning": "as comparações concordaram, ou não puderam ser feitas: " +
				"nada aqui contradiz o kernel. Isso NÃO é prova de host limpo — é " +
				"a ausência de uma contradição específica.",
		}
		// O que a própria comparação declarou não ter conseguido fazer.
		//
		// Isto é uma PROJEÇÃO FILTRADA de observability.collector_gaps, não uma
		// segunda contabilidade: as duas saem do mesmo facts.Partial, e a
		// diferença é só o recorte. A distinção importa porque duas contagens
		// que se recalculam divergem em silêncio — foi o defeito que
		// check.GroupByIDSev existiu para corrigir —, e uma que apenas filtra a
		// outra não pode divergir.
		//
		// O recorte se paga: collector_gaps mistura todo coletor da execução, e
		// quem lê "not_compared" precisa do POR QUÊ deste eixo, não de procurá-lo
		// no meio de bpf, logs e net. TestLacunaDeclaradaEhAMesmaDoEnvelope
		// segura a identidade entre as duas.
		if g := r.Fatos.Partial["cross"]; len(g) > 0 {
			dados["declared_gaps"] = g
		}
		if quebrada {
			dados["meaning"] = "duas visões do MESMO kernel discordam, e por " +
				"caminhos de código diferentes. Alguma coisa entre elas está " +
				"filtrando o que você vê. A partir daqui, ausência de achado neste " +
				"host não vale como prova; os achados continuam valendo, e valem " +
				"mais."
		}
		return envelopar(r, ObservabilidadeDeFatos(r.Fatos), dados), nil
	},
}

func eixoDeProcessos(f *facts.Facts) map[string]any {
	c := &f.Cross

	// A LISTAGEM é a testemunha de base, e omiti-la fazia a resposta parecer
	// uma comparação entre as duas sondagens. Não é: cada sondagem é conferida
	// contra o que o readdir de /proc devolveu, e é a listagem que um rootkit
	// filtra.
	//
	// A contagem dela não sobrevive ao dump — PidsListados é `json:"-"`, porque
	// é o que o readdir devolveu e não o que foi lido, e o dump carrega o
	// segundo. Então ela sai quando existe e some quando não existe, em vez de
	// ser reconstruída a partir de len(Processes): somar processo lido com
	// processo que sumiu produziria um número que ninguém mediu.
	listagem := map[string]any{
		"name": "listagem de /proc (readdir)",
		"read": c.ProbeAte > 0 || c.ProbeProcfsAte > 0,
	}
	if n := len(f.PidsListados); n > 0 {
		listagem["count"] = n
	}
	testemunhas := []map[string]any{
		listagem,
		{"name": "sondagem por sinal (kill(pid,0))", "reach": c.ProbeAte,
			"truncated": c.ProbeTeto, "read": c.ProbeAte > 0},
		{"name": "sondagem por /proc/<pid>", "reach": c.ProbeProcfsAte,
			"read": c.ProbeProcfsAte > 0},
	}
	div := make([]map[string]any, 0, len(c.Hidden)+len(c.Threads))
	for _, h := range c.Hidden {
		div = append(div, map[string]any{
			"kind": "pid_oculto", "pid": h.PID, "comm": h.Comm,
			"detected_by": h.Como,
			"meaning": "este pid respondeu ao kernel e não apareceu na listagem " +
				"de /proc: as duas respostas vêm do mesmo kernel",
		})
	}
	for _, t := range c.Threads {
		div = append(div, map[string]any{
			"kind": "contagem_de_threads", "pid": t.PID,
			"status_threads": t.Status, "task_entries": t.Task,
			"meaning": "o status do processo declara um número de threads e o " +
				"diretório de tarefas mostra outro",
		})
	}

	e := map[string]any{
		"axis": "processes", "witnesses": testemunhas,
		"note": "cada sondagem é conferida contra a LISTAGEM de /proc, e não " +
			"contra a outra sondagem. A contagem da listagem não é carregada por " +
			"dump — quando ela falta aqui, é isso, e não ausência de leitura.",
	}
	switch {
	case len(div) > 0:
		e["state"], e["divergences"] = "disagree", div
		e["meaning"] = "há processo que responde ao kernel e não aparece na " +
			"listagem, ou cuja contagem de threads diverge de si mesma"
	case c.ProbeAte == 0 && c.ProbeProcfsAte == 0:
		e["state"] = "not_compared"
		e["meaning"] = "nenhuma sondagem rodou: não há segunda testemunha, e " +
			"'nenhum processo oculto' aqui não é afirmação"
	default:
		e["state"] = "agree"
		e["meaning"] = "nenhum processo oculto ATÉ o alcance de cada sondagem — " +
			"leia reach: acima dele não se olhou, e não se afirma nada"
		if c.PidMax > 0 && c.ProbeAte > 0 && c.ProbeAte < c.PidMax {
			e["meaning"] = "nenhum processo oculto até " + strconv.Itoa(c.ProbeAte) +
				", e o pid_max deste host é " + strconv.Itoa(c.PidMax) +
				": a faixa acima disso NÃO foi sondada"
		}
	}
	return e
}

func eixoDeSockets(c *facts.CrossView) map[string]any {
	netlink := map[string]any{
		"name": "NETLINK_INET_DIAG", "count": c.SocketDiag,
		"read": c.SocketDiagLido, "truncated": c.SocketDiagCortado,
	}
	if c.SocketDiagMotivo != "" {
		netlink["reason"] = c.SocketDiagMotivo
	}
	e := map[string]any{
		"axis": "sockets",
		"witnesses": []map[string]any{
			{"name": "/proc/net", "count": c.SocketProc, "read": true},
			netlink,
		},
	}
	switch {
	case len(c.SocketOcultos) > 0:
		div := make([]map[string]any, 0, len(c.SocketOcultos))
		for _, so := range c.SocketOcultos {
			div = append(div, map[string]any{"kind": "socket_oculto", "socket": so})
		}
		e["state"], e["divergences"] = "disagree", div
		e["meaning"] = "o netlink entrega conexão que o /proc/net nega. As duas " +
			"tabelas são do mesmo kernel, por caminhos de código diferentes"
	case !c.SocketDiagLido:
		e["state"] = "not_compared"
		e["meaning"] = "a segunda visão não respondeu, então não houve " +
			"comparação: um socket escondido do /proc/net passaria despercebido"
	case c.SocketDiagCortado:
		e["state"] = "not_compared"
		e["meaning"] = "a resposta do netlink foi CORTADA: a parte não lida não " +
			"foi comparada com nada"
	default:
		e["state"] = "agree"
		e["meaning"] = "as duas tabelas de conexão mostram o mesmo conjunto"
	}
	return e
}

func eixoDeModulos(c *facts.CrossView) map[string]any {
	e := map[string]any{
		"axis": "modules",
		"witnesses": []map[string]any{
			{"name": "/proc/modules", "count": len(c.ModProc), "read": len(c.ModProc) > 0},
			{"name": "/sys/module", "count": len(c.ModSys), "read": len(c.ModSys) > 0},
		},
	}
	// As contagens divergem por construção e isso NÃO é achado: /sys/module lista
	// também o que foi compilado DENTRO do kernel, que nunca aparece em
	// /proc/modules. Por isso a comparação corre num sentido só — presente em
	// /proc e ausente em /sys — e o sentido inverso não é divergência. Publicar
	// dois números diferentes sob "agree" sem dizer isto seria uma contradição
	// aparente na cara de quem lê.
	e["note"] = "as contagens de /proc/modules e /sys/module divergem por " +
		"construção: /sys/module lista também os módulos compilados DENTRO do " +
		"kernel, que nunca aparecem em /proc/modules. Por isso a comparação corre " +
		"num sentido só — presente em /proc e ausente em /sys. O sentido inverso " +
		"não é divergência, e não foi verificado."

	div := make([]map[string]any, 0, len(c.ModDiff))
	for _, m := range c.ModDiff {
		div = append(div, map[string]any{"kind": "modulo_em_uma_interface_so",
			"module": m,
			"meaning": "aparece em /proc/modules e não em /sys/module: um módulo " +
				"que se desencadeia de uma lista continua na outra"})
	}
	switch {
	case len(div) > 0:
		e["state"], e["divergences"] = "disagree", div
		e["meaning"] = "um módulo aparece numa interface do kernel e some de outra"
	case len(c.ModProc) == 0 && len(c.ModSys) == 0:
		e["state"] = "not_compared"
		e["meaning"] = "nenhuma interface de módulo foi lida: não há comparação"
	default:
		e["state"] = "agree"
		e["meaning"] = "as interfaces de módulo mostram o mesmo conjunto"
	}
	return e
}

// eixoDeFtrace é separado do par /proc×/sys porque a comparação é OUTRA, com
// testemunha própria e falha própria.
//
// Fundir os dois num estado só apagaria um deles: com o ftrace ilegível — que é
// o caso comum, porque exige root — um "agree" do par /proc×/sys carregaria
// junto a afirmação de que nada se escondeu do ftrace, e essa afirmação nunca
// foi feita. E é justamente a comparação que pega o LKM que se desencadeia da
// lista, ou seja, a que mais importa.
func eixoDeFtrace(c *facts.CrossView) map[string]any {
	e := map[string]any{
		"axis": "modules_ftrace",
		"witnesses": []map[string]any{
			{"name": "registro do ftrace (available_filter_functions)",
				"count": len(c.ModFtrace), "read": len(c.ModFtrace) > 0},
			{"name": "/proc/modules", "count": len(c.ModProc),
				"read": len(c.ModProc) > 0},
		},
		"note": "esta comparação é a que pega o módulo que se DESENCADEIA das " +
			"listas: o registro do ftrace só é limpo no descarregamento real. Ler " +
			"available_filter_functions exige root, e num contêiner sem tracing " +
			"próprio o arquivo nem existe.",
	}
	switch {
	case len(c.ModFtraceDiff) > 0:
		div := make([]map[string]any, 0, len(c.ModFtraceDiff))
		for _, m := range c.ModFtraceDiff {
			div = append(div, map[string]any{"kind": "modulo_so_no_ftrace",
				"module": m,
				"meaning": "o ftrace tem função rastreável anotada para este módulo " +
					"e ele nega estar carregado"})
		}
		e["state"], e["divergences"] = "disagree", div
		e["meaning"] = "o kernel guarda função rastreável de um módulo que ele " +
			"próprio diz não ter carregado"
	case len(c.ModFtrace) == 0 || len(c.ModProc) == 0:
		e["state"] = "not_compared"
		e["meaning"] = "o registro do ftrace não foi lido — ou este host não " +
			"expõe tracing próprio, ou lê-lo exigiria privilégio que a coleta não " +
			"tinha — e a comparação que pega o módulo desencadeado NÃO foi feita"
	default:
		e["state"] = "agree"
		e["meaning"] = "todo módulo com função rastreável no ftrace também se " +
			"declara carregado em /proc/modules"
	}
	return e
}
