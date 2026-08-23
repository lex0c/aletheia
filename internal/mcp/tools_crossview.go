package mcp

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/lex0c/aletheia/internal/check"
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
// Cinco eixos, e cada um é UM PAR de testemunhas com um estado entre elas.
//
// O par é a unidade porque o estado é uma relação, e relação não tem três
// pontas: /proc/modules e /sys/module se conferem por um motivo, o ftrace e
// /proc/modules por outro, e as duas comparações falham separado. Enquanto elas
// dividiam um eixo, o "agree" de uma carregava de graça a afirmação da outra —
// e no host onde isto foi escrito a segunda nunca chegou a acontecer, porque
// ler available_filter_functions exige root.
//
// # trust_broken é do MOTOR, não dos eixos
//
// O booleano vem de KernelTrustBroken do Report — a mesma fonte que coverage.get
// publica —, nunca de varrer os eixos por "disagree". São coisas diferentes: os
// eixos EXPLICAM, o motor DECIDE. O quinto eixo (bpf) existe justamente porque
// sem ele a tool que responde "o kernel mente?" era cega para o modo mais forte
// de mentir — um programa eBPF que existe e não aparece na enumeração. Amarrar o
// booleano ao motor garante que a tool nunca diga "nada contradiz o kernel"
// enquanto o motor diz o oposto; o eixo bpf faz a explicação acompanhar.
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
	Descricao: "Compara as visões INDEPENDENTES que o kernel dá de si em cinco " +
		"pares de testemunhas: processos (listagem de /proc contra sondagem por " +
		"sinal), sockets (/proc/net contra NETLINK_INET_DIAG), módulos " +
		"(/proc/modules contra /sys/module), módulos pelo ftrace (o registro de " +
		"funções rastreáveis contra /proc/modules — o par que pega o módulo que " +
		"se DESENCADEIA das listas) e eBPF (enumeração do kernel contra as " +
		"referências vivas por fd/pin/link).\n\n" +
		"Leia ANTES de concluir qualquer coisa a partir de uma ausência. Quando " +
		"duas visões do MESMO kernel discordam, o kernel mentiu para uma delas — " +
		"e a partir daí nenhum 'não encontrei' deste host vale como prova. Os " +
		"achados continuam valendo; as ausências, não.\n\n" +
		"Cada eixo tem TRÊS estados, e o terceiro é o que um booleano apaga: " +
		"agree, disagree e not_compared. 'Nenhum socket oculto' com o netlink " +
		"indisponível é a mesma frase de 'nenhum socket oculto' com as duas " +
		"visões batendo, e as conclusões são opostas.\n\n" +
		"O ALCANCE vem junto: 'nenhum PID oculto até 4.194.304' e 'até 65.536' " +
		"são afirmações diferentes.\n\n" +
		"state é OBSERVAÇÃO (as testemunhas discordam?); trust_breaking é " +
		"INTERPRETAÇÃO do motor (a discordância é forte o bastante para " +
		"desqualificar o kernel?). Uma contagem de threads que oscila fica em " +
		"disagree com trust_breaking=false. Confie em trust_broken/trust_breaking " +
		"para decidir o valor das ausências, não no state sozinho.",
	Entrada: entradaSnapshot(""),
	Saida: esquemaEnvelope(`{"type":"object","required":["trust_broken","axes"],
"properties":{
 "trust_broken":{"type":"boolean","description":"vem da MESMA fonte que coverage.get: len(kernel_trust_broken)>0 do motor, nao um recalculo dos eixos. true = duas visoes do kernel discordam. A partir daqui, ausencia de achado neste host NAO vale como prova — os achados continuam valendo"},
 "breakers":{"type":"array","items":{"type":"string"},"description":"presente quando trust_broken: a lista AUTORITATIVA do que quebrou, verbatim do motor (o mesmo que observability.kernel_trust_broken). Um quebra-confiança que nenhum eixo explique aparece AQUI mesmo assim"},
 "meaning":{"type":"string","description":"o que este estado significa para o resto da investigacao, em prosa"},
 "axes":{"type":"array","items":{"type":"object",
  "required":["axis","state","meaning"],
  "properties":{
   "axis":{"type":"string","enum":["processes","sockets","modules","modules_ftrace","bpf"]},
   "state":{"type":"string","enum":["agree","disagree","not_compared"],
    "description":"OBSERVACAO, nao veredito. agree: as testemunhas olharam e batem. disagree: olharam e DIVERGEM — sozinho NAO prova que o kernel mentiu, uma divergencia pode ser corrida residual (WARN). not_compared: uma testemunha necessaria nao respondeu, e aqui 'nada oculto' nao significa nada"},
   "trust_breaking":{"type":"boolean","description":"INTERPRETACAO do motor: esta divergencia foi forte o bastante (finding CRITICAL kernelBreaker) para desqualificar o kernel? Vem da mesma fonte que trust_broken. disagree com trust_breaking=false é ruido com corrida, nao ocultacao"},
   "witnesses":{"type":"array","items":{"type":"object",
    "properties":{
     "name":{"type":"string"},
     "count":{"type":"integer","description":"quantos objetos esta testemunha viu"},
     "reach":{"type":"integer","description":"ate onde ela olhou, quando o alcance é limitado"},
     "read":{"type":"boolean","description":"se esta testemunha foi de fato lida — FATO coletado, nao inferido por count>0: fonte lida com zero é diferente de fonte ilegivel"},
     "truncated":{"type":"boolean"},
     "protocols":{"type":"object","description":"sockets/proc-net: estado por protocolo inet — compared | proc_unreadable | diag_skipped. agree exige os quatro compared","additionalProperties":{"type":"string"}},
     "reason":{"type":"string","description":"por que ela nao respondeu, quando nao respondeu"}}}},
   "divergences":{"type":"array","items":{"type":"object"},
    "description":"o que uma testemunha viu e a outra negou. Pequeno por natureza: é o achado. Cortado no teto quando patologicamente grande"},
   "divergences_total":{"type":"integer","description":"o total real de divergencias, mesmo quando a lista foi cortada"},
   "divergences_truncated":{"type":"boolean","description":"true quando divergences traz menos que divergences_total"},
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

		// trust_broken NÃO é recalculado a partir dos eixos: ele vem da ÚNICA
		// fonte autoritativa, o mesmo Report que coverage.get publica.
		//
		// Recalcular criaria duas verdades sobre o mesmo retrato. E elas
		// DIVERGIRIAM: os eixos aqui são processos, sockets e módulos, mas o
		// motor tem um quarto quebra-confiança que nenhum deles cobre —
		// cross.bpf_hidden, um programa eBPF que existe e não aparece na
		// enumeração. Um host com só esse defeito teria os eixos todos em agree
		// e KernelTrustBroken != []. A tool diria "nada contradiz o kernel"
		// enquanto o motor diria o oposto. Uma propriedade de segurança global
		// tem uma fonte só.
		//
		// Relatorio() é memoizado por retrato: se coverage.get ou findings.list
		// já rodou, isto é de graça; se não, roda o mesmo check que rodaria.
		rel := r.Relatorio()
		quebrada := len(rel.KernelTrustBroken) > 0

		c := &r.Fatos.Cross
		eixos := []map[string]any{
			eixoDeProcessos(r.Fatos),
			eixoDeSockets(c),
			eixoDeModulos(c),
			eixoDeFtrace(c),
			eixoDeBPF(r.Fatos),
		}

		// trust_breaking separa OBSERVAÇÃO de INTERPRETAÇÃO, por eixo.
		//
		// state é a relação entre as testemunhas: elas discordam ou não. Mas nem
		// toda discordância desqualifica o kernel — o motor sabe disso e a tool
		// tem de respeitar. cross.thread_count é WARN (resta uma corrida em
		// processo que encolhe sem parar), e um hidden_pid achado só por sondagem
		// também é WARN; só a via por PPID, que mata a corrida, sobe a CRITICAL.
		// Um eixo pode então estar em disagree com o kernel intacto.
		//
		// trust_breaking é a conclusão do MOTOR, não um recálculo: testa se a
		// frase deste breaker está em KernelTrustBroken, a lista que o motor já
		// publicou (e que só é populada com finding CRITICAL e fonte live). O
		// mapa eixo→ID é roteamento da decisão, não a decisão.
		quebras := map[string]bool{}
		for _, m := range rel.KernelTrustBroken {
			quebras[m] = true
		}
		breakerDoEixo := map[string]string{
			"processes": "cross.hidden_pid", "sockets": "cross.socket_view",
			"modules": "cross.module_view", "modules_ftrace": "cross.module_view",
			"bpf": "cross.bpf_hidden",
		}
		algumDisagreeFraco := false
		for _, e := range eixos {
			// trust_breaking exige que o eixo tenha OBSERVADO a divergência (state
			// disagree) E que ela seja a que quebrou a confiança. Sem o primeiro,
			// um cross.module_view que disparou pela via do ftrace marcaria também
			// o eixo de módulos /proc×/sys que CONCORDOU — os dois compartilham o
			// ID do breaker. A quebra é do eixo que a viu.
			ehDisagree := e["state"] == "disagree"
			quebrou := false
			if msg, ok := check.MensagemDeQuebraDeKernel(breakerDoEixo[e["axis"].(string)]); ok {
				quebrou = quebras[msg]
			}
			tb := ehDisagree && quebrou
			e["trust_breaking"] = tb
			if ehDisagree && !tb {
				algumDisagreeFraco = true
			}
		}

		dados := map[string]any{
			"trust_broken": quebrada,
			"axes":         eixos,
			"meaning": "as comparações concordaram, ou não puderam ser feitas: " +
				"nada aqui contradiz o kernel. Isso NÃO é prova de host limpo — é " +
				"a ausência de uma contradição específica.",
		}
		if !quebrada && algumDisagreeFraco {
			// Há divergência de OBSERVAÇÃO, mas nenhuma forte o bastante para
			// desqualificar o kernel. Dizer "nada contradiz o kernel" ao lado de
			// um eixo em disagree seria misturar as duas semânticas.
			dados["meaning"] = "algum eixo tem divergência de observação, mas " +
				"nenhuma forte o bastante para desqualificar o kernel (nenhum " +
				"quebra-confiança CRITICAL). Leia trust_breaking por eixo: uma " +
				"contagem de threads que oscila, ou um pid visto só por sondagem, " +
				"é ruído com corrida residual — não prova de ocultação. As " +
				"ausências deste host ainda valem."
		}
		if quebrada {
			// A LISTA autoritativa do que quebrou, verbatim do motor. Ela também
			// sai em observability.kernel_trust_broken (mesmo slice, mesma
			// fonte); aparece aqui, ao lado dos eixos, para o modelo correlacionar
			// o booleano com o motivo sem trocar de bloco. Se um dia entrar um
			// quinto quebra-confiança que nenhum eixo explique, ele aparece AQUI
			// mesmo assim — a lista não depende de os eixos o cobrirem.
			dados["breakers"] = rel.KernelTrustBroken
			dados["meaning"] = "duas visões do MESMO kernel discordam, e por " +
				"caminhos de código diferentes. Alguma coisa entre elas está " +
				"filtrando o que você vê. A partir daqui, ausência de achado neste " +
				"host não vale como prova; os achados continuam valendo, e valem " +
				"mais. Veja breakers e os eixos em disagree."
		}
		return envelopar(r, ObservabilidadeDeRelatorio(rel), dados), nil
	},
}

// maxDivergencias é o teto por eixo. A divergência é o achado, e o achado é
// pequeno por natureza — mas "por natureza" não é garantia, e esta é a tool que
// diz se o kernel está mentindo: ela não pode ser a que estoura o frame por
// tamanho e falha inteira justamente quando há mais o que mostrar. Acima do
// teto, a lista é cortada SEMANTICAMENTE e o corte é declarado, como toda
// truncagem neste servidor — nunca JSON cortado no meio.
const maxDivergencias = 100

// comCorte planta as divergências no eixo, cortando no teto e declarando o
// corte. total é sempre publicado, então o número real nunca some.
func comCorte(e map[string]any, div []map[string]any) {
	e["divergences_total"] = len(div)
	if len(div) > maxDivergencias {
		e["divergences"] = div[:maxDivergencias]
		e["divergences_truncated"] = true
	} else {
		e["divergences"] = div
	}
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
	// read vem do FATO coletado (ProcListLida = o readdir de /proc teve
	// sucesso), não de "alguma sondagem rodou". São eventos diferentes: o
	// readdir podia falhar por conta própria, e antes disto a testemunha de base
	// era marcada lida quando na verdade quem foi lido foi a SONDAGEM.
	listagem := map[string]any{
		"name": "listagem de /proc (readdir)",
		"read": c.ProcListLida,
	}
	if c.ProcListN > 0 {
		listagem["count"] = c.ProcListN
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
		// A divergência já CONFIRMADA sobrevive a qualquer lacuna posterior: o
		// achado vale mesmo que a listagem de base tenha ficado ilegível depois.
		e["state"] = "disagree"
		comCorte(e, div)
		e["meaning"] = "há processo que responde ao kernel e não aparece na " +
			"listagem, ou cuja contagem de threads diverge de si mesma"
	case !c.ProcListLida:
		e["state"] = "not_compared"
		e["meaning"] = "o readdir de /proc — a testemunha de base — não foi lido: " +
			"sem ele não há contra o que conferir a sondagem"
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
	// O confronto é por protocolo, então a testemunha /proc/net carrega o estado
	// de cada um em vez de um read agregado que esconde qual protocolo faltou.
	comparados, naoComparados := particionaProtocolos(c.SocketProtos)
	procNet := map[string]any{
		"name": "/proc/net", "count": c.SocketProc,
		"read":      len(comparados) > 0,
		"protocols": c.SocketProtos,
	}
	e := map[string]any{
		"axis": "sockets",
		"witnesses": []map[string]any{
			procNet,
			netlink,
		},
	}
	switch {
	case len(c.SocketOcultos) > 0:
		div := make([]map[string]any, 0, len(c.SocketOcultos))
		for _, so := range c.SocketOcultos {
			div = append(div, map[string]any{"kind": "socket_oculto", "socket": so})
		}
		e["state"] = "disagree"
		comCorte(e, div)
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
	case len(naoComparados) > 0:
		// Qualquer protocolo NÃO confrontado leva o eixo a not_compared, não a
		// um "agree com nota". udp_diag costuma não estar carregado, e o netlink
		// pula udp/udp6 para não autocarregar — dois protocolos inteiros sem
		// olhar. Chamar isso de "agree" esconderia um backdoor de UDP atrás de um
		// /proc/net/udp que ninguém confrontou. O que foi comparado concorda; o
		// que não foi, não foi.
		e["state"] = "not_compared"
		e["meaning"] = "nem todos os protocolos foram confrontados — " +
			descreveProtocolosPendentes(c.SocketProtos) + ". O que foi comparado " +
			"concorda, mas um socket escondido de um protocolo não confrontado " +
			"passaria despercebido"
	default:
		e["state"] = "agree"
		e["meaning"] = "as duas tabelas de conexão mostram o mesmo conjunto nos " +
			"quatro protocolos inet"
	}
	return e
}

// particionaProtocolos separa os protocolos confrontados dos que não foram.
func particionaProtocolos(m map[string]string) (comparados, naoComparados []string) {
	for proto, estado := range m {
		if estado == "compared" {
			comparados = append(comparados, proto)
		} else {
			naoComparados = append(naoComparados, proto)
		}
	}
	return
}

// descreveProtocolosPendentes lista, em ordem estável, o que faltou e por quê.
func descreveProtocolosPendentes(m map[string]string) string {
	var partes []string
	for _, proto := range []string{"tcp", "tcp6", "udp", "udp6"} {
		switch m[proto] {
		case "diag_skipped":
			partes = append(partes, proto+" não consultado (handler de diagnóstico ausente; pular evita autocarregar)")
		case "proc_unreadable":
			partes = append(partes, proto+" com /proc/net ilegível")
		}
	}
	return strings.Join(partes, "; ")
}

func eixoDeModulos(c *facts.CrossView) map[string]any {
	// read vem de ModProcLido/ModSysLido, não da cardinalidade: /proc/modules
	// lido com zero módulos existe (um kernel sem módulo carregado), e é o
	// oposto de /proc/modules negado por EACCES. Marcar read por len()>0
	// fundiria os dois — e num host onde /proc/modules deu EACCES e /sys/module
	// leu 300, a resposta diria "agree" com uma testemunha marcada não lida.
	e := map[string]any{
		"axis": "modules",
		"witnesses": []map[string]any{
			{"name": "/proc/modules", "count": len(c.ModProc), "read": c.ModProcLido},
			{"name": "/sys/module", "count": len(c.ModSys), "read": c.ModSysLido},
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
		e["state"] = "disagree"
		comCorte(e, div)
		e["meaning"] = "um módulo aparece numa interface do kernel e some de outra"
	case !c.ModProcLido || !c.ModSysLido:
		// not_compared vem do estado de LEITURA, não de len()==0: uma fonte
		// ilegível não é uma fonte vazia, e sem as duas lidas não houve confronto.
		e["state"] = "not_compared"
		e["meaning"] = "uma das interfaces de módulo não foi lida: não há confronto"
	default:
		e["state"] = "agree"
		// A frase descreve o que foi de fato VERIFICADO, não mais que isso. A
		// comparação corre num sentido só (/proc ⊂ /sys por construção), então
		// "mostram o mesmo conjunto" afirmava demais — o próprio note desmentia.
		e["meaning"] = "nenhum módulo declarado em /proc/modules faltou em /sys/module"
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
				"count": len(c.ModFtrace), "read": c.ModFtraceLido},
			{"name": "/proc/modules", "count": len(c.ModProc),
				"read": c.ModProcLido},
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
		e["state"] = "disagree"
		comCorte(e, div)
		e["meaning"] = "o kernel guarda função rastreável de um módulo que ele " +
			"próprio diz não ter carregado"
	case !c.ModFtraceLido || !c.ModProcLido:
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

// eixoDeBPF é o quarto quebra-confiança do kernel, e o que faltava.
//
// coverage.get e a catraca de trust_broken já sabem que cross.bpf_hidden é
// kernelBreaker; o que não existia era a EXPLICAÇÃO perguntável: quando o motor
// diz que a confiança quebrou por BPF, qual foi a divergência. Um programa eBPF
// que existe e não aparece na enumeração é a forma mais forte de ocultamento de
// kernel — e a tool que responde "o kernel está mentindo?" não podia vê-la.
//
// Este eixo reflete a ROTA DE ENUMERAÇÃO, que está limpa nos fatos: a lista de
// programas (idr_get_next) contra os ids CITADOS por descritor, pin ou link
// (idr_find). Esconder de forma consistente das duas é mais difícil, e a
// divergência é o achado.
//
// Ele NÃO recalcula o veredito: o gate de OcultosConfirmados é o mesmo do
// check (sem a confirmação de duas passadas, id citado e não listado é
// inconclusivo, não acusação), e a segunda rota do bpf_hidden — trampolim de
// ftrace sem programa que o explique — depende de lógica de tipos que vive no
// check. Por isso o veredito autoritativo é trust_broken/breakers, e o note
// deste eixo aponta para lá: um "agree" AQUI é sobre a rota de enumeração, não
// um atestado de que não há problema de BPF.
func eixoDeBPF(f *facts.Facts) map[string]any {
	b := &f.BPF
	enumeracao := map[string]any{
		"name":  "enumeração do kernel (bpf(2), idr_get_next)",
		"count": len(b.Programas), "read": b.Enumerado,
		"truncated": b.ProgramasCortado,
	}
	if !b.Enumerado && b.Motivo != "" {
		enumeracao["reason"] = b.Motivo
	}
	e := map[string]any{
		"axis": "bpf",
		"witnesses": []map[string]any{
			enumeracao,
			// Sem campo read: b.Enumerado prova que a ENUMERAÇÃO rodou, não que
			// toda superfície capaz de citar um id — fd, pin, link — foi
			// completamente observada. Publicar read=Enumerado aqui afirmaria o
			// que o fato não sustenta. O confronto vive na divergência confirmada.
			{"name": "referência direta (fd/pin/link → idr_find)"},
		},
		"note": "este eixo cobre a rota de ENUMERAÇÃO. A segunda rota do " +
			"bpf_hidden — trampolim de ftrace sem programa que o explique — é " +
			"decidida pelo motor; o veredito completo de BPF está em trust_broken " +
			"e breakers, e um 'agree' aqui não é atestado de que não há problema.",
	}
	switch {
	case b.OcultosConfirmados && len(b.Ocultos) > 0:
		div := make([]map[string]any, 0, len(b.Ocultos))
		for _, id := range b.Ocultos {
			div = append(div, map[string]any{"kind": "bpf_id_oculto", "prog_id": id,
				"meaning": "este id é citado por um descritor, pin ou link e a " +
					"enumeração do kernel não o devolve: perguntar pelo id e pedir a " +
					"lista são caminhos diferentes dentro do kernel"})
		}
		e["state"] = "disagree"
		comCorte(e, div)
		e["meaning"] = "há id de eBPF citado por referência viva que a enumeração " +
			"do kernel nega existir"
	case !b.Enumerado:
		e["state"] = "not_compared"
		e["meaning"] = "a enumeração de eBPF não rodou — normalmente falta " +
			"CAP_BPF/root —, então não houve contra o que conferir as referências"
	case len(b.Ocultos) > 0 && !b.OcultosConfirmados:
		// Mesma prudência do check: id citado e não listado sem a confirmação de
		// duas passadas é inconclusivo — dump anterior à correção do truncamento,
		// ou coleta que não completou. Não se acusa a partir dele.
		e["state"] = "not_compared"
		e["meaning"] = "há id de eBPF citado e não listado, mas a confirmação de " +
			"ocultamento (duas enumerações completas) não consta: inconclusivo, " +
			"não é divergência"
	default:
		e["state"] = "agree"
		e["meaning"] = "todo id de eBPF citado por referência viva também aparece " +
			"na enumeração do kernel"
	}
	return e
}
