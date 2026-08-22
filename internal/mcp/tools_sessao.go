package mcp

import (
	"encoding/json"
	"strings"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

// argsSnapshot é o handle que quase toda tool aceita.
type argsSnapshot struct {
	SnapshotID string `json:"snapshot_id,omitempty"`
}

// retratoDe resolve o handle.
//
// Omitir o ID vale quando há UM retrato: exigir o handle ali seria burocracia
// sem ambiguidade a resolver. Com dois ou mais ele passa a ser obrigatório, e
// isso não é rigor gratuito — escolher um "padrão" faria o modelo receber
// resposta sobre o retrato errado sem nunca saber que havia outro, que é a
// forma mais cara de erro num servidor de investigação.
func (s *Servidor) retratoDe(id string) (*Retrato, *ErroRPC) {
	if id == "" {
		if r, ok := s.acervo.Unico(); ok {
			return r, nil
		}
		if s.acervo.Vazio() {
			if s.pol.Modo != ModoSnapshot {
				return nil, erro(CodInvalidParams,
					"nenhum retrato existe ainda: chame snapshot.capture primeiro. "+
						"Este servidor responde sobre RETRATOS, e não sobre o estado do "+
						"momento — é o que impede uma investigação de misturar instantes "+
						"diferentes e de perguntar sobre um pid já reciclado")
			}
			return nil, erro(CodInvalidParams,
				"nenhum retrato foi carregado neste servidor")
		}
		return nil, erroComDados(CodInvalidParams,
			`ha mais de um retrato carregado: informe "snapshot_id"`,
			map[string]any{"snapshots": s.ids()})
	}
	if er := validarTexto("snapshot_id", id); er != nil {
		return nil, er
	}
	r, err := s.acervo.Retrato(id)
	if err != nil {
		// A dica é do MODO: em snapshot o conjunto foi fixado no lançamento, e
		// em live ele é cunhado por snapshot.capture. Mandar o operador conferir
		// o lançamento num servidor live o manda para o lugar errado.
		dica := "os retratos deste servidor foram declarados no lançamento"
		if s.pol.Modo != ModoSnapshot {
			dica = "retratos são cunhados por snapshot.capture, e somem com " +
				"snapshot.release ou quando o servidor termina"
		}
		return nil, erroComDados(CodInvalidParams, err.Error(),
			map[string]any{"snapshots": s.ids(), "hint": dica})
	}
	return r, nil
}

// ids são os handles, e SÓ eles.
//
// O erro JSON-RPC levava o RÓTULO junto, que é `hostname · data` lido verbatim
// do dump — texto do alvo, dentro de `ErroRPC.Data`, fora de qualquer envelope
// e sem marca de confiança. O doc do ErroRPC diz, com todas as letras, que
// `Data` "NUNCA" carrega texto vindo do host; a linha que o violava está a
// quarenta arquivos de distância da que o promete.
//
// O id resolve o que o erro precisa resolver — ele é hash do CONTEÚDO, e é com
// ele que a chamada seguinte acerta. Quem precisa do rótulo legível é o
// operador, e ele o tem no stderr desde o lançamento.
func (s *Servidor) ids() []string {
	out := make([]string, 0, len(s.acervo.Todos()))
	for _, r := range s.acervo.Todos() {
		out = append(out, r.ID)
	}
	return out
}

// rotulos leva o hostname do alvo, e por isso só é servido DENTRO de envelope
// marcado — nunca num erro de protocolo.
// retratoComFonte resolve o handle E confere se a pergunta se aplica a ELE.
//
// # Por que o portão do registry não basta
//
// Ferramenta.Fontes é conferido uma vez, contra Acervo.Fontes(), que é a UNIÃO
// bitwise de todos os retratos carregados. Com `--snapshot live.json --snapshot
// imagem.json` a união é live|image, então process.get entra no registry — e
// um process.get sobre o retrato de IMAGEM respondia `found:false` com o sinal
// "ele pode ter terminado, ou nunca ter existido".
//
// Essa frase é FALSA sobre uma imagem montada: ali não existe /proc, e nunca
// existiu processo nenhum para ter terminado. É a confusão que a ferramenta
// inteira existe para não cometer — ausência lida como resposta, quando o certo
// é "esta pergunta não se aplica a esta fonte".
func (s *Servidor) retratoComFonte(id string, fontes env.Source, escopoMin Escopo) (*Retrato, *ErroRPC) {
	r, er := s.retratoDe(id)
	if er != nil {
		return nil, er
	}
	if er := exigirEscopo(r, escopoMin); er != nil {
		return nil, er
	}
	if fontes != 0 && r.Fonte&fontes == 0 {
		return nil, erroComDados(CodInvalidParams,
			"este retrato foi coletado de uma imagem montada (source: "+
				r.Fonte.String()+"): não há /proc, e portanto não há processo nem "+
				"socket sobre o qual responder. Isto NÃO é 'não encontrei' — é uma "+
				"pergunta que não se aplica a esta fonte.",
			map[string]any{"snapshot_id": r.ID, "source": r.Fonte.String()})
	}
	return r, nil
}

// exigirEscopo recusa a pergunta que o retrato não sustenta.
//
// A recusa é melhor que a resposta degradada porque a degradação aqui é MUDA:
// as famílias que o volátil não coletou saem vazias, e o dossiê conclui
// "não aparece em nada que esta coleta examinou" sobre algo que ninguém
// examinou. É a distinção entre "não achei" e "não consegui olhar", perdida
// dentro da própria tool que existe para mantê-la.
func exigirEscopo(r *Retrato, minimo Escopo) *ErroRPC {
	if minimo != EscopoCompleto || r.Escopo() == EscopoCompleto {
		return nil
	}
	return erroComDados(CodInvalidParams,
		"esta pergunta exige um retrato COMPLETO, e "+r.ID+" é volátil: ele leu "+
			"/proc e sockets, e não examinou pacote, agendamento, unit, hash nem "+
			"atributo de inode. Responder aqui produziria uma ausência que se lê "+
			"como resposta. Capture com scope=complete.",
		map[string]any{"snapshot_id": r.ID, "scope": string(r.Escopo()),
			"required_scope": string(EscopoCompleto)})
}

func (s *Servidor) rotulos() []map[string]string {
	var out []map[string]string
	for _, r := range s.acervo.Todos() {
		out = append(out, map[string]string{"snapshot_id": r.ID, "label": r.Rotulo})
	}
	return out
}

// envelopar monta a resposta padrão de uma tool sobre um retrato.
//
// As regiões adversárias são DERIVADAS da observabilidade, e não fixadas em
// "data": uma lacuna de coleta cita nomes que o alvo escolheu, e o caminho dela
// precisa entrar na lista. Ver Confianca.Regioes.
func envelopar(r *Retrato, o Observabilidade, dados any) Envelope {
	return Envelope{
		Procedencia:     r.Procedencia(),
		Observabilidade: o,
		Confianca:       ConfiancaDoHost(RegioesDoHost(o)...),
		Dados:           dados,
	}
}

// ------------------------------------------------------------ session.status

type dadosStatus struct {
	Modo   string `json:"mode"`
	Perfil string `json:"profile"`

	Privilegio Privilegio `json:"privilege"`

	// As três promessas, legíveis por máquina. Elas são invariantes deste
	// servidor e não configuração: não existe flag que as mude.
	EgressoDeRede bool `json:"network_egress"`
	MutacaoDoHost bool `json:"host_mutation"`
	ExecucaoDeCmd bool `json:"command_execution"`

	RootAutorizado      bool `json:"root_authorized"`
	SegredosAutorizados bool `json:"secrets_authorized"`

	// Redacao é o que os retratos carregados PROVAM sobre a própria redação —
	// nunca o que este servidor gostaria de afirmar. Ver Procedencia.Redacao.
	Redacao       []map[string]string `json:"redaction,omitempty"`
	NotaDeRedacao string              `json:"redaction_note,omitempty"`

	Retratos []map[string]string `json:"snapshots,omitempty"`

	// Coleta é o orçamento de TRABALHO, e ele é publicado porque um limite que
	// só se descobre batendo nele obriga o modelo a gastar uma captura inteira
	// para aprender que não podia. Ausente em modo snapshot, onde não há
	// aquisição a orçar.
	Coleta *orcamento `json:"capture_budget,omitempty"`

	// FerramentasIndisponiveis é a AUSÊNCIA DECLARADA.
	//
	// A tool que não se aplica some de tools/list — superfície que não existe
	// não pode ser induzida por prompt injection. Mas sumir em silêncio
	// contradiz a regra desta ferramenta, que é declarar o que não foi
	// coberto. As duas valem, sobre coisas diferentes: o CALLABLE some, a
	// ausência é dita aqui.
	FerramentasIndisponiveis []Indisponivel `json:"unavailable_tools,omitempty"`
}

type orcamento struct {
	TetoMs  int64 `json:"total_ms"`
	GastoMs int64 `json:"spent_ms"`
	RestaMs int64 `json:"remaining_ms"`
	// Devolvivel é sempre false: release devolve MEMÓRIA, não trabalho.
	Devolvivel bool `json:"reclaimable"`
}

const notaDeRedacaoSnapshot = "este servidor responde sobre um DUMP. Quando o " +
	"artefato traz o carimbo (redaction: applied), toda superfície textual dele " +
	"passou pela redação na ORIGEM, e não existe flag que destrave o que não está " +
	"no arquivo — não conclua que não havia segredo. Quando ele diz absent, o " +
	"artefato NÃO PROVA ter sido redigido: trate o conteúdo como possivelmente " +
	"em claro, e desconfie da procedência do arquivo."

var toolStatus = Ferramenta{
	Anotacoes: SomenteLeitura,
	// NÃO é DadosDoMotor: a resposta lista os retratos carregados, e o rótulo
	// de cada um é o hostname lido do dump. A classe declara o conteúdo mais
	// forte que a tool emite, e "não há dado do alvo" aqui era falso.
	Dados:  DadosRedigidosNaOrigem,
	Nome:   "session.status",
	Titulo: "O que esta execução pode e não pode ver",
	Descricao: "Modo, perfil, privilégio efetivo deste processo e as tools que NÃO " +
		"estão disponíveis, com o motivo. Comece por aqui: ele diz o alcance da " +
		"investigação antes de você tirar conclusão de qualquer outra resposta.",
	Entrada: json.RawMessage(entradaVazia),
	Saida: esquemaSimples(`{"type":"object","required":["mode","profile","privilege",
"network_egress","host_mutation","command_execution"],"properties":{
 "mode":{"type":"string","enum":["snapshot","live","image"]},
 "profile":{"type":"string","enum":["standard","full"]},
 "privilege":{"type":"object","description":"euid NAO basta: uma capability como CAP_DAC_READ_SEARCH torna um uid=1000 capaz de ler /etc/shadow.",
  "properties":{"uid":{"type":"integer"},"euid":{"type":"integer"},"root":{"type":"boolean"},
   "caps_read":{"type":"boolean","description":"false significa que nao foi possivel olhar — nao que nao ha capability"},
   "effective_caps":{"type":"array","items":{"type":"string"}},
   "elevated":{"type":"boolean"},
   "elevation_notes":{"type":"array","items":{"type":"string"}}}},
 "network_egress":{"type":"boolean","description":"sempre false: nenhuma tool inicia conexao nem resolve nome"},
 "host_mutation":{"type":"boolean","description":"sempre false: nenhuma tool escreve no host"},
 "command_execution":{"type":"boolean","description":"sempre false: nao existe tool que execute comando"},
 "capture_budget":{"type":"object","description":"quanto tempo de leitura do host esta sessao ainda pode gastar em snapshot.capture. Ausente em modo snapshot, onde nao ha aquisicao. Esgotado, os retratos ja tirados continuam respondendo — o que acaba é a capacidade de tirar outro.",
  "properties":{"total_ms":{"type":"integer"},"spent_ms":{"type":"integer"},
   "remaining_ms":{"type":"integer"},
   "reclaimable":{"type":"boolean","description":"sempre false: snapshot.release devolve memoria, nao trabalho ja feito"}}},
 "root_authorized":{"type":"boolean"},
 "secrets_authorized":{"type":"boolean"},
 "redaction":{"type":"array","description":"o que cada retrato PROVA sobre a propria redacao, lido do carimbo do artefato — nunca o que este servidor afirma. Ausente fora do modo snapshot, onde os retratos nascem de captura e nao de arquivo.",
  "items":{"type":"object","properties":{
   "snapshot_id":{"type":"string"},
   "redaction":{"type":"string","enum":["applied","absent","unknown_version"]}}}},
 "redaction_note":{"type":"string"},
 "snapshots":{"type":"array","items":{"type":"object"}},
 "unavailable_tools":{"type":"array","items":{"type":"object",
  "properties":{"name":{"type":"string"},"reason":{"type":"string"}}}}}}`),
	Rodar: func(s *Servidor, args json.RawMessage) (any, *ErroRPC) {
		var a struct{}
		if er := decodificarArgs(args, &a); er != nil {
			return nil, er
		}
		d := dadosStatus{
			Modo: s.pol.Modo.String(), Perfil: s.pol.Perfil.String(),
			Privilegio:               LerPrivilegio(),
			RootAutorizado:           s.pol.PermitirRoot,
			SegredosAutorizados:      s.pol.PermitirSegredos,
			Retratos:                 s.rotulos(),
			FerramentasIndisponiveis: s.fora,
		}
		if s.pol.Modo != ModoSnapshot {
			gasto, resta := s.orcamentoDeColeta()
			d.Coleta = &orcamento{
				TetoMs:  s.pol.OrcamentoDeColeta.Milliseconds(),
				GastoMs: gasto.Milliseconds(),
				RestaMs: resta.Milliseconds(),
			}
		}
		if s.pol.Modo == ModoSnapshot {
			for _, r := range s.acervo.Todos() {
				d.Redacao = append(d.Redacao, map[string]string{
					"snapshot_id": r.ID, "redaction": r.Procedencia().Redacao,
				})
			}
			d.NotaDeRedacao = notaDeRedacaoSnapshot
		}
		return EnvelopeSimples{Confianca: ConfiancaDoHost(), Dados: d}, nil
	},
}

// ------------------------------------------------------------- snapshot.list

type itemRetrato struct {
	SnapshotID string `json:"snapshot_id"`
	Rotulo     string `json:"label"`
	Host       string `json:"host,omitempty"`
	Fonte      string `json:"source"`
	// Escopo e SustentaAchado viajam na LISTAGEM porque é ali que o modelo
	// reencontra um handle cuja captura já saiu do contexto dele.
	Escopo         string   `json:"scope"`
	SustentaAchado bool     `json:"supports_findings"`
	ColetadoEm     string   `json:"collected_at,omitempty"`
	ColetadoPor    string   `json:"collected_by,omitempty"`
	Caps           []string `json:"caps,omitempty"`
}

var toolSnapshotList = Ferramenta{
	Anotacoes: SomenteLeitura,
	Dados:     DadosRedigidosNaOrigem,
	Nome:      "snapshot.list",
	Titulo:    "Os retratos que este servidor pode consultar",
	Descricao: "Lista os retratos carregados: id, alcance, e se sustentam achado.\n\n" +
		"Em modo snapshot são os dumps que o operador fixou no lançamento. Em live " +
		"e image são os que snapshot.capture cunhou nesta sessão, e a lista começa " +
		"VAZIA — lista vazia ali significa 'ninguém tirou retrato ainda', nunca " +
		"'não há o que ver'.\n\n" +
		"Nenhuma tool aceita caminho de arquivo: tudo que este processo pode abrir " +
		"foi fixado pelo operador quando ele iniciou o servidor.",
	Entrada: json.RawMessage(entradaVazia),
	Saida: esquemaSimples(`{"type":"object","required":["snapshots"],"properties":{
 "snapshots":{"type":"array","items":{"type":"object","required":["snapshot_id","source","scope"],
  "properties":{"snapshot_id":{"type":"string"},"label":{"type":"string"},
   "host":{"type":"string"},"source":{"type":"string","enum":["live","image"]},
   "scope":{"type":"string","enum":["volatile","complete"],"description":"volatile leu /proc e sockets e mais nada — nem pacote, nem agendamento, nem unit"},
   "supports_findings":{"type":"boolean"},
   "collected_at":{"type":"string"},"collected_by":{"type":"string"},
   "caps":{"type":"array","items":{"type":"string"}}}}}}}`),
	Rodar: func(s *Servidor, args json.RawMessage) (any, *ErroRPC) {
		var a struct{}
		if er := decodificarArgs(args, &a); er != nil {
			return nil, er
		}
		itens := []itemRetrato{}
		for _, r := range s.acervo.Todos() {
			p := r.Procedencia()
			itens = append(itens, itemRetrato{
				SnapshotID: r.ID, Rotulo: r.Rotulo, Host: p.Host, Fonte: p.Fonte,
				Escopo:         string(r.Escopo()),
				SustentaAchado: r.Escopo() == EscopoCompleto,
				ColetadoEm:     p.ColetadoEm, ColetadoPor: p.ColetadoPor, Caps: p.Caps,
			})
		}
		return EnvelopeSimples{
			Confianca: ConfiancaDoHost(),
			Dados:     map[string]any{"snapshots": itens},
		}, nil
	},
}

// ------------------------------------------------------------- snapshot.info

var toolSnapshotInfo = Ferramenta{
	Anotacoes: SomenteLeitura,
	Dados:     DadosRedigidosNaOrigem,
	Nome:      "snapshot.info",
	Titulo:    "Em que condições este retrato foi tirado",
	Descricao: "Procedência completa de um retrato: quando, por quem, de onde, com " +
		"que capacidades, e o que a coleta não conseguiu ler. É o que decide o peso " +
		"de tudo o mais que você perguntar sobre ele.",
	Entrada: entradaSnapshot(""),
	Saida:   esquemaEnvelope(`{"type":"object","properties":{"label":{"type":"string"},"clock":{"type":"string"}}}`, false),
	Rodar: func(s *Servidor, args json.RawMessage) (any, *ErroRPC) {
		var a argsSnapshot
		if er := decodificarArgs(args, &a); er != nil {
			return nil, er
		}
		r, er := s.retratoDe(a.SnapshotID)
		if er != nil {
			return nil, er
		}
		return envelopar(r, ObservabilidadeDeFatos(r.Fatos), map[string]any{
			"label": r.Rotulo,
			// O relógio da coleta: sem NTP sincronizado, todo achado datado é
			// frágil, e quem interpreta uma timeline precisa saber disso antes.
			"clock": r.Dump.Ambiente.ClockTexto,
		}), nil
	},
}

// ------------------------------------------------------------- host.overview

var toolHostOverview = Ferramenta{
	Anotacoes: SomenteLeitura,
	Dados:     DadosRedigidosNaOrigem,
	Nome:      "host.overview",
	Titulo:    "Que host é este",
	Descricao: "Kernel, sistema, libc, virtualização, carga contra número de CPUs e " +
		"tempo de boot. É o contexto que pesa todo o resto: load 8.0 é rotina em 12 " +
		"CPUs e é um host afogado sob cota de 0,5.",
	Entrada: entradaSnapshot(""),
	Saida:   esquemaEnvelope(`{"type":"object"}`, false),
	Rodar: func(s *Servidor, args json.RawMessage) (any, *ErroRPC) {
		var a argsSnapshot
		if er := decodificarArgs(args, &a); er != nil {
			return nil, er
		}
		r, er := s.retratoDe(a.SnapshotID)
		if er != nil {
			return nil, er
		}
		return envelopar(r, ObservabilidadeDeFatos(r.Fatos), hostDe(r.Fatos)), nil
	},
}

func hostDe(f *facts.Facts) map[string]any {
	h := f.Host
	return map[string]any{
		"hostname": h.Hostname, "kernel": h.Kernel, "os": h.OS,
		"virt": h.Virt, "libc": h.Libc, "in_container": h.EmContainer,
		"num_cpu": h.NumCPU, "cpu_quota": h.CPUQuota,
		"load1": h.Load1, "load5": h.Load5, "load15": h.Load15,
		"uptime": h.Uptime, "boot_utc": h.BootUTC,
	}
}

// ------------------------------------------------------------ checks.catalog

type itemCheck struct {
	ID              string   `json:"id"`
	Ref             string   `json:"ref"`
	Titulo          string   `json:"title"`
	Grupo           string   `json:"group"`
	Modo            string   `json:"mode"`
	Requer          string   `json:"requires,omitempty"`
	FalsosPositivos []string `json:"false_positives,omitempty"`
}

var toolChecksCatalog = Ferramenta{
	Anotacoes: SomenteLeitura,
	Dados:     DadosDoMotor,
	Nome:      "checks.catalog",
	Titulo:    "O que o motor determinístico sabe concluir",
	Descricao: "O catálogo de checks deste binário: id, seção do runbook, grupo, o " +
		"que cada um exige do ambiente e os FALSOS POSITIVOS conhecidos. Leia os " +
		"falsos positivos antes de acusar. Você não pode criar finding — este é o " +
		"conjunto de conclusões que existem, e o resto é hipótese sua.",
	Entrada: json.RawMessage(`{"type":"object","additionalProperties":false,"properties":{
 "group":{"type":"string","description":"filtra por grupo (proc, net, persist, priv, integrity, kernel, app, cloud, ioc)"}}}`),
	Saida: json.RawMessage(`{"type":"object","required":["checks","total"],"properties":{
 "total":{"type":"integer"},
 "checks":{"type":"array","items":{"type":"object","required":["id","group"],
  "properties":{"id":{"type":"string"},"ref":{"type":"string"},"title":{"type":"string"},
   "group":{"type":"string"},"mode":{"type":"string"},"requires":{"type":"string"},
   "false_positives":{"type":"array","items":{"type":"string"}}}}}}}`),
	Rodar: func(s *Servidor, args json.RawMessage) (any, *ErroRPC) {
		var a struct {
			Grupo string `json:"group,omitempty"`
		}
		if er := decodificarArgs(args, &a); er != nil {
			return nil, er
		}
		if er := validarGrupo(a.Grupo); er != nil {
			return nil, er
		}
		itens := []itemCheck{}
		for _, c := range check.All() {
			if a.Grupo != "" && !strings.EqualFold(c.Group, a.Grupo) {
				continue
			}
			itens = append(itens, itemCheck{
				ID: c.ID, Ref: c.Ref, Titulo: c.Title, Grupo: c.Group,
				Modo: c.Mode.String(), Requer: c.Requires.String(),
				FalsosPositivos: c.FalsePositives,
			})
		}
		return map[string]any{"checks": itens, "total": len(itens)}, nil
	},
}
