package mcp

import (
	"encoding/json"
	"strings"

	"github.com/lex0c/aletheia/internal/check"
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
			return nil, erro(CodInvalidParams,
				"nenhum retrato foi carregado neste servidor")
		}
		return nil, erroComDados(CodInvalidParams,
			`ha mais de um retrato carregado: informe "snapshot_id"`,
			map[string]any{"snapshots": s.rotulos()})
	}
	if er := validarTexto("snapshot_id", id); er != nil {
		return nil, er
	}
	r, err := s.acervo.Retrato(id)
	if err != nil {
		return nil, erroComDados(CodInvalidParams, err.Error(),
			map[string]any{"snapshots": s.rotulos()})
	}
	return r, nil
}

func (s *Servidor) rotulos() []map[string]string {
	var out []map[string]string
	for _, r := range s.acervo.Todos() {
		out = append(out, map[string]string{"snapshot_id": r.ID, "label": r.Rotulo})
	}
	return out
}

// envelopar monta a resposta padrão de uma tool sobre um retrato.
func envelopar(r *Retrato, o Observabilidade, dados any) Envelope {
	return Envelope{
		Procedencia:     r.Procedencia(),
		Observabilidade: o,
		Confianca:       ConfiancaDoHost(),
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

	// RedigidoNaOrigem só é verdadeiro em modo snapshot, e é o que impede o
	// modelo de ler a ausência de segredo como prova de que não havia nenhum.
	RedigidoNaOrigem bool   `json:"redacted_at_source"`
	NotaDeRedacao    string `json:"redaction_note,omitempty"`

	Retratos []map[string]string `json:"snapshots,omitempty"`

	// FerramentasIndisponiveis é a AUSÊNCIA DECLARADA.
	//
	// A tool que não se aplica some de tools/list — superfície que não existe
	// não pode ser induzida por prompt injection. Mas sumir em silêncio
	// contradiz a regra desta ferramenta, que é declarar o que não foi
	// coberto. As duas valem, sobre coisas diferentes: o CALLABLE some, a
	// ausência é dita aqui.
	FerramentasIndisponiveis []Indisponivel `json:"unavailable_tools,omitempty"`
}

const notaDeRedacaoSnapshot = "este servidor responde sobre um DUMP, e o dump já " +
	"foi redigido na origem: argv, linha de cron, variável de crontab e ExecStart " +
	"saíram do host mascarados, e o environ já sai do coletor só com os NOMES das " +
	"variáveis mais uma allowlist de valores. Não existe flag que destrave isso " +
	"aqui, porque o segredo não está no artefato. Não conclua que não havia segredo."

var toolStatus = Ferramenta{
	Dados:  DadosDoMotor,
	Nome:   "session.status",
	Titulo: "O que esta execução pode e não pode ver",
	Descricao: "Modo, perfil, privilégio efetivo deste processo e as tools que NÃO " +
		"estão disponíveis, com o motivo. Comece por aqui: ele diz o alcance da " +
		"investigação antes de você tirar conclusão de qualquer outra resposta.",
	Entrada: json.RawMessage(entradaVazia),
	Saida: json.RawMessage(`{"type":"object","required":["mode","profile","privilege",
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
 "root_authorized":{"type":"boolean"},
 "secrets_authorized":{"type":"boolean"},
 "redacted_at_source":{"type":"boolean"},
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
		if s.pol.Modo == ModoSnapshot {
			d.RedigidoNaOrigem = true
			d.NotaDeRedacao = notaDeRedacaoSnapshot
		}
		return d, nil
	},
}

// ------------------------------------------------------------- snapshot.list

type itemRetrato struct {
	SnapshotID  string   `json:"snapshot_id"`
	Rotulo      string   `json:"label"`
	Host        string   `json:"host,omitempty"`
	Fonte       string   `json:"source"`
	ColetadoEm  string   `json:"collected_at,omitempty"`
	ColetadoPor string   `json:"collected_by,omitempty"`
	Caps        []string `json:"caps,omitempty"`
}

var toolSnapshotList = Ferramenta{
	Dados:  DadosRedigidosNaOrigem,
	Nome:   "snapshot.list",
	Titulo: "Os retratos que este servidor pode consultar",
	Descricao: "Lista os dumps declarados no lançamento, com seu snapshot_id. " +
		"Nenhuma tool aceita caminho de arquivo: tudo que este processo pode abrir " +
		"foi fixado pelo operador quando ele iniciou o servidor.",
	Entrada: json.RawMessage(entradaVazia),
	Saida: json.RawMessage(`{"type":"object","required":["snapshots"],"properties":{
 "snapshots":{"type":"array","items":{"type":"object","required":["snapshot_id","source"],
  "properties":{"snapshot_id":{"type":"string"},"label":{"type":"string"},
   "host":{"type":"string"},"source":{"type":"string","enum":["live","image"]},
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
				ColetadoEm: p.ColetadoEm, ColetadoPor: p.ColetadoPor, Caps: p.Caps,
			})
		}
		return map[string]any{"snapshots": itens}, nil
	},
}

// ------------------------------------------------------------- snapshot.info

var toolSnapshotInfo = Ferramenta{
	Dados:  DadosRedigidosNaOrigem,
	Nome:   "snapshot.info",
	Titulo: "Em que condições este retrato foi tirado",
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
	Dados:  DadosRedigidosNaOrigem,
	Nome:   "host.overview",
	Titulo: "Que host é este",
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
	Dados:  DadosDoMotor,
	Nome:   "checks.catalog",
	Titulo: "O que o motor determinístico sabe concluir",
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
		if er := validarTexto("group", a.Grupo); er != nil {
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
