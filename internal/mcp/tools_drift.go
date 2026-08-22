package mcp

import (
	"encoding/json"
	"time"

	"github.com/lex0c/aletheia/internal/drift"
	"github.com/lex0c/aletheia/internal/env"
)

// snapshot.compare: o eixo que nenhum check alcança.
//
// O scan pergunta "há evidência de comprometimento AGORA?". Esta pergunta é
// outra: o que MUDOU desde um retrato que eu tinha. Ela alcança a mudança de
// uma forma legítima para OUTRA forma legítima — um ExecStart que passa a
// apontar para outro binário de pacote, uma chave de SSH trocada por outra bem
// formada, um `command=` retirado de uma chave existente. Não há regra a
// escrever; o que denuncia é a transição.

var toolSnapshotCompare = Ferramenta{
	Anotacoes: SomenteLeitura,
	Dados:     DadosRedigidosNaOrigem,
	EscopoMin: EscopoCompleto,
	Nome:      "snapshot.compare",
	Titulo:    "O que mudou entre dois retratos",
	Descricao: "Compara dois retratos declarados no lançamento e devolve o que " +
		"surgiu, sumiu e mudou. A mudança é datada por INTERVALO ('entre t0 e t1'), " +
		"nunca por instante: a ferramenta não estava presente na hora. LEIA " +
		"coverage: os dois retratos precisam ter tido o mesmo alcance, e as famílias " +
		"em que um lado viu menos que o outro saem DECLARADAS como não comparadas — " +
		"o silêncio delas não vale como 'nada mudou'.",
	Entrada: json.RawMessage(`{"type":"object","additionalProperties":false,
"required":["before_id","after_id"],
"properties":{
 "before_id":{"type":"string","description":"snapshot_id do retrato ANTERIOR"},
 "after_id":{"type":"string","description":"snapshot_id do retrato POSTERIOR"}}}`),
	Saida: esquemaEnvelope(`{"type":"object","required":["changes","coverage_by_family"],
"properties":{
 "caveat":{"type":"string","description":"presente quando a ordem dos retratos é ambígua — leia antes de interpretar o sentido das mudancas"},
 "from_host":{"type":"string"},"to_host":{"type":"string"},
 "from_when":{"type":"string"},"to_when":{"type":"string"},
 "counted_only":{"type":"integer","description":"mudancas em campos que nao decidem nada (hash, mtime, tamanho): sai o numero, e nao a lista"},
 "changes":{"type":"array","items":{"type":"object",
  "properties":{"type":{"type":"string"},"title":{"type":"string"},"id":{"type":"string"},
   "kind":{"type":"string","enum":["surgiu","sumiu","mudou"]},
   "field":{"type":"string"},"before":{"type":"string"},"after":{"type":"string"},
   "fields":{"type":"array","items":{"type":"string"}},
   "decides":{"type":"boolean","description":"esta mudanca é, por si, o evento de seguranca — nao uma pista sobre ele"},
   "targets":{"type":"array","items":{"type":"string"}}}}},
 "coverage_by_family":{"type":"array","items":{"type":"object",
  "description":"o que ESTA comparacao alcancou, familia por familia. symmetric:false significa que um lado viu menos que o outro.",
  "properties":{"type":{"type":"string"},"title":{"type":"string"},
   "no_appeared":{"type":"boolean"},"no_disappeared":{"type":"boolean"},
   "no_changed":{"type":"boolean"},"symmetric":{"type":"boolean"},
   "reasons":{"type":"array","items":{"type":"string"}}}}}}}`, false),
	Rodar: func(s *Servidor, args json.RawMessage) (any, *ErroRPC) {
		var a struct {
			Antes  string `json:"before_id"`
			Depois string `json:"after_id"`
		}
		if er := decodificarArgs(args, &a); er != nil {
			return nil, er
		}
		if a.Antes == "" || a.Depois == "" {
			return nil, erro(CodInvalidParams,
				`snapshot.compare exige "before_id" e "after_id"`)
		}
		if a.Antes == a.Depois {
			return nil, erro(CodInvalidParams,
				"before_id e after_id são o mesmo retrato: não há o que comparar")
		}
		antes, er := s.retratoDe(a.Antes)
		if er != nil {
			return nil, er
		}
		depois, er := s.retratoDe(a.Depois)
		if er != nil {
			return nil, er
		}
		// ESCOPOS DIFERENTES NÃO SE COMPARAM.
		//
		// Um retrato volátil não tem unit, cron, pacote nem hash — não porque o
		// host não os tenha, mas porque ninguém olhou. Comparado com um
		// completo, TUDO que só existe no completo sai como "sumiu": medido,
		// 771 mudanças, 770 delas remoções. Um modelo leria isso como um evento
		// catastrófico de remoção em massa, e o evento não aconteceu.
		//
		// É a mesma regra que o `drift` do CLI já aplica às CAPACIDADES —
		// comparar um retrato com root contra um sem root fabricaria "sumiu"
		// para tudo que só root enxerga. O escopo é o mesmo eixo, um nível
		// acima.
		if antes.Escopo() != depois.Escopo() {
			return nil, erroComDados(CodInvalidParams,
				"os dois retratos têm ALCANCES diferentes ("+string(antes.Escopo())+
					" e "+string(depois.Escopo())+"): o volátil não examina unit, cron, "+
					"pacote nem hash, e comparar os dois faria TUDO que só o completo "+
					"vê sair como \"sumiu\" — uma remoção em massa que não aconteceu",
				map[string]any{
					"before_scope": string(antes.Escopo()),
					"after_scope":  string(depois.Escopo()),
				})
		}
		la, ld := ladoDe(antes), ladoDe(depois)
		ressalva, er := conferirOrdem(la, ld)
		if er != nil {
			return nil, er
		}

		d := drift.Comparar(la, ld)

		mudancas := []map[string]any{}
		for _, m := range d.Mudancas {
			mudancas = append(mudancas, map[string]any{
				"type": m.Tipo, "title": m.Titulo, "id": m.ID, "kind": m.Kind,
				"field": m.Campo, "before": m.Antes, "after": m.Depois,
				"fields": m.Campos, "decides": m.Decide, "targets": m.Alvos,
			})
		}
		cobertura := []map[string]any{}
		for _, c := range d.Cobertura {
			cobertura = append(cobertura, map[string]any{
				"type": c.Tipo, "title": c.Titulo,
				"no_appeared": c.SemSurgiu, "no_disappeared": c.SemSumiu,
				"no_changed": c.SemMudou, "symmetric": c.Simetrico,
				"reasons": c.Motivos,
			})
		}

		// A procedência é a do retrato POSTERIOR — é sobre o estado dele que a
		// resposta fala —, e os dois lados vão no corpo para que nenhum dos
		// dois fique implícito.
		obs := ObservabilidadeDeFatos(depois.Fatos)
		corpo := map[string]any{
			"from_host": d.DeHost, "to_host": d.ParaHost,
			"from_when": d.DeQuando, "to_when": d.AteQuando,
			"counted_only":       d.Contadas,
			"changes":            mudancas,
			"coverage_by_family": cobertura,
		}
		if ressalva != "" {
			corpo["caveat"] = ressalva
		}
		return envelopar(depois, obs, corpo), nil
	},
}

// conferirOrdem recusa a comparação invertida, e ressalva a ambígua.
//
// # Por que isso não é preciosismo
//
// Com os retratos trocados, drift.Comparar roda com os lados invertidos: a
// chave de SSH que o atacante ACRESCENTOU volta como kind "sumiu", e a que ele
// REMOVEU volta como "surgiu". O modelo lê a história ao contrário, e o
// intervalo sai negativo sem que nada o diga. O CLI recusa isto com exit 3 e a
// frase "pior que drift nenhum"; o servidor aceitava calado.
//
// Hosts DIFERENTES não são recusa: pode ser deriva de relógio entre duas
// máquinas, e comparar dois hosts é legítimo. Mas o modelo não tem stderr onde
// ler o aviso do CLI, então a ressalva viaja no corpo da resposta.
func conferirOrdem(antes, depois drift.Lado) (string, *ErroRPC) {
	ta, erra := time.Parse(time.RFC3339, antes.Quando)
	td, errd := time.Parse(time.RFC3339, depois.Quando)
	if erra != nil || errd != nil || !ta.After(td) {
		return "", nil
	}
	if antes.Host != "" && antes.Host == depois.Host {
		return "", erroComDados(CodInvalidParams,
			"before_id é MAIS NOVO que after_id no mesmo host ("+antes.Quando+
				" > "+depois.Quando+"): com a ordem trocada, o que foi REMOVIDO sai "+
				"como \"surgiu\" e o intervalo sai negativo. Inverta os dois.",
			map[string]any{"before_when": antes.Quando, "after_when": depois.Quando})
	}
	return "os retratos são de HOSTS DIFERENTES e o primeiro é mais novo que o " +
		"segundo (" + antes.Quando + " > " + depois.Quando + "): pode ser deriva de " +
		"relógio, pode ser ordem trocada. A comparação seguiu, e o intervalo sai " +
		"como está — leia o sentido de cada mudança com isso em mente.", nil
}

// ladoDe monta o lado da comparação a partir de um retrato.
//
// As caps viajam porque a comparação DEPENDE delas: sem saber o que cada ponta
// pôde enxergar, "sumiu" não distingue o que saiu do host do que ninguém olhou.
// É a mesma montagem que o `aletheia drift` faz, e por isso os dois respondem a
// mesma coisa sobre os mesmos dois arquivos.
func ladoDe(r *Retrato) drift.Lado {
	caps, _ := env.CapsDeNomes(r.Dump.Ambiente.Caps)
	host := ""
	if r.Fatos != nil {
		host = r.Fatos.Host.Hostname
	}
	return drift.Lado{
		F: r.Fatos, Caps: caps, Host: host, Quando: r.Dump.Ambiente.CollectedAt,
	}
}
