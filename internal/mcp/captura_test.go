package mcp

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	_ "github.com/lex0c/aletheia/internal/checks" // registra o catálogo
	"github.com/lex0c/aletheia/internal/env"
)

// servidorVivo monta um servidor de AQUISIÇÃO sobre o host onde o teste roda.
func servidorVivo(t *testing.T, modo Modo, raiz string) *Servidor {
	t.Helper()
	a := NovoAcervo()
	a.Teto = 2
	s := NovoServidor(Policy{Modo: modo}, a, "teste", nil, func() (*env.Env, error) {
		return env.Probe(env.Options{Root: raiz, Version: "teste"}), nil
	})
	t.Cleanup(func() {
		for _, r := range a.Todos() {
			_ = a.Liberar(r.ID)
		}
	})
	return s
}

func capturar(t *testing.T, s *Servidor, escopo string) map[string]any {
	t.Helper()
	saida, er := s.porNome["snapshot.capture"].Rodar(s,
		json.RawMessage(`{"scope":"`+escopo+`"}`))
	if er != nil {
		t.Fatalf("captura %s: %v", escopo, er)
	}
	b, _ := json.Marshal(saida)
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// A CAPTURA ATRAVESSA A REDAÇÃO.
//
// A coleta ao vivo produz um Facts CRU — argv inteiro, o .bashrc do usuário, o
// histórico de shell. As tools deste servidor declaram DadosRedigidosNaOrigem,
// que promete "não contém segredo em claro", e servir aquele Facts direto
// tornaria a promessa falsa outra vez, pela porta nova.
//
// A prova é estrutural, e junto com a catraca global de internal/dump — que
// afirma que NENHUMA superfície vaza — ela fecha a cadeia: se a captura passa
// por dump.De, ela herda aquela garantia inteira.
func TestCapturaPassaPelaRedacao(t *testing.T) {
	s := servidorVivo(t, ModoLive, "")
	env := capturar(t, s, "volatile")
	proc := env["provenance"].(map[string]any)

	if proc["redaction"] != "applied" {
		t.Fatalf("a captura precisa carregar o carimbo da redação, tem %v",
			proc["redaction"])
	}
	// E o sidecar é um QUARTO estado: não existe arquivo para conferir, o que é
	// diferente de "existe e não pude verificar".
	if proc["sidecar"] != "sidecar_not_applicable" {
		t.Fatalf("captura não tem sidecar a conferir, tem %v", proc["sidecar"])
	}
	// O handle diz no PRÓPRIO nome que não é hash de conteúdo.
	id := env["data"].(map[string]any)["snapshot_id"].(string)
	if !strings.HasPrefix(id, "snap-live-") {
		t.Fatalf("o handle de captura precisa se declarar: %s", id)
	}
}

// VOLÁTIL NÃO CONCLUI, contra um /proc de verdade.
//
// O motor recusa rodar check sobre fatos voláteis, porque um check de unit
// encontraria zero units e reportaria "nada encontrado" onde o certo é "não
// olhei". A resposta honesta é zero achados COM o catálogo inteiro em
// not_checked — e é o que a tool precisa entregar, não uma lista vazia.
func TestCapturaVolatilNaoConclui(t *testing.T) {
	s := servidorVivo(t, ModoLive, "")
	cap := capturar(t, s, "volatile")
	if cap["data"].(map[string]any)["supports_findings"] != false {
		t.Fatal("a captura volátil precisa DIZER que não sustenta achado")
	}

	saida, er := s.porNome["findings.list"].Rodar(s, json.RawMessage(`{}`))
	if er != nil {
		t.Fatal(er)
	}
	b, _ := json.Marshal(saida)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	obs := m["observability"].(map[string]any)
	cob := obs["coverage"].(map[string]any)

	if n := m["data"].(map[string]any)["total"].(float64); n != 0 {
		t.Fatalf("coleta volátil não sustenta achado, tem %v", n)
	}
	if obs["verdict"] == "OK" {
		t.Fatal("volátil respondendo OK é a mentira exata que o motor recusa")
	}
	if cob["complete"].(float64) != 0 {
		t.Fatalf("nenhum check pode ter rodado: complete=%v", cob["complete"])
	}
	nc, _ := cob["not_checked"].([]any)
	if len(nc) == 0 {
		t.Fatal("o catálogo inteiro tinha de sair NÃO VERIFICADO, com motivo")
	}
}

// O teto existe porque cada retrato segura os fatos INTEIROS na memória de um
// processo que roda no host investigado. E o release devolve a vaga.
func TestTetoDeRetratosVivosELiberacao(t *testing.T) {
	s := servidorVivo(t, ModoLive, "")
	primeiro := capturar(t, s, "volatile")["data"].(map[string]any)["snapshot_id"].(string)
	capturar(t, s, "volatile")

	if _, er := s.porNome["snapshot.capture"].Rodar(s,
		json.RawMessage(`{"scope":"volatile"}`)); er == nil {
		t.Fatal("a terceira captura passou do teto de 2 e não foi recusada")
	}

	if _, er := s.porNome["snapshot.release"].Rodar(s,
		json.RawMessage(`{"snapshot_id":"`+primeiro+`"}`)); er != nil {
		t.Fatalf("release: %v", er)
	}
	if _, er := s.porNome["snapshot.capture"].Rodar(s,
		json.RawMessage(`{"scope":"volatile"}`)); er != nil {
		t.Fatalf("o release tinha de devolver a vaga: %v", er)
	}
	// E o liberado some de verdade.
	if _, er := s.retratoDe(primeiro); er == nil {
		t.Fatal("o retrato liberado continua respondendo")
	}
}

// A AQUISIÇÃO NÃO EXISTE EM MODO SNAPSHOT.
//
// Toda tool daquele modo responde de memória sobre um artefato selado, e ter ali
// uma tool capaz de provocar leitura do host contradiria a promessa do modo —
// que é o motivo de ele existir.
func TestCapturaNaoExisteEmModoSnapshot(t *testing.T) {
	s, _ := servidorDeTeste(t, fatosDeTeste())
	for _, nome := range []string{"snapshot.capture", "snapshot.release"} {
		if _, existe := s.porNome[nome]; existe {
			t.Errorf("%s não pode existir em ModoSnapshot: nenhuma leitura do host "+
				"acontece ali", nome)
		}
	}
	// E a ausência é DECLARADA, com o motivo.
	achou := false
	for _, i := range s.Indisponiveis() {
		if i.Nome == "snapshot.capture" && i.Motivo != "" {
			achou = true
		}
	}
	if !achou {
		t.Error("a ausência precisa vir declarada em unavailable_tools")
	}
}

// Escopo volátil sobre IMAGEM é recusado com o motivo: ali não há /proc, e uma
// captura vazia se leria como "o host não tem processo nenhum".
func TestVolatilNaoSeAplicaAImagem(t *testing.T) {
	s := servidorVivo(t, ModoImagem, t.TempDir())
	_, er := s.porNome["snapshot.capture"].Rodar(s, json.RawMessage(`{"scope":"volatile"}`))
	if er == nil {
		t.Fatal("volátil sobre imagem tinha de ser recusado")
	}
	if !strings.Contains(er.Message, "host vivo") {
		t.Fatalf("a recusa precisa dizer por quê: %q", er.Message)
	}
}

// AS ANOTAÇÕES SÃO POR TOOL, e as duas que mudam estado não podem se anunciar
// somente-leitura.
//
// O cliente usa esses hints para decidir se pede confirmação ao operador. O
// release é o que mais importa numa resposta a incidente: um retrato volátil que
// capturou um processo memfd pode não ser reproduzível — o processo terminou —, e
// anunciá-lo como não destrutivo faz o cliente descartar evidência sem perguntar.
//
// A catraca do M4 não pega isto: ela roda em ModoSnapshot, onde as duas nem
// entram no registry.
func TestAquisicaoNaoSeAnunciaSomenteLeitura(t *testing.T) {
	s := servidorVivo(t, ModoLive, "")

	quer := map[string]struct{ leitura, destrutiva bool }{
		"snapshot.capture": {leitura: false, destrutiva: false},
		"snapshot.release": {leitura: false, destrutiva: true},
	}
	for nome, q := range quer {
		f, ok := s.porNome[nome]
		if !ok {
			t.Fatalf("%s devia existir em modo live", nome)
		}
		if f.Anotacoes.SomenteLeitura != q.leitura {
			t.Errorf("%s: readOnlyHint=%v, queria %v — ela MUDA o estado do servidor",
				nome, f.Anotacoes.SomenteLeitura, q.leitura)
		}
		if f.Anotacoes.Destrutiva != q.destrutiva {
			t.Errorf("%s: destructiveHint=%v, queria %v", nome,
				f.Anotacoes.Destrutiva, q.destrutiva)
		}
	}

	// E toda tool de LEITURA continua se anunciando como tal — a mudança não
	// pode ter passado o pincel em todas.
	for _, f := range s.ativas {
		if f.Nome == "snapshot.capture" || f.Nome == "snapshot.release" {
			continue
		}
		if !f.Anotacoes.SomenteLeitura {
			t.Errorf("%s não muda nada e não se anuncia somente-leitura", f.Nome)
		}
	}
}

// E o escopo do retrato é parte da resposta, não só da captura.
func TestEscopoViajaNaProcedenciaENaListagem(t *testing.T) {
	s := servidorVivo(t, ModoLive, "")
	capturar(t, s, "volatile")

	env := chamar(t, s, "host.overview", `{}`)
	if got := env["provenance"].(map[string]any)["scope"]; got != "volatile" {
		t.Errorf("provenance.scope = %v", got)
	}
	lista := chamar(t, s, "snapshot.list", `{}`)
	itens := lista["data"].(map[string]any)["snapshots"].([]any)
	it := itens[0].(map[string]any)
	if it["scope"] != "volatile" || it["supports_findings"] != false {
		t.Errorf("snapshot.list não carrega o alcance: %v", it)
	}
}

// O dossiê que a coleta volátil não sustenta é RECUSADO, e não respondido com
// uma ausência que se lê como resposta.
func TestDossieQueExigeCompletoRecusaOVolatil(t *testing.T) {
	s := servidorVivo(t, ModoLive, "")
	capturar(t, s, "volatile")

	for _, c := range []struct{ tool, args string }{
		{"file.inspect", `{"path":"/etc/cron.d/backdoor"}`},
		{"net.ip", `{"address":"198.51.100.7"}`},
	} {
		_, er := s.porNome[c.tool].Rodar(s, json.RawMessage(c.args))
		if er == nil {
			t.Errorf("%s respondeu sobre um retrato que não examinou pacote nem "+
				"agendamento — 'não achei' ali não é resposta", c.tool)
			continue
		}
		if !strings.Contains(er.Message, "volátil") {
			t.Errorf("%s: a recusa precisa dizer por quê: %q", c.tool, er.Message)
		}
	}
	// E o que a coleta volátil SUSTENTA continua respondendo.
	if _, er := s.porNome["process.census"].Rodar(s, json.RawMessage(`{}`)); er != nil {
		t.Fatalf("process.census se sustenta em volátil: %v", er)
	}
}

// O TETO LIMITA MEMÓRIA; O ORÇAMENTO LIMITA TRABALHO.
//
// Capturar e liberar em laço mantém sempre um só retrato vivo, então o teto
// nunca dispara — e cada volta cobra uma varredura do host investigado. É o
// laço que um modelo faz sozinho quando o resultado parece estranho.
func TestCapturarEliberarEmLacoEsbarraNoOrcamento(t *testing.T) {
	s := servidorVivo(t, ModoLive, "")
	// Um orçamento de um nanossegundo: a primeira captura já o consome, e a
	// segunda é recusada mesmo com o acervo vazio.
	s.pol.OrcamentoDeColeta = time.Nanosecond

	primeira := capturar(t, s, "volatile")
	id := primeira["data"].(map[string]any)["snapshot_id"].(string)
	if _, er := s.porNome["snapshot.release"].Rodar(s,
		json.RawMessage(`{"snapshot_id":"`+id+`"}`)); er != nil {
		t.Fatalf("release: %v", er)
	}
	if n := len(s.acervo.Todos()); n != 0 {
		t.Fatalf("o acervo devia estar vazio, tem %d", n)
	}

	_, er := s.porNome["snapshot.capture"].Rodar(s, json.RawMessage(`{"scope":"volatile"}`))
	if er == nil {
		t.Fatal("com o acervo vazio o TETO não impede nada — e sem orçamento " +
			"nada impede o laço de varrer o host para sempre")
	}
	for _, quer := range []string{"orçamento", "release NÃO devolve orçamento"} {
		if !strings.Contains(er.Message, quer) {
			t.Errorf("a recusa precisa explicar o que acabou e que liberar não "+
				"resolve; falta %q em: %s", quer, er.Message)
		}
	}
}

// E o limite é LEGÍVEL antes de ser batido.
func TestOrcamentoDeColetaEhPublicado(t *testing.T) {
	s := servidorVivo(t, ModoLive, "")
	st := chamar(t, s, "session.status", `{}`)
	b, ok := st["data"].(map[string]any)["capture_budget"].(map[string]any)
	if !ok {
		t.Fatal("session.status não publica o orçamento: um limite que só se " +
			"descobre batendo nele custa uma captura inteira para ser aprendido")
	}
	if b["remaining_ms"].(float64) <= 0 {
		t.Error("uma sessão nova nasce sem orçamento")
	}
	if b["reclaimable"] != false {
		t.Error("reclaimable tem de ser false: release devolve memória, não trabalho")
	}

	capturar(t, s, "volatile")
	depois := chamar(t, s, "session.status", `{}`)
	b2 := depois["data"].(map[string]any)["capture_budget"].(map[string]any)
	if b2["spent_ms"].(float64) <= 0 {
		t.Error("a captura não cobrou nada do orçamento")
	}
	if b2["remaining_ms"].(float64) >= b["remaining_ms"].(float64) {
		t.Error("o que sobra não diminuiu depois de uma captura")
	}

	// E em modo snapshot não há aquisição a orçar: o campo tem de estar AUSENTE,
	// e não zerado — zero se leria como "orçamento esgotado".
	sn, _ := servidorDeTeste(t, fatosDeTeste())
	st2 := chamar(t, sn, "session.status", `{}`)
	if _, tem := st2["data"].(map[string]any)["capture_budget"]; tem {
		t.Error("modo snapshot publicou orçamento de coleta: não há o que orçar")
	}
}
