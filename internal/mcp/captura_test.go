package mcp

import (
	"encoding/json"
	"strings"
	"testing"

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
