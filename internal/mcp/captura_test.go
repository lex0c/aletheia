package mcp

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
	if _, er := s.retratoDe(primeiro, EscopoQualquer); er == nil {
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

// TODA TOOL QUE DECLARA EscopoCompleto O IMPÕE.
//
// EscopoMin era declaração e não portão: file.inspect e net.ip recusavam porque
// os handlers DELES passavam a exigência adiante, e snapshot.compare declarava a
// mesma coisa sem impô-la. Dois retratos voláteis passavam, e o drift comparava
// duas coletas que nunca olharam unit — devolvendo simetria sobre o nada.
//
// A catraca é sobre o REGISTRY, e não sobre a lista de hoje: uma tool futura que
// declare a exigência e esqueça de aplicá-la falha aqui, e uma que apareça sem
// linha na tabela falha pedindo a linha.
func TestQuemExigeCompletoRecusaOVolatil(t *testing.T) {
	s := servidorVivo(t, ModoLive, "")
	primeiro := capturar(t, s, "volatile")["data"].(map[string]any)["snapshot_id"].(string)
	segundo := capturar(t, s, "volatile")["data"].(map[string]any)["snapshot_id"].(string)

	// O snapshot_id vai explícito: com dois retratos carregados, omiti-lo
	// produziria uma recusa por AMBIGUIDADE, e o teste passaria sem nunca ter
	// exercitado o portão de escopo.
	args := map[string]string{
		"net.ip":       fmt.Sprintf(`{"address":"127.0.0.1","snapshot_id":%q}`, primeiro),
		"file.inspect": fmt.Sprintf(`{"path":"/etc/passwd","snapshot_id":%q}`, primeiro),
		"snapshot.compare": fmt.Sprintf(`{"before_id":%q,"after_id":%q}`,
			primeiro, segundo),
	}

	exigentes := 0
	for _, f := range s.ativas {
		if f.EscopoMin != EscopoCompleto {
			continue
		}
		exigentes++
		a, ok := args[f.Nome]
		if !ok {
			t.Errorf("%s declara EscopoMin: EscopoCompleto e não está na tabela "+
				"deste teste. Sem argumento válido, ninguém confere se a "+
				"declaração é portão ou decoração.", f.Nome)
			continue
		}
		_, er := f.Rodar(s, json.RawMessage(a))
		if er == nil {
			t.Errorf("%s declara exigir um retrato COMPLETO e respondeu sobre "+
				"volátil: a declaração não é portão", f.Nome)
			continue
		}
		if !strings.Contains(er.Message, "volátil") {
			t.Errorf("%s: a recusa precisa dizer por quê: %s", f.Nome, er.Message)
		}
	}
	if exigentes == 0 {
		t.Fatal("nenhuma tool declara EscopoCompleto: ou o registry mudou, ou " +
			"esta catraca virou decoração")
	}
}

// E a matriz inteira do compare, que é onde o buraco estava.
func TestCompararExigeOsDoisCompletos(t *testing.T) {
	s := servidorVivo(t, ModoLive, "")
	s.acervo.Teto = 4
	vol1 := capturar(t, s, "volatile")["data"].(map[string]any)["snapshot_id"].(string)
	vol2 := capturar(t, s, "volatile")["data"].(map[string]any)["snapshot_id"].(string)
	com1 := capturar(t, s, "complete")["data"].(map[string]any)["snapshot_id"].(string)
	com2 := capturar(t, s, "complete")["data"].(map[string]any)["snapshot_id"].(string)

	casos := []struct {
		nome          string
		antes, depois string
		aceita        bool
	}{
		{"volátil × volátil", vol1, vol2, false},
		{"volátil × completo", vol1, com1, false},
		{"completo × volátil", com1, vol1, false},
		{"completo × completo", com1, com2, true},
	}
	for _, c := range casos {
		_, er := s.porNome["snapshot.compare"].Rodar(s, json.RawMessage(
			fmt.Sprintf(`{"before_id":%q,"after_id":%q}`, c.antes, c.depois)))
		if c.aceita && er != nil {
			t.Errorf("%s: recusado — %s", c.nome, er.Message)
		}
		if !c.aceita && er == nil {
			t.Errorf("%s: ACEITO. Um retrato volátil não coletou unit, cron nem "+
				"pacote, e o Env dele ainda carrega CapFilesystem: o drift lê "+
				"'nenhuma unit antes, nenhuma unit depois' como simetria e "+
				"devolve changes=[] sobre o que ninguém olhou", c.nome)
		}
	}
}

// descritoresAbertos conta o que este processo segura. É a medida direta: um
// os.Root aberto e não fechado aparece aqui, e nenhum raciocínio sobre
// ownership substitui contar.
func descritoresAbertos(t *testing.T) int {
	t.Helper()
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("sem /proc/self/fd: %v", err)
	}
	return len(ents)
}

// A CAPTURA RECUSADA NÃO DEIXA DESCRITOR PARA TRÁS.
//
// Em --root, o env.Probe do chamador abre um os.Root ANTES de Capturar ser
// chamada. Os dois caminhos de recusa precoce — teto cheio e "volátil não vale
// para imagem" — retornavam antes de qualquer Close, e o snapshot.release não
// alcança esses Env porque eles nunca entraram no acervo.
//
// Um modelo em laço contra um acervo cheio abria um descritor por chamada, e o
// orçamento de trabalho quase não os cobrava: o cronômetro só media o trecho
// depois da aquisição.
func TestCapturaRecusadaNaoVazaDescritor(t *testing.T) {
	raiz := t.TempDir()
	if err := os.MkdirAll(filepath.Join(raiz, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	s := servidorVivo(t, ModoImagem, raiz)

	// Uma primeira chamada para pagar qualquer alocação preguiçosa; a contagem
	// começa depois dela.
	_, _ = s.porNome["snapshot.capture"].Rodar(s, json.RawMessage(`{"scope":"volatile"}`))
	antes := descritoresAbertos(t)

	// 1. volátil sobre imagem: recusa antes de coletar qualquer coisa.
	for i := 0; i < 20; i++ {
		if _, er := s.porNome["snapshot.capture"].Rodar(s,
			json.RawMessage(`{"scope":"volatile"}`)); er == nil {
			t.Fatal("volátil não se aplica a uma imagem montada")
		}
	}
	if depois := descritoresAbertos(t); depois > antes {
		t.Errorf("20 recusas de escopo deixaram %d descritor(es) abertos "+
			"(%d -> %d). Em --root cada aquisição abre um os.Root, e o "+
			"snapshot.release não alcança um Env que nunca entrou no acervo",
			depois-antes, antes, depois)
	}

	// 2. teto cheio: recusa antes de coletar, com o mesmo problema.
	s.acervo.Teto = 1
	capturar(t, s, "complete")
	antes = descritoresAbertos(t)
	for i := 0; i < 20; i++ {
		if _, er := s.porNome["snapshot.capture"].Rodar(s,
			json.RawMessage(`{"scope":"complete"}`)); er == nil {
			t.Fatal("o teto era 1 e já havia um retrato")
		}
	}
	if depois := descritoresAbertos(t); depois > antes {
		t.Errorf("20 recusas por teto deixaram %d descritor(es) abertos (%d -> %d)",
			depois-antes, antes, depois)
	}
}

// "NÃO SEI" NÃO É "NÃO TENHO".
//
// O portão decidia por priv.Elevado, que é falso quando as capabilities não
// puderam ser lidas. Num ambiente de resgate sem /proc — que é onde esta
// ferramenta é usada — a incerteza virava a resposta mais tranquilizadora, e o
// servidor subia sem consentimento para ler o host com um alcance que ele mesmo
// não conhecia.
func TestPrivilegioIndeterminadoExigeConsentimentoNaAquisicao(t *testing.T) {
	casos := []struct {
		nome  string
		priv  Privilegio
		modo  Modo
		exige bool
		diz   string
	}{
		{"root", Privilegio{Root: true, CapsLidas: true}, ModoLive, true, "euid 0"},
		{"uid comum, caps lidas e vazias", Privilegio{CapsLidas: true}, ModoLive, false, ""},
		{"uid comum com capability", Privilegio{CapsLidas: true,
			CapsEfetivas: []string{"CAP_BPF"}}, ModoLive, true, "capability de observação"},

		// O caso da correção: leitura falhou, e o servidor vai LER o host.
		{"caps ilegíveis, aquisição", Privilegio{}, ModoLive, true, "NÃO foi possível determinar"},
		{"caps ilegíveis, imagem", Privilegio{}, ModoImagem, true, "NÃO foi possível determinar"},

		// E servindo artefato o privilégio não muda uma linha do que chega ao
		// modelo: recusar ali tiraria o --snapshot do resgate sem ganhar nada.
		{"caps ilegíveis, snapshot", Privilegio{}, ModoSnapshot, false, ""},
	}
	for _, c := range casos {
		exige, porQue := ExigeConsentimento(c.priv, c.modo)
		if exige != c.exige {
			t.Errorf("%s: exige=%v, queria %v (%s)", c.nome, exige, c.exige, porQue)
			continue
		}
		if c.diz != "" && !strings.Contains(porQue, c.diz) {
			t.Errorf("%s: a recusa precisa dizer por quê; falta %q em: %s",
				c.nome, c.diz, porQue)
		}
		if !c.exige && porQue != "" {
			t.Errorf("%s: não exige e deu motivo: %s", c.nome, porQue)
		}
	}
}

// --capture-budget=0 DESLIGA MESMO.
//
// Zero por omissão e zero DITO eram a mesma coisa: Padroes() trocava os dois
// pelo padrão, e a CLI imprimia "desliga o teto" antes de subir com dez
// minutos. Errar para o lado seguro não desculpa a interface mentir sobre uma
// opção explícita do operador.
func TestSemTetoDeColetaNaoVoltaAoPadrao(t *testing.T) {
	p := Policy{Modo: ModoLive, SemTetoDeColeta: true}.Padroes()
	if p.OrcamentoDeColeta != 0 {
		t.Fatalf("Padroes() ressuscitou o teto: %s", p.OrcamentoDeColeta)
	}

	a := NovoAcervo()
	s := NovoServidor(p, a, "teste", nil, func() (*env.Env, error) {
		return env.Probe(env.Options{Version: "teste"}), nil
	})
	t.Cleanup(func() {
		for _, r := range a.Todos() {
			_ = a.Liberar(r.ID)
		}
	})

	gasto, resta, comTeto := s.orcamentoDeColeta()
	if comTeto {
		t.Fatal("o servidor subiu com teto depois de o operador o desligar")
	}
	if gasto != 0 || resta != 0 {
		t.Errorf("sessão nova: gasto=%s resta=%s", gasto, resta)
	}

	// E capturar continua possível depois de gastar — não há saldo a acabar.
	capturar(t, s, "volatile")
	if _, er := s.porNome["snapshot.capture"].Rodar(s,
		json.RawMessage(`{"scope":"volatile"}`)); er != nil {
		t.Fatalf("com o teto desligado a segunda captura tem de passar: %v", er)
	}

	// O status diz "ilimitado" em vez de publicar um saldo que se leria como
	// esgotado.
	b := chamar(t, s, "session.status", `{}`)["data"].(map[string]any)["capture_budget"].(map[string]any)
	if b["unlimited"] != true {
		t.Errorf("session.status não declara o desligamento: %v", b)
	}
	if _, tem := b["remaining_ms"]; tem {
		t.Error(`remaining_ms presente com o teto desligado: "resta 0" ali se ` +
			`leria como esgotado, que é o oposto`)
	}
	if b["cooperative"] != true {
		t.Error("o orçamento não se declara cooperativo")
	}
}

// O PRAZO DA VARREDURA É O MENOR ENTRE OS DOIS.
//
// O saldo admitia a captura e o WalkDeadline saía de Budget sem olhar o que
// restava: um "teto total" de 1s autorizava dois minutos de varredura.
//
// A medida é do PRAZO, e não do tempo que a captura levou. Uma captura normal
// dura ~1,5s de qualquer jeito, então cronometrar não distinguiria um prazo de
// 40ms de um de dois minutos — o teste passaria sem o grampo existir.
func TestPrazoDaVarreduraNaoUltrapassaOSaldo(t *testing.T) {
	const saldo = 40 * time.Millisecond

	a := NovoAcervo()
	a.Teto = 4
	var prazo time.Duration
	var mediu bool
	s := NovoServidor(
		Policy{Modo: ModoLive, Budget: 2 * time.Minute, OrcamentoDeColeta: saldo},
		a, "teste", nil, nil)
	s.adquirir = func() (*env.Env, error) {
		e := env.Probe(env.Options{Version: "teste"})
		// O Env é observado DEPOIS que a tool escreve o prazo nele — a leitura
		// acontece no defer abaixo, quando a captura já passou por aqui.
		t.Cleanup(func() {
			if !e.WalkDeadline.IsZero() {
				mediu = true
			}
		})
		return e, nil
	}
	t.Cleanup(func() {
		for _, r := range a.Todos() {
			_ = a.Liberar(r.ID)
		}
	})

	// Para ler o prazo é preciso segurar o Env: o adquirir devolve o ponteiro, e
	// a tool o preenche antes de entregá-lo a Capturar.
	var capturado *env.Env
	s.adquirir = func() (*env.Env, error) {
		capturado = env.Probe(env.Options{Version: "teste"})
		return capturado, nil
	}

	inicio := time.Now()
	if _, er := s.porNome["snapshot.capture"].Rodar(s,
		json.RawMessage(`{"scope":"complete"}`)); er != nil {
		t.Fatalf("há saldo: a captura devia ser ADMITIDA, apenas com prazo curto: %v", er)
	}
	if capturado == nil || capturado.WalkDeadline.IsZero() {
		t.Fatal("a captura completa não definiu WalkDeadline nenhum")
	}
	prazo = capturado.WalkDeadline.Sub(inicio)
	mediu = true

	// A folga é a distância entre DOIS RELÓGIOS: este teste marca antes de
	// chamar a tool, e a tool marca antes de sondar o ambiente. Medido, a
	// diferença fica em dezenas de microssegundos — e a coisa contra a qual isto
	// protege são DOIS MINUTOS, então a folga não afrouxa nada. A mutação que
	// devolve o prazo ao Budget marca 2m0,017s.
	const folga = 5 * time.Millisecond
	if prazo > saldo+folga {
		t.Errorf("WalkDeadline ficou em %s com saldo de %s (Budget=2min): o "+
			"prazo da varredura tem de ser o MENOR entre o orçamento por "+
			"captura e o que resta da sessão — senão um teto total de 1s "+
			"autoriza dois minutos de trabalho no host", prazo, saldo)
	}
	if prazo >= s.pol.Budget {
		t.Errorf("o prazo (%s) veio do Budget por captura e não do saldo", prazo)
	}
	if !mediu {
		t.Fatal("o teste não chegou a medir nada")
	}

	// E o saldo agora acabou, então a próxima é recusada.
	if _, er := s.porNome["snapshot.capture"].Rodar(s,
		json.RawMessage(`{"scope":"complete"}`)); er == nil {
		t.Error("o saldo acabou e a captura seguinte passou")
	}
}
