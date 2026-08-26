package dump

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/facts"
)

// ataqueDeForma monta o artefato pequeno que decodifica grande.
func ataqueDeForma(n int) []byte {
	var b bytes.Buffer
	b.WriteString(`{"schema":2,"facts":{"schema_version":`)
	b.WriteString(itoa(facts.SchemaVersion))
	b.WriteString(`,"processes":[`)
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString("{}")
	}
	b.WriteString(`]}}`)
	return b.Bytes()
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func gravar(t *testing.T, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "d.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// O TETO DE BYTES NÃO ERA O TETO DE MEMÓRIA.
//
// MaxDump limita o JSON serializado; a memória é da estrutura decodificada, e
// quem escreve o arquivo escolhe a razão. Medido antes desta guarda: 0,86 MiB
// de `{}` produziam 600 MiB de heap vivo e 1 GiB alocado — 699×. No teto de
// 512 MiB o analisador precisaria de centenas de gigabytes, ou seja, MaxDump
// nunca chegava a disparar: o OOM chegava antes, e um processo morto por OOM
// sai com status 2, que a automação de frota lê como CRITICAL.
func TestFormaRecusaAmplificacao(t *testing.T) {
	b := ataqueDeForma(300_000)

	var antes, depois runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&antes)
	_, err := Carregar(gravar(t, b))
	runtime.ReadMemStats(&depois)

	if !errors.Is(err, ErrForma) {
		t.Fatalf("err=%v, queria ErrForma", err)
	}
	alocado := depois.TotalAlloc - antes.TotalAlloc
	t.Logf("arquivo %d bytes, alocado na recusa: %.1f MiB",
		len(b), float64(alocado)/(1<<20))
	// O ponto da guarda é a recusa custar a leitura do arquivo, e não a
	// decodificação dele. Um múltiplo pequeno do próprio arquivo é o teto certo
	// para essa afirmação; 1 GiB era o que acontecia antes.
	if alocado > 16*uint64(len(b)) {
		t.Errorf("a recusa alocou %d bytes para um arquivo de %d: a guarda "+
			"está agindo DEPOIS do custo que ela existe para impedir",
			alocado, len(b))
	}
}

// A CHAVE DENTRO DE UMA STRING NÃO ABRE NADA.
//
// É a única sutileza do contador, e errá-la recusaria artefato legítimo: uma
// linha de comando coletada de um host tem `{`, `[` e aspas escapadas dentro
// dela o tempo todo. `awk '{print $1}'` num argv basta.
func TestFormaIgnoraDelimitadorDentroDeString(t *testing.T) {
	// 400 chaves dentro de strings num arquivo curto: se fossem contadas, a
	// razão mínima recusaria na hora.
	ruido := strings.Repeat(`{[`, 200)
	d := map[string]any{
		"schema": Schema,
		"facts": map[string]any{
			"schema_version": facts.SchemaVersion,
			"hostname":       "awk '" + ruido + "print $1}' e uma aspa escapada: \" fim",
		},
	}
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if err := medirForma(b); err != nil {
		t.Fatalf("delimitador dentro de string foi contado: %v", err)
	}

	// E a barra invertida não pode esconder a aspa de fechamento: se ela
	// escondesse, o resto do documento seria lido como se fosse string e as
	// aberturas de verdade sumiriam do contador.
	comBarra := []byte(`{"a":"termina com barra escapada\\","b":[{},{},{}]}`)
	var prova any
	if err := json.Unmarshal(comBarra, &prova); err != nil {
		t.Fatalf("o caso de teste não é JSON válido: %v", err)
	}
	if err := medirForma(comBarra); err != nil {
		t.Fatalf("recusou um documento de 3 objetos: %v", err)
	}
}

// O ANINHAMENTO TEM TETO, e ele não é o do decodificador do Go.
//
// A bomba de aninhamento CRUA — `[[[[...]]]]` — nem chega aqui: ela é toda
// abertura e nenhum byte, então a razão mínima a recusa primeiro. Quem alcança
// este teto é a bomba ACOLCHOADA, com recheio suficiente para parecer
// proporcional, e é assim que o teste tem de montá-la para estar testando o que
// diz testar. A primeira versão dele usava a forma crua e passava pelo motivo
// errado.
func TestFormaRecusaAninhamentoFundo(t *testing.T) {
	n := MaxProfundidade + 5
	recheio := `"` + strings.Repeat("a", 64) + `",`
	b := []byte(strings.Repeat("["+recheio, n) + strings.Repeat("]", n))

	err := medirForma(b)
	if !errors.Is(err, ErrForma) {
		t.Fatalf("err=%v, queria ErrForma", err)
	}
	if !strings.Contains(err.Error(), "aninhamento") {
		t.Fatalf("a recusa precisa dizer que foi o aninhamento: %v", err)
	}

	// E a forma crua também é recusada — pela razão, que é a resposta certa
	// para ela.
	crua := []byte(strings.Repeat("[", n) + strings.Repeat("]", n))
	if err := medirForma(crua); !errors.Is(err, ErrForma) {
		t.Errorf("bomba crua: err=%v", err)
	}
}

// OS DOIS TETOS DIZEM COISAS DIFERENTES.
//
// Estourar a razão é uma afirmação sobre o ARQUIVO: ele não descreve um host.
// Estourar o teto absoluto é uma afirmação sobre o ANALISADOR: o orçamento
// acabou, e o artefato pode ser um proxy com centenas de milhares de sockets.
// Uma mensagem só mandaria o operador procurar atacante onde há um host grande.
func TestFormaSeparaOsDoisMotivos(t *testing.T) {
	razao := medirForma(ataqueDeForma(300_000))
	if razao == nil || !strings.Contains(razao.Error(), "não é um retrato de host") {
		t.Errorf("razão: a mensagem precisa acusar o arquivo: %v", razao)
	}

	// Proporção plausível e volume acima do orçamento: recheio suficiente para
	// passar da razão mínima, aberturas suficientes para passar do absoluto.
	var b bytes.Buffer
	b.WriteString(`{"schema":2,"facts":{"schema_version":` + itoa(facts.SchemaVersion) + `,"processes":[`)
	for i := 0; i <= MaxAberturas; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"exe":"/usr/bin/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`)
	}
	b.WriteString(`]}}`)
	absoluto := medirForma(b.Bytes())
	if absoluto == nil || !strings.Contains(absoluto.Error(), "orçamento") {
		t.Errorf("absoluto: a mensagem precisa falar do analisador: %v", absoluto)
	}
	if strings.Contains(absoluto.Error(), "não é um retrato de host") {
		t.Error("o teto absoluto está acusando o arquivo de ser malicioso, e um " +
			"host grande de verdade chega nele")
	}
}

// O PORTÃO DE ESQUEMA RECUSA ANTES DE DECODIFICAR.
//
// Ele era a última linha, depois do Unmarshal completo: um dump declarando
// `"schema": 0` era integralmente decodificado para então ser recusado por dois
// bytes que estavam no começo dele.
//
// A asserção se CALIBRA contra o caminho aceito, em vez de usar um múltiplo
// fixo do tamanho do arquivo. Sob `-race` a mesma decodificação aloca o dobro,
// e um número absoluto transformaria a mudança de modo de build em falha de
// teste — que é o teste medindo o instrumento em vez de medir o código.
func TestPortaoDeEsquemaNaoDecodificaOResto(t *testing.T) {
	corpo := func(esquema int) []byte {
		var b bytes.Buffer
		b.WriteString(`{"schema":` + itoa(esquema) + `,"facts":{"schema_version":` +
			itoa(facts.SchemaVersion) + `,"processes":[`)
		for i := 0; i < 20_000; i++ {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(`{"exe":"/usr/bin/xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}`)
		}
		b.WriteString(`]}}`)
		return b.Bytes()
	}

	custo := func(b []byte) (uint64, error) {
		p := gravar(t, b)
		var antes, depois runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&antes)
		d, err := Carregar(p)
		runtime.ReadMemStats(&depois)
		runtime.KeepAlive(d)
		return depois.TotalAlloc - antes.TotalAlloc, err
	}

	aceito, err := custo(corpo(Schema))
	if err != nil {
		t.Fatalf("o artefato de controle tinha de carregar: %v", err)
	}
	recusado, err := custo(corpo(99))
	if !errors.Is(err, ErrEsquema) {
		t.Fatalf("err=%v, queria ErrEsquema", err)
	}

	t.Logf("aceito=%.2f MiB  recusado=%.2f MiB  (%.0f%% do custo de decodificar)",
		float64(aceito)/(1<<20), float64(recusado)/(1<<20),
		100*float64(recusado)/float64(aceito))
	// Os dois artefatos diferem em DOIS BYTES. Se recusar custar perto do que
	// aceitar custa, o portão está rodando depois da decodificação.
	if recusado*4 > aceito {
		t.Errorf("recusar custou %d de %d bytes que custa aceitar: o portão "+
			"está lendo o artefato inteiro para descobrir que não devia",
			recusado, aceito)
	}
}

// E ELE ACERTA COM OS CAMPOS EM QUALQUER ORDEM.
//
// O caminho rápido para no primeiro `schema_version` e não tem como voltar
// atrás para achar um `schema` que venha depois. A ordem que este binário
// escreve nunca é essa, mas premissa sobre ordem de campo em JSON é premissa
// sobre o que outro escritor faz.
func TestPortaoDeEsquemaComCamposForaDeOrdem(t *testing.T) {
	casos := []struct {
		nome string
		doc  string
		quer error
	}{
		{"facts antes de schema, ambos certos",
			`{"facts":{"schema_version":` + itoa(facts.SchemaVersion) + `},"schema":` + itoa(Schema) + `}`, nil},
		{"facts antes de schema, schema errado",
			`{"facts":{"schema_version":` + itoa(facts.SchemaVersion) + `},"schema":99}`, ErrEsquema},
		{"schema_version no fim de facts",
			`{"schema":` + itoa(Schema) + `,"facts":{"hostname":"h","processes":[],"schema_version":` + itoa(facts.SchemaVersion) + `}}`, nil},
		{"facts nulo", `{"schema":` + itoa(Schema) + `,"facts":null}`, ErrVazio},
		{"sem facts", `{"schema":` + itoa(Schema) + `}`, ErrVazio},
		{"facts sem schema_version",
			`{"schema":` + itoa(Schema) + `,"facts":{"hostname":"h"}}`, ErrEsquema},
		{"campo grande antes de facts",
			`{"schema":` + itoa(Schema) + `,"env":{"a":[1,2,{"b":[3]}]},"facts":{"schema_version":` + itoa(facts.SchemaVersion) + `}}`, nil},
	}
	for _, c := range casos {
		t.Run(c.nome, func(t *testing.T) {
			err := portaoDeEsquema([]byte(c.doc))
			if c.quer == nil && err != nil {
				t.Fatalf("recusou um artefato válido: %v", err)
			}
			if c.quer != nil && !errors.Is(err, c.quer) {
				t.Fatalf("err=%v, queria %v", err, c.quer)
			}
			// O caminho rápido e o raso têm de concordar SEMPRE. Duas respostas
			// para a mesma pergunta é como nasce o artefato que passa por uma
			// porta e é recusado pela outra.
			raso := portaoRaso([]byte(c.doc))
			if (err == nil) != (raso == nil) {
				t.Errorf("rápido=%v mas raso=%v", err, raso)
			}
		})
	}
}

// E UM DUMP DE VERDADE CONTINUA CARREGANDO.
//
// Sem isto, um orçamento apertado demais passaria em todos os testes acima e
// quebraria a ferramenta no único caso que importa.
func TestDumpRealPassaNoOrcamento(t *testing.T) {
	d := &Dump{Schema: Schema, Facts: &facts.Facts{SchemaVersion: facts.SchemaVersion}}
	for i := 0; i < 2000; i++ {
		d.Facts.Processes = append(d.Facts.Processes, facts.Process{
			PID: i, Exe: "/usr/lib/systemd/systemd", Comm: "systemd",
			Argv: []string{"/usr/lib/systemd/systemd", "--user"},
		})
	}
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if err := medirForma(b); err != nil {
		t.Fatalf("um retrato de 2000 processos foi recusado: %v", err)
	}
	lido, err := Carregar(gravar(t, b))
	if err != nil {
		t.Fatalf("Carregar: %v", err)
	}
	if len(lido.Facts.Processes) != 2000 {
		t.Errorf("voltaram %d processos", len(lido.Facts.Processes))
	}
}

// O CONTADOR NÃO PODE SUBCONTAR JSON VÁLIDO.
//
// É a única forma de a guarda falhar em silêncio. Se `medirForma` acreditar que
// está dentro de uma string quando não está, as aberturas de verdade somem do
// contador e o artefato que o orçamento existe para recusar passa por ele — e
// passa sem nenhum sintoma, porque a decodificação seguinte funciona.
//
// Contar A MAIS é o lado seguro: o efeito é recusar um artefato legítimo, e
// contra isso há TestDumpRealPassaNoOrcamento. Contar a MENOS não tem teste que
// o encontre por amostragem, porque depende de qual escape o adversário
// escolhe. Então a asserção é contra o próprio encoding/json, sobre entrada que
// ele aceita: as duas gramáticas têm de concordar exatamente.
func FuzzFormaConcordaComOParser(f *testing.F) {
	f.Add([]byte(`{"a":1}`))
	f.Add([]byte(`{"a":"{{{["}`))
	f.Add([]byte(`{"a":"escapa \" e segue","b":[{},{}]}`))
	f.Add([]byte(`{"a":"barra dupla no fim\\","b":[{}]}`))
	f.Add([]byte(`{"a":"unicode de aspa " no meio","b":[{},{},{}]}`))
	f.Add([]byte(`[[[[[]]]]]`))
	f.Add([]byte(`{"":""}`))
	f.Add(ataqueDeForma(3))

	f.Fuzz(func(t *testing.T, b []byte) {
		// Só entrada que o parser ACEITA: sobre lixo, o Unmarshal é quem
		// recusa, e divergir ali não deixa nada passar.
		var qualquer any
		if json.Unmarshal(b, &qualquer) != nil {
			return
		}

		verdade := 0
		dec := json.NewDecoder(bytes.NewReader(b))
		for {
			tk, err := dec.Token()
			if err != nil {
				break
			}
			if d, ok := tk.(json.Delim); ok && (d == '{' || d == '[') {
				verdade++
			}
		}

		meu := contarAberturas(b)
		if meu < verdade {
			t.Fatalf("SUBCONTOU: %d contra %d do parser, em %q\n"+
				"Um contador que enxerga menos contêineres do que existem deixa "+
				"passar exatamente o artefato que o orçamento recusa.",
				meu, verdade, b)
		}
		if meu != verdade {
			t.Errorf("divergiu para mais: %d contra %d, em %q", meu, verdade, b)
		}
	})
}

// O PISO DA RAZÃO PROTEGE O ALVO POBRE.
//
// A razão mínima, aplicada desde o primeiro byte, recusaria justamente o
// artefato mais DENSO — e o mais denso é o retrato de um alvo sem processo,
// sem socket e sem log, onde só sobra a estrutura fixa. Medido: uma raiz
// mínima mede 100 bytes por abertura e um rootfs Alpine mede 72, contra os 166
// de uma workstation viva. Recusar um deles no meio de um incidente é pior do
// que decodificar os seis megabytes que o piso admite.
func TestRazaoNaoRecusaArtefatoPequenoEDenso(t *testing.T) {
	// Um documento denso o bastante para violar a razão, e pequeno o bastante
	// para não importar: abaixo do piso ele tem de passar.
	var b bytes.Buffer
	b.WriteString(`{"schema":` + itoa(Schema) + `,"facts":{"schema_version":` +
		itoa(facts.SchemaVersion) + `,"processes":[`)
	const n = MinAberturasParaRazao - 100
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString("{}")
	}
	b.WriteString(`]}}`)

	razao := float64(b.Len()) / float64(n+3)
	if razao >= MinBytesPorAbertura {
		t.Fatalf("o caso de teste não é denso o bastante (%.1f B/abertura): "+
			"ele passaria pela razão de qualquer jeito", razao)
	}
	if err := medirForma(b.Bytes()); err != nil {
		t.Fatalf("recusou %d aberturas abaixo do piso de %d: %v",
			n, MinAberturasParaRazao, err)
	}

	// E acima do piso a mesma densidade É recusada — o piso não é uma brecha,
	// é um limiar.
	if err := medirForma(ataqueDeForma(MinAberturasParaRazao + 1000)); !errors.Is(err, ErrForma) {
		t.Errorf("acima do piso a razão tinha de morder: %v", err)
	}
}
