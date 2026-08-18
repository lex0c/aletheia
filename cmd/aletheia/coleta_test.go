package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lex0c/aletheia/internal/dump"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

// coletaEm data, com um implante memfd que começou uma hora antes.
//
// O memfd é o alvo porque ele existe INTEIRO nos fatos: exe apontando para
// memória anônima é um campo, não uma leitura de disco — que é justamente a
// propriedade que faz o `analyze` valer.
func dumpDeTeste(t *testing.T, coletaEm time.Time, caps env.Cap) string {
	t.Helper()
	e := &env.Env{
		Source:      env.SourceLive,
		Caps:        caps,
		CapReason:   map[string]string{"root": "coleta feita sem sudo: metade dos processos ficou ilegível"},
		Now:         coletaEm,
		Clock:       env.ClockSynced,
		ToolVersion: "0.0.9-coletora",
		ToolSHA256:  "f00dcafe",
	}
	f := &facts.Facts{
		SchemaVersion: facts.SchemaVersion,
		CollectedAt:   coletaEm.Format(time.RFC3339),
		Source:        "live",
		Host:          facts.Host{Hostname: "web-01"},
		Processes: []facts.Process{{
			PID: 812, Comm: "nginx", Exe: "/memfd:x", ExeMemfd: true,
			StartUTC: coletaEm.Add(-time.Hour).Format(time.RFC3339),
		}},
	}
	p := filepath.Join(t.TempDir(), "host.json")
	fh, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	if err := dump.De(e, f).Escrever(fh); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCollectRecusaInvocacaoAmbigua(t *testing.T) {
	casos := map[string][]string{
		"sem --out":          {},
		"--root inexistente": {"--out", "-", "--root", filepath.Join(t.TempDir(), "nada")},
	}
	for nome, args := range casos {
		t.Run(nome, func(t *testing.T) {
			if code := semSaida(t, func() int { return runCollect(args) }); code != 3 {
				t.Errorf("exit = %d, queria 3", code)
			}
		})
	}
}

func TestAnalyzeRecusaOQueNaoSabeLer(t *testing.T) {
	bom := dumpDeTeste(t, time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC), env.CapProcfs|env.CapFilesystem)
	ruim := filepath.Join(t.TempDir(), "outro-esquema.json")
	if err := os.WriteFile(ruim, []byte(`{"schema":99,"facts":{"schema_version":1}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	casos := map[string][]string{
		"sem argumento":           {},
		"dois argumentos":         {bom, bom},
		"arquivo ausente":         {filepath.Join(t.TempDir(), "nao-existe.json")},
		"esquema de outra versão": {ruim},
		"--mode inválido":         {"--mode", "talvez", bom},
	}
	for nome, args := range casos {
		t.Run(nome, func(t *testing.T) {
			if code := semSaida(t, func() int { return runAnalyze(args) }); code != 3 {
				t.Errorf("exit = %d, queria 3 (ERROR de invocação)", code)
			}
		})
	}
}

// O caminho principal: o retrato entra, o veredito sai — e o relatório diz, em
// letras, que nada foi olhado agora.
func TestAnalyzeConcluiSobreORetrato(t *testing.T) {
	coleta := time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)
	d := dumpDeTeste(t, coleta, env.CapProcfs|env.CapFilesystem)
	jsonl := filepath.Join(t.TempDir(), "saida.jsonl")

	code := semSaida(t, func() int { return runAnalyze([]string{"--json", jsonl, d}) })
	if code != 2 {
		t.Fatalf("exit = %d, queria 2 — o memfd do dump é crítico", code)
	}

	linhas := jsonlDe(t, jsonl)
	var achado, analise, cobertura map[string]string
	for _, l := range linhas {
		switch l["id"] {
		case "proc.memfd_exec":
			achado = l
		case "analysis":
			analise = l
		case "coverage":
			cobertura = l
		}
	}
	if achado == nil {
		t.Fatalf("o achado não sobreviveu à ida e volta: %v", linhas)
	}
	// O `ts` do achado é o da COLETA: é a data que o incidente tem, não a hora
	// em que alguém abriu o arquivo.
	if achado["ts"] != "2026-01-15T10:00:00Z" {
		t.Errorf("ts = %q, queria o instante da coleta", achado["ts"])
	}
	if achado["host"] != "web-01" {
		t.Errorf("host = %q — o achado é do host coletado, não de quem analisa", achado["host"])
	}

	// A linha de análise existe para que a agregação de frota não confunda um
	// replay de um retrato antigo com uma varredura de agora.
	if analise == nil {
		t.Fatal("faltou a linha de análise no JSONL")
	}
	if analise["collected_by"] != "aletheia/0.0.9-coletora" || analise["analyzed_by"] == "" {
		t.Errorf("a linha de análise não nomeia as DUAS ferramentas: %v", analise)
	}
	if cobertura["replay"] == "" && cobertura["verdict"] == "" {
		t.Errorf("cobertura sem marca de replay: %v", cobertura)
	}
}

// A regra que sustenta o comando: a cobertura é a DA COLETA.
//
// O teste roda a análise numa máquina que pode ter tudo, sobre um dump que não
// tinha nada. Se o `analyze` sondasse o ambiente local, o check de procfs
// rodaria e a cobertura subiria — um relatório afirmando ter verificado
// processos que ninguém listou.
func TestAnalyzeNaoMelhoraACoberturaDaColeta(t *testing.T) {
	d := dumpDeTeste(t, time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC), 0) // coleta cega
	jsonl := filepath.Join(t.TempDir(), "saida.jsonl")

	code := semSaida(t, func() int {
		return runAnalyze([]string{"--only", "proc", "--json", jsonl, d})
	})
	if code != 1 {
		t.Fatalf("exit = %d, queria 1 (INCOMPLETE): a coleta não viu processo nenhum", code)
	}

	var cobertura map[string]any
	for _, l := range jsonlCru(t, jsonl) {
		if l["id"] == "coverage" {
			cobertura = l
		}
	}
	if cobertura == nil {
		t.Fatal("sem linha de cobertura")
	}
	if c, _ := cobertura["complete"].(float64); c != 0 {
		t.Errorf("complete = %v, queria 0 — nenhum check de processo podia rodar", c)
	}
	nc, _ := cobertura["not_checked"].([]any)
	if len(nc) == 0 {
		t.Fatal("nada foi declarado NÃO VERIFICADO numa coleta sem procfs")
	}
	// E o motivo precisa ser o que a COLETA escreveu, não um genérico da análise.
	primeiro, _ := nc[0].(map[string]any)
	razao, _ := primeiro["reason"].(string)
	if razao == "" || razao == "indisponível" {
		t.Errorf("motivo = %q — a análise perdeu o que a coleta tinha registrado", razao)
	}
}

// A janela é ancorada na COLETA, não no relógio de quem analisa.
//
// O dump é de janeiro e o achado é de uma hora antes dele. `--since 2h` sobre um
// retrato significa "as 2 horas anteriores ao retrato". Ancorado em agora, o
// achado sairia do relatório — e o operador leria que nada aconteceu na janela.
func TestJanelaDoAnalyzeEhAncoradaNaColeta(t *testing.T) {
	d := dumpDeTeste(t, time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC), env.CapProcfs|env.CapFilesystem)
	jsonl := filepath.Join(t.TempDir(), "saida.jsonl")

	code := semSaida(t, func() int {
		return runAnalyze([]string{"--since", "2h", "--json", jsonl, d})
	})
	if code != 2 {
		t.Fatalf("exit = %d, queria 2: o achado é de dentro da janela", code)
	}
	var achado bool
	for _, l := range jsonlDe(t, jsonl) {
		if l["id"] == "proc.memfd_exec" {
			achado = true
		}
	}
	if !achado {
		t.Error("a janela cortou um achado que está DENTRO dela: o âncora foi " +
			"para o relógio de quem analisa, não para o da coleta")
	}
}

// O hash é o único indicador que a análise não consegue procurar sozinha: ele é
// calculado durante a coleta. Uma lista trazida depois precisa produzir LACUNA
// declarada, e nunca um relatório limpo.
func TestHashDeIOCSemColetaViraLacunaDeclarada(t *testing.T) {
	d := dumpDeTeste(t, time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC), env.CapProcfs|env.CapFilesystem)
	lista := filepath.Join(t.TempDir(), "ioc.txt")
	conteudo := "hashes:\n  - 9f2c1e4b7a3d5f6081c2e3d4a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5c6d7e\n"
	if err := os.WriteFile(lista, []byte(conteudo), 0o600); err != nil {
		t.Fatal(err)
	}
	jsonl := filepath.Join(t.TempDir(), "saida.jsonl")

	semSaida(t, func() int {
		return runAnalyze([]string{"--ioc", lista, "--json", jsonl, d})
	})

	var gaps []any
	for _, l := range jsonlCru(t, jsonl) {
		if l["id"] == "coverage" {
			gaps, _ = l["collector_gaps"].([]any)
		}
	}
	var achou bool
	for _, g := range gaps {
		if s, _ := g.(string); strings.Contains(s, "hash se calcula durante a coleta") {
			achou = true
		}
	}
	if !achou {
		t.Errorf("o hash não procurado saiu como silêncio, e não como lacuna: %v", gaps)
	}
}

// jsonlCru devolve as linhas com os valores como estão — o `jsonlDe` do
// preserve só traz os campos de texto, e aqui a cobertura tem número e lista.
func jsonlCru(t *testing.T, p string) []map[string]any {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("lendo %s: %v", p, err)
	}
	var out []map[string]any
	for _, ln := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if ln == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(ln), &m); err != nil {
			t.Fatalf("%s: linha não é JSON: %v", p, err)
		}
		out = append(out, m)
	}
	return out
}

// A cadeia de custódia do `collect` era mais fraca que a do `preserve`: o dump
// carregava `tool_sha256` DENTRO do próprio JSON, editável junto com o resto, e
// não havia soma do artefato.
//
// O que estes testes fixam não é autenticação — quem edita o dump edita o
// arquivo de soma ao lado, e nenhum dos dois carrega chave. É a detecção de
// alteração e de corrupção de transporte, num arquivo que atravessa scp,
// pendrive e três máquinas antes de virar conclusão.
func TestSomaDoDumpDetectaAlteracao(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "d.json")
	conteudo := []byte(`{"schema":1,"env":{"source":"live"}}` + "\n")
	if err := os.WriteFile(p, conteudo, 0o600); err != nil {
		t.Fatal(err)
	}
	soma := sha256.Sum256(conteudo)
	if err := os.WriteFile(p+".sha256",
		[]byte(hex.EncodeToString(soma[:])+"  d.json\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var b bytes.Buffer
	conferirSoma(&b, p)
	if !strings.Contains(b.String(), "confere") {
		t.Errorf("dump íntegro precisa dizer que confere: %q", b.String())
	}

	// Uma alteração de um byte.
	if err := os.WriteFile(p, append(conteudo, ' '), 0o600); err != nil {
		t.Fatal(err)
	}
	b.Reset()
	conferirSoma(&b, p)
	got := b.String()
	if !strings.Contains(got, "NÃO CONFERE") {
		t.Errorf("um byte a mais precisa ser pego: %q", got)
	}
	// E a saída precisa mandar comparar com o número que saiu do host.
	if !strings.Contains(got, "war log") {
		t.Errorf("a custódia de verdade é o número anotado fora: %q", got)
	}
}

// Sem arquivo de soma — dump de versão anterior, ou vindo de stdin — a análise
// segue calada. Exigir a soma quebraria todo dump já coletado.
func TestSemArquivoDeSomaAAnaliseSegue(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "d.json")
	if err := os.WriteFile(p, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	conferirSoma(&b, p)
	if b.Len() != 0 {
		t.Errorf("sem soma não há o que dizer: %q", b.String())
	}
	b.Reset()
	conferirSoma(&b, "-")
	if b.Len() != 0 {
		t.Errorf("stdin não tem arquivo ao lado: %q", b.String())
	}
}

// Bug 4: o resumo do collect escondia lacuna de coletor quando as caps estavam
// todas presentes. E pior, só lia f.Partial — a truncagem de SUID vai para
// f.PersistDenied e não aparecia NUNCA. Os dois têm de sair, mesmo com ambiente
// completo, senão o resumo diz "completo" com a varredura truncada por baixo.
func TestResumoMostraGapMesmoComCapsCompletas(t *testing.T) {
	var buf bytes.Buffer
	e := &env.Env{Now: time.Date(2026, 8, 18, 0, 0, 0, 0, time.UTC), Source: env.SourceLive}
	for _, n := range env.TodasAsCaps() {
		c, _ := env.CapDeNome(n)
		e.Caps |= c
	}
	f := &facts.Facts{PersistDenied: map[string][]string{
		"suid": {"a varredura de SUID parou em 40000 diretórios: o excedente NÃO foi examinado"},
	}}
	resumoDaColeta(&buf, e, f, "host.json", "abc123")
	out := buf.String()
	if strings.Contains(out, "ambiente completo") {
		t.Error("com truncagem de SUID não se pode dizer 'ambiente completo'")
	}
	if !strings.Contains(out, "O QUE ESTA COLETA NÃO VIU") || !strings.Contains(out, "40000 diretórios") {
		t.Errorf("a truncagem de SUID (PersistDenied) precisa sair no resumo: %q", out)
	}
}
