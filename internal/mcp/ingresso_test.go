package mcp

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/dump"
	"github.com/lex0c/aletheia/internal/facts"
)

// O CARIMBO DO ARTEFATO NÃO É BARREIRA DE SEGURANÇA.
//
// O portão de DadosCrus classifica a TOOL; o carimbo classifica o ARTEFATO. Nada
// obrigava o segundo a ser verdade — e um dump não é autenticado, o que o
// próprio envelope deste servidor afirma em `authenticated: false`.
//
// Então --allow-secrets tinha uma porta lateral: bastava servir um dump que se
// declarasse não redigido — ou que MENTISSE que foi, carregando texto cru — e as
// tools comuns o entregavam sem consentimento nenhum.
//
// A propriedade nova separa os dois papéis:
//
//	redaction           PROCEDÊNCIA: o que o arquivo afirma sobre si
//	redaction_enforced  ENFORCEMENT: o que este binário fez antes de servir
//
// Só o segundo vale como garantia, e ele é do servidor.
func TestCarimboMentirosoNaoContornaOConsentimento(t *testing.T) {
	const segredo = "S3cr3tD0Host"

	// Um artefato HOSTIL: diz que foi redigido, e carrega senha em claro.
	f := &facts.Facts{
		SchemaVersion: facts.SchemaVersion,
		CollectedAt:   "2026-08-17T21:03:11Z",
		Source:        "live",
		Host:          facts.Host{Hostname: "web-01"},
		Processes: []facts.Process{{
			PID: 812, Comm: "mysqldump", Exe: "/usr/bin/mysqldump",
			Argv: []string{"mysqldump", "-u", "root", "-p" + segredo, "prod"},
		}},
	}
	d := &dump.Dump{
		Schema:  dump.Schema,
		Redacao: dump.Redacao{Aplicada: true, Versao: dump.RedacaoVersao},
		Facts:   f,
	}
	d.Ambiente.Source = "live"
	d.Ambiente.Caps = []string{"procfs"}
	d.Ambiente.CollectedAt = "2026-08-17T21:03:11Z"

	caminho := filepath.Join(t.TempDir(), "hostil.json")
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caminho, b, 0o600); err != nil {
		t.Fatal(err)
	}

	// 1. Por padrão, a redação é IMPOSTA no ingresso.
	a := NovoAcervo()
	r, err := a.Carregar(caminho)
	if err != nil {
		t.Fatal(err)
	}
	argv := strings.Join(r.Fatos.Processes[0].Argv, " ")
	if strings.Contains(argv, segredo) {
		t.Errorf("o segredo de um dump que MENTE sobre o próprio carimbo chegou "+
			"aos fatos servidos: %q\nO carimbo é procedência, e quem escreve o "+
			"arquivo escolhe o que ele diz.", argv)
	}
	if !r.Redigido {
		t.Error("o retrato não se declara redigido depois da imposição")
	}
	if got := r.Procedencia().RedacaoImposta; got != ImposicaoAplicada {
		t.Errorf("redaction_enforced=%q", got)
	}
	// E a PROCEDÊNCIA continua contando o que o arquivo afirmava: as duas
	// perguntas são diferentes, e achatá-las perderia a pista de que o artefato
	// mentiu.
	if got := r.Procedencia().Redacao; got != string(dump.RedacaoAplicada) {
		t.Errorf("a procedência tem de continuar ecoando o carimbo: %q", got)
	}

	// 2. Com o consentimento do operador, o artefato é servido como está.
	cru := NovoAcervo()
	cru.ServirCru = true
	rc, err := cru.Carregar(caminho)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(rc.Fatos.Processes[0].Argv, " "), segredo) {
		t.Error("com --allow-secrets o artefato tem de ser servido COMO ESTÁ: " +
			"a flag não promete recuperar o que já saiu redigido do host, mas " +
			"também não pode redigir o que o operador mandou servir")
	}
	if got := rc.Procedencia().RedacaoImposta; got != ImposicaoDispensada {
		t.Errorf("redaction_enforced=%q com o consentimento dado", got)
	}
}

// E a imposição não custa evidência: a redação é idempotente, então um artefato
// honesto atravessa o ingresso byte a byte igual.
//
// Sem isto, re-redigir na carga seria uma perda silenciosa — o defeito que a
// própria redação já cometeu uma vez, quando redigirPar copiava a struct e
// reescrevia só um campo.
func TestImposicaoNaoAlteraArtefatoHonesto(t *testing.T) {
	f := fatosDeTeste()
	f.Processes[1].Argv = []string{"nginx", "-g", "daemon off;"}

	var buf strings.Builder
	honesto := dump.De(ambienteDeTeste(), f)
	b, err := json.Marshal(honesto)
	if err != nil {
		t.Fatal(err)
	}
	buf.Write(b)

	caminho := filepath.Join(t.TempDir(), "honesto.json")
	if err := os.WriteFile(caminho, []byte(buf.String()), 0o600); err != nil {
		t.Fatal(err)
	}

	comImposicao := NovoAcervo()
	r1, err := comImposicao.Carregar(caminho)
	if err != nil {
		t.Fatal(err)
	}
	semImposicao := NovoAcervo()
	semImposicao.ServirCru = true
	r2, err := semImposicao.Carregar(caminho)
	if err != nil {
		t.Fatal(err)
	}

	b1, _ := json.Marshal(r1.Fatos)
	b2, _ := json.Marshal(r2.Fatos)
	if string(b1) != string(b2) {
		t.Errorf("a redação de ingresso MUDOU um artefato já redigido: ela tem "+
			"de ser idempotente, senão a imposição custa evidência.\n%d vs %d bytes",
			len(b1), len(b2))
	}
}

// UM DUMP HOSTIL NÃO ENTREGA SEGREDO POR UM CAMPO DE BYTES.
//
// A redação de ingresso é o que sustenta `redaction_enforced: enforced`, e ela é
// uma caminhada reflexiva. Ela tratava string e descia até o elemento de um
// []byte — onde encontrava um uint8, para o qual não havia caso, e o devolvia
// igual.
//
// O campo Process.EnvBruto, que existe justamente para guardar bytes crus,
// atravessava intacto. Nenhuma tool servida hoje o expõe sem consentimento, mas
// a garantia publicada no envelope era objetivamente falsa para aquele tipo — e
// uma fronteira de segurança não vale "enquanto ninguém encostar".
//
// Este teste é o caminho do MCP inteiro: artefato hostil em disco, carga pelo
// acervo, e a busca no que ficou servido.
func TestDumpHostilNaoServeSegredoEmCampoDeBytes(t *testing.T) {
	const segredo = "AWS_SECRET_ACCESS_KEY=SUPERSECRETO-DO-HOST"

	f := &facts.Facts{
		SchemaVersion: facts.SchemaVersion,
		CollectedAt:   "2026-08-17T21:03:11Z",
		Source:        "live",
		Host:          facts.Host{Hostname: "web-01"},
		Processes: []facts.Process{{
			PID: 812, Comm: "app", EnvLido: true,
			EnvBruto: [][]byte{[]byte(segredo)},
		}},
	}
	// O artefato AFIRMA que foi redigido. Ele não foi.
	d := &dump.Dump{
		Schema:  dump.Schema,
		Redacao: dump.Redacao{Aplicada: true, Versao: dump.RedacaoVersao},
		Facts:   f,
	}
	d.Ambiente.Source = "live"
	d.Ambiente.Caps = []string{"procfs"}
	d.Ambiente.CollectedAt = "2026-08-17T21:03:11Z"

	caminho := filepath.Join(t.TempDir(), "hostil.json")
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "SUPERSECRETO") &&
		!strings.Contains(string(b), base64.StdEncoding.EncodeToString([]byte(segredo))) {
		t.Fatal("o segredo não entrou no artefato: o teste não mede nada")
	}
	if err := os.WriteFile(caminho, b, 0o600); err != nil {
		t.Fatal(err)
	}

	a := NovoAcervo()
	r, err := a.Carregar(caminho)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Redigido || r.Procedencia().RedacaoImposta != ImposicaoAplicada {
		t.Fatalf("o retrato não se declara imposto: %v", r.Procedencia().RedacaoImposta)
	}

	for _, p := range r.Fatos.Processes {
		for i, cru := range p.EnvBruto {
			if bytes.Contains(cru, []byte("SUPERSECRETO")) {
				t.Fatalf("pid %d, entrada %d: o segredo atravessou a redação de "+
					"ingresso num campo de bytes, e o servidor declarou "+
					"redaction_enforced=enforced sobre ele.\n%q", p.PID, i, cru)
			}
		}
	}
}
