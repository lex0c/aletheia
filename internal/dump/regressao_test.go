package dump

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/facts"
)

// A CATRACA DA FORMA PARTIDA, e por que a anterior não bastava.
//
// A catraca global enche toda superfície com UMA string que contém o segredo
// embutido (`--password=X`). Ela passa com qualquer redator que olhe dentro de
// um token — e não vê a forma que exige contexto:
//
//	["mysql", "-p", "S3CR3T"]
//
// Aqui a flag e o valor são tokens SEPARADOS, e só um redator com estado entre
// eles liga os dois. A caminhada por string perdia esse estado e devolvia o
// segredo em claro — um vazamento que a redação anterior, curada e com contexto,
// não tinha. Foi assim que "consertar um vazamento" abriu outro.
func TestFormaPartidaNaoVaza(t *testing.T) {
	casos := []struct {
		nome  string
		fatos func() *facts.Facts
	}{
		{".bashrc com -p separado", func() *facts.Facts {
			// A superfície que motivou a reescrita inteira. Ela pegava a forma
			// EMBUTIDA e deixava passar a partida, porque a etiquetagem inicial
			// só cobriu os quatro campos que a redação curada já protegia — e o
			// .bashrc nunca esteve entre eles.
			return &facts.Facts{Triggers: []facts.Trigger{{Lines: []facts.TriggerLine{
				{Text: "mysql -p " + sentinela}}}}}
		}},
		{"ProxyCommand com -p separado", func() *facts.Facts {
			return &facts.Facts{SSHClientExec: []facts.SSHClientExec{
				{Command: "ssh -p " + sentinela}}}
		}},
		{"core_pattern com flag separada", func() *facts.Facts {
			return &facts.Facts{Helpers: []facts.HelperDoKernel{
				{Valor: "|/bin/x --password " + sentinela}}}
		}},
		{"flag POR EXTENSO em texto livre", func() *facts.Facts {
			// Aqui não há etiqueta de comando, e mesmo assim a forma partida é
			// pega: `--password` não é outra coisa em lugar nenhum. É a de UMA
			// LETRA que é ambígua, e essa fica para os campos que se declaram.
			return &facts.Facts{ExecOculto: []string{"app --token " + sentinela}}
		}},
		{"argv com -p separado", func() *facts.Facts {
			return &facts.Facts{Processes: []facts.Process{
				{PID: 1, Argv: []string{"mysql", "-p", sentinela, "prod"}}}}
		}},
		{"argv com cabeçalho de auth partido", func() *facts.Facts {
			return &facts.Facts{Processes: []facts.Process{
				{PID: 1, Argv: []string{"curl", "-H", "Authorization:", "Bearer", sentinela}}}}
		}},
		{"environ nomeado pela chave", func() *facts.Facts {
			return &facts.Facts{Processes: []facts.Process{
				{PID: 1, Env: map[string]string{"password": sentinela}}}}
		}},
		{"variável de crontab nomeada pela chave", func() *facts.Facts {
			return &facts.Facts{Cron: []facts.CronEntry{
				{Env: []facts.EnvSetting{{Key: "token", Value: sentinela}}}}}
		}},
	}
	for _, c := range casos {
		t.Run(c.nome, func(t *testing.T) {
			f := c.fatos()
			f.SchemaVersion = facts.SchemaVersion
			var buf bytes.Buffer
			if err := De(ambienteDeTeste(), f).Escrever(&buf); err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(buf.Bytes(), []byte(sentinela)) {
				t.Fatalf("o segredo saiu em claro — a forma PARTIDA precisa de um "+
					"redator com estado, e o campo tem de declarar a classe dele "+
					"(redact:\"cmdline\" para argv, \"valor\" para nome/valor).\n%s",
					buf.String())
			}
		})
	}
}

// A CATRACA DA CORRUPÇÃO — o outro sentido do mesmo defeito.
//
// Aplicar o redator de linha de comando a texto que não é comando estraga o que
// não é segredo. Medido antes do conserto: uma regra de auditd
// `-w /etc/passwd -p wa -k identity` saía como `-w <redacted> -p <redacted> …`,
// e num valor multilinha um `Authorization:` na primeira linha mascarava todas
// as seguintes.
//
// Isso é pior que ruído: o Facts cru não é guardado em lugar nenhum, então a
// evidência perdida no artefato é irrecuperável.
func TestEvidenciaSemSegredoAtravessaIntacta(t *testing.T) {
	// O corpus vai num campo de TEXTO LIVRE, que é o padrão e a maioria.
	//
	// Um campo etiquetado como comando recebe semântica de comando de propósito,
	// e ali `-w /etc/passwd -p wa` SERIA mascarado — o que está certo se o campo
	// guarda comando, e é por isso que a etiqueta é por campo. A primeira versão
	// deste teste enfiava o corpus inteiro em Trigger.Lines[].Text, que é linha
	// de .bashrc: uma regra de auditd não mora ali, e o fixture é que estava
	// irreal. Corrigir o fixture é diferente de mover a trave — a regra de
	// auditd é afirmada logo abaixo, no campo em que ela de fato vive.
	limpos := []string{
		"/usr/bin/ssh",
		"/etc/ssl/private/server.key",
		"|/usr/share/apport/apport %p %s %c %d %P",
		"Description=Um serviço  qualquer",
		"#!/bin/sh\nset -e\nexec /usr/bin/app --port 8080\n",
		"  if x:\n    y()\n",
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGx3 systemd-timesync@localhost",
	}
	for _, s := range limpos {
		f := &facts.Facts{
			SchemaVersion: facts.SchemaVersion,
			ExecOculto:    []string{s},
		}
		var buf bytes.Buffer
		if err := De(ambienteDeTeste(), f).Escrever(&buf); err != nil {
			t.Fatal(err)
		}
		esperado, _ := json.Marshal(s)
		if !bytes.Contains(buf.Bytes(), esperado) {
			t.Errorf("a redação CORROMPEU evidência sem segredo:\n  %q\n  saída: %s",
				s, recorte(buf.String(), s))
		}
	}
}

// E a regra de auditd, no campo em que ela vive: intacta.
//
// Ela é o caso que mostrou por que a semântica de comando não pode ser o padrão
// — `-w` e `-p` são flags de segredo numa linha de comando e são "watch" e
// "permissions" numa regra de auditoria.
func TestRegraDeAuditdAtravessaIntacta(t *testing.T) {
	regra := "-w /etc/passwd -p wa -k identity"
	f := &facts.Facts{
		SchemaVersion: facts.SchemaVersion,
		Audit:         facts.Auditoria{Regras: []facts.RegraAudit{{Texto: regra}}},
	}
	var buf bytes.Buffer
	if err := De(ambienteDeTeste(), f).Escrever(&buf); err != nil {
		t.Fatal(err)
	}
	esperado, _ := json.Marshal(regra)
	if !bytes.Contains(buf.Bytes(), esperado) {
		t.Fatalf("a regra de auditd foi corrompida: %s", buf.String())
	}
}

// E o multilinha não contamina: um cabeçalho numa linha não pode mascarar as
// seguintes.
func TestCabecalhoNaoContaminaAsLinhasSeguintes(t *testing.T) {
	f := &facts.Facts{
		SchemaVersion: facts.SchemaVersion,
		Triggers: []facts.Trigger{{Lines: []facts.TriggerLine{{
			Text: "curl -H Authorization: Bearer " + sentinela +
				"\n/usr/bin/app --port 8080\n/etc/passwd\n"}}}},
	}
	var buf bytes.Buffer
	if err := De(ambienteDeTeste(), f).Escrever(&buf); err != nil {
		t.Fatal(err)
	}
	saida := buf.String()
	if strings.Contains(saida, sentinela) {
		t.Fatal("o segredo do cabeçalho vazou")
	}
	for _, sobrevivente := range []string{"/usr/bin/app", "--port", "8080", "/etc/passwd"} {
		if !strings.Contains(saida, sobrevivente) {
			t.Errorf("%q foi mascarado por um cabeçalho de OUTRA linha", sobrevivente)
		}
	}
}

func recorte(s, ancora string) string {
	if i := strings.Index(s, ancora[:min(8, len(ancora))]); i > 40 {
		return s[i-40 : min(i+120, len(s))]
	}
	return s[:min(200, len(s))]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

var _ = reflect.TypeOf
