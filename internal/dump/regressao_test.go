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
	limpos := []string{
		"/usr/bin/ssh",
		"/etc/ssl/private/server.key",
		"-w /etc/passwd -p wa -k identity",
		"|/usr/share/apport/apport %p %s %c %d %P",
		"Description=Um serviço  qualquer",
		"#!/bin/sh\nset -e\nexec /usr/bin/app --port 8080\n",
		"  if x:\n    y()\n",
		"ExecStart=/usr/bin/env sleep 30",
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGx3 systemd-timesync@localhost",
	}
	for _, s := range limpos {
		f := &facts.Facts{
			SchemaVersion: facts.SchemaVersion,
			Triggers:      []facts.Trigger{{File: "/root/.bashrc", Lines: []facts.TriggerLine{{Text: s}}}},
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
