package redact

import "testing"

// Texto redige e PRESERVA a forma. Ela existe porque a redação passou a valer
// para toda superfície textual do dump, e ali há trecho de código, linha de log
// e configuração alinhada — coisas que Fields+Join destruiria.
func TestTextoPreservaEspacamentoENewline(t *testing.T) {
	casos := []struct{ nome, entrada, quer string }{
		{"vazio", "", ""},
		{"token só", "/usr/bin/ssh", "/usr/bin/ssh"},
		{"espaçamento duplo", "a  b\tc", "a  b\tc"},
		{"multilinha intacta", "linha um\nlinha dois\n", "linha um\nlinha dois\n"},
		{"indentação preservada", "  if x:\n    y()\n", "  if x:\n    y()\n"},
		{"segredo redigido, forma mantida",
			"curl  --token=S3CR3T\thttps://x", "curl  --token=<redacted>\thttps://x"},
		{"multilinha com segredo numa linha",
			"ok\nmysql --password=abc\nfim", "ok\nmysql --password=<redacted>\nfim"},
	}
	for _, c := range casos {
		t.Run(c.nome, func(t *testing.T) {
			if got := Texto(c.entrada); got != c.quer {
				t.Fatalf("quero %q, tenho %q", c.quer, got)
			}
		})
	}
}

// E o que ela NÃO pode fazer é perder byte: a forense lê este artefato meses
// depois, e o que não é segredo tem de atravessar idêntico.
func TestTextoSemSegredoAtravessaIdentico(t *testing.T) {
	for _, s := range []string{
		"", " ", "\n", "  \t\n  ", "a", " a ", "a\n\nb",
		"/etc/systemd/system/foo.service", "Description=Um serviço  qualquer",
		"#!/bin/sh\nset -e\nexec /usr/bin/app --port 8080\n",
	} {
		if got := Texto(s); got != s {
			t.Errorf("mudou sem segredo: %q -> %q", s, got)
		}
	}
}
