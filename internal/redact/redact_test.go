package redact

import (
	"strings"
	"testing"
)

// SPEC 5.4: a redação é da camada de saída. O relatório vai para ticket, e-mail
// e post-mortem, e imprime cmdline com senha — redigir só o dump seria proteger
// o artefato MENOS exposto.
func TestCmdlineRedigeSegredoEPreservaIdentidade(t *testing.T) {
	cases := []struct {
		name   string
		argv   []string
		vazado string
	}{
		{"mysql -p colado", []string{"mysqldump", "-u", "root", "-pS3cr3tP4ss", "prod"}, "S3cr3tP4ss"},
		{"--password=", []string{"psql", "--password=hunter2"}, "hunter2"},
		{"flag separada", []string{"curl", "--token", "ghp_abc123", "https://x"}, "ghp_abc123"},
		{"URL com credencial", []string{"git", "clone", "https://user:tok3n@host/r.git"}, "tok3n"},
		{"env-like no argv", []string{"app", "DB_PASSWORD=abc123xyz"}, "abc123xyz"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := strings.Join(Cmdline(c.argv), " ")
			if strings.Contains(got, c.vazado) {
				t.Errorf("segredo vazou: %q", got)
			}
			if !strings.Contains(got, c.argv[0]) {
				t.Errorf("a redação apagou o que IDENTIFICA o processo: %q", got)
			}
		})
	}
}

// Redigir demais também custa: o operador precisa reconhecer o processo.
func TestCmdlineNaoRedigeArgumentoInocente(t *testing.T) {
	argv := []string{"nginx", "-g", "daemon off;", "-c", "/etc/nginx/nginx.conf"}
	got := strings.Join(Cmdline(argv), " ")
	for _, want := range []string{"nginx", "daemon off;", "/etc/nginx/nginx.conf"} {
		if !strings.Contains(got, want) {
			t.Errorf("argumento inocente foi redigido: %q não contém %q", got, want)
		}
	}
}
