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

// O índice vinha da string MINÚSCULA e fatiava a ORIGINAL.
//
// `strings.ToLower` muda o comprimento em bytes de dois pontos de código no
// mapeamento simples do Go: U+023A e U+023E, que ocupam 2 bytes e viram 3. Um
// deles antes da chave empurra o índice um byte para a FRENTE, e o corte passa
// a cair DEPOIS do "=" — levando junto o começo do segredo. Com o segredo
// curto o bastante, a guarda de tamanho (medida na original) reprova e a
// redação não acontece de jeito nenhum: a senha inteira vai para o relatório,
// para o ticket e para o e-mail.
//
// A asserção é do texto EXATO. `Contains` não serviria: o vazamento é de um
// byte por caractere desses, e um teste que procura a senha inteira dá o
// mesmo verde com metade dela na tela.
func TestSegredoNaoVazaPorCaixaQueMudaDeTamanho(t *testing.T) {
	casos := []struct{ arg, quer string }{
		// Um Ⱥ antes da chave: o corte cai um byte depois do "=".
		{"--Ⱥ--password=S3cr3t", "--Ⱥ--password=<redacted>"},
		{"--ȾȾȾ--token=abcdef", "--ȾȾȾ--token=<redacted>"},
		// E o caso em que a guarda reprova e NADA é redigido.
		{"Ⱥ--secret=x", "Ⱥ--secret=<redacted>"},
	}
	for _, c := range casos {
		got := Cmdline([]string{"app", c.arg})
		if len(got) != 2 || got[1] != c.quer {
			t.Errorf("Cmdline(%q) = %q, queria %q", c.arg, got[1], c.quer)
		}
	}
}

// E a redação continua acontecendo em maiúscula pura, que é o caso comum de
// quem escreve a flag com a caixa da documentação.
func TestChaveEmMaiusculaAindaEhRedigida(t *testing.T) {
	got := Cmdline([]string{"app", "--PASSWORD=hunter2", "--Token", "xyz"})
	juntos := strings.Join(got, " ")
	if strings.Contains(juntos, "hunter2") || strings.Contains(juntos, "xyz") {
		t.Errorf("caixa alta escapou da redação: %q", juntos)
	}
}
