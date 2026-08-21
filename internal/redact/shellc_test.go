package redact

import (
	"strings"
	"testing"
)

// Um argumento que É uma linha de comando inteira precisa ser redigido POR
// DENTRO.
//
// `sh -c "mysqldump -u root -pS3cr3t db"` carrega o comando todo em UM token de
// argv, e a varredura por token não olhava para dentro dele: a senha atravessava
// a redação e saía crua na evidência de proc.shell_from_service — justamente o
// check feito para reportar essa forma. É o modo de uso mais comum do shell num
// incidente, e o vazamento ia para o relatório humano, para o JSONL da frota e
// para o ticket.
//
// O defeito ficou escondido porque o check que o expunha não redigia nada; ao
// ligar redact.Cmdline lá, ele apareceu.
func TestArgumentoQueEhLinhaDeComandoEhRedigidoPorDentro(t *testing.T) {
	casos := []struct {
		nome   string
		argv   []string
		segred string
	}{
		{
			"mysql com -p colado dentro do -c",
			[]string{"bash", "-c", "mysqldump -u root -pS3cr3tD3Verdade db"},
			"S3cr3tD3Verdade",
		},
		{
			"flag isolada dentro do -c",
			[]string{"sh", "-c", "curl --header Authorization: Bearer tok_abc123 http://x"},
			"tok_abc123",
		},
		{
			"atribuição dentro do -c",
			[]string{"sh", "-c", "env PASSWORD=hunter2 ./deploy.sh"},
			"hunter2",
		},
		{
			"URL com credencial dentro do -c",
			[]string{"bash", "-c", "git clone https://user:tokensecreto@example.com/r.git"},
			"tokensecreto",
		},
	}
	for _, c := range casos {
		got := strings.Join(Cmdline(c.argv), " ")
		if strings.Contains(got, c.segred) {
			t.Errorf("%s: o segredo saiu cru\n  entrada: %q\n  saída:   %q",
				c.nome, c.argv, got)
		}
		// A ESTRUTURA precisa sobreviver: quem investiga tem de reconhecer o
		// comando. Redigir a linha inteira seria destruir a evidência para
		// proteger uma parte dela.
		if !strings.Contains(got, c.argv[0]) {
			t.Errorf("%s: o programa sumiu da saída %q", c.nome, got)
		}
	}
}

// E o caminho comum não pode ser mexido: uma linha sem segredo passa igual.
func TestLinhaDeComandoSemSegredoPassaIntacta(t *testing.T) {
	argv := []string{"bash", "-c", "tar -czf /backup/a.tgz /var/www"}
	got := Cmdline(argv)
	if len(got) != len(argv) {
		t.Fatalf("mudou o número de tokens: %q", got)
	}
	for i := range argv {
		if got[i] != argv[i] {
			t.Errorf("token %d virou %q, era %q — comando sem segredo foi alterado",
				i, got[i], argv[i])
		}
	}
}

// A redação do cabeçalho de autorização é por CONTEXTO, não por lista de
// esquemas: uma lista solta redigiria o argumento seguinte a qualquer `token`
// da linha, destruindo evidência sem ganhar segredo.
func TestPalavraTokenForaDeCabecalhoNaoRedigeOVizinho(t *testing.T) {
	for _, argv := range [][]string{
		{"vault", "token", "lookup"},
		{"aws", "sso", "token", "list"},
		{"bash", "-c", "vault token lookup -format=json"},
	} {
		got := strings.Join(Cmdline(argv), " ")
		if strings.Contains(got, "<redacted>") {
			t.Errorf("%q virou %q: `token` como palavra comum não abre cabeçalho "+
				"de autorização, e redigir o vizinho destrói evidência", argv, got)
		}
	}
}

// E o limite do cabeçalho é a próxima opção ou a URL — sem isso a redação
// engoliria o resto da linha, inclusive o destino, que é a evidência principal.
func TestCabecalhoAuthNaoEngoleORestoDaLinha(t *testing.T) {
	argv := []string{"bash", "-c",
		"curl -H Authorization: Bearer tok_secreto https://c2.example/beacon -v"}
	got := strings.Join(Cmdline(argv), " ")
	if strings.Contains(got, "tok_secreto") {
		t.Errorf("a credencial vazou: %q", got)
	}
	for _, quer := range []string{"curl", "https://c2.example/beacon", "-v"} {
		if !strings.Contains(got, quer) {
			t.Errorf("a redação engoliu %q, que é evidência: %q", quer, got)
		}
	}
}
