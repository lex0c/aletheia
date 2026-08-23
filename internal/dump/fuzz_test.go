package dump

import (
	"os"
	"path/filepath"
	"testing"
)

// O ARTEFATO É ENTRADA ADVERSÁRIA, e este é o parser que o come.
//
// O modelo de ameaça do `--snapshot` é explícito: um dump não é autenticado, e
// quem o escreveu escolhe o que ele diz. O servidor MCP re-redige no ingresso
// justamente por isso — mas a re-redação acontece DEPOIS do parse, e o parse
// acontece antes de qualquer defesa.
//
// Pior: a redação de ingresso é uma caminhada REFLEXIVA sobre a estrutura que o
// atacante controlou. Um ponteiro nulo, um mapa com chave vazia, um slice
// gigante — tudo isso passa por reflect antes de qualquer check rodar.
//
// A propriedade é modesta e forte: nenhuma entrada faz o carregamento entrar em
// pânico. Um pânico aqui derruba o processo do lado do ANALISTA, e é o único
// caminho de código que roda antes de o servidor ter qualquer estado.
func FuzzCarregar(f *testing.F) {
	f.Add([]byte(`{"schema":2,"redaction":{"applied":true,"version":1},"env":{"source":"live"},"facts":{"schema_version":17}}`))
	f.Add([]byte(`{"schema":2,"facts":{"processes":[{"pid":1,"argv":["x"]}]}}`))
	f.Add([]byte(`{"schema":2,"facts":{"cron":[{"file":"/x","cmd":"y","env":[{"key":"K","value":"V"}]}]}}`))
	f.Add([]byte(`{"schema":2,"facts":{"triggers":[{"file":"/x","lines":[{"n":1,"text":"y"}]}]}}`))
	f.Add([]byte(`{"schema":2,"facts":{"processes":[{"pid":1,"env":{"":""}}]}}`))
	f.Add([]byte(`{"schema":99}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Add([]byte(``))

	dir := f.TempDir()
	caminho := filepath.Join(dir, "d.json")

	f.Fuzz(func(t *testing.T, bruto []byte) {
		if err := os.WriteFile(caminho, bruto, 0o600); err != nil {
			t.Skip()
		}
		d, err := Carregar(caminho)
		if err != nil {
			return
		}
		if d == nil || d.Facts == nil {
			return
		}
		// O CAMINHO DE INGRESSO INTEIRO: a redação reflexiva sobre dado que o
		// atacante moldou, e o índice em cima do resultado. É o que o servidor
		// MCP faz em toda carga.
		r := Redigir(d.Facts)
		if r != nil {
			r.Index()
		}
		_, _ = d.Env(nil)
	})
}
