package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// AS RECUSAS DE INVOCAÇÃO do `activity`, que até aqui só tinham sido conferidas
// à mão no terminal.
//
// Elas não são detalhe de ergonomia: a política do comando é recusar
// ambiguidade em vez de resolvê-la por precedência silenciosa, e a alternativa
// que cada uma evita é sempre a mesma — devolver 0 e uma lista vazia sobre um
// recorte que ninguém pediu. Um operador lê isso como resposta do host.
//
// Todas retornam ANTES da coleta, então o teste não toca em /proc nem no
// filesystem do host.
func TestActivityRecusaInvocacaoAmbigua(t *testing.T) {
	// `quer` é a substring da recusa esperada, e ela não é decoração: sem
	// afirmar QUAL recusa disparou, metade destes casos passaria por outro
	// motivo — `--from /tmp/x.json --root /tmp` também sai 3 pelo arquivo
	// inexistente, e o teste ficaria cego para a remoção da guarda de par.
	casos := []struct {
		nome string
		args []string
		quer string
	}{
		{"--around com --since", []string{
			"--around", "2026-08-25T03:15Z", "--since", "24h"},
			"--around não combina"},
		{"--around com --until", []string{
			"--around", "2026-08-25T03:15Z", "--until", "2026-08-26T00:00Z"},
			"--around não combina"},
		{"--from com --root", []string{"--from", "/tmp/x.json", "--root", "/tmp"},
			"--from e --root não combinam"},
		{"--summary com --group-by", []string{"--summary", "--group-by", "ip"},
			"--summary e --group-by não combinam"},
		{"--window sem --around", []string{"--window", "5m"},
			"só faz sentido com --around"},
		{"--window negativo", []string{"--around", "2026-08-25T03:15Z", "--window", "-5m"},
			"precisa ser positivo"},
		{"--group-by em eixo inexistente", []string{"--group-by", "porta"},
			"não é um eixo"},
		// O --kind com erro de digitação caía na mensagem tranquilizadora de
		// "nenhum evento no recorte pedido", que é a pior resposta possível a
		// um erro de invocação.
		{"--kind que não casa tipo nenhum", []string{"--kind", "porta"},
			"não casa tipo nenhum"},
		{"--since em formato irreconhecível", []string{"--since", "ontem"},
			"--since"},
		{"posicional", []string{"/var/log/wtmp"}, "argumento inesperado"},
		{"--root que não é diretório", []string{"--root", "/etc/hostname"},
			"não é um diretório"},
	}

	for _, c := range casos {
		t.Run(c.nome, func(t *testing.T) {
			code, saida := comStderr(t, func() int { return runActivity(c.args) })
			if code != 3 {
				t.Errorf("exit = %d, queria 3 — invocação ambígua respondida "+
					"como se fosse pergunta sobre o host", code)
			}
			if !strings.Contains(saida, c.quer) {
				t.Errorf("a recusa não citou %q — pode ter saído 3 por outro "+
					"motivo, e a guarda que este caso protege ficaria cega.\n%s",
					c.quer, saida)
			}
		})
	}
}

// A janela INVERTIDA é erro de invocação, e não um host silencioso: ela é
// vazia por construção, e responder 0 com "nenhum evento no recorte pedido"
// manda o operador ler o rodapé de cobertura para explicar um silêncio que é
// da linha de comando.
func TestActivityRecusaJanelaInvertida(t *testing.T) {
	code, saida := comStderr(t, func() int {
		return runActivity([]string{
			"--since", "2026-08-26T00:00Z", "--until", "2026-08-01T00:00Z"})
	})
	if code != 3 || !strings.Contains(saida, "janela está invertida") {
		t.Errorf("exit = %d, saída:\n%s", code, saida)
	}
}

// `--until` SOZINHO não herda o --since padrão: ele significa "tudo até este
// instante", que é uma janela válida. Herdar as 24h padrão a tornava invertida
// e sempre vazia.
//
// Aqui a coleta chega a rodar, então o alvo é uma raiz montada mínima — a
// pergunta é sobre o recorte, não sobre o host.
func TestActivityUntilSozinhoNaoHerdaOSincePadrao(t *testing.T) {
	raiz := t.TempDir()
	if err := os.MkdirAll(filepath.Join(raiz, "var", "log"), 0o755); err != nil {
		t.Fatal(err)
	}
	code, saida := comStderr(t, func() int {
		return runActivity([]string{
			"--until", "2026-08-26T00:00Z", "--root", raiz, "--no-progress"})
	})
	if code != 0 {
		t.Errorf("exit = %d, queria 0: `tudo até um instante` é janela válida.\n%s",
			code, saida)
	}
}

// comStderr roda f com os.Stderr desviado para um pipe e devolve o que foi
// escrito. É por ele que o teste distingue "saiu 3" de "saiu 3 PELO MOTIVO
// certo" — a distinção que separa uma guarda protegida de uma guarda que pode
// ser removida sem nada falhar.
func comStderr(t *testing.T, f func() int) (int, string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	antes := os.Stderr
	os.Stderr = w

	// Drenar em paralelo: uma recusa maior que o buffer do pipe travaria f.
	pronto := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		pronto <- string(b)
	}()

	code := f()
	os.Stderr = antes
	w.Close()
	saida := <-pronto
	r.Close()
	return code, saida
}
