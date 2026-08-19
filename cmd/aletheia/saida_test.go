package main

import (
	"os"
	"path/filepath"
	"testing"
)

// openJSONOut nunca destrói dado do host: recusa arquivo regular existente
// (baseline --out e scan --json passam por aqui, e um deslize não pode zerar um
// log do alvo).
func TestOpenJSONOutRecusaArquivoRegularExistente(t *testing.T) {
	p := filepath.Join(t.TempDir(), "existente.jsonl")
	if err := os.WriteFile(p, []byte("dado do host\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if fh, err := openJSONOut(p); err == nil {
		fh.Close()
		t.Error("abriu um arquivo regular existente — nunca sobrescrever o host")
	}
	if b, _ := os.ReadFile(p); string(b) != "dado do host\n" {
		t.Errorf("o arquivo foi truncado: %q", b)
	}
}

// Symlink plantado no destino: O_CREATE|O_EXCL falha em symlink, então a escrita
// não é redirecionada para fora nem cria o alvo.
func TestOpenJSONOutRecusaSymlink(t *testing.T) {
	dir := t.TempDir()
	alvo := filepath.Join(dir, "fora.txt") // dangling de propósito
	link := filepath.Join(dir, "saida.jsonl")
	if err := os.Symlink(alvo, link); err != nil {
		t.Fatal(err)
	}
	if fh, err := openJSONOut(link); err == nil {
		fh.Close()
		t.Error("criou o destino através de um symlink — devia recusar")
	}
	if _, err := os.Lstat(alvo); err == nil {
		t.Error("escreveu através do symlink para fora do destino pretendido")
	}
}
