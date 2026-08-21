package facts

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/lex0c/aletheia/internal/env"
)

// CONFORMIDADE SINTÁTICA com o parser do systemd.
//
// Estes não são "mais uma diretiva rara": são a pequena gramática que decide se
// um Exec existe. Três bypasses saíram dela em sequência, todos com a mesma
// forma — o systemd lê o arquivo de um jeito, esta ferramenta de outro, e a
// diferença some em silêncio com a cobertura completa.
//
// Cada caso abaixo foi medido contra o systemd-analyze antes de virar teste.

// O BOM é caractere de FORMATAÇÃO, não espaço — desde o Unicode 4.0 — e o
// TrimSpace do Go não o remove. O systemd o come explicitamente (bom_seen no
// config_parse), então um arquivo salvo com BOM executa normalmente enquanto o
// `[Service]` não era reconhecido aqui como seção.
//
// Medido: `systemd-analyze verify` passa limpo no arquivo com BOM.
func TestUnitBOMAntesDaPrimeiraSecao(t *testing.T) {
	raiz := t.TempDir()
	os.WriteFile(filepath.Join(raiz, "x.service"),
		[]byte("\ufeff[Service]\nExecStart=/tmp/.implant\n"), 0o644)
	e := env.Probe(env.Options{Root: raiz, Version: "test"})
	t.Cleanup(func() { e.Close() })

	u := parseUnitFile(&Facts{}, e, "/x.service", "system", "service", false)
	if len(u.Exec) != 1 || u.Exec[0].Cmd != "/tmp/.implant" {
		t.Fatalf("BOM antes da seção escondia o Exec inteiro: %+v", u.Exec)
	}
}

// A PARIDADE das barras finais decide a continuação. O systemd percorre a linha
// mantendo estado de escape: uma barra escapa a próxima, então `\\` é barra
// literal e não emenda.
//
// Medido contra o systemd-analyze: com UMA barra ele reclama "Unknown key
// 'ExecStart' in section [Unit]" (a linha emendou e engoliu o cabeçalho); com
// DUAS, verifica limpo.
func TestContinuaNaProxima(t *testing.T) {
	casos := []struct {
		linha string
		quer  bool
	}{
		{`Description=foo`, false},
		{`Description=foo\`, true},
		{`Description=foo\\`, false},
		{`Description=foo\\\`, true},
		{`Description=foo\\\\`, false},
		{``, false},
		{`\`, true},
	}
	for _, c := range casos {
		if got := continuaNaProxima(c.linha); got != c.quer {
			t.Errorf("%q -> %v, queria %v", c.linha, got, c.quer)
		}
	}
}

// E o efeito no parser: `Description=foo\\` seguido de `[Service]` fazia o
// cabeçalho ser engolido pela Description, o ExecStart caía numa seção que
// nunca abriu e sumia.
func TestUnitBarraDuplaNaoEngoleASecao(t *testing.T) {
	raiz := t.TempDir()
	os.WriteFile(filepath.Join(raiz, "x.service"),
		[]byte("[Unit]\nDescription=foo\\\\\n[Service]\nExecStart=/tmp/.implant\n"), 0o644)
	e := env.Probe(env.Options{Root: raiz, Version: "test"})
	t.Cleanup(func() { e.Close() })

	u := parseUnitFile(&Facts{}, e, "/x.service", "system", "service", false)
	if len(u.Exec) != 1 || u.Exec[0].Cmd != "/tmp/.implant" {
		t.Fatalf("barra dupla não emenda: o [Service] tinha de abrir: %+v", u.Exec)
	}
	// E a continuação de verdade (uma barra) tem de continuar emendando.
	os.WriteFile(filepath.Join(raiz, "y.service"),
		[]byte("[Service]\nExecStart=/tmp/.a \\\n  --flag\n"), 0o644)
	u = parseUnitFile(&Facts{}, e, "/y.service", "system", "service", false)
	if len(u.Exec) != 1 || u.Exec[0].Cmd != "/tmp/.a --flag" {
		t.Errorf("uma barra continua emendando: %+v", u.Exec)
	}
}

// O drop-in TYPE-WIDE (`service.d`) herda o tipo do nome do diretório, que não
// tem ponto. Sem isto ele caía em "tipo desconhecido" e reabria o bypass de
// seção×tipo inteiro — e é o mais alcançável de todos, porque atinge TODA unit
// daquele tipo de uma vez.
func TestKindOfDropinTypeWide(t *testing.T) {
	casos := map[string]string{
		"agent.service":  "service",
		"foo-.service":   "service",
		"foo@.service":   "service",
		"service":        "service",
		"timer":          "timer",
		"socket":         "socket",
		"qualquer-coisa": "", // não é tipo: não inventa um
	}
	for alvo, quer := range casos {
		if got := kindOfDropin(alvo); got != quer {
			t.Errorf("kindOfDropin(%q) = %q, queria %q", alvo, got, quer)
		}
	}
}

// E o efeito: reset em [Socket] dentro de um service.d não pode zerar o Exec.
func TestDropinTypeWideNaoAceitaResetDeOutroTipo(t *testing.T) {
	raiz := t.TempDir()
	dir := filepath.Join(raiz, "etc/systemd/system/service.d")
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "90-x.conf"),
		[]byte("[Service]\nExecStartPre=/tmp/.implant\n\n[Socket]\nExecStartPre=\n"), 0o644)
	e := env.Probe(env.Options{Root: raiz, Version: "test"})
	t.Cleanup(func() { e.Close() })

	u := parseUnitFile(&Facts{}, e, "/etc/systemd/system/service.d/90-x.conf",
		"system", kindOfDropin("service"), false)
	if len(u.Exec) != 1 {
		t.Fatalf("o service.d é .service: [Socket] não reseta nada ali: %+v", u.Exec)
	}
}
