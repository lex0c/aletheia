// Package variante mede o eixo que os cenários não medem: uma técnica em VÁRIAS
// FORMAS.
//
// A catraca de cenário prova que um check dispara sobre a forma que a fixture
// tem; a tabela de evasão prova que o CLASSIFICADOR casa as variantes. Entre as
// duas há um vão — o pipeline collect->check inteiro —, e foi ali que o dracut
// 0644 caiu: o classificador entendia o arquivo e o check o descartava um andar
// acima, em silêncio. Só um teste que planta o arquivo, roda o COLETOR de
// verdade contra um --root e então o CHECK pega essa classe.
//
// Cada técnica é uma linha ATT&CK, e cada variante é uma forma que um atacante
// escolhe de graça: o mesmo payload noutro diretório, noutra sintaxe, com um
// byte separador diferente. FIRE = tem de disparar em TODAS; BLIND = ponto cego
// declarado, tem de calar (e o dia em que passar a disparar, o teste obriga a
// promover).
package variante

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/check"
	_ "github.com/lex0c/aletheia/internal/checks" // registra os checks via init()
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

// variante é uma forma de uma técnica, e o que se espera dela.
type variante struct {
	nome string
	// arquivos são plantados no rootfs antes da varredura. O valor é o
	// conteúdo; o modo é 0644, salvo quando o nome pede executável (sufixo *).
	arquivos map[string]string
	// dispara: o check tem de acender. cego: tem de calar, e a nota diz por quê.
	esperaID string
	cego     bool
	nota     string
}

// tecnica agrupa as variantes de uma mesma técnica ATT&CK.
type tecnica struct {
	attack    string
	nome      string
	variantes []variante
}

func rodar(t *testing.T, v variante) *check.Report {
	t.Helper()
	raiz := t.TempDir()
	for rel, conteudo := range v.arquivos {
		modo := os.FileMode(0o644)
		if strings.HasPrefix(rel, "*") {
			rel, modo = rel[1:], 0o755
		}
		full := filepath.Join(raiz, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(conteudo), modo); err != nil {
			t.Fatal(err)
		}
	}
	e := env.Probe(env.Options{Root: raiz, Version: "test"})
	t.Cleanup(func() { e.Close() })
	f := facts.Collect(e)
	return check.Run(check.All(), f, e)
}

func disparou(r *check.Report, id string) bool {
	for i := range r.Findings {
		if r.Findings[i].ID == id {
			return true
		}
	}
	return false
}

func TestVariantes(t *testing.T) {
	for _, tec := range tabela {
		t.Run(tec.attack+"_"+tec.nome, func(t *testing.T) {
			for _, v := range tec.variantes {
				t.Run(v.nome, func(t *testing.T) {
					r := rodar(t, v)
					got := disparou(r, v.esperaID)
					switch {
					case v.cego && got:
						t.Errorf("SURPRESA: %s passou a disparar %s — o ponto cego "+
							"FECHOU, promova de BLIND para FIRE.\nnota: %s", v.nome, v.esperaID, v.nota)
					case !v.cego && !got:
						t.Errorf("VARIANTE ESCAPOU: %q não disparou %s.\nnota: %s\n"+
							"achados: %s", v.nome, v.esperaID, v.nota, idsDe(r))
					}
				})
			}
		})
	}
}

func idsDe(r *check.Report) string {
	var ids []string
	for i := range r.Findings {
		ids = append(ids, r.Findings[i].ID)
	}
	if len(ids) == 0 {
		return "(nenhum)"
	}
	return strings.Join(ids, ", ")
}
