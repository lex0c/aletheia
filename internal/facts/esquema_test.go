package facts

import (
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// A CATRACA do SchemaVersion, porque a regra sozinha não bastou.
//
// A regra está escrita em facts.go e é clara: sobe quando um fato serializado
// novo, ou uma mudança de semântica de um existente, puder alterar a conclusão
// de quem analisar o dump depois. Ela foi ampliada num dia e violada duas vezes
// nesse mesmo dia, por quem a escreveu. Antes disso, três commits seguidos a
// tinham furado na versão estreita.
//
// O padrão é o mesmo que esta base já reconheceu na suíte de cenários: regra que
// depende de alguém lembrar é regra que vai ser esquecida. O conserto é uma
// catraca, não mais disciplina.
//
// # O que esta catraca pega, e o que NÃO pega
//
// Pega a metade mecânica: campo serializado novo, renomeado, removido, ou com o
// tipo trocado. É a classe de 3 das 5 omissões históricas, e a única que dá para
// detectar por construção.
//
// NÃO pega mudança de SEMÂNTICA com o mesmo campo — a tolerância que passou a
// permitir 60s no PIDReciclado não muda campo nenhum. Essa metade continua sendo
// disciplina de revisão, e fingir que o teste resolve seria pior que não ter o
// teste: daria uma sensação de cobertura que não existe.
func TestImpressaoDoEsquema(t *testing.T) {
	const (
		esquemaEsperado  = 12
		impressaoGravada = "149dde1898a49c46"
	)
	if SchemaVersion != esquemaEsperado {
		t.Fatalf("SchemaVersion=%d e este teste conhece o %d: atualize os dois "+
			"JUNTOS, que é o ponto dele", SchemaVersion, esquemaEsperado)
	}
	got := impressaoDeEsquema(reflect.TypeOf(Facts{}))
	if got != impressaoGravada {
		t.Errorf(`a forma serializada de Facts MUDOU.

impressão gravada: %s
impressão atual:   %s

Pergunte-se o que a regra do SchemaVersion manda perguntar: um dump da versão
ANTERIOR, lido por este binário, traria o campo novo vazio — e vazio significa
alguma coisa para algum check? Se sim, suba o SchemaVersion.

Se a resposta for não (campo puramente informativo, que nenhum check lê), a
impressão pode ser atualizada sozinha — mas escreva no commit por que não subiu.`,
			impressaoGravada, got)
	}
}

// impressaoDeEsquema resume a forma SERIALIZADA de um tipo: nomes de campo JSON
// e seus tipos, recursivamente, em ordem estável.
//
// Só o que sai no dump entra: campo com `json:"-"` ou não exportado é interno à
// coleta e não pode ser lido por binário nenhum depois.
func impressaoDeEsquema(t reflect.Type) string {
	h := sha256.New()
	h.Write([]byte(descreveTipo(t, map[reflect.Type]bool{})))
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func descreveTipo(t reflect.Type, visto map[reflect.Type]bool) string {
	switch t.Kind() {
	case reflect.Ptr, reflect.Slice, reflect.Array:
		return t.Kind().String() + "<" + descreveTipo(t.Elem(), visto) + ">"
	case reflect.Map:
		return "map<" + descreveTipo(t.Key(), visto) + "," + descreveTipo(t.Elem(), visto) + ">"
	case reflect.Struct:
		if visto[t] {
			return "…" // ciclo: já descrito acima
		}
		visto[t] = true
		defer delete(visto, t)
		var campos []string
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if f.PkgPath != "" {
				continue // não exportado: não vai para o dump
			}
			nome, _, _ := strings.Cut(f.Tag.Get("json"), ",")
			if nome == "-" {
				continue
			}
			if nome == "" {
				nome = f.Name
			}
			campos = append(campos, nome+":"+descreveTipo(f.Type, visto))
		}
		sort.Strings(campos)
		return "{" + strings.Join(campos, ";") + "}"
	default:
		return t.Kind().String()
	}
}
