package info

import (
	"reflect"
	"strings"
	"testing"
)

// A CATRACA DA TAG, e o defeito que a pediu.
//
// Os tipos de saída deste pacote são publicados por `info --json` e pelo
// servidor MCP, em snake_case inglês como o resto do JSON do projeto. A
// etiquetagem foi feita de uma vez, por script, e um campo escapou assim:
//
//	Tipo string // "cron sobreposto" | "pool" | … `json:"kind"`
//
// A tag foi para DENTRO do comentário de linha. O campo ficou sem tag nenhuma e
// passou a sair como `"Tipo"` — a única chave CamelCase portuguesa num
// documento snake_case. Um consumidor (ou um modelo) chaveado em `kind` lê null
// e perde o sinal de repetição nomeada, que é o que o Padrao acrescenta sobre
// um `ps`.
//
// `go vet` não vê: tag dentro de comentário não é tag malformada, é AUSÊNCIA de
// tag. E os outputSchemas envolvidos são o coringa `{"type":"object"}`, então
// nada mais o pegaria.
func TestTodoCampoPublicadoTemTagJSON(t *testing.T) {
	tipos := []any{
		Dossie{}, Bloco{}, Linha{},
		CensoDeProcessos{}, UsuarioNoCenso{}, Contagem{}, Padrao{},
		CensoDeRede{}, Escuta{}, Falante{}, TetoDeRede{},
		CensoDeGit{}, Reescrita{},
		ArvoreDeProcessos{}, NoDaArvore{},
	}
	for _, x := range tipos {
		tp := reflect.TypeOf(x)
		for i := 0; i < tp.NumField(); i++ {
			f := tp.Field(i)
			if !f.IsExported() {
				continue
			}
			tag, tem := f.Tag.Lookup("json")
			if !tem {
				t.Errorf("%s.%s não tem tag json: ele sai com o nome Go, "+
					"CamelCase e em português, num documento snake_case",
					tp.Name(), f.Name)
				continue
			}
			nome := strings.Split(tag, ",")[0]
			if nome == "" || nome == "-" {
				continue
			}
			if nome != strings.ToLower(nome) {
				t.Errorf("%s.%s: chave %q não é snake_case", tp.Name(), f.Name, nome)
			}
			if nome == strings.ToLower(f.Name) && len(nome) > 3 && !ehIngles(nome) {
				t.Logf("%s.%s: chave %q parece o nome Go em minúsculas — confira "+
					"se é intencional", tp.Name(), f.Name, nome)
			}
		}
	}
}

// ehIngles é uma heurística FRACA de propósito: ela só alimenta um t.Logf, e
// não uma falha. Nomear a fronteira entre português e inglês por lista de
// palavras seria uma catraca que quebra por gosto, e não por defeito.
func ehIngles(s string) bool {
	for _, p := range []string{"pid", "uid", "gid", "n", "state", "port", "proto",
		"bind", "exe", "name", "value", "label", "kind", "target", "found",
		"total", "used", "limit", "read", "refs", "packs", "dir", "head",
		"hooks", "remotes", "cycle", "tasks", "processes", "connections",
		"destinations", "endpoints", "public", "ports", "note", "detail",
		"action", "from", "to", "who", "message", "recover", "children"} {
		if s == p || strings.HasPrefix(s, p+"_") {
			return true
		}
	}
	return false
}
