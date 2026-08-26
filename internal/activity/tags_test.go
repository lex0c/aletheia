package activity

import (
	"reflect"
	"strings"
	"testing"
)

// A CATRACA DA TAG, irmã da de internal/info.
//
// Os tipos deste pacote são publicados por `activity --json`, em snake_case
// inglês como o resto do JSON do projeto. Campo sem tag sai com o NOME GO —
// CamelCase e em português — dentro de um documento snake_case, e um consumidor
// chaveado no nome certo lê null e perde o sinal.
//
// `go vet` não pega: tag esquecida não é tag malformada, é ausência de tag.
func TestTodoCampoPublicadoTemTagJSON(t *testing.T) {
	tipos := []any{
		Fonte{}, Sessao{}, Contagem{}, Resumo{},
		Evento{}, Grupo{}, Sumario{},
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
		}
	}
}

// O namespace de Kind é a interface do --kind, e o filtro casa por PREFIXO.
// Um kind sem ponto seria um ramo que nenhum prefixo alcança sem ser o nome
// inteiro — e a hierarquia existe justamente para o operador poder pedir
// `auth` sem conhecer os filhos.
func TestKindsSaoPontuados(t *testing.T) {
	for _, k := range []Kind{
		KindLoginAceito, KindLoginRecusado, KindSessaoAberta, KindSessaoFechada,
		KindBoot, KindSudo, KindSu, KindContaCriada, KindContaModificada,
		KindExecAudit, KindExecCron,
	} {
		if !strings.Contains(string(k), ".") {
			t.Errorf("o kind %q não tem ramo: nenhum --kind de prefixo o alcança "+
				"sem escrever o nome inteiro", k)
		}
	}
}
