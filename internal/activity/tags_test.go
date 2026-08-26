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

// TODO kind que o parser de log emite precisa ter tradução E estar no namespace
// publicado.
//
// A lista abaixo é a de internal/facts/logparse.go e logaudit.go. Ela é
// explícita de propósito: os kinds são literais espalhados pelo parser, e não
// há como derivá-los por reflexão — é a mesma forma das catracas de completude.
//
// O defeito que ela trava: kind não mapeado PASSA com o nome de origem (ver
// deLogKind, e é decisão), então `activity` imprimia `kernel.oom` enquanto
// `activity --kind kernel` respondia que o tipo não existe. O comando ficava
// incoerente consigo mesmo.
func TestKindsDoParserTemTraducao(t *testing.T) {
	doParser := []string{
		"auth.accepted", "auth.failed", "auth.invalid_user",
		"auth.sudo", "auth.su",
		"account.created", "account.modified",
		"audit.exec", "audit.lost",
		"cron.exec", "service.failed",
		"kernel.module_loaded", "kernel.oom", "kernel.segfault",
	}
	publicado := map[Kind]bool{}
	for _, k := range TodosOsKinds {
		publicado[k] = true
	}
	for _, orig := range doParser {
		k, ok := deLogKind[orig]
		if !ok {
			t.Errorf("o kind %q do parser não tem tradução: ele passa com o nome "+
				"de origem e fica fora do --kind", orig)
			continue
		}
		if !publicado[k] {
			t.Errorf("%q traduz para %q, que não está em TodosOsKinds: o evento "+
				"aparece na linha do tempo e o --kind o recusa", orig, k)
		}
	}
	// E o caminho de volta: nenhum kind publicado pode ser inalcançável.
	for _, k := range TodosOsKinds {
		if !PrefixoValido(string(k)) {
			t.Errorf("o kind publicado %q não casa nem com o próprio nome", k)
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
