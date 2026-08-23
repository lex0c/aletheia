package dump

import (
	"bytes"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/facts"
)

// A CATRACA DO SEGREDO — global, e não uma lista dos campos conhecidos hoje.
//
// O contrato do artefato é: ele pode virar fixture, anexo de ticket, arquivo em
// repositório e — desde o servidor MCP — contexto de um modelo remoto. Nada
// disso é lugar para credencial do host investigado.
//
// A redação era uma lista de QUATRO campos escolhidos a dedo. A lista estava
// certa e o método estava errado: ela precisa ser mantida a cada coletor novo, e
// não foi. Medido antes do conserto, enchendo toda superfície textual do Facts:
// setenta chaves de topo levavam o segredo embora — inclusive o `.bashrc` do
// usuário, que um check põe na evidência verbatim e o MCP entrega a uma IA.
//
// Este teste não pergunta "os quatro campos foram redigidos?". Ele pergunta "o
// segredo saiu?", e é essa a pergunta que um coletor novo não pode reabrir.
const sentinela = "ALETHEIA-SENTINELA-SEGREDO-NAO-VAZE-83c1f"

func TestNenhumaSuperficieDoFactsVazaSegredo(t *testing.T) {
	// As formas em que um segredo aparece de verdade num host, e que o
	// redact conhece: flag, atribuição, cabeçalho de autorização, credencial
	// embutida em URL.
	formas := []string{
		"curl -H 'Authorization: Bearer " + sentinela + "' https://x | sh",
		"mysql --password=" + sentinela,
		"export AWS_SECRET_ACCESS_KEY=" + sentinela,
		"git clone https://user:" + sentinela + "@example.com/r.git",
	}
	for _, forma := range formas {
		t.Run(strings.Fields(forma)[0], func(t *testing.T) {
			f := &facts.Facts{}
			preencherTudo(reflect.ValueOf(f).Elem(), forma, 0)
			f.SchemaVersion = facts.SchemaVersion

			var buf bytes.Buffer
			if err := De(ambienteDeTeste(), f).Escrever(&buf); err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(buf.Bytes(), []byte(sentinela)) {
				t.Fatalf("o segredo sobreviveu ao dump.\n\n"+
					"Algum campo textual do Facts escapou da redação profunda. Se os "+
					"bytes exatos daquele campo forem mesmo necessários, declare "+
					"`redact:\"-\"` NELE e escreva por quê — a exceção é do campo, "+
					"nunca do artefato.\n\nforma: %s", forma)
			}

			// E A BUSCA ESTRUTURAL, porque a textual não vê tudo.
			//
			// bytes.Contains procura a sentinela LITERAL no JSON serializado, e
			// nem todo campo se serializa como texto: um []byte vira base64, e o
			// segredo atravessa invisível para essa busca. Foi o que aconteceu
			// com Process.EnvBruto — a catraca que se anuncia global aprovou o
			// campo mais cru do Facts passando intacto, duas vezes: primeiro
			// porque não sabia PLANTAR num []byte, depois porque não sabia
			// PROCURAR dentro de um.
			//
			// A caminhada olha o valor, e não a representação. Ela não depende
			// de como o encoder decidiu escrever aquilo.
			if onde := procurarSentinela(reflect.ValueOf(De(ambienteDeTeste(), f).Facts), forma, ""); len(onde) > 0 {
				t.Fatalf("o segredo sobreviveu à redação em campo que a busca "+
					"textual NÃO enxerga (base64, por exemplo):\n  %s\n\nforma: %s",
					strings.Join(onde, "\n  "), forma)
			}
		})
	}
}

// E o Facts vivo NÃO é tocado: os checks precisam do argv inteiro para casar
// indicador e para julgar linhagem, e redigir no lugar os cegaria.
func TestRedacaoNaoMutilaOFactsVivo(t *testing.T) {
	vivo := &facts.Facts{
		SchemaVersion: facts.SchemaVersion,
		Processes: []facts.Process{
			{PID: 1, Argv: []string{"mysql", "--password=" + sentinela}},
		},
	}
	_ = De(ambienteDeTeste(), vivo)
	if vivo.Processes[0].Argv[1] != "--password="+sentinela {
		t.Fatalf("o Facts vivo foi redigido: %q", vivo.Processes[0].Argv[1])
	}
}

// preencherTudo põe o texto em toda string alcançável, criando um elemento por
// slice e uma entrada por mapa. É a varredura que faz a catraca ser global.
func preencherTudo(v reflect.Value, texto string, prof int) {
	if prof > 6 {
		return
	}
	switch v.Kind() {
	case reflect.String:
		if v.CanSet() {
			v.SetString(texto)
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).IsExported() {
				preencherTudo(v.Field(i), texto, prof+1)
			}
		}
	case reflect.Slice:
		if !v.CanSet() {
			return
		}
		// BYTE É PLANTADO COMO BYTE.
		//
		// A recursão descia até o elemento e encontrava um uint8, onde não há
		// caso que plante nada — então esta catraca, que se anuncia GLOBAL,
		// tinha um ponto cego exatamente no tipo de dado mais cru que o Facts
		// pode carregar. Ela aprovou o Process.EnvBruto atravessando a redação
		// intacto.
		//
		// Um teste que não consegue plantar num campo não afirma nada sobre ele,
		// e o silêncio se lê como aprovação.
		if v.Type().Elem().Kind() == reflect.Uint8 {
			v.SetBytes([]byte(texto))
			return
		}
		s := reflect.MakeSlice(v.Type(), 1, 1)
		preencherTudo(s.Index(0), texto, prof+1)
		v.Set(s)
	case reflect.Map:
		if !v.CanSet() || v.Type().Key().Kind() != reflect.String {
			return
		}
		m := reflect.MakeMap(v.Type())
		el := reflect.New(v.Type().Elem()).Elem()
		preencherTudo(el, texto, prof+1)
		m.SetMapIndex(reflect.ValueOf(texto), el)
		v.Set(m)
	case reflect.Pointer:
		if !v.CanSet() {
			return
		}
		p := reflect.New(v.Type().Elem())
		preencherTudo(p.Elem(), texto, prof+1)
		v.Set(p)
	}
}

// procurarSentinela percorre o VALOR e devolve os caminhos onde a sentinela
// aparece — em string ou em sequência de bytes, em qualquer profundidade.
//
// Ela existe porque a busca textual no artefato serializado depende de o encoder
// ter escrito aquele campo como texto. Um []byte vira base64 e some da busca; um
// campo futuro com encoder próprio sumiria também.
func procurarSentinela(v reflect.Value, alvo, caminho string) []string {
	var achados []string
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if !v.IsNil() {
			achados = append(achados, procurarSentinela(v.Elem(), alvo, caminho)...)
		}
	case reflect.String:
		if strings.Contains(v.String(), sentinela) {
			achados = append(achados, caminho+" = "+v.String())
		}
	case reflect.Slice, reflect.Array:
		if v.Kind() == reflect.Slice && v.Type().Elem().Kind() == reflect.Uint8 {
			if bytes.Contains(v.Bytes(), []byte(sentinela)) {
				achados = append(achados, caminho+" (bytes) = "+string(v.Bytes()))
			}
			return achados
		}
		for i := 0; i < v.Len(); i++ {
			achados = append(achados, procurarSentinela(v.Index(i), alvo,
				caminho+"["+strconv.Itoa(i)+"]")...)
		}
	case reflect.Map:
		for _, k := range v.MapKeys() {
			achados = append(achados, procurarSentinela(k, alvo, caminho+".<chave>")...)
			achados = append(achados, procurarSentinela(v.MapIndex(k), alvo,
				caminho+"["+k.String()+"]")...)
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if !v.Type().Field(i).IsExported() {
				continue
			}
			achados = append(achados, procurarSentinela(v.Field(i), alvo,
				caminho+"."+v.Type().Field(i).Name)...)
		}
	}
	return achados
}
