package dump

import (
	"bytes"
	"reflect"
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
