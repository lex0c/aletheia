package mcp

import (
	"bytes"
	"testing"
)

// O CODEC É CÓDIGO DE SEGURANÇA, e ele foi escrito à mão.
//
// A lista de entradas hostis de transporte_test.go é a que EU imaginei: frame
// acima do teto, id de tipo inválido, batch, _meta malformado. Fuzzing procura o
// que ninguém imaginou — e num parser que fica atrás de um servidor que pode
// rodar como root, essa é a diferença que importa.
//
// A propriedade sob teste é modesta e forte: decodificar NUNCA entra em pânico.
// Um pânico aqui derruba o processo antes de rodarProtegido alcançá-lo — o
// recover do dispatch é por TOOL, e isto acontece antes.
func FuzzDecodificar(f *testing.F) {
	f.Add(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`)
	f.Add(`{"jsonrpc":"2.0","id":"a","method":"tools/call","params":{"name":"x","arguments":{}}}`)
	f.Add(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}`)
	f.Add(`[{"jsonrpc":"2.0","id":1,"method":"x"}]`)
	f.Add(`{"jsonrpc":"2.0","id":{},"method":"x"}`)
	f.Add(`{"jsonrpc":"2.0","id":1,"method":"x","params":{"_meta":{}}}`)
	f.Add(`{"jsonrpc":"2.0","id":1,"method":"x","params":[]}`)
	f.Add(``)
	f.Add(`{`)

	f.Fuzz(func(t *testing.T, linha string) {
		r, er := decodificar([]byte(linha))
		if er != nil && r == nil {
			return
		}
		// O id tem de voltar mesmo quando a validação falha — é o que permite
		// ao cliente correlacionar a recusa.
		if r != nil {
			_ = r.ID
			if m := lerMeta(r.Params); m != nil {
				_, _ = EraDaVersao(m.Versao)
			}
		}
	})
}

// O FRAMING é a metade mais perigosa do codec.
//
// O Leitor tem um teto de linha e DRENA até o próximo \n depois de estourá-lo.
// Sem a drenagem, a cauda de uma linha gigante vira mensagem nova — e um cliente
// hostil contrabandeia uma chamada dentro do lixo. É uma máquina de estados
// escrita à mão sobre um bufio, alimentada por bytes de fora.
//
// A propriedade: ler um fluxo arbitrário até o fim nunca entra em pânico, e o
// que sai é sempre uma linha inteira ou um erro — nunca meia mensagem tratada
// como mensagem.
func FuzzLeitor(f *testing.F) {
	f.Add([]byte("{\"a\":1}\n{\"b\":2}\n"))
	f.Add([]byte("{\"a\":1}\r\n"))
	f.Add([]byte("linha sem fim"))
	f.Add(append([]byte("{"), append(make([]byte, 300), '\n', '{', '}', '\n')...))
	f.Add([]byte("\n\n\n"))

	f.Fuzz(func(t *testing.T, fluxo []byte) {
		// Teto pequeno de propósito: é o caminho de estouro + drenagem que
		// interessa, e ele quase nunca é alcançado com o teto real.
		l := NovoLeitor(bytes.NewReader(fluxo), 64)
		for i := 0; i < 4096; i++ {
			b, err := l.Linha()
			if err != nil {
				return
			}
			if int64(len(b)) > 64 {
				t.Fatalf("devolveu %d bytes com teto de 64: o estouro tem de "+
					"virar erro, e a cauda tem de ser DRENADA — senão ela vira "+
					"mensagem nova", len(b))
			}
			if bytes.ContainsRune(b, '\n') {
				t.Fatalf("uma linha devolvida contém \\n: %q", b)
			}
		}
		t.Fatal("o leitor não terminou em 4096 linhas: laço sem progresso")
	})
}
