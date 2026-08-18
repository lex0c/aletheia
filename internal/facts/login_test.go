package facts

import (
	"testing"
	"time"
)

// registro monta um utmp de um dos dois layouts, com usuário e timestamp.
func registro(tam int, user string, quando int64) []byte {
	r := make([]byte, tam)
	r[0] = 7 // USER_PROCESS
	copy(r[44:76], user)
	copy(r[8:40], "pts/0")
	copy(r[76:332], "10.0.0.9")
	if tam == tamUtmp64 {
		for i := 0; i < 8; i++ {
			r[344+i] = byte(quando >> (8 * uint(i)))
		}
		return r
	}
	for i := 0; i < 4; i++ {
		r[340+i] = byte(quando >> (8 * uint(i)))
	}
	return r
}

// O defeito que uma revisão de compatibilidade achou: o registro de utmp tem 384
// bytes no x86 com glibc e 400 em arm64 e na musl. Ler um de 400 com passo de
// 384 não falha — produz usuário vindo do meio de outro campo, timestamp sempre
// zero, e NENHUMA lacuna declarada, porque a leitura do arquivo deu certo.
func TestUtmpDosDoisTamanhos(t *testing.T) {
	quando := time.Date(2026, 8, 17, 21, 3, 11, 0, time.UTC).Unix()
	for _, tam := range []int{tamUtmp32, tamUtmp64} {
		var b []byte
		for _, u := range []string{"deploy", "root", "app"} {
			b = append(b, registro(tam, u, quando)...)
		}
		got, ok := tamanhoDoRegistro(int64(len(b)))
		if !ok || got != tam {
			t.Fatalf("tamanho %d: detectou %d (ok=%v)", tam, got, ok)
		}
		if s := segundoDoRegistro(b[:tam], tam); s != quando {
			t.Errorf("tamanho %d: timestamp = %d, queria %d — no layout de 400 "+
				"o segundo mora no offset 344 e tem 64 bits", tam, s, quando)
		}
	}
}

// Arquivo que não é múltiplo de nenhum dos dois layouts NÃO é interpretado: um
// inventário de login inventado é pior que nenhum.
func TestUtmpDeTamanhoDesconhecidoNaoEhChutado(t *testing.T) {
	if _, ok := tamanhoDoRegistro(999); ok {
		t.Error("999 bytes não é múltiplo de 384 nem de 400: não dá para interpretar")
	}
	// E quando os dois dividem, vence o layout da arquitetura em que este
	// binário roda — a resposta certa em todo host que não teve o arquivo
	// copiado de outra máquina.
	if got, ok := tamanhoDoRegistro(0); !ok || got != tamanhoNativoDeUtmp {
		t.Errorf("arquivo vazio: detectou %d, queria o nativo %d", got, tamanhoNativoDeUtmp)
	}
}
