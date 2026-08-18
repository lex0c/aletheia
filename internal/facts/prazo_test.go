package facts

import (
	"strings"
	"testing"
	"time"

	"github.com/lex0c/aletheia/internal/env"
)

// A varredura de filesystem para quando o prazo passa, e o que sobrou na fila
// NÃO é visitado — vira lacuna DECLARADA, não "nenhum SUID". É o time-box que
// deixa o wtf caber no orçamento num FS grande.
func TestVarreduraParaNoPrazoEDeclaraLacuna(t *testing.T) {
	e := &env.Env{WalkDeadline: time.Now().Add(-time.Hour)} // prazo já vencido
	f := &Facts{}
	v := &varredura{
		e:     e,
		f:     f,
		fila:  []tarefaDir{{dir: "/nunca/visitado/a"}, {dir: "/nunca/visitado/b"}},
		donos: novoAcumuladorDeDonos(),
	}
	v.rodar(2)

	if !v.truncadoTempo {
		t.Fatal("com o prazo vencido, a varredura tinha de marcar truncagem por tempo")
	}
	if len(f.Suid) != 0 {
		t.Errorf("nada podia ser visitado depois do prazo: %v", f.Suid)
	}
}

// Prazo ZERO é o padrão do scan: sem teto, WalkExpired é sempre falso, e a
// varredura roda inteira como antes. Confundir "sem prazo" com "prazo vencido"
// truncaria toda varredura de scan.
func TestSemPrazoNaoTrunca(t *testing.T) {
	e := &env.Env{} // WalkDeadline zero
	if e.WalkExpired() {
		t.Error("sem prazo definido, a varredura nunca pode se dar por vencida")
	}
	// prazo no futuro também não expira agora
	e.WalkDeadline = time.Now().Add(time.Hour)
	if e.WalkExpired() {
		t.Error("prazo no futuro não está vencido")
	}
}

// A mensagem da lacuna diz TEMPO e aponta o `scan` como a saída — senão o
// operador lê "varredura truncada" e não sabe que é o teto do wtf, nem que há
// um comando sem esse teto.
func TestMensagemDaLacunaDeTempoApontaScan(t *testing.T) {
	e := &env.Env{WalkDeadline: time.Now().Add(-time.Hour)}
	f := &Facts{}
	collectSuid(f, e)
	msgs := strings.Join(f.PersistDenied["suid"], " ")
	if !strings.Contains(msgs, "orçamento de tempo") || !strings.Contains(msgs, "scan") {
		t.Errorf("a lacuna de tempo tem de dizer o motivo e a saída: %q", msgs)
	}
}
