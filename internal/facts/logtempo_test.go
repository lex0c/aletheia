package facts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lex0c/aletheia/internal/env"
)

// tzFixa constrói um fuso sem depender do zoneinfo da máquina que roda o teste.
// É a mesma razão pela qual a produção decodifica o TZif do alvo: o fuso de quem
// investiga não pode entrar na conta.
func tzFixa(offsetHoras int) *time.Location {
	return time.FixedZone("teste", offsetHoras*3600)
}

// O ANO vem da âncora caminhando PARA TRÁS.
//
// O arquivo não pode ter sido escrito antes da linha que contém, então uma data
// posterior ao mtime pertence ao ano anterior. Sem isso, toda linha de dezembro
// num auth.log.1 rotacionado em janeiro sai com um ano a mais — e o achado é
// datado no futuro, onde a guarda de âncora o descarta.
func TestAnoDeSyslogVemDaAncoraParaTras(t *testing.T) {
	casos := []struct {
		nome   string
		ancora time.Time
		agora  time.Time
		mes    time.Month
		dia    int
		quer   string
	}{
		{
			nome:   "mesmo ano",
			ancora: time.Date(2026, 8, 24, 3, 0, 0, 0, time.UTC),
			agora:  time.Date(2026, 8, 24, 10, 0, 0, 0, time.UTC),
			mes:    time.August, dia: 24, quer: "2026-08-24T01:20:33Z",
		},
		{
			nome:   "virada de ano: dezembro num arquivo de janeiro",
			ancora: time.Date(2026, 1, 3, 6, 25, 0, 0, time.UTC),
			agora:  time.Date(2026, 1, 5, 12, 0, 0, 0, time.UTC),
			mes:    time.December, dia: 31, quer: "2025-12-31T01:20:33Z",
		},
		{
			nome: "data DEPOIS do mtime pertence ao ano anterior",
			// O arquivo não pode ter sido escrito antes da linha que contém.
			// "Aug 26" num arquivo com mtime de 24/08/2026 é de 2025 — e é essa
			// inferência que torna linha datada no futuro praticamente
			// impossível na forma tradicional.
			ancora: time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC),
			agora:  time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC),
			mes:    time.August, dia: 26, quer: "2025-08-26T01:20:33Z",
		},
	}
	for _, c := range casos {
		t.Run(c.nome, func(t *testing.T) {
			ctx := contextoDeTempo{Loc: time.UTC, Ancora: c.ancora, Agora: c.agora}
			got, ok := instanteDeSyslog(c.mes, c.dia, 1, 20, 33, ctx)
			if !ok {
				t.Fatal("não datou")
			}
			if utc(got) != c.quer {
				t.Errorf("= %s, quer %s", utc(got), c.quer)
			}
		})
	}
}

// O FUSO é do alvo, e a data sai em UTC.
//
// Um sudo às 03:22 num host em -03 aconteceu às 06:22 UTC. Sem converter, a
// janela que liga login a persistência erra pelo offset inteiro e nunca fecha.
func TestFusoDoAlvoEntraNaConversao(t *testing.T) {
	ancora := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	agora := time.Date(2026, 8, 24, 18, 0, 0, 0, time.UTC)

	got, ok := instanteDeSyslog(time.August, 24, 3, 22, 17,
		contextoDeTempo{Loc: tzFixa(-3), Ancora: ancora, Agora: agora})
	if !ok {
		t.Fatal("não datou")
	}
	if utc(got) != "2026-08-24T06:22:17Z" {
		t.Errorf("= %s, quer 2026-08-24T06:22:17Z (03:22 em -03)", utc(got))
	}
}

// Data que NÃO EXISTE é recusada, e não normalizada.
//
// O time.Date transforma 29 de fevereiro de ano comum em 1º de março sem
// reclamar. O achado sairia datado de um dia que a linha não menciona — e o
// caso só aparece quando a inferência de ano já errou, que é justamente quando
// a data não vale nada.
func TestDataInexistenteEhRecusada(t *testing.T) {
	ctx := contextoDeTempo{
		Loc:    time.UTC,
		Ancora: time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC),
		Agora:  time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC),
	}
	if got, ok := instanteDeSyslog(time.February, 29, 1, 0, 0, ctx); ok {
		t.Errorf("29/02 de 2026 (nem 2025) não existe, e saiu %s", utc(got))
	}

	// E o ano bissexto de verdade continua funcionando.
	ctx.Ancora = time.Date(2024, 3, 1, 0, 0, 0, 0, time.UTC)
	ctx.Agora = time.Date(2024, 3, 1, 0, 0, 0, 0, time.UTC)
	if got, ok := instanteDeSyslog(time.February, 29, 1, 0, 0, ctx); !ok {
		t.Error("29/02/2024 existe e foi recusado")
	} else if utc(got) != "2024-02-29T01:00:00Z" {
		t.Errorf("= %s", utc(got))
	}
}

// MTIME FORJADO não produz evento datado no futuro.
//
// A âncora é o mtime, e o mtime é falsificável com um `touch` — coletarTimestomp
// existe por isso. Sem a guarda, um `touch -d 2099-01-01 /var/log/auth.log`
// dataria todos os eventos daquele arquivo em 2099, e o relatório afirmaria uma
// data que o adversário escreveu. É a mesma guarda do DerivarAncora, e pelo
// mesmo motivo: data no futuro é SINAL, não referência.
func TestMtimeNoFuturoNaoData(t *testing.T) {
	ctx := contextoDeTempo{
		Loc:    time.UTC,
		Ancora: time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC),
		Agora:  time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC),
	}
	if got, ok := instanteDeSyslog(time.January, 1, 12, 0, 0, ctx); ok {
		t.Errorf("mtime em 2099 não pode datar evento nenhum, saiu %s", utc(got))
	}

	// E a folga existe: algumas horas à frente é deriva de relógio, não forja.
	ctx.Ancora = time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	if _, ok := instanteDeSyslog(time.August, 24, 20, 0, 0, ctx); !ok {
		t.Error("8h à frente cabe na folga de relógio e foi recusado")
	}
}

// Sem âncora não há ano, e não há data. Silêncio aqui seria datar tudo no ano
// zero — que o relatório leria como data.
func TestSemAncoraNaoData(t *testing.T) {
	if _, ok := instanteDeSyslog(time.August, 24, 1, 0, 0, contextoDeTempo{Loc: time.UTC}); ok {
		t.Error("sem mtime não há de onde inferir o ano")
	}
}

// O epoch do auditd é UTC por construção — nenhuma inferência.
func TestInstanteDeEpoch(t *testing.T) {
	got, ok := instanteDeEpoch("1755990137.123")
	if !ok {
		t.Fatal("não leu o epoch")
	}
	if got.UTC().Format(time.RFC3339Nano) != "2025-08-23T23:02:17.123Z" {
		t.Errorf("= %s", got.UTC().Format(time.RFC3339Nano))
	}
	for _, ruim := range []string{"", "abc", "1755990137", "-5.000", "1755990137.9999"} {
		if _, ok := instanteDeEpoch(ruim); ok {
			t.Errorf("%q deveria ser recusado", ruim)
		}
	}
}

// A forma ISO do rsyslog moderno traz ano E offset: não passa por inferência.
func TestInstanteISO(t *testing.T) {
	got, ok := instanteISO("2026-08-24T01:20:33.123456+02:00")
	if !ok {
		t.Fatal("não leu a forma ISO")
	}
	if utc(got) != "2026-08-23T23:20:33Z" {
		t.Errorf("= %s, quer o mesmo instante em UTC", utc(got))
	}
}

// AUSENTE e ILEGÍVEL são respostas diferentes, e a diferença vai para a
// evidência: sem /etc/localtime a glibc usa UTC de verdade; com ele ilegível, o
// offset é desconhecido e UTC é suposição.
func TestFusoAusenteNaoEhSuposicaoMasIlegivelEh(t *testing.T) {
	t.Run("ausente", func(t *testing.T) {
		f := &Facts{}
		loc, suposto := fusoDoAlvo(f, env.Probe(env.Options{Root: t.TempDir()}))
		if loc != time.UTC || suposto {
			t.Errorf("loc=%v suposto=%v — sem /etc/localtime o host escreve em UTC", loc, suposto)
		}
		if len(f.Partial["logeventos"]) != 0 {
			t.Errorf("ausência não é lacuna: %v", f.Partial["logeventos"])
		}
	})

	t.Run("ilegivel", func(t *testing.T) {
		raiz := t.TempDir()
		p := filepath.Join(raiz, "etc")
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(p, "localtime"), []byte("x"), 0o000); err != nil {
			t.Fatal(err)
		}
		if os.Geteuid() == 0 {
			t.Skip("como root o modo 000 não nega leitura")
		}
		f := &Facts{}
		loc, suposto := fusoDoAlvo(f, env.Probe(env.Options{Root: raiz}))
		if loc != time.UTC || !suposto {
			t.Errorf("loc=%v suposto=%v — ilegível é suposição declarada", loc, suposto)
		}
		if len(f.Partial["logeventos"]) == 0 {
			t.Error("fuso ilegível precisa declarar lacuna: a data de todo evento fica deslocada")
		}
	})

	t.Run("invalido", func(t *testing.T) {
		raiz := t.TempDir()
		p := filepath.Join(raiz, "etc")
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(p, "localtime"), []byte("não é TZif"), 0o644); err != nil {
			t.Fatal(err)
		}
		f := &Facts{}
		loc, suposto := fusoDoAlvo(f, env.Probe(env.Options{Root: raiz}))
		if loc != time.UTC || !suposto {
			t.Errorf("loc=%v suposto=%v", loc, suposto)
		}
		if !strings.Contains(strings.Join(f.Partial["logeventos"], " "), "TZif") {
			t.Errorf("a lacuna precisa dizer que o arquivo não é TZif: %v", f.Partial["logeventos"])
		}
	})
}

// O TZif do ALVO é decodificado dos BYTES — nunca do zoneinfo de quem
// investiga. Num --root de imagem montada, o contrário dataria o log do alvo
// com o fuso do analista, que é o erro de classe que o os.Root existe para
// impedir no resto da coleta.
func TestFusoSaiDoTZifDoAlvo(t *testing.T) {
	raiz := t.TempDir()
	if err := os.MkdirAll(filepath.Join(raiz, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(raiz, "etc/localtime"), tzifDe(-3*3600, "-03"), 0o644); err != nil {
		t.Fatal(err)
	}
	f := &Facts{}
	loc, suposto := fusoDoAlvo(f, env.Probe(env.Options{Root: raiz}))
	if suposto {
		t.Fatalf("TZif válido não é suposição: %v", f.Partial["logeventos"])
	}
	// A prova é o OFFSET aplicado, não o ponteiro: um instante de agosto neste
	// fuso tem que sair três horas à frente em UTC.
	got, ok := instanteDeSyslog(time.August, 24, 3, 22, 17, contextoDeTempo{
		Loc:    loc,
		Ancora: time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC),
		Agora:  time.Date(2026, 8, 24, 18, 0, 0, 0, time.UTC),
	})
	if !ok {
		t.Fatal("não datou")
	}
	if utc(got) != "2026-08-24T06:22:17Z" {
		t.Errorf("= %s, quer 2026-08-24T06:22:17Z — o offset do alvo não foi aplicado", utc(got))
	}
}

// tzifDe monta um TZif v1 mínimo e válido: um único tipo de offset, sem
// transição nenhuma.
//
// À mão, e de propósito: depender de /usr/share/zoneinfo existir na máquina que
// roda o teste seria depender do zoneinfo do analista — exatamente o que a
// produção recusa fazer.
func tzifDe(offset int32, abrev string) []byte {
	b := make([]byte, 0, 64)
	b = append(b, 'T', 'Z', 'i', 'f', 0) // magic + versão 1
	b = append(b, make([]byte, 15)...)   // reservado
	be := func(n uint32) { b = append(b, byte(n>>24), byte(n>>16), byte(n>>8), byte(n)) }
	be(0)                      // isutcnt
	be(0)                      // isstdcnt
	be(0)                      // leapcnt
	be(0)                      // timecnt: nenhuma transição
	be(1)                      // typecnt: um único tipo
	be(uint32(len(abrev) + 1)) // charcnt
	be(uint32(offset))         // ttinfo.utoff
	b = append(b, 0)           // ttinfo.isdst
	b = append(b, 0)           // ttinfo.desigidx
	b = append(b, abrev...)
	b = append(b, 0)
	return b
}
