package baseline

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/facts"
)

func fatosCom(pid int, exe string) *facts.Facts {
	return &facts.Facts{Processes: []facts.Process{{PID: pid, Exe: exe}}}
}

// A PROPRIEDADE QUE NÃO PODE SER VIOLADA: casar com a baseline nunca apaga.
//
// Se o host já estava comprometido na captura, o implante entra na baseline. O
// que impede isso de virar bênção permanente é o achado CONTINUAR impresso, com
// a data e com a frase que separa "não é novo" de "é legítimo".
func TestBaselineNuncaApaga(t *testing.T) {
	f := &facts.Facts{}
	r := &check.Report{Findings: []check.Finding{
		{ID: "persist.suid_unowned", Subject: "/usr/local/sbin/x", Sev: check.SevCritical},
	}}
	b := &Baseline{Schema: Schema, Host: "h", CapturedAt: "2026-01-01T00:00:00Z",
		Keys: []string{"persist.suid_unowned|/usr/local/sbin/x"}}

	if n := b.Aplicar(r, f); n != 1 {
		t.Fatalf("rebaixados = %d", n)
	}
	if len(r.Findings) != 1 {
		t.Fatal("o achado SUMIU: baseline não pode apagar, só rebaixar")
	}
	fd := r.Findings[0]
	if fd.Sev != check.SevWarn {
		t.Errorf("sev = %v, crítico desce UM nível", fd.Sev)
	}
	if !fd.Baseline || fd.Novo {
		t.Error("o achado precisa sair marcado como conhecido, não como novo")
	}
	if !strings.Contains(strings.Join(fd.Evidence, " "), "NÃO prova que é legítimo") {
		t.Error("a evidência precisa dizer que estar na baseline não é aprovação")
	}
}

// O piso é INFO: nada some do relatório por causa da baseline.
func TestRebaixamentoTemPiso(t *testing.T) {
	casos := map[check.Severity]check.Severity{
		check.SevCritical: check.SevWarn,
		check.SevWarn:     check.SevInfo,
		check.SevManual:   check.SevInfo,
		check.SevInfo:     check.SevInfo,
	}
	for entrada, quer := range casos {
		if got := rebaixar(entrada); got != quer {
			t.Errorf("rebaixar(%v) = %v, quer %v", entrada, got, quer)
		}
	}
}

// O que NÃO está na baseline é a informação mais valiosa da execução.
func TestNovoEhMarcado(t *testing.T) {
	f := &facts.Facts{}
	r := &check.Report{Findings: []check.Finding{
		{ID: "a", Subject: "/x", Sev: check.SevCritical},
		{ID: "b", Subject: "/y", Sev: check.SevCritical},
	}}
	b := &Baseline{Schema: Schema, Keys: []string{"a|/x"}}
	b.Aplicar(r, f)

	if !r.Findings[0].Baseline || r.Findings[0].Novo {
		t.Error("/x estava na baseline")
	}
	if r.Findings[1].Baseline || !r.Findings[1].Novo {
		t.Error("/y não estava, e é o que interessa")
	}
	if r.Findings[1].Sev != check.SevCritical {
		t.Error("achado novo não pode ser rebaixado")
	}
}

// PID muda a cada boot: a identidade estável de um achado de processo é o
// EXECUTÁVEL. Sem isso, nenhum achado de processo casaria com a baseline.
func TestChaveDeProcessoUsaExe(t *testing.T) {
	fd := check.Finding{ID: "proc.suspicious_path", Subject: "pid=17"}

	k1 := Chave(fatosCom(17, "/tmp/.x"), fd)
	fd2 := check.Finding{ID: "proc.suspicious_path", Subject: "pid=4242"}
	k2 := Chave(fatosCom(4242, "/tmp/.x"), fd2)
	if k1 == "" || k1 != k2 {
		t.Fatalf("o mesmo binário em PID diferente precisa dar a mesma chave: %q vs %q", k1, k2)
	}

	// Sem exe legível não há identidade estável, e chave nenhuma é melhor que
	// uma que abençoaria qualquer processo que aparecesse naquele PID depois.
	if k := Chave(fatosCom(17, ""), fd); k != "" {
		t.Errorf("processo sem exe não pode receber chave: %q", k)
	}
}

// Baseline de esquema anterior é RECUSADA, não interpretada torto: casar chave
// errada abençoaria achado que ninguém aprovou.
func TestEsquemaIncompativelEhRecusado(t *testing.T) {
	dir := t.TempDir()
	bom := dir + "/bom.json"
	ruim := dir + "/ruim.json"

	if err := os.WriteFile(bom,
		[]byte(`{"schema":1,"host":"h","keys":["a|/x"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ruim,
		[]byte(`{"schema":99,"host":"h","keys":["a|/x"]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Carregar(bom); err != nil {
		t.Fatalf("baseline do esquema corrente precisa carregar: %v", err)
	}
	if _, err := Carregar(ruim); !errors.Is(err, ErrEsquema) {
		t.Errorf("esquema diferente precisa ser RECUSADO, não interpretado: %v", err)
	}
	if _, err := Carregar(dir + "/nao-existe.json"); err == nil {
		t.Error("arquivo ausente precisa falhar alto, não virar baseline vazia")
	}
}

// Uma baseline que rebaixa achado é uma autoridade, e autoridade precisa ser
// examinável: de onde veio, de quando, e por que desconfiar.
func TestRessalvas(t *testing.T) {
	agora := time.Date(2026, 8, 17, 0, 0, 0, 0, time.UTC)

	velha := &Baseline{Host: "outro", CapturedAt: "2025-01-01T00:00:00Z", Completa: false,
		CoberturaTxt: "40/55"}
	rs := strings.Join(velha.Ressalvas("esteHost", agora), " | ")
	for _, quer := range []string{"OUTRO host", "dias", "incompleta"} {
		if !strings.Contains(rs, quer) {
			t.Errorf("ressalva %q ausente em: %s", quer, rs)
		}
	}

	boa := &Baseline{Host: "esteHost", CapturedAt: "2026-08-10T00:00:00Z", Completa: true}
	if rs := boa.Ressalvas("esteHost", agora); len(rs) != 0 {
		t.Errorf("baseline recente, completa e do mesmo host não tem ressalva: %v", rs)
	}
}

// A captura DIZ quando viu menos do que devia. Baseline montada em execução
// degradada descreve menos do que parece, e o que faltou vira "novo" depois.
func TestCapturaRegistraCoberturaIncompleta(t *testing.T) {
	r := &check.Report{
		Coverage: check.Coverage{Total: 55, Complete: 40, CollectorGaps: []string{"sem root"}},
	}
	b := Capturar(r, &facts.Facts{}, "h", "v", time.Now())
	if b.Completa {
		t.Error("cobertura 40/55 com lacuna não é captura completa")
	}
	if b.CoberturaTxt != "40/55" {
		t.Errorf("cobertura = %q", b.CoberturaTxt)
	}
}
