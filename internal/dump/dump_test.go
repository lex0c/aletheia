package dump

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

func ambienteDeTeste() *env.Env {
	e := &env.Env{
		Source:      env.SourceLive,
		Caps:        env.CapProcfs | env.CapFilesystem,
		CapReason:   map[string]string{"root": "não estamos como root: /etc/shadow e /root ficam invisíveis"},
		Now:         time.Date(2026, 8, 17, 21, 3, 11, 0, time.UTC),
		Clock:       env.ClockSynced,
		ToolVersion: "0.1.0",
		ToolSHA256:  "abc123",
		ToolPath:    "/opt/ir/aletheia",
		NumCPU:      8,
	}
	return e
}

func fatosDeTeste() *facts.Facts {
	return &facts.Facts{
		SchemaVersion: facts.SchemaVersion,
		CollectedAt:   "2026-08-17T21:03:11Z",
		Source:        "live",
		Host:          facts.Host{Hostname: "web-01"},
		Processes: []facts.Process{
			{PID: 812, Comm: "mysqldump", Exe: "/usr/bin/mysqldump",
				Argv: []string{"mysqldump", "-u", "root", "-pS3cr3tP4ss", "prod"}},
		},
	}
}

func idaEVolta(t *testing.T, e *env.Env, f *facts.Facts) *Dump {
	t.Helper()
	var buf bytes.Buffer
	if err := De(e, f).Escrever(&buf); err != nil {
		t.Fatalf("Escrever: %v", err)
	}
	p := filepath.Join(t.TempDir(), "dump.json")
	if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := Carregar(p)
	if err != nil {
		t.Fatalf("Carregar: %v", err)
	}
	return d
}

func TestIdaEVoltaPreservaOsFatosEOAmbiente(t *testing.T) {
	d := idaEVolta(t, ambienteDeTeste(), fatosDeTeste())

	if d.Facts.Host.Hostname != "web-01" || len(d.Facts.Processes) != 1 {
		t.Fatalf("fatos não sobreviveram: %+v", d.Facts.Host)
	}
	if d.Ambiente.CollectedAt != "2026-08-17T21:03:11Z" {
		t.Errorf("CollectedAt = %q", d.Ambiente.CollectedAt)
	}
	if d.Ambiente.Tool != "0.1.0" || d.Ambiente.ToolSHA != "abc123" {
		t.Errorf("proveniência perdida: %+v", d.Ambiente)
	}

	e := d.Env(nil)
	if !e.Has(env.CapProcfs) || !e.Has(env.CapFilesystem) {
		t.Errorf("capacidades da coleta não voltaram: %v", e.Caps.Names())
	}
	if !e.Now.Equal(time.Date(2026, 8, 17, 21, 3, 11, 0, time.UTC)) {
		t.Errorf("Now = %v, queria o instante da COLETA", e.Now)
	}
	if e.Clock != env.ClockSynced {
		t.Errorf("Clock = %v", e.Clock)
	}
}

// A regra que sustenta o comando inteiro: a análise HERDA a cobertura da
// coleta e não pode melhorá-la.
//
// Sondar o ambiente local aqui seria trivial e o efeito é silencioso — números
// maiores, veredito melhor, nenhum erro. Por isso o teste afirma as duas
// pontas: a capacidade ausente continua ausente, e o MOTIVO que aparece é o que
// a coleta escreveu, não um genérico inventado na análise.
func TestAnaliseNaoRecuperaCapacidadeQueAColetaNaoTinha(t *testing.T) {
	d := idaEVolta(t, ambienteDeTeste(), fatosDeTeste())
	e := d.Env(nil)

	if e.Has(env.CapRoot) {
		t.Fatal("a análise concedeu root a uma coleta que não tinha: é a cobertura " +
			"do host de quem analisa vazando para o relatório de outro host")
	}
	if r := e.Reason(env.CapRoot); !strings.Contains(r, "/etc/shadow") {
		t.Errorf("Reason(root) = %q, queria o motivo REGISTRADO NA COLETA", r)
	}
}

// Capacidade que este binário conhece e o dump não menciona: a coleta é de uma
// versão que não a sondava. Um "indisponível" seco se confundiria com "sondei e
// não tinha" — que é exatamente a distinção que a ferramenta existe para manter.
func TestCapacidadeQueAColetaNaoSondouSeDeclaraAssim(t *testing.T) {
	d := &Dump{Schema: Schema, Facts: fatosDeTeste(), Ambiente: Ambiente{
		Source: "live", Caps: []string{"procfs"},
	}}
	e := d.Env(nil)
	r := e.Reason(env.CapDebugfs)
	if !strings.Contains(r, "não sondou") {
		t.Errorf("Reason(debugfs) = %q — precisa dizer que NINGUÉM olhou, e não "+
			"que olhou e não tinha", r)
	}
	if e.Has(env.CapDebugfs) {
		t.Error("capacidade não declarada não pode ser concedida")
	}
}

// O caso oposto: o dump vem de uma versão MAIS NOVA e declara uma capacidade
// que este binário não conhece. Ignorar em silêncio esconderia que existe um
// eixo inteiro que esta análise não avaliou.
func TestCapacidadeDesconhecidaDoDumpEDeclarada(t *testing.T) {
	d := &Dump{Schema: Schema, Facts: fatosDeTeste(), Ambiente: Ambiente{
		Source: "live", Caps: []string{"procfs", "quantum"},
	}}
	if es := d.Estranhas(); len(es) != 1 || es[0] != "quantum" {
		t.Fatalf("Estranhas = %v, queria [quantum]", es)
	}
	e := d.Env(nil)
	if !e.Has(env.CapProcfs) {
		t.Error("a capacidade conhecida ao lado da desconhecida se perdeu")
	}
	if r := e.CapReason["dump:quantum"]; !strings.Contains(r, "não conhece") {
		t.Errorf("a capacidade desconhecida precisa ficar registrada: %q", r)
	}
}

// O dump SAI DO HOST: vira fixture, anexo de ticket, arquivo em repositório. O
// environ já saía redigido do coletor; o argv era o que faltava.
func TestOArgvSaiRedigidoDoDump(t *testing.T) {
	f := fatosDeTeste()
	d := idaEVolta(t, ambienteDeTeste(), f)

	argv := strings.Join(d.Facts.Processes[0].Argv, " ")
	if strings.Contains(argv, "S3cr3tP4ss") {
		t.Errorf("a senha foi para o arquivo: %q", argv)
	}
	if !strings.Contains(argv, "mysqldump") {
		t.Errorf("a redação levou junto o que IDENTIFICA o processo: %q", argv)
	}

	// E o Facts vivo continua inteiro: a execução em curso precisa do argv
	// completo para casar indicador e julgar linhagem. Redigir na memória
	// enfraqueceria a varredura para proteger um arquivo que ela nem escreveu.
	if !strings.Contains(strings.Join(f.Processes[0].Argv, " "), "S3cr3tP4ss") {
		t.Error("a redação do dump mexeu no Facts da execução")
	}
}

// Recusar é a resposta certa: um retrato mal lido produz conclusão sobre um host
// que não existe, e ninguém revisa a conclusão de um arquivo que "abriu".
func TestEsquemaIncompativelEhRecusado(t *testing.T) {
	casos := map[string]string{
		"dump de outra versão":  `{"schema":99,"env":{},"facts":{"schema_version":1}}`,
		"fatos de outra versão": `{"schema":1,"env":{},"facts":{"schema_version":99}}`,
		"sem fatos":             `{"schema":1,"env":{}}`,
		"não é json":            `isto não é um dump`,
	}
	for nome, conteudo := range casos {
		p := filepath.Join(t.TempDir(), "d.json")
		if err := os.WriteFile(p, []byte(conteudo), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Carregar(p); err == nil {
			t.Errorf("%s: deveria ser recusado", nome)
		}
	}
}

// Data ilegível não vira "agora": viraria uma janela de investigação ancorada
// no relógio errado, e o recorte sairia silenciosamente deslocado.
func TestDataIlegivelNaoViraAgora(t *testing.T) {
	d := &Dump{Schema: Schema, Facts: fatosDeTeste(), Ambiente: Ambiente{
		Source: "live", CollectedAt: "ontem de manhã",
	}}
	if !d.Env(nil).Now.IsZero() {
		t.Error("data ilegível precisa ficar vazia, para o relatório poder dizer isso")
	}
}
