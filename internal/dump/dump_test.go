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
	"github.com/lex0c/aletheia/internal/safeio"
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

	e, _ := d.Env(nil)
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
	e, _ := d.Env(nil)

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
	e, _ := d.Env(nil)
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
	e, _ := d.Env(nil)
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
	e, _ := d.Env(nil)
	if !e.Now.IsZero() {
		t.Error("data ilegível precisa ficar vazia, para o relatório poder dizer isso")
	}
}

// A origem decide QUAIS CHECKS rodam. Um dump de uma versão mais nova, com um
// terceiro modo, era tratado como host vivo em silêncio: os checks de processo
// rodariam sobre fatos onde processo não existe e concluiriam ausência a
// partir de um modo que nunca foi olhado.
func TestOrigemDesconhecidaNaoViraHostVivo(t *testing.T) {
	d := &Dump{Schema: Schema, Facts: fatosDeTeste(), Ambiente: Ambiente{
		Source: "remote", CollectedAt: "2026-08-17T00:00:00Z",
	}}
	if _, err := d.Env(nil); err == nil {
		t.Error("origem que este binário não conhece precisa RECUSAR a análise, " +
			"e não virar 'live' por omissão")
	}
	// E as duas conhecidas continuam passando, inclusive a vazia dos dumps
	// antigos, que não gravavam o campo e eram todos de coleta ao vivo.
	for _, origem := range []string{"live", "image", ""} {
		d.Ambiente.Source = origem
		if _, err := d.Env(nil); err != nil {
			t.Errorf("origem %q recusada: %v", origem, err)
		}
	}
}

// O dump vem de um host possivelmente comprometido: tamanho é entrada não
// confiável. Acima de MaxDump ele é recusado com erro controlado, em vez de
// estourar a memória do analisador (o LimitReader nem carrega o resto).
func TestDumpAcimaDoTetoEhRecusado(t *testing.T) {
	orig := MaxDump
	MaxDump = 64
	defer func() { MaxDump = orig }()
	p := filepath.Join(t.TempDir(), "grande.json")
	if err := os.WriteFile(p, []byte(`{"schema":1`+strings.Repeat(" ", 300)+`}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Carregar(p); err == nil {
		t.Error("dump acima de MaxDump devia ser recusado, não carregado")
	}
}

// O ARTEFATO QUE É UM DEVICE NÃO PODE SER ABERTO PARA DESCOBRIR QUE É UM DEVICE.
//
// AbrirArtefato já recusava fifo, socket e device — mas com O_NONBLOCK e fstat
// DEPOIS, o que fecha o fifo e não fecha o device: o open() do driver roda antes
// da recusa. Um `--snapshot` apontado para um link plantado chegava lá.
func TestArtefatoDeviceEhRecusadoSemAbrir(t *testing.T) {
	p := filepath.Join(t.TempDir(), "incident.json")
	if err := os.Symlink("/dev/zero", p); err != nil {
		t.Skipf("sem symlink: %v", err)
	}
	var reais []string
	safeio.ObservarAberturaReal = func(c string) { reais = append(reais, c) }
	t.Cleanup(func() { safeio.ObservarAberturaReal = nil })

	fh, err := AbrirArtefato(p)
	if err == nil {
		fh.Close()
		t.Fatal("um device não é dump: tinha de ser recusado")
	}
	if len(reais) > 0 {
		t.Errorf("o device foi ABERTO antes da recusa: %v", reais)
	}
}
