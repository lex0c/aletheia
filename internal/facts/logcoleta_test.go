package facts

import (
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lex0c/aletheia/internal/env"
)

// raizDeLog monta uma raiz com arquivos de log e devolve o Facts já coletado.
func raizDeLog(t *testing.T, arquivos map[string]string, prep func(raiz string, e *envOpts)) *Facts {
	t.Helper()
	raiz := t.TempDir()
	for rel, c := range arquivos {
		full := filepath.Join(raiz, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	o := &envOpts{}
	if prep != nil {
		prep(raiz, o)
	}
	e := env.Probe(env.Options{Root: raiz, Version: "test"})
	defer e.Close()
	e.SemLogs = o.semLogs
	e.LogsTudo = o.tudo
	e.LogsDesde = o.desde

	f := &Facts{}
	collectLogs(f, e)
	collectEventosDeLog(f, e)
	return f
}

type envOpts struct {
	semLogs bool
	tudo    bool
	desde   time.Time
}

// O CASO BASE: linhas viram eventos, e a fonte diz o que foi lido.
func TestColetaDeLogProduzEventoEObservabilidade(t *testing.T) {
	f := raizDeLog(t, map[string]string{
		"var/log/auth.log": linhasDeAuth(3),
	}, nil)

	if f.LogEstado != LogColetado {
		t.Errorf("LogEstado = %q, quer %q", f.LogEstado, LogColetado)
	}
	if len(f.EventosDeLog) != 3 {
		t.Fatalf("%d eventos, quer 3", len(f.EventosDeLog))
	}
	if len(f.FontesDeLog) != 1 {
		t.Fatalf("%d fontes, quer 1", len(f.FontesDeLog))
	}
	s := f.FontesDeLog[0]
	if s.Estado != FonteLida || s.LinhasCandidatas != 3 || s.LinhasReconhecidas != 3 {
		t.Errorf("fonte = %+v", s)
	}
	if !contemString(s.Familias, "auth") {
		t.Errorf("famílias = %v, quer conter auth", s.Familias)
	}
	if !f.LogTextoCompleto {
		t.Error("tudo legível e LogTextoCompleto falso")
	}
}

// FORA DE ESCOPO ≠ LACUNA: sem arquivo de log em TEXTO, a pergunta não cabe
// neste host — é o journald-only do Debian 12 e do Fedora. Declarar lacuna aqui
// derrubaria a cobertura de metade da frota para sempre.
func TestSemFonteEmTextoEhForaDeEscopoENaoLacuna(t *testing.T) {
	f := raizDeLog(t, map[string]string{
		"var/log/journal/x/system.journal": "\x00binário\x00",
	}, nil)

	if f.LogEstado != LogForaDeEscopo {
		t.Errorf("LogEstado = %q, quer %q", f.LogEstado, LogForaDeEscopo)
	}
	if len(f.Partial["logeventos"]) != 0 {
		t.Errorf("escopo NÃO é lacuna: %v", f.Partial["logeventos"])
	}
	c := f.CoberturaLog("auth")
	if c.Existe {
		t.Error("não há fonte de auth neste host")
	}
	if c.Motivo == "" {
		t.Error("o motivo precisa ser dito: é ele que separa escopo de silêncio")
	}
}

// DESLIGADO também não é lacuna — é escolha declarada de quem rodou. E o estado
// viaja para que um analyze sobre esse dump responda NÃO VERIFICADO em vez de
// "não achei".
func TestNoLogsNaoEmiteLacuna(t *testing.T) {
	f := raizDeLog(t, map[string]string{
		"var/log/auth.log": linhasDeAuth(3),
	}, func(_ string, o *envOpts) { o.semLogs = true })

	if f.LogEstado != LogDesativado {
		t.Errorf("LogEstado = %q", f.LogEstado)
	}
	if len(f.Partial["logeventos"]) != 0 {
		t.Errorf("desligado não é lacuna: %v", f.Partial["logeventos"])
	}
	if len(f.EventosDeLog) != 0 {
		t.Error("com --no-logs nada pode ser lido")
	}
	if c := f.CoberturaLog("auth"); c.Lida || c.Motivo == "" {
		t.Errorf("a cobertura precisa dizer que foi desligada: %+v", c)
	}
}

// O HORIZONTE EFETIVO É O ALCANÇADO, NÃO O PEDIDO.
//
// É o P1 do plano: num arquivo grande lido pela cauda, o `--since 7d` não vira
// sete dias de observação. Guardar o pedido como se fosse cobertura afirmaria
// dias de história que ninguém leu.
func TestHorizonteEfetivoNaoEhOPedido(t *testing.T) {
	// Um auth.log MAIOR que o teto por arquivo: a cauda cobre só o fim.
	var b strings.Builder
	linha := "Aug 24 01:20:33 h sshd[1]: Accepted password for ana from 10.0.0.1 port 5 ssh2\n"
	for b.Len() < maxLogBytesArquivo+(2<<20) {
		b.WriteString(linha)
	}
	f := raizDeLog(t, map[string]string{"var/log/auth.log": b.String()}, nil)

	if len(f.FontesDeLog) != 1 {
		t.Fatalf("%d fontes", len(f.FontesDeLog))
	}
	s := f.FontesDeLog[0]
	if !s.CorteNoInicio || !s.LeituraDescontinua {
		t.Errorf("arquivo maior que o teto precisa marcar corte e descontinuidade: %+v", s)
	}
	if s.Estado != FonteTruncada {
		t.Errorf("Estado = %q, quer %q", s.Estado, FonteTruncada)
	}
	if f.LogEstado != LogParcial {
		t.Errorf("LogEstado = %q, quer %q", f.LogEstado, LogParcial)
	}
	// E a cobertura precisa DIZER que tem buraco: a cabeça e a cauda não são um
	// intervalo contínuo.
	if c := f.CoberturaLog("auth"); !c.Buraco {
		t.Errorf("cobertura sem buraco sobre leitura descontínua: %+v", c)
	}
	if len(f.Partial["logeventos"]) == 0 {
		t.Error("o teto mordeu e não foi declarado")
	}
}

// A JANELA decide quais ARQUIVOS abrir. Um arquivo velho demais não é aberto, e
// isso sai DECLARADO — não em silêncio.
func TestArquivoForaDaJanelaNaoEhAberto(t *testing.T) {
	f := raizDeLog(t, map[string]string{
		"var/log/auth.log":   linhasDeAuth(2),
		"var/log/auth.log.1": linhasDeAuth(2),
	}, func(raiz string, o *envOpts) {
		velho := time.Now().Add(-90 * 24 * time.Hour)
		if err := os.Chtimes(filepath.Join(raiz, "var/log/auth.log.1"), velho, velho); err != nil {
			t.Fatal(err)
		}
	})

	for _, s := range f.FontesDeLog {
		if strings.HasSuffix(s.Path, "auth.log.1") && s.Estado != FonteForaDaJanela {
			t.Errorf("a geração velha deveria estar fora da janela: %+v", s)
		}
	}
}

// O .gz É LIDO. A rotação é onde mora a história de dias atrás, e ignorá-la
// deixaria a feature respondendo só pelas últimas horas.
func TestRotacionadoGzEhLido(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(linhasDeAuth(2))); err != nil {
		t.Fatal(err)
	}
	zw.Close()

	f := raizDeLog(t, map[string]string{
		// O arquivo vivo tem uma linha DIFERENTE das do .gz: linhas idênticas em
		// arquivos diferentes são deduplicadas de propósito, e isso é assunto de
		// outro teste.
		"var/log/auth.log": "Aug 24 09:00:00 h sshd[1]: Accepted password for bob " +
			"from 10.0.0.9 port 5 ssh2\n",
		"var/log/auth.log.2.gz": buf.String(),
	}, nil)

	if len(f.EventosDeLog) != 3 {
		t.Fatalf("%d eventos, quer 3 (1 vivo + 2 do .gz)", len(f.EventosDeLog))
	}
}

// DEDUPE ENTRE ARQUIVOS, e NÃO dentro do mesmo.
//
// O rsyslog manda a mesma mensagem do sshd para auth.log e para syslog conforme
// a configuração. Já duas linhas idênticas DENTRO de um arquivo são duas
// ocorrências de verdade — num arranque de força bruta a quarenta tentativas por
// segundo elas são idênticas mesmo, e colapsá-las apagaria a campanha.
func TestDedupeEntreArquivosMasNaoDentroDoMesmo(t *testing.T) {
	linha := "Aug 24 01:20:33 h sshd[1]: Failed password for root from 1.2.3.4 port 5 ssh2\n"

	f := raizDeLog(t, map[string]string{
		"var/log/auth.log": linha,
		"var/log/syslog":   linha,
	}, nil)
	if n := len(f.EventosDeLog); n != 1 {
		t.Errorf("%d eventos entre dois arquivos, quer 1 — a mesma mensagem duplicada", n)
	}

	f = raizDeLog(t, map[string]string{
		"var/log/auth.log": linha + linha + linha,
	}, nil)
	if n := len(f.EventosDeLog); n != 3 {
		t.Errorf("%d eventos no MESMO arquivo, quer 3 — são ocorrências distintas", n)
	}
}

// A CAPACIDADE DO PARSER é medida contra as CANDIDATAS.
//
// Um arquivo cheio de linhas de postgres e docker não tem parser quebrado: ele
// tem produtores que este parser não promete entender. Medir contra o total de
// linhas poria lacuna em toda varredura saudável.
func TestRuidoDeAplicacaoNaoAcusaParserQuebrado(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 500; i++ {
		b.WriteString("Aug 24 01:20:33 h postgres[10]: connection authorized: user=app\n")
	}
	b.WriteString("Aug 24 01:20:34 h sshd[1]: Accepted password for ana from 10.0.0.1 port 5 ssh2\n")

	f := raizDeLog(t, map[string]string{"var/log/syslog": b.String()}, nil)
	if len(f.Partial["logeventos"]) != 0 {
		t.Errorf("ruído de aplicação não é parser quebrado: %v", f.Partial["logeventos"])
	}
	if len(f.EventosDeLog) != 1 {
		t.Errorf("%d eventos, quer 1", len(f.EventosDeLog))
	}
}

// E o contrário: MUITAS candidatas e quase nenhuma compreendida é o formato do
// host diferindo do esperado — o falso "limpo" mais convincente que existe,
// porque nada falhou.
func TestCandidatasNaoCompreendidasViramLacuna(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 200; i++ {
		b.WriteString("Aug 24 01:20:33 h sshd[1]: mensagem em um formato que este parser nunca viu\n")
	}
	f := raizDeLog(t, map[string]string{"var/log/auth.log": b.String()}, nil)

	juntas := strings.Join(f.Partial["logeventos"], " ")
	if !strings.Contains(juntas, "compreendidas") {
		t.Errorf("faltou a lacuna de capacidade do parser: %v", f.Partial["logeventos"])
	}
}

// ARQUIVO ILEGÍVEL É LACUNA, e é o par do teste de escopo acima: o auth.log é
// 0640 root:adm em Debian por desenho, então sem root esta é a resposta honesta.
func TestArquivoIlegivelEhLacunaComFonteMarcada(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("como root o modo 000 não nega leitura")
	}
	f := raizDeLog(t, map[string]string{
		"var/log/auth.log": linhasDeAuth(2),
	}, func(raiz string, _ *envOpts) {
		if err := os.Chmod(filepath.Join(raiz, "var/log/auth.log"), 0o000); err != nil {
			t.Fatal(err)
		}
	})

	if len(f.Partial["logeventos"]) == 0 {
		t.Error("arquivo que EXISTE e não abre é lacuna declarada")
	}
	if len(f.FontesDeLog) != 1 || f.FontesDeLog[0].Estado != FonteIlegivel {
		t.Errorf("fontes = %+v", f.FontesDeLog)
	}
	// A família EXISTE (o arquivo está lá) e NÃO foi lida: é a distinção que
	// decide entre escopo e lacuna no motor.
	c := f.CoberturaLog("auth")
	if !c.Existe || c.Lida {
		t.Errorf("cobertura = %+v, quer Existe=true Lida=false", c)
	}
}

// A COBERTURA CONTÍNUA para no primeiro buraco: é a única coisa sobre a qual um
// check pode afirmar ausência.
func TestCoberturaContinuaParaNoBuraco(t *testing.T) {
	f := &Facts{
		LogEstado: LogColetado,
		FontesDeLog: []FonteDeLog{
			{Path: "/var/log/auth.log", Familias: []string{"auth"}, Estado: FonteLida,
				CobertoDesde: "2026-08-24T00:00:00Z", CobertoAte: "2026-08-24T12:00:00Z"},
			{Path: "/var/log/auth.log.1", Familias: []string{"auth"}, Estado: FonteLida,
				CobertoDesde: "2026-08-23T00:00:00Z", CobertoAte: "2026-08-24T00:00:00Z"},
			// Geração com BURACO antes dela: termina bem antes do começo da anterior.
			{Path: "/var/log/auth.log.2", Familias: []string{"auth"}, Estado: FonteLida,
				CobertoDesde: "2026-08-01T00:00:00Z", CobertoAte: "2026-08-10T00:00:00Z"},
		},
	}
	c := f.CoberturaLog("auth")
	if c.ContinuoDesde != "2026-08-23T00:00:00Z" {
		t.Errorf("ContinuoDesde = %q, quer parar no buraco (23/08)", c.ContinuoDesde)
	}
	if c.ContinuoAte != "2026-08-24T12:00:00Z" {
		t.Errorf("ContinuoAte = %q", c.ContinuoAte)
	}
	if !c.Buraco {
		t.Error("o buraco precisa ser dito")
	}
}

// ---------------------------------------------------------------------------

func linhasDeAuth(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteString("Aug 24 01:2" + string(rune('0'+i%10)) +
			":33 h sshd[1]: Accepted password for ana from 10.0.0.1 port 5 ssh2\n")
	}
	return b.String()
}

// FONTE QUE EXISTE E NÃO PÔDE SER VISTA é LACUNA, e nunca escopo.
//
// Medido num host real: /var/log/audit é 0700 root em toda distribuição que
// instala auditd. Sem root o diretório não LISTA, o audit.log não entra no
// inventário de rotação, e a coleta concluía "este host não tem log em texto" —
// uma afirmação sobre um arquivo que ninguém conseguiu olhar.
//
// É o par exato do teste de escopo: lá o arquivo não existe, aqui ele existe e
// não abre, e a diferença entre os dois decide se um check sai do denominador
// ou vira lacuna.
func TestDiretorioDeLogSemListagemNaoViraForaDeEscopo(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("como root o modo 000 não nega leitura")
	}
	raiz := t.TempDir()
	dir := filepath.Join(raiz, "var/log/audit")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "audit.log"),
		[]byte("type=SYSCALL msg=audit(1755990137.123:1): syscall=59 pid=1 uid=0 comm=\"sh\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// 0700 sem os bits de leitura: o diretório não lista.
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	e := env.Probe(env.Options{Root: raiz, Version: "test"})
	defer e.Close()
	f := &Facts{}
	collectLogs(f, e)
	collectEventosDeLog(f, e)

	if f.LogEstado == LogForaDeEscopo {
		t.Fatal("arquivo que não pôde ser VISTO virou 'não existe': é a equivalência " +
			"que esta ferramenta existe para recusar")
	}
	if len(f.Partial["logeventos"]) == 0 {
		t.Error("o inacessível precisa ser declarado")
	}
	// E a família precisa constar como EXISTENTE e NÃO LIDA: é isso que mantém
	// o check no denominador em vez de tirá-lo dele.
	c := f.CoberturaLog("audit")
	if !c.Existe || c.Lida {
		t.Errorf("cobertura = %+v, quer Existe=true Lida=false", c)
	}
}

// O TETO RÍGIDO VALE SOBRE O QUE É CONSIDERADO, e não só sobre o que é lido.
//
// Medido: `touch -t 202001010000 /var/log/auth.log.{1..3000}` punha 3001 fontes
// no dump. As velhas nem eram abertas — ficavam fora da janela — e ainda assim
// cada uma virava uma entrada serializada. A lista de arquivos de /var/log é
// escolhida por quem controla o host.
func TestTetoRigidoValeSobreOsArquivosCONSIDERADOS(t *testing.T) {
	arquivos := map[string]string{"var/log/auth.log": linhasDeAuth(1)}
	for i := 1; i <= maxLogArquivosHard+100; i++ {
		arquivos["var/log/auth.log."+strconv.Itoa(i)] = "x\n"
	}
	f := raizDeLog(t, arquivos, func(raiz string, _ *envOpts) {
		velho := time.Now().Add(-365 * 24 * time.Hour)
		for i := 1; i <= maxLogArquivosHard+100; i++ {
			p := filepath.Join(raiz, "var/log/auth.log."+strconv.Itoa(i))
			if err := os.Chtimes(p, velho, velho); err != nil {
				t.Fatal(err)
			}
		}
	})

	if n := len(f.FontesDeLog); n > maxLogArquivosHard {
		t.Errorf("%d fontes no dump, teto rígido é %d", n, maxLogArquivosHard)
	}
	if len(f.Partial["logeventos"]) == 0 {
		t.Error("o corte precisa ser DECLARADO: sem isso ele é truncagem silenciosa")
	}
}

// FORA DA JANELA não é "lido", e não é incompletude.
//
// São dois erros opostos, e os dois estavam presentes: o arquivo que ninguém
// abriu contava como lido — fazendo o motivo da cobertura afirmar que ele foi
// examinado — e ao mesmo tempo derrubava o fato de completude, que ficaria falso
// em todo host do mundo, porque sempre há uma geração mais antiga que o
// horizonte.
func TestForaDaJanelaNaoEhLidoNemIncompletude(t *testing.T) {
	f := raizDeLog(t, map[string]string{
		"var/log/auth.log":   linhasDeAuth(2),
		"var/log/auth.log.1": linhasDeAuth(2),
	}, func(raiz string, _ *envOpts) {
		velho := time.Now().Add(-90 * 24 * time.Hour)
		if err := os.Chtimes(filepath.Join(raiz, "var/log/auth.log.1"), velho, velho); err != nil {
			t.Fatal(err)
		}
	})

	if !f.LogTextoCompleto {
		t.Error("geração fora da janela não pode derrubar a completude: ela é a " +
			"janela fazendo o trabalho pedido, e já viaja em LogJanelaSolicitada")
	}

	// E o arquivo que ficou fora não pode contar como lido.
	so := &Facts{
		LogEstado: LogColetado,
		FontesDeLog: []FonteDeLog{
			{Path: "/var/log/auth.log.9", Familias: []string{"auth"}, Estado: FonteForaDaJanela},
		},
	}
	c := so.CoberturaLog("auth")
	if !c.Existe || c.Lida {
		t.Errorf("cobertura = %+v, quer Existe=true Lida=false", c)
	}
}

// O DENOMINADOR do audit.log são os tipos que o montador promete consumir.
//
// Contar toda linha com envelope válido como reconhecida tornava a medição
// VÁCUA: um arquivo inteiro de tipos desconhecidos saía com razão perfeita — a
// mesma cegueira que o estado `naoReconhecida` existe para acusar no syslog.
func TestTipoDeAuditDesconhecidoNaoContaComoReconhecido(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 100; i++ {
		b.WriteString("type=TIPO_QUE_NAO_CONSUMIMOS msg=audit(173650000" +
			strconv.Itoa(i%10) + ".000:" + strconv.Itoa(i) + "): campo=valor\n")
	}
	b.WriteString(`type=SYSCALL msg=audit(1736500999.000:999): syscall=59 pid=1 uid=0 comm="sh"` + "\n")

	f := raizDeLog(t, map[string]string{"var/log/audit/audit.log": b.String()}, nil)
	if len(f.FontesDeLog) != 1 {
		t.Fatalf("%d fontes", len(f.FontesDeLog))
	}
	s := f.FontesDeLog[0]
	if s.LinhasParseadas != 101 {
		t.Errorf("LinhasParseadas = %d, quer 101 — o envelope foi compreendido", s.LinhasParseadas)
	}
	if s.LinhasCandidatas != 1 {
		t.Errorf("LinhasCandidatas = %d, quer 1 — só o SYSCALL é prometido", s.LinhasCandidatas)
	}
}
