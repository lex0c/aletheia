package facts

import (
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
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

// A JANELA NÃO OLHA O MTIME — ela olha o CONTEÚDO que foi lido.
//
// O gate por mtime custava três comandos para sumir com uma geração inteira:
//
//	mv /var/log/auth.log /var/log/auth.log.1
//	touch -d '2020-01-01' /var/log/auth.log.1
//	: > /var/log/auth.log
//
// e como `fora_da_janela` não conta contra a completude, aquilo saía sem lacuna
// nenhuma. Agora o mtime não decide abertura: a geração é lida.
func TestJanelaNaoConfiaNoMtimeDoRotacionado(t *testing.T) {
	f := raizDeLog(t, map[string]string{
		"var/log/auth.log":   "",
		"var/log/auth.log.1": linhasDeAuth(2),
	}, func(raiz string, _ *envOpts) {
		antigo := time.Now().Add(-2000 * 24 * time.Hour)
		if err := os.Chtimes(filepath.Join(raiz, "var/log/auth.log.1"), antigo, antigo); err != nil {
			t.Fatal(err)
		}
	})

	de := map[string]string{}
	for _, s := range f.FontesDeLog {
		de[s.Path] = s.Estado
	}
	if de["/var/log/auth.log.1"] != FonteLida {
		t.Errorf("a geração rotacionada precisa ser LIDA (estado %q): o mtime é do "+
			"alvo, e deixá-lo decidir abertura entrega o esconderijo", de["/var/log/auth.log.1"])
	}
	if len(f.EventosDeLog) == 0 {
		t.Error("o conteúdo movido para a geração rotacionada não foi observado")
	}
}

// E a janela continua limitando custo, por CONTEÚDO OBSERVADO: quando uma
// geração acaba inteira antes do horizonte, as mais antigas daquela família não
// precisam ser abertas — elas só podem ser mais velhas ainda.
func TestJanelaParaDeAbrirDepoisDeUmaGeracaoAntiga(t *testing.T) {
	antiga := "Jan 02 01:00:00 h sshd[1]: Accepted password for ana from 10.0.0.1 port 5 ssh2\n"
	f := raizDeLog(t, map[string]string{
		"var/log/auth.log":   linhasDeAuth(1),
		"var/log/auth.log.1": antiga,
		"var/log/auth.log.2": antiga,
	}, func(raiz string, o *envOpts) {
		o.desde = time.Now().Add(-24 * time.Hour)
		antigo := time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC)
		for _, n := range []string{"var/log/auth.log.1", "var/log/auth.log.2"} {
			if err := os.Chtimes(filepath.Join(raiz, n), antigo, antigo); err != nil {
				t.Fatal(err)
			}
		}
	})

	de := map[string]string{}
	for _, s := range f.FontesDeLog {
		de[s.Path] = s.Estado
	}
	if de["/var/log/auth.log.1"] != FonteLida {
		t.Errorf("a primeira geração é lida para SE SABER que ela é antiga: %q",
			de["/var/log/auth.log.1"])
	}
	if de["/var/log/auth.log.2"] != FonteForaDaJanela {
		t.Errorf("a geração seguinte não precisa ser aberta: %q", de["/var/log/auth.log.2"])
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
	// E o fato de RESUMO precisa concordar com o detalhado: um arquivo LIDO com
	// lacuna ainda é coleta parcial. Dizer `collected` aqui seria dois fatos da
	// mesma coleta se contradizendo.
	if f.LogEstado != LogParcial {
		t.Errorf("LogEstado = %q, quer partial — a fonte carrega lacuna", f.LogEstado)
	}
	if f.FontesDeLog[0].Lacuna == "" {
		t.Error("a lacuna precisa estar NO ARQUIVO, para o check degradar pela família")
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

// LOG TROCADO POR OUTRA COISA não é "este host não tem log".
//
// Um `mkfifo /var/log/auth.log` — ou um link para /dev/null — some do
// inventário, que filtra arquivo comum, e fazia a família inteira parecer
// inexistente: a coleta concluía FORA DE ESCOPO, os checks saíam do
// denominador, e a cobertura ficava intacta. Apontar o log para o vazio é a
// forma mais barata de anti-forense que existe — a mesma que o
// antiforense.shell_history já reconhece para o histórico — e ela não pode
// comprar silêncio com aparência de escopo.
func TestLogTrocadoPorOutroObjetoNaoViraForaDeEscopo(t *testing.T) {
	casos := []struct {
		nome string
		cria func(t *testing.T, p string)
		quer string
	}{
		{
			nome: "fifo",
			cria: func(t *testing.T, p string) {
				if err := syscall.Mkfifo(p, 0o644); err != nil {
					t.Skipf("mkfifo indisponível aqui: %v", err)
				}
			},
			quer: "fifo",
		},
		{
			nome: "link para /dev/null",
			cria: func(t *testing.T, p string) {
				if err := os.Symlink("/dev/null", p); err != nil {
					t.Fatal(err)
				}
			},
			quer: "link simbólico",
		},
		{
			nome: "diretório",
			cria: func(t *testing.T, p string) {
				if err := os.Mkdir(p, 0o755); err != nil {
					t.Fatal(err)
				}
			},
			quer: "diretório",
		},
	}

	for _, c := range casos {
		t.Run(c.nome, func(t *testing.T) {
			raiz := t.TempDir()
			if err := os.MkdirAll(filepath.Join(raiz, "var/log"), 0o755); err != nil {
				t.Fatal(err)
			}
			c.cria(t, filepath.Join(raiz, "var/log/auth.log"))

			e := env.Probe(env.Options{Root: raiz, Version: "test"})
			defer e.Close()
			f := &Facts{}
			collectLogs(f, e)
			collectEventosDeLog(f, e)

			if f.LogEstado == LogForaDeEscopo {
				t.Fatal("o arquivo EXISTE: chamar isto de fora de escopo entrega " +
					"silêncio a quem trocou o log de lugar")
			}
			juntas := strings.Join(f.Partial["logeventos"], " ")
			if !strings.Contains(juntas, c.quer) {
				t.Errorf("a lacuna precisa NOMEAR o que está no lugar (%s): %v", c.quer, f.Partial["logeventos"])
			}
			// E a família precisa continuar EXISTINDO e não lida: é isso que
			// mantém os checks no denominador.
			cob := f.CoberturaLog("auth")
			if !cob.Existe || cob.Lida {
				t.Errorf("cobertura = %+v, quer Existe=true Lida=false", cob)
			}
		})
	}
}

// COBERTURA MEDE OBSERVAÇÃO, NÃO ACHADO.
//
// Este é o teste que faltava, e a falta dele escondia o defeito: os outros
// montavam FonteDeLog À MÃO, já com CobertoDesde/Ate preenchidos, em vez de
// gerar a fonte a partir de um arquivo de verdade.
//
// Um auth.log real é quase todo linha de rotina — `Connection closed by …` —
// que o parser reconhece e deliberadamente não transforma em evento. Derivando
// o intervalo dos EVENTOS, a cobertura de um arquivo lido das 10:00 às 23:50
// encolhia para o instante do único evento interessante. E é sobre esse
// intervalo que o antiforense.log_time_gap afirma "N dias sem UMA linha de
// autenticação" — uma frase falsa sobre um arquivo cheio de linhas.
func TestCoberturaSaiDasLinhasDatadasENaoDosEventos(t *testing.T) {
	f := raizDeLog(t, map[string]string{
		"var/log/auth.log": "" +
			"Aug 24 10:00:00 h sshd[1]: Connection closed by 1.2.3.4 port 5 [preauth]\n" +
			"Aug 24 12:00:00 h sshd[1]: Connection closed by 1.2.3.4 port 5 [preauth]\n" +
			"Aug 24 18:00:00 h sshd[1]: Failed password for root from 1.2.3.4 port 5 ssh2\n" +
			"Aug 24 23:50:00 h sshd[1]: Connection closed by 1.2.3.4 port 5 [preauth]\n",
	}, nil)

	if len(f.EventosDeLog) != 1 {
		t.Fatalf("%d eventos, quer 1 (só o Failed password)", len(f.EventosDeLog))
	}
	s := f.FontesDeLog[0]
	if s.CobertoDesde == "" || s.CobertoAte == "" {
		t.Fatalf("sem cobertura: %+v", s)
	}
	// O arquivo foi observado das 10:00 às 23:50, e não às 18:00 em ponto.
	if !strings.HasSuffix(s.CobertoDesde, "T10:00:00Z") {
		t.Errorf("CobertoDesde = %q, quer a PRIMEIRA linha datada (10:00)", s.CobertoDesde)
	}
	if !strings.HasSuffix(s.CobertoAte, "T23:50:00Z") {
		t.Errorf("CobertoAte = %q, quer a ÚLTIMA linha datada (23:50)", s.CobertoAte)
	}
}

// E a consequência disso no check: um arquivo cheio de linhas de rotina não
// pode virar "vão de tempo". Sem a correção, duas gerações com eventos em
// pontas opostas fabricavam um buraco onde havia registro o tempo todo.
func TestArquivoCheioDeRotinaNaoFabricaVao(t *testing.T) {
	linhas := func(dia string, horas ...string) string {
		var b strings.Builder
		for _, h := range horas {
			b.WriteString("Aug " + dia + " " + h + " h sshd[1]: Connection closed by 1.2.3.4 port 5 [preauth]\n")
		}
		return b.String()
	}
	f := raizDeLog(t, map[string]string{
		// A geração antiga tem evento só no começo; a viva, só no fim. Entre os
		// dois eventos há três dias — e linha de rotina em todos eles.
		"var/log/auth.log.1": "Aug 20 00:05:00 h sshd[1]: Failed password for root from 1.2.3.4 port 5 ssh2\n" +
			linhas("20", "06:00:00", "12:00:00", "18:00:00", "23:00:00") +
			linhas("21", "06:00:00", "12:00:00", "23:00:00"),
		"var/log/auth.log": linhas("22", "00:10:00", "06:00:00", "12:00:00") +
			"Aug 22 18:00:00 h sshd[1]: Failed password for root from 1.2.3.4 port 5 ssh2\n",
	}, nil)

	de := map[string]FonteDeLog{}
	for _, s := range f.FontesDeLog {
		de[s.Path] = s
	}
	antiga, viva := de["/var/log/auth.log.1"], de["/var/log/auth.log"]
	if antiga.CobertoAte == "" || viva.CobertoDesde == "" {
		t.Fatalf("cobertura vazia: %+v %+v", antiga, viva)
	}
	// O fim da antiga (21 às 23:00) encosta no começo da viva (22 às 00:10):
	// menos de duas horas, e não os três dias que os EVENTOS sugeririam.
	if !strings.HasSuffix(antiga.CobertoAte, "-21T23:00:00Z") {
		t.Errorf("fim da geração antiga = %q", antiga.CobertoAte)
	}
	if !strings.HasSuffix(viva.CobertoDesde, "-22T00:10:00Z") {
		t.Errorf("começo da viva = %q", viva.CobertoDesde)
	}
}

// MTIME É DO ALVO, e não decide leitura em geração nenhuma.
//
// `touch -d '2025-01-01' /var/log/auth.log` custa nada e, com a janela padrão,
// fazia o conteúdo ATUAL não ser lido: sem evento, sem lacuna, e os checks de
// auth saindo COMPLETOS.
func TestMtimeForjadoNaoImpedeALeitura(t *testing.T) {
	f := raizDeLog(t, map[string]string{
		"var/log/auth.log":   linhasDeAuth(2),
		"var/log/auth.log.1": linhasDeAuth(2),
	}, func(raiz string, _ *envOpts) {
		antigo := time.Now().Add(-400 * 24 * time.Hour)
		for _, n := range []string{"var/log/auth.log", "var/log/auth.log.1"} {
			if err := os.Chtimes(filepath.Join(raiz, n), antigo, antigo); err != nil {
				t.Fatal(err)
			}
		}
	})

	for _, s := range f.FontesDeLog {
		if s.Estado != FonteLida {
			t.Errorf("%s: estado = %q, quer lido — o mtime não decide abertura",
				s.Path, s.Estado)
		}
	}
	if len(f.EventosDeLog) == 0 {
		t.Error("nenhum evento: o conteúdo não foi lido")
	}
}

// O MTIME NÃO PODE DECIDIR O ANO DO ARQUIVO VIVO.
//
// Corrigir só o gate de abertura fechou uma porta e deixou a outra: o arquivo
// passava a ser lido, e o `touch -d` continuava escolhendo o ANO das linhas.
// Um ano a menos empurra o achado para fora de `--since 7d`, e o relatório passa
// a mostrar só a contagem dele — o adversário escolhendo o que o operador lê.
//
// O arquivo vivo é o que está sendo escrito AGORA: a última linha dele é, por
// definição, recente. A âncora dele é a COLETA.
func TestAnoDoArquivoVivoNaoVemDoMtime(t *testing.T) {
	f := raizDeLog(t, map[string]string{
		"var/log/auth.log": linhasDeAuth(2),
	}, func(raiz string, _ *envOpts) {
		antigo := time.Now().Add(-400 * 24 * time.Hour)
		if err := os.Chtimes(filepath.Join(raiz, "var/log/auth.log"), antigo, antigo); err != nil {
			t.Fatal(err)
		}
	})

	if len(f.EventosDeLog) == 0 {
		t.Fatal("o arquivo vivo precisa ser lido")
	}
	limite := utc(time.Now().Add(-366 * 24 * time.Hour))
	for _, ev := range f.EventosDeLog {
		if ev.At < limite {
			t.Errorf("evento datado em %s — o mtime forjado (400 dias atrás) escolheu "+
				"o ano, e um `touch -d` passa a decidir o que cai fora da janela", ev.At)
		}
	}
}

// TETO GLOBAL NÃO PODE APAGAR UMA FAMÍLIA.
//
// Sair do laço sem registrar os alvos restantes fazia a família deles sumir de
// FontesDeLog — e é dali que escopoDaFamilia decide se a pergunta cabe no host.
// Um audit.log que esgotasse o orçamento antes do auth.log tirava os checks de
// auth do DENOMINADOR, com a frase "este host não tem log em TEXTO" sobre um
// arquivo que a coleta apenas não alcançou.
func TestTetoGlobalNaoTransformaFamiliaEmForaDeEscopo(t *testing.T) {
	// audit.log ordena ANTES de auth.log e gasta o orçamento de eventos.
	var b strings.Builder
	for i := 0; i <= maxEventosLog; i++ {
		b.WriteString("type=SYSCALL msg=audit(17365000" + strconv.Itoa(10000+i) +
			".000:" + strconv.Itoa(i) + "): syscall=59 pid=1 uid=0 comm=\"x\"\n")
	}
	f := raizDeLog(t, map[string]string{
		"var/log/audit/audit.log": b.String(),
		"var/log/auth.log":        linhasDeAuth(2),
	}, nil)

	c := f.CoberturaLog("auth")
	if !c.Existe {
		t.Fatal("o auth.log existe no host: dizer que não é a mentira que separa " +
			"escopo de lacuna")
	}
	if c.Lida {
		t.Error("e ele NÃO foi lido: Lida precisa ser falso")
	}
	achou := false
	for _, s := range f.FontesDeLog {
		if s.Path == "/var/log/auth.log" {
			achou = true
			if s.Estado != FonteNaoLida || s.Lacuna == "" {
				t.Errorf("fonte = %+v, quer nao_visitada com lacuna", s)
			}
		}
	}
	if !achou {
		t.Error("o alvo não visitado precisa CONSTAR das fontes")
	}
}

// O TETO DE EVENTOS VALE DURANTE A EXTRAÇÃO, não depois.
//
// Antes, leFonteDeLog montava os eventos do arquivo INTEIRO e o chamador cortava
// em 5000: o dump saía limitado e a alocação que o teto existe para impedir já
// tinha acontecido — sobre um arquivo cujo conteúdo o adversário escolhe.
//
// E parar a extração também interrompe a COBERTURA: continuar lendo carimbos
// depois de deixar de extrair afirmaria que aquele trecho foi observado, quando
// dali em diante evento nenhum seria detectado.
func TestTetoDeEventosParaAExtracaoEACobertura(t *testing.T) {
	var b strings.Builder
	for i := 0; i < maxEventosLog+10; i++ {
		b.WriteString("Aug 24 01:00:00 h sshd[1]: Failed password for root from 1.2.3.4 port 5 ssh2\n")
	}
	// A última linha é datada BEM depois: se a cobertura a alcançar, ela está
	// afirmando observação de um trecho que a extração já tinha abandonado.
	b.WriteString("Aug 24 23:59:00 h sshd[1]: Failed password for root from 1.2.3.4 port 5 ssh2\n")

	f := raizDeLog(t, map[string]string{"var/log/auth.log": b.String()}, nil)

	if n := len(f.EventosDeLog); n > maxEventosLog {
		t.Errorf("%d eventos, teto é %d", n, maxEventosLog)
	}
	s := f.FontesDeLog[0]
	if s.Estado != FonteTruncada || s.Lacuna == "" {
		t.Errorf("o corte precisa ser declarado NO ARQUIVO: %+v", s)
	}
	if strings.HasSuffix(s.CobertoAte, "T23:59:00Z") {
		t.Error("a cobertura passou do ponto em que a extração parou: ela estaria " +
			"afirmando observação onde evento nenhum seria detectado")
	}
	if f.LogEstado != LogParcial {
		t.Errorf("LogEstado = %q, quer partial", f.LogEstado)
	}
}

// O TETO DE EVENTOS VALE PARA O AUDITD TAMBÉM.
//
// A correção anterior morde durante o laço de linhas, e o auditd escapava por
// fora dele: nada fechava no meio do fluxo, e o Fecha() do fim despejava o
// arquivo inteiro de uma vez. Com dez mil seriais distintos, o retrato saía com
// o dobro do teto.
func TestTetoDeEventosValeParaOAuditd(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 2*maxEventosLog; i++ {
		// Sem terminador e no MESMO instante: o pior caso para o montador, que é
		// onde o backstop precisa segurar sem furar o orçamento.
		b.WriteString("type=SYSCALL msg=audit(1736500000.000:" + strconv.Itoa(i) +
			"): syscall=59 pid=1 uid=0 comm=\"x\"\n")
	}
	f := raizDeLog(t, map[string]string{"var/log/audit/audit.log": b.String()}, nil)

	if n := len(f.EventosDeLog); n > maxEventosLog {
		t.Errorf("%d eventos, teto é %d", n, maxEventosLog)
	}
	if f.LogEstado != LogParcial {
		t.Errorf("LogEstado = %q, quer partial", f.LogEstado)
	}
	if f.FontesDeLog[0].Lacuna == "" {
		t.Error("o corte precisa ser declarado no arquivo")
	}
}

// E o host MOVIMENTADO com fluxo normal não ganha lacuna nenhuma: os eventos
// fecham pelo terminador que o kernel emite, o backstop não morde, e a coleta
// sai completa. Antes, todo audit.log com mais de cinco mil eventos ganhava uma
// lacuna que não significava nada — porque o teto era o único mecanismo de
// finalização.
func TestAuditMovimentadoNaoFabricaLacuna(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 300; i++ {
		ep := strconv.Itoa(1736500000 + i)
		b.WriteString("type=SYSCALL msg=audit(" + ep + ".000:" + strconv.Itoa(i) +
			"): syscall=59 pid=1 uid=0 comm=\"x\"\n")
		b.WriteString("type=EOE msg=audit(" + ep + ".000:" + strconv.Itoa(i) + "): \n")
	}
	f := raizDeLog(t, map[string]string{"var/log/audit/audit.log": b.String()}, nil)

	if len(f.Partial["logeventos"]) != 0 {
		t.Errorf("fluxo normal não pode virar lacuna: %v", f.Partial["logeventos"])
	}
	if f.LogEstado != LogColetado {
		t.Errorf("LogEstado = %q, quer collected", f.LogEstado)
	}
	if len(f.EventosDeLog) != 300 {
		t.Errorf("%d eventos, quer 300", len(f.EventosDeLog))
	}
}
