package progress

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// A regra que protege o stdout: um bytes.Buffer NÃO é terminal, então tudo cala.
// É o mesmo caminho de um pipe ou de `2>arquivo` — automação e JSONL intactos.
func TestSemTerminalNaoEscreveNada(t *testing.T) {
	var buf bytes.Buffer
	r := New(&buf, time.Now(), false, false)
	r.Stage("varredura de filesystem")
	r.Stop()
	if buf.Len() != 0 {
		t.Errorf("sem terminal, nada pode sair — veio %q", buf.String())
	}
}

// E o disabled (--no-progress) cala mesmo que fosse terminal: a flag ganha da
// detecção.
func TestDisabledCala(t *testing.T) {
	var buf bytes.Buffer
	r := New(&buf, time.Now(), true, false)
	if r.tty {
		t.Fatal("disabled tem de desligar o tty")
	}
	r.Stage("x")
	r.Stop()
	if buf.Len() != 0 {
		t.Errorf("--no-progress não pode escrever: %q", buf.String())
	}
}

// Com terminal, o desenho traz o rótulo, o tempo e o retorno de carro que
// reescreve a linha; e o Stop apaga com o clear-to-EOL. Constrói o reporter à
// mão com tty=true porque um bytes.Buffer nunca seria detectado como terminal.
func TestDesenhoTrazRotuloTempoEApaga(t *testing.T) {
	var buf bytes.Buffer
	r := &Reporter{w: &buf, tty: true, start: time.Now().Add(-3 * time.Second), done: make(chan struct{})}
	r.Stage("processos")
	saida := buf.String()
	if !strings.Contains(saida, "\r") {
		t.Error("sem \\r a linha não se reescreve — vira scroll")
	}
	if !strings.Contains(saida, "processos") {
		t.Error("o estágio precisa aparecer: é ele que diz ONDE travou")
	}
	if !strings.Contains(saida, "s\x1b[K") && !strings.Contains(saida, "s") {
		t.Error("o tempo decorrido precisa aparecer")
	}
	buf.Reset()
	r.Stop()
	if !strings.Contains(buf.String(), "\x1b[K") {
		t.Error("Stop tem de APAGAR a linha, senão o relatório nasce sobre ela")
	}
}

// Stop duas vezes — o explícito antes do relatório e o defer de segurança — não
// pode entrar em pânico fechando o canal duas vezes.
func TestStopIdempotente(t *testing.T) {
	var buf bytes.Buffer
	r := &Reporter{w: &buf, tty: true, start: time.Now(), done: make(chan struct{})}
	r.Stop()
	r.Stop() // não pode dar panic
}

// A segunda linha mostra o DETALHE (o caminho sendo lido), truncado pela cauda
// (o nome do arquivo importa mais que a raiz), e some no Stop.
func TestSegundaLinhaMostraODetalhe(t *testing.T) {
	var buf bytes.Buffer
	r := &Reporter{w: &buf, tty: true, largura: 80, start: time.Now(), done: make(chan struct{})}
	r.Detalhe("/var/www/site/app/controller/Administrador.class.php")
	r.draw()
	saida := buf.String()
	if !strings.Contains(saida, "Administrador.class.php") {
		t.Errorf("a cauda do caminho precisa aparecer na 2ª linha: %q", saida)
	}
	// duas linhas: tem a quebra e o sobe-cursor no redesenho.
	buf.Reset()
	r.draw() // segundo desenho: sobe para a 1ª linha
	if !strings.Contains(buf.String(), "\x1b[A") {
		t.Error("o redesenho precisa subir o cursor para reescrever as duas linhas")
	}
	// Stop apaga as DUAS linhas.
	buf.Reset()
	r.Stop()
	if strings.Count(buf.String(), "\x1b[K") < 2 {
		t.Errorf("Stop tem de apagar as duas linhas: %q", buf.String())
	}
}

// Caminho longo é truncado pela cauda para não passar da largura e quebrar (o
// que faria o \033[A subir para o lugar errado).
func TestCaminhoLongoTruncaPelaCauda(t *testing.T) {
	got := encurtarCauda("/muito/longo/"+strings.Repeat("x", 200)+"/fim.php", 30)
	if len([]rune(got)) > 30 {
		t.Errorf("passou da largura: %d runas", len([]rune(got)))
	}
	if !strings.HasSuffix(got, "fim.php") {
		t.Errorf("a cauda (o arquivo) tem de sobreviver: %q", got)
	}
	if !strings.HasPrefix(got, "…") {
		t.Errorf("truncou sem marcar: %q", got)
	}
}

// O caminho sai na cor SECUNDÁRIA (cinza, o mesmo "fraco" do relatório), e o
// reset vem ANTES do clear-to-EOL — senão o apagar-até-o-fim carregaria o
// atributo e pintaria o resto da linha.
func TestDetalheSaiEmCorSecundaria(t *testing.T) {
	var buf bytes.Buffer
	r := &Reporter{w: &buf, tty: true, cor: true, largura: 80, start: time.Now(), done: make(chan struct{})}
	r.Detalhe("/var/www/site/app/Administrador.class.php")
	r.draw()
	saida := buf.String()
	if !strings.Contains(saida, "\x1b[90mAdministrador.class.php") &&
		!strings.Contains(saida, "\x1b[90m/var/www") {
		t.Errorf("o caminho tem de abrir em cinza: %q", saida)
	}
	if !strings.Contains(saida, "\x1b[0m\x1b[K") {
		t.Errorf("o reset tem de vir antes do \\033[K: %q", saida)
	}
	// A legenda continua na cor normal: é o sinal PRIMÁRIO.
	if strings.Contains(saida, "\x1b[90mcoletando") {
		t.Errorf("o rótulo do estágio não pode recuar para cinza: %q", saida)
	}
}

// Sem cor (NO_COLOR, TERM=dumb, saída redirecionada), nenhum escape de COR sai —
// só os de posicionamento, que são o que faz a linha se reescrever.
func TestSemCorNenhumEscapeDeCorNoDetalhe(t *testing.T) {
	var buf bytes.Buffer
	r := &Reporter{w: &buf, tty: true, cor: false, largura: 80, start: time.Now(), done: make(chan struct{})}
	r.Detalhe("/etc/cron.d/backdoor")
	r.draw()
	if strings.Contains(buf.String(), "\x1b[90m") || strings.Contains(buf.String(), "\x1b[0m") {
		t.Errorf("sem cor, nenhum SGR pode sair: %q", buf.String())
	}
}

// A cor não conta coluna: pintar não pode fazer a linha passar da largura, senão
// ela quebra e o \033[A sobe para o lugar errado. Mede o VISÍVEL dos dois modos.
func TestCorNaoAlteraOTruncamento(t *testing.T) {
	longo := "/muito/longo/" + strings.Repeat("x", 300) + "/fim.php"
	medir := func(cor bool) string {
		var buf bytes.Buffer
		r := &Reporter{w: &buf, tty: true, cor: cor, largura: 60, start: time.Now(), done: make(chan struct{})}
		r.Detalhe(longo)
		r.draw()
		s := buf.String()
		s = strings.ReplaceAll(s, "\x1b[90m", "")
		s = strings.ReplaceAll(s, "\x1b[0m", "")
		return s
	}
	if com, sem := medir(true), medir(false); com != sem {
		t.Errorf("tirando o SGR, o desenho tem de ser idêntico:\ncom: %q\nsem: %q", com, sem)
	}
}

// Estágio sem varredura de diretório (host, rede, finalizando) tem a 2ª linha
// VAZIA — e vazio não pode virar um par de escapes invisíveis.
func TestDetalheVazioNaoEmiteCor(t *testing.T) {
	var buf bytes.Buffer
	r := &Reporter{w: &buf, tty: true, cor: true, largura: 80, start: time.Now(), done: make(chan struct{})}
	r.Stage("rede") // Stage limpa o detalhe
	if strings.Contains(buf.String(), "\x1b[90m") {
		t.Errorf("detalhe vazio não pode abrir cor: %q", buf.String())
	}
}

// Cor pedida NÃO liga o desenho: sem terminal continua tudo mudo. É a regra que
// mantém o JSONL e o `2>log` intactos, e ela ganha da cor.
func TestCorNaoLigaODesenhoSemTerminal(t *testing.T) {
	var buf bytes.Buffer
	r := New(&buf, time.Now(), false, true)
	if r.cor {
		t.Error("sem tty, cor tem de ficar desligada")
	}
	r.Detalhe("/etc/passwd")
	r.Stage("processos")
	r.Stop()
	if buf.Len() != 0 {
		t.Errorf("sem terminal, nada sai nem com cor: %q", buf.String())
	}
}
