package report

import (
	"strings"
	"testing"
	"time"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/facts"
)

// fontesLidas é o estado normal: as três testemunhas abertas.
func fontesLidas(nLogins int) []facts.FonteDeLogin {
	return []facts.FonteDeLogin{
		{Path: "/var/log/wtmp", Papel: facts.PapelHistorico, Estado: facts.FonteLoginLida,
			Lidos: nLogins, Registros: nLogins},
		{Path: "/var/log/btmp", Papel: facts.PapelRecusadas, Estado: facts.FonteLoginLida},
		{Path: "/run/utmp", Papel: facts.PapelSessoes, Estado: facts.FonteLoginLida},
	}
}

func quando(h int) string {
	return wtfEnv().Now.Add(-time.Duration(h) * time.Hour).Format("2006-01-02T15:04:05Z")
}

func blocoDeAtividade(out string) []string {
	var linhas []string
	dentro := false
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "atividade ") {
			dentro = true
		}
		if !dentro {
			continue
		}
		if strings.TrimSpace(l) == "" {
			break
		}
		linhas = append(linhas, l)
	}
	return linhas
}

func relatorioVazio() *check.Report {
	return &check.Report{Coverage: check.Coverage{Total: 10, Complete: 10}}
}

// O teto de quatro linhas é a promessa de UMA TELA. O bloco divide a tela com
// os achados, e é o achado que decide.
func TestBlocoDeAtividadeCabeEmQuatroLinhas(t *testing.T) {
	f := &facts.Facts{
		FontesDeLogin: fontesLidas(3),
		Logins: []facts.Login{
			{Tipo: facts.TipoLoginUsuario, User: "deploy", Origem: "10.0.0.9", QuandoU: quando(2)},
			{Tipo: facts.TipoLoginUsuario, User: "root", Origem: "10.0.0.8", QuandoU: quando(3)},
			{Tipo: facts.TipoLoginUsuario, User: "deploy", Origem: "10.0.0.9", QuandoU: quando(1), Agora: true},
		},
	}
	linhas := blocoDeAtividade(renderWtf(relatorioVazio(), f))
	if n := len(linhas); n == 0 || n > 4 {
		t.Errorf("o bloco saiu com %d linhas, e o teto é 4:\n%s",
			n, strings.Join(linhas, "\n"))
	}
}

// A distinção entre a janela PEDIDA e a OBSERVADA é a razão de o bloco existir.
// Sem os dois rótulos ditos, os números de baixo são lidos como se cobrissem a
// janela inteira — e num host movimentado o btmp alcança uma tarde.
func TestCabecalhoDizSolicitadoEObservado(t *testing.T) {
	f := &facts.Facts{FontesDeLogin: fontesLidas(0)}
	out := renderWtf(relatorioVazio(), f)
	for _, quer := range []string{"solicitado 24h", "observado:"} {
		if !strings.Contains(out, quer) {
			t.Errorf("falta %q no cabeçalho do bloco:\n%s", quer, out)
		}
	}
}

// O defeito que mais importa não cometer: btmp fechado virando "0 recusas".
//
// Sem root o btmp é ilegível em toda distribuição, então este é o caminho
// PADRÃO de uma varredura sem privilégio — e "nenhuma tentativa recusada" é a
// leitura tranquilizadora sobre um arquivo que ninguém abriu.
func TestBtmpFechadoNuncaImprimeZeroRecusas(t *testing.T) {
	f := &facts.Facts{FontesDeLogin: fontesLidas(0)}
	f.FontesDeLogin[1] = facts.FonteDeLogin{
		Path: "/var/log/btmp", Papel: facts.PapelRecusadas,
		Estado: facts.FonteLoginIlegivel, Motivo: "permission denied",
	}
	out := renderWtf(relatorioVazio(), f)
	if !strings.Contains(out, "NÃO EXAMINADAS") {
		t.Errorf("btmp fechado precisa sair como NÃO EXAMINADAS:\n%s", out)
	}
	if strings.Contains(out, "recusadas  nenhuma") || strings.Contains(out, "recusadas  0") {
		t.Errorf("btmp fechado saiu como ausência de tentativa:\n%s", out)
	}
	if !strings.Contains(out, "permission denied") {
		t.Errorf("o MOTIVO precisa viajar junto — é ele que diz o que fazer "+
			"(rodar com sudo):\n%s", out)
	}
}

// Arquivo que não existe é ESCOPO, e escopo não é lacuna: um contêiner sem btmp
// não tem tentativa recusada a esconder. As duas frases mandam o operador para
// lugares diferentes.
func TestBtmpAusenteNaoEhOMesmoQueIlegivel(t *testing.T) {
	f := &facts.Facts{FontesDeLogin: fontesLidas(0)}
	f.FontesDeLogin[1] = facts.FonteDeLogin{
		Path: "/var/log/btmp", Papel: facts.PapelRecusadas, Estado: facts.FonteLoginAusente,
	}
	out := renderWtf(relatorioVazio(), f)
	if !strings.Contains(out, "não há btmp neste host") {
		t.Errorf("ausência de fonte é escopo declarado:\n%s", out)
	}
	if strings.Contains(out, "NÃO EXAMINADAS") {
		t.Errorf("arquivo ausente não é lacuna de leitura:\n%s", out)
	}
}

// "nova" afirma que o host nunca viu aquela origem. O que se sabe é só que ela
// não está nos registros que sobraram, e a diferença entre as duas frases é
// toda a diferença entre evidência e alarme.
func TestNuncaDizOrigemNova(t *testing.T) {
	f := &facts.Facts{
		FontesDeLogin: fontesLidas(2),
		Logins: []facts.Login{
			{Tipo: facts.TipoLoginUsuario, User: "deploy", Origem: "10.0.0.9", QuandoU: quando(300)},
			{Tipo: facts.TipoLoginUsuario, User: "deploy", Origem: "185.44.1.7", QuandoU: quando(2)},
		},
	}
	out := renderWtf(relatorioVazio(), f)
	if strings.Contains(out, " nova") || strings.Contains(out, " novas") {
		t.Errorf("a saída afirmou que uma origem é NOVA:\n%s", out)
	}
	if !strings.Contains(out, "não observadas anteriormente") {
		t.Errorf("a origem sem passado precisa aparecer, com a redação que diz "+
			"o que de fato se sabe:\n%s", out)
	}
}

// O campo de origem do utmp traz `:0` para sessão de X. Escrever `lex@:0` faz o
// display local parecer um endereço remoto, bem na linha que o operador
// percorre procurando o que não reconhece.
func TestSessaoLocalNaoGanhaArroba(t *testing.T) {
	f := &facts.Facts{
		FontesDeLogin: fontesLidas(1),
		Logins: []facts.Login{
			{Tipo: facts.TipoLoginUsuario, User: "lex", Origem: ":0", Linha: "tty7",
				QuandoU: quando(1), Agora: true},
		},
	}
	out := renderWtf(relatorioVazio(), f)
	if strings.Contains(out, "lex@:0") {
		t.Errorf("o display do X saiu como origem de rede:\n%s", out)
	}
	if !strings.Contains(out, "lex tty7") {
		t.Errorf("a sessão local precisa aparecer, pela tty:\n%s", out)
	}
}

// O ut_user tem 32 bytes escolhidos pelo alvo, e a origem 256. Um ESC ali
// reescreve a tela da ferramenta que está caçando quem o escreveu.
func TestNomeDeUsuarioAdversarialNaoEscapaDoTerminal(t *testing.T) {
	f := &facts.Facts{
		FontesDeLogin: fontesLidas(1),
		Logins: []facts.Login{
			{Tipo: facts.TipoLoginUsuario, User: "ok\x1b[2J\x1b[HRESULT: OK",
				Origem: "10.0.0.9", QuandoU: quando(1), Agora: true},
		},
	}
	out := renderWtf(relatorioVazio(), f)
	if strings.Contains(out, "\x1b[2J") {
		t.Errorf("sequência de terminal atravessou para a saída:\n%q", out)
	}
	if !strings.Contains(out, `\x1b`) {
		t.Errorf("o escape precisa aparecer VISÍVEL: o operador tem de ver que o "+
			"alvo tentou isso:\n%s", out)
	}
}

// Coleta que não rodou (o retrato volátil do `watch`) não pode imprimir zeros.
func TestSemColetaDeLoginOBlocoNaoSai(t *testing.T) {
	out := renderWtf(relatorioVazio(), &facts.Facts{})
	if strings.Contains(out, "atividade ·") {
		t.Errorf("o bloco saiu sobre uma coleta que não aconteceu:\n%s", out)
	}
}

// O MESMO defeito do btmp, pela porta do wtmp — e ele não é hipotético: o CIS
// Benchmark manda pôr 0640 no /var/log/wtmp, e onde essa recomendação foi
// seguida uma varredura sem root lê zero registro. "0 aceitas" ali afirmaria
// que ninguém entrou num host que ninguém conseguiu ler.
func TestWtmpFechadoNuncaImprimeZeroEntradas(t *testing.T) {
	f := &facts.Facts{FontesDeLogin: fontesLidas(0)}
	f.FontesDeLogin[0] = facts.FonteDeLogin{
		Path: "/var/log/wtmp", Papel: facts.PapelHistorico,
		Estado: facts.FonteLoginIlegivel, Motivo: "permission denied",
	}
	out := renderWtf(relatorioVazio(), f)
	if !strings.Contains(out, "NÃO EXAMINADAS — wtmp") {
		t.Errorf("wtmp fechado precisa sair como NÃO EXAMINADAS:\n%s", out)
	}
	if strings.Contains(out, "0 aceitas") {
		t.Errorf("wtmp fechado saiu como ausência de entrada:\n%s", out)
	}
}
