package facts

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lex0c/aletheia/internal/env"
)

// O defeito que FonteDeLogin existe para fechar, travado aqui.
//
// A leitura de wtmp/btmp/utmp é da CAUDA, com teto de maxRegistrosLogin. Depois
// de collectLogins, quem quisesse saber se o teto mordeu só tinha `f.Logins`
// para olhar — e ali a pergunta é INDECIDÍVEL: um arquivo com exatamente 2000
// registros e um com 57.000 lido pelo fim produzem o mesmo número.
//
// A dedução erra nas duas direções, e a cara é sempre de dado bom. A cara é o
// lado caro: a cauda de um arquivo enorme passa por histórico completo, e é
// sobre ela que alguém afirma "nenhuma entrada antes das 14h" num host cuja
// leitura alcançou as 13h50.
func TestTetoDaCaudaDeLoginNaoSeDeduzPelaContagem(t *testing.T) {
	quando := time.Date(2026, 8, 17, 21, 3, 11, 0, time.UTC).Unix()
	tam := tamanhoNativoDeUtmp

	casos := []struct {
		nome     string
		n        int
		truncada bool
		lidos    int
	}{
		// O caso que a contagem não separa do de baixo.
		{nome: "arquivo com exatamente o teto de registros", n: maxRegistrosLogin,
			truncada: false, lidos: maxRegistrosLogin},
		{nome: "arquivo grande lido pela cauda", n: maxRegistrosLogin + 1200,
			truncada: true, lidos: maxRegistrosLogin},
		{nome: "arquivo pequeno lido inteiro", n: 3,
			truncada: false, lidos: 3},
	}

	for _, c := range casos {
		t.Run(c.nome, func(t *testing.T) {
			dir := t.TempDir()
			caminho := filepath.Join(dir, "wtmp")
			b := make([]byte, 0, c.n*tam)
			for i := 0; i < c.n; i++ {
				b = append(b, registro(tam, "deploy", quando)...)
			}
			if err := os.WriteFile(caminho, b, 0o600); err != nil {
				t.Fatal(err)
			}

			f := &Facts{}
			if !lerUtmp(f, &env.Env{}, caminho, PapelHistorico, false, false) {
				t.Fatal("a leitura falhou")
			}
			if len(f.FontesDeLogin) != 1 {
				t.Fatalf("FontesDeLogin = %d, queria 1: toda saída de lerUtmp "+
					"registra a fonte", len(f.FontesDeLogin))
			}
			s := f.FontesDeLogin[0]
			if s.Truncada != c.truncada {
				t.Errorf("Truncada = %v, queria %v — é este bit, e não a "+
					"contagem, que responde se o teto mordeu", s.Truncada, c.truncada)
			}
			if s.Registros != c.n {
				t.Errorf("Registros = %d, queria %d: o total é o que o arquivo "+
					"TEM, e sai do stat antes de a cauda ser recortada",
					s.Registros, c.n)
			}
			if s.Lidos != c.lidos {
				t.Errorf("Lidos = %d, queria %d", s.Lidos, c.lidos)
			}
			if s.Estado != FonteLoginLida || s.Papel != PapelHistorico {
				t.Errorf("estado=%q papel=%q", s.Estado, s.Papel)
			}
			// O layout escolhido viaja junto: ler um wtmp de 400 com passo de
			// 384 não falha, produz registro desalinhado e NENHUMA lacuna. Sem
			// este campo, esse erro é inauditável depois que a VM some.
			if s.TamRegistro != tam {
				t.Errorf("TamRegistro = %d, queria %d", s.TamRegistro, tam)
			}
		})
	}
}

// AUSENTE e ILEGÍVEL são conclusões diferentes, e o booleano de retorno as
// junta: as duas fazem `HistoricoDeLoginLido` valer o mesmo em quem só olha
// para f.Logins. A diferença é a que separa "este host não tem btmp" de "esta
// execução não é root".
func TestFonteDeLoginSeparaAusenteDeIlegivel(t *testing.T) {
	dir := t.TempDir()

	f := &Facts{}
	if !lerUtmp(f, &env.Env{}, filepath.Join(dir, "nao-existe"), PapelRecusadas, true, false) {
		t.Error("arquivo ausente devolveu false: ausência de FONTE não é lacuna")
	}
	if s := f.FontesDeLogin[0]; s.Estado != FonteLoginAusente {
		t.Errorf("estado = %q, queria %q", s.Estado, FonteLoginAusente)
	}

	// Tamanho que não divide nem 384 nem 400: existe, abriu, e não foi
	// decodificado. É estado próprio, não "ausente" e não "lido".
	torto := filepath.Join(dir, "btmp")
	if err := os.WriteFile(torto, make([]byte, 500), 0o600); err != nil {
		t.Fatal(err)
	}
	g := &Facts{}
	if lerUtmp(g, &env.Env{}, torto, PapelRecusadas, true, false) {
		t.Error("tamanho não interpretável devolveu true")
	}
	s := g.FontesDeLogin[0]
	if s.Estado != FonteLoginNaoInterpretada {
		t.Errorf("estado = %q, queria %q", s.Estado, FonteLoginNaoInterpretada)
	}
	if s.Motivo == "" {
		t.Error("fonte não lida sem Motivo: o campo existe para o dump carregar " +
			"a causa junto, e não só a frase solta em PersistDenied")
	}
}

// Registro sem data ENTRA no inventário e é contado à parte.
//
// Sem essa contagem, "wtmp observado desde 10h atrás" afirma um intervalo
// CONTÍNUO sobre uma leitura que pode ter buracos no meio — e é sobre esse
// intervalo que alguém afirma ausência de evento.
func TestRegistroSemDataEhContadoENaoAncoraAJanela(t *testing.T) {
	tam := tamanhoNativoDeUtmp
	quando := time.Date(2026, 8, 17, 21, 3, 11, 0, time.UTC).Unix()

	var b []byte
	b = append(b, registro(tam, "deploy", quando)...)
	b = append(b, registro(tam, "root", 0)...) // sem timestamp
	b = append(b, registro(tam, "app", quando)...)
	// Slot vazio: sem usuário e sem tipo de boot. Ele é descartado, e NÃO conta
	// como evento cuja data se perdeu.
	b = append(b, make([]byte, tam)...)

	dir := t.TempDir()
	caminho := filepath.Join(dir, "wtmp")
	if err := os.WriteFile(caminho, b, 0o600); err != nil {
		t.Fatal(err)
	}

	f := &Facts{}
	if !lerUtmp(f, &env.Env{}, caminho, PapelHistorico, false, false) {
		t.Fatal("a leitura falhou")
	}
	if got := f.FontesDeLogin[0].SemData; got != 1 {
		t.Errorf("SemData = %d, queria 1: só o registro que ENTRA no inventário "+
			"sem data conta; o slot vazio do arquivo não é evento", got)
	}
	if len(f.Logins) != 3 {
		t.Fatalf("Logins = %d, queria 3", len(f.Logins))
	}
}

// A IDENTIDADE DA SÉRIE, provada contra o collectLogs de verdade.
//
// Este teste existe porque a versão anterior do consumidor (activity) montava a
// fixture à mão com `Base: "wtmp"` e comparava contra isso — uma representação
// que este coletor não produz. O código passava no teste e não funcionava em
// produção, que é o pior resultado possível de um teste.
func TestBaseDaSerieEhCaminhoCompleto(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "var", "log")
	if err := os.MkdirAll(log, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"wtmp", "wtmp.1", "wtmp-20260801", "btmp"} {
		if err := os.WriteFile(filepath.Join(log, n), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	f := &Facts{}
	collectLogs(f, env.Probe(env.Options{Root: dir}))

	achou := 0
	for i := range f.Logs {
		a := &f.Logs[i]
		if a.Base == "wtmp" {
			t.Fatalf("Base = %q: se algum dia virar o nome nu, todo consumidor "+
				"que compara com caminho completo passa a casar zero em "+
				"silêncio — que foi o defeito que este teste trava", a.Base)
		}
		if a.Path == "/var/log/wtmp.1" || a.Path == "/var/log/wtmp-20260801" {
			if a.Base != "/var/log/wtmp" {
				t.Errorf("%s: Base = %q, queria /var/log/wtmp", a.Path, a.Base)
			}
			achou++
		}
	}
	if achou != 2 {
		t.Errorf("as duas gerações rotacionadas precisam ser reconhecidas como "+
			"da MESMA série; achei %d", achou)
	}
}

// Registro sem conta POR NATUREZA não pode ser descartado pelo guarda de
// usuário vazio: com ele iam o desligamento (RUN_LVL), a mudança de relógio
// (OLD_TIME/NEW_TIME) e o encerramento de sessão cujo slot já foi zerado — e o
// intervalo entre um desligamento e o boot seguinte é o tempo em que o host
// comprovadamente não observou nada.
func TestRegistroSemContaPorNaturezaSobrevive(t *testing.T) {
	tam := tamanhoNativoDeUtmp
	semUser := func(tipo int) []byte {
		r := make([]byte, tam)
		r[0] = byte(tipo)
		copy(r[8:40], "~")
		copy(r[76:332], "6.12.0-arch1")
		if tam == tamUtmp64 {
			r[344] = 1
		} else {
			r[340] = 1
		}
		return r
	}
	var b []byte
	for _, tipo := range []int{TipoRunLevel, TipoTempoAntigo, TipoTempoNovo, TipoSaida} {
		b = append(b, semUser(tipo)...)
	}
	b = append(b, make([]byte, tam)...) // slot NUNCA usado: este sim é descartado

	dir := t.TempDir()
	caminho := filepath.Join(dir, "wtmp")
	if err := os.WriteFile(caminho, b, 0o600); err != nil {
		t.Fatal(err)
	}

	f := &Facts{}
	if !lerUtmp(f, &env.Env{}, caminho, PapelHistorico, false, false) {
		t.Fatal("a leitura falhou")
	}
	if len(f.Logins) != 4 {
		t.Fatalf("Logins = %d, queria 4: os quatro tipos não têm conta por "+
			"natureza, e exigir usuário deles é exigir um campo que o formato "+
			"não preenche", len(f.Logins))
	}
	for _, l := range f.Logins {
		if l.Tipo == TipoVazio {
			t.Error("o slot nunca usado entrou no inventário")
		}
	}
}
