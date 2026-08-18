package checks

import (
	"testing"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/facts"
)

func rodaWtmp(t *testing.T, f *facts.Facts) *check.Report {
	t.Helper()
	f.Index()
	return check.Run([]check.Check{sessaoSemRegistro}, f, testEnv())
}

// A forma do achado: sessão aberta agora, histórico vazio, sem wtmp
// rotacionado ao lado. Isto TEM que continuar disparando — é o cruzamento que
// pega o rastro apagado.
func TestSessaoAbertaComHistoricoZeradoAcusa(t *testing.T) {
	f := &facts.Facts{
		HistoricoDeLoginLido: true,
		Logins: []facts.Login{
			{Tipo: facts.TipoLoginUsuario, User: "deploy", Agora: true},
		},
	}
	r := rodaWtmp(t, f)
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevCritical {
		t.Fatalf("o achado é o cruzamento que data a invasão: %+v", r.Findings)
	}
}

// E o defeito: o CIS Benchmark manda pôr 0640 no /var/log/wtmp, e essa
// recomendação é seguida. Sem root, a leitura falha, o histórico sai vazio —
// que é a forma EXATA do achado — e a ferramenta acusava de anti-forense o
// administrador que endureceu a própria máquina. Num CRITICAL irreversível.
func TestWtmpIlegivelNaoFabricaAntiforense(t *testing.T) {
	f := &facts.Facts{
		HistoricoDeLoginLido: false,
		Logins: []facts.Login{
			{Tipo: facts.TipoLoginUsuario, User: "deploy", Agora: true},
		},
		PersistDenied: map[string][]string{
			"login": {"/var/log/wtmp não pôde ser lido: o HISTÓRICO de login não foi examinado"},
		},
	}
	r := rodaWtmp(t, f)
	if len(r.Findings) != 0 {
		t.Errorf("permissão negada virou evidência de rastro apagado: %+v", r.Findings)
	}
	if len(r.Coverage.Partial) == 0 {
		t.Error("e o silêncio precisa aparecer como LACUNA: calar sem declarar " +
			"trocaria um falso positivo por um falso negativo")
	}
}

// Rotação legítima: wtmp vivo vazio com wtmp.1 ao lado é o logrotate fazendo o
// trabalho dele.
func TestWtmpRotacionadoNaoViraAchado(t *testing.T) {
	f := &facts.Facts{
		HistoricoDeLoginLido: true,
		Logins: []facts.Login{
			{Tipo: facts.TipoLoginUsuario, User: "deploy", Agora: true},
		},
		Logs: []facts.ArquivoDeLog{{Base: "wtmp", Geracao: 1}},
	}
	if r := rodaWtmp(t, f); len(r.Findings) != 0 {
		t.Errorf("o logrotate produz esta forma legitimamente: %+v", r.Findings)
	}
}
