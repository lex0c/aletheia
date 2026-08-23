package checks

import (
	"testing"

	"github.com/lex0c/aletheia/internal/env"

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

// O `dateext` é o padrão de fábrica da família RHEL, e por isso ele NÃO pode
// derrubar a cobertura.
//
// A distinção é a mesma que checks/nss.go já paga em musl, e o comentário de lá
// diz por que ela reaparece: o instinto certo — "não silencie" — escolhe o canal
// errado. Lacuna é "esta pergunta cabia neste host e eu não consegui
// responder". Aqui a pergunta NÃO CABE: o esquema de nomes é outro, e é assim em
// todo Rocky, Alma, CentOS e Fedora recém-instalado.
//
// Como Partial, isso faria TODA varredura da família RHEL sair INCOMPLETE com
// exit 1, inclusive a de um host limpo — e uma lacuna que nunca fecha deixa de
// ser lida, que é o oposto do que ela existe para fazer.
func TestDateextSaiComoInfoENaoDerrubaACobertura(t *testing.T) {
	f := &facts.Facts{Logs: []facts.ArquivoDeLog{
		{Path: "/var/log/secure", Base: "/var/log/secure", Geracao: 0},
		{Path: "/var/log/secure-20260801", Base: "/var/log/secure", Geracao: 1, Datada: true},
		{Path: "/var/log/secure-20260815", Base: "/var/log/secure", Geracao: 1, Datada: true},
	}}
	f.Index()
	// Com CapRoot: sem ele o engine já anexa um Partial pelo `Optional`, e essa
	// lacuna é do AMBIENTE DE TESTE, não do dateext. Isolar importa — a
	// afirmação aqui é sobre o que o CHECK declara, não sobre rodar sem root.
	e := testEnv()
	e.Caps |= env.CapRoot
	r := check.Run([]check.Check{rotacaoComBuraco}, f, e)

	if len(r.Coverage.Partial) > 0 {
		t.Errorf("dateext virou LACUNA de cobertura: %+v\n"+
			"Isso faz todo host RHEL sair INCOMPLETE com exit 1, inclusive limpo. "+
			"O esquema de nomes não caber é ESCOPO, não lacuna.", r.Coverage.Partial)
	}
	if r.Coverage.Complete != r.Coverage.Total {
		t.Errorf("cobertura %d/%d: o check não saiu completo num host que só tem "+
			"séries datadas", r.Coverage.Complete, r.Coverage.Total)
	}
	var info int
	for _, fd := range r.Findings {
		if fd.Sev == check.SevInfo {
			info++
		}
		if fd.Sev >= check.SevWarn {
			t.Errorf("dateext produziu acusação (%s): derivar buraco de aritmética "+
				"de datas troca o falso limpo por falso positivo", fd.ID)
		}
	}
	if info != 1 {
		t.Errorf("o escopo reduzido não foi DITO (%d achados INFO): silenciar de vez "+
			"é o outro erro — o operador precisa saber que a deleção pega no Debian "+
			"é invisível aqui", info)
	}
}

// E a metade que não pode ser perdida: com CONTADOR, o buraco continua sendo
// achado e continua sendo acusação.
func TestBuracoPorContadorContinuaAcusando(t *testing.T) {
	f := &facts.Facts{Logs: []facts.ArquivoDeLog{
		{Path: "/var/log/auth.log", Base: "/var/log/auth.log", Geracao: 0},
		{Path: "/var/log/auth.log.1", Base: "/var/log/auth.log", Geracao: 1},
		{Path: "/var/log/auth.log.3.gz", Base: "/var/log/auth.log", Geracao: 3},
	}}
	f.Index()
	e := testEnv()
	e.Caps |= env.CapRoot
	r := check.Run([]check.Check{rotacaoComBuraco}, f, e)
	var acusou bool
	for _, fd := range r.Findings {
		if fd.Sev >= check.SevWarn {
			acusou = true
		}
	}
	if !acusou {
		t.Errorf("o buraco por contador deixou de ser acusado: %+v", r.Findings)
	}
}
