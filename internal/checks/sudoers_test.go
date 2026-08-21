package checks

import (
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/facts"
)

func regraNoHost(host string, textos ...string) *facts.Facts {
	f := &facts.Facts{Host: facts.Host{Hostname: host}}
	for i, t := range textos {
		f.Sudoers = append(f.Sudoers, facts.SudoRule{
			File: "/etc/sudoers.d/frota", Line: i + 1, Text: t,
		})
	}
	return f
}

// O HOST_LIST É PARTE DA REGRA, e não lê-lo custava um CRÍTICO falso por host
// da frota.
//
// Sudoers distribuído por configuração central é o desenho normal: o mesmo
// arquivo vai para todas as máquinas e cada uma usa a parte dela. Sem resolver
// o Host_List, `ops db01=(root) NOPASSWD: ALL` saía "root inteiro, sem
// responder nada" em web01, api02 e em todo o resto.
func TestSudoHostListDecideSeARegraValeAqui(t *testing.T) {
	casos := []struct {
		host  string
		regra string
		sev   check.Severity
		porqu string
	}{
		{"web01", "ops ALL=(root) NOPASSWD: ALL", check.SevCritical,
			"ALL casa qualquer host"},
		{"web01", "ops web01=(root) NOPASSWD: ALL", check.SevCritical,
			"o host nomeado é este"},
		{"web01.interno.example", "ops web01=(root) NOPASSWD: ALL", check.SevCritical,
			"o sudoers traz o nome curto e o host é o FQDN: casa"},
		{"web01", "ops web01.interno.example=(root) NOPASSWD: ALL", check.SevCritical,
			"e o contrário também"},
		{"web01", "ops db01=(root) NOPASSWD: ALL", check.SevInfo,
			"a regra é de OUTRO host: sai como informação, não como crítico"},
		{"web01", "ops db01,web01=(root) NOPASSWD: ALL", check.SevCritical,
			"lista com este host dentro"},
		// O que NÃO dá para decidir continua valendo aqui: alias, netgroup e
		// endereço não viram absolvição.
		{"web01", "ops SERVIDORES=(root) NOPASSWD: ALL", check.SevCritical,
			"Host_Alias não resolvido não absolve"},
		{"web01", "ops +producao=(root) NOPASSWD: ALL", check.SevCritical,
			"netgroup não resolvido não absolve"},
		{"web01", "ops 10.0.0.0/8=(root) NOPASSWD: ALL", check.SevCritical,
			"endereço de rede não resolvido não absolve"},
		{"", "ops db01=(root) NOPASSWD: ALL", check.SevCritical,
			"sem hostname não há o que comparar, e o desconhecido mantém a severidade"},
	}
	for _, c := range casos {
		r := sudoSemSenha.Run(sudoSemSenha, regraNoHost(c.host, c.regra), testEnv())
		if len(r.Findings) != 1 {
			t.Errorf("%s @ %q: achados = %d", c.regra, c.host, len(r.Findings))
			continue
		}
		if got := r.Findings[0].Sev; got != c.sev {
			t.Errorf("%s @ %q\n  severidade=%v, queria %v — %s",
				c.regra, c.host, got, c.sev, c.porqu)
		}
	}
}

// A regra indeterminada mantém a severidade E DIZ que manteve. Sem a frase, o
// operador não tem como saber que há um alias no caminho.
func TestSudoHostIndeterminadoSaiDito(t *testing.T) {
	r := sudoSemSenha.Run(sudoSemSenha,
		regraNoHost("web01", "ops SERVIDORES=(root) NOPASSWD: ALL"), testEnv())
	ev := strings.Join(r.Findings[0].Evidence, " ")
	if !strings.Contains(ev, "NÃO foi resolvido") {
		t.Errorf("a evidência precisa dizer que o Host_List não foi resolvido:\n%s", ev)
	}
}

// As regras de outro host não SOMEM: viram um achado informativo com a
// contagem. Some é o que a ferramenta não pode fazer com um fato que ela leu.
func TestSudoRegrasDeOutroHostViramUmInfo(t *testing.T) {
	f := regraNoHost("web01",
		"ops db01=(root) NOPASSWD: ALL",
		"ops db02=(root) NOPASSWD: /bin/bash",
		"ops web01=(root) NOPASSWD: /usr/bin/find",
	)
	r := sudoSemSenha.Run(sudoSemSenha, f, testEnv())
	var crit, info int
	for _, fd := range r.Findings {
		switch fd.Sev {
		case check.SevCritical:
			crit++
		case check.SevInfo:
			info++
		}
	}
	if crit != 1 {
		t.Errorf("só a regra deste host é crítica: %d críticos", crit)
	}
	if info != 1 {
		t.Fatalf("as duas de fora viram UM info, não dois achados: %d", info)
	}
	for _, fd := range r.Findings {
		if fd.Sev != check.SevInfo {
			continue
		}
		ev := strings.Join(fd.Evidence, " ")
		for _, quer := range []string{"2 regra(s)", "db01", "db02"} {
			if !strings.Contains(ev, quer) {
				t.Errorf("o info precisa citar %q para o fato não sumir:\n%s", quer, ev)
			}
		}
	}
}

// Uma linha pode ter mais de uma seção `Host_List = Cmnd_Spec_List`, separadas
// por `:`. É gramática do sudoers, e o `:` não pode ser confundido com o
// dois-pontos de uma tag.
func TestSudoSeccaoPorHostNaMesmaLinha(t *testing.T) {
	const l = "ops web01 = /bin/systemctl restart api : db01 = ALL"
	reg := parseRegraSudo(l)
	if len(reg.Specs) != 2 {
		t.Fatalf("duas seções, duas specs: %+v", reg.Specs)
	}
	if got := reg.Specs[0].Hosts; len(got) != 1 || got[0] != "web01" {
		t.Errorf("a primeira seção é de web01: %v", got)
	}
	if got := reg.Specs[1].Hosts; len(got) != 1 || got[0] != "db01" {
		t.Errorf("a segunda seção é de db01: %v", got)
	}
	if !reg.Specs[1].Tudo {
		t.Error("a segunda seção concede ALL")
	}
}

// O `:` que é ARGUMENTO não pode cortar a regra ao meio: se cortasse, o resto
// dela herdaria um Host_List inventado — que é o caminho para suprimir um
// achado por engano.
func TestSudoDoisPontosDeArgumentoNaoAbreSeccao(t *testing.T) {
	reg := parseRegraSudo("ops ALL=(root) NOPASSWD: /bin/chown ana : ana /srv")
	if len(reg.Specs) != 1 {
		t.Fatalf("uma seção só: %+v", reg.Specs)
	}
	if got := reg.Specs[0].Hosts; len(got) != 1 || got[0] != "ALL" {
		t.Errorf("o Host_List continua sendo o da linha: %v", got)
	}
}

// O runas é ESTADO e vale para os comandos seguintes da mesma lista — e o
// primeiro comando da lista pode não ter runas nenhum.
func TestSudoRunasEHerdadoPelosComandosSeguintes(t *testing.T) {
	reg := parseRegraSudo("ops ALL=(postgres) NOPASSWD: /bin/ls, /usr/bin/find")
	if len(reg.Specs) != 2 {
		t.Fatalf("%+v", reg.Specs)
	}
	for i, sp := range reg.Specs {
		if sp.ComoRoot {
			t.Errorf("spec %d: o runas (postgres) vale para os dois", i)
		}
	}
}

// A regra que só NEGA não concede: `!` tira do conjunto.
func TestSudoNegacaoNaoConcede(t *testing.T) {
	reg := parseRegraSudo("ops ALL=(root) NOPASSWD: !/bin/bash")
	if len(reg.Specs) != 1 || !reg.Specs[0].Negado {
		t.Fatalf("%+v", reg.Specs)
	}
	r := sudoSemSenha.Run(sudoSemSenha,
		regraNoHost("web01", "ops ALL=(root) NOPASSWD: !/bin/bash"), testEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevWarn {
		t.Fatalf("%+v", r.Findings)
	}
	// E o achado precisa DIZER que não extraiu comando concedido — silêncio
	// disfarçado de leitura é o defeito que a ferramenta inteira evita.
	if !strings.Contains(strings.Join(r.Findings[0].Evidence, " "), "NÃO extraiu") {
		t.Error("a falha de leitura precisa sair dita")
	}
}

// Definição de alias tem `=` e NÃO é concessão a usuário: lê-la como User_Spec
// inventaria um usuário chamado Cmnd_Alias.
func TestSudoDefinicaoDeAliasNaoEhUserSpec(t *testing.T) {
	for _, l := range []string{
		"Cmnd_Alias PGCTL = /usr/bin/pg_ctl",
		"User_Alias ADMINS = ana, bob",
		"Host_Alias SERVIDORES = web01, db01",
		"Defaults:jenkins !authenticate",
	} {
		if reg := parseRegraSudo(l); reg.Ok {
			t.Errorf("%q não é User_Spec: %+v", l, reg)
		}
	}
}

// O NOME do sujeito não pode virar sintaxe: `defaultsdeploy` é um usuário, e a
// leitura por `HasPrefix` cru o lia como diretiva `Defaults` — a regra dele
// deixava de ser avaliada e o crítico virava aviso.
func TestSudoNomeDeUsuarioNaoViraDiretiva(t *testing.T) {
	reg := parseRegraSudo("defaultsdeploy ALL=(root) NOPASSWD: ALL")
	if !reg.Ok || len(reg.Specs) != 1 || !reg.Specs[0].Tudo {
		t.Fatalf("é User_Spec de um usuário chamado defaultsdeploy: %+v", reg)
	}
	r := sudoSemSenha.Run(sudoSemSenha,
		regraNoHost("web01", "defaultsdeploy ALL=(root) NOPASSWD: ALL"), testEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevCritical {
		t.Fatalf("%+v", r.Findings)
	}
	// E o contrário continua valendo.
	if !ehLinhaNaoSpec("Defaults:jenkins !authenticate") {
		t.Error("`Defaults:` continua sendo diretiva")
	}
}

// Definição de alias cujo NOME contém NOPASSWD não é achado: ela não concede
// nada, e acusá-la seria acusar a nomenclatura de alguém.
func TestSudoAliasComNomeNopasswdNaoEhAchado(t *testing.T) {
	f := regraNoHost("web01", "Cmnd_Alias NOPASSWD_OPS = /usr/bin/systemctl status app")
	if r := sudoSemSenha.Run(sudoSemSenha, f, testEnv()); len(r.Findings) != 0 {
		t.Fatalf("%+v", r.Findings)
	}
}
