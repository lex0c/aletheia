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

// LISTA COM NEGAÇÃO: vence a ÚLTIMA entrada que casa, e não a primeira.
//
// A primeira versão desta resolução devolvia no primeiro casamento, e por isso
// lia o `ALL` de `ALL,!web01` e imprimia CRITICAL em web01 — sobre a regra
// escrita justamente para não valer ali. O sudo percorre a lista ao contrário e
// para no primeiro casamento, que dá no mesmo.
func TestSudoNegacaoNaListaDeHosts(t *testing.T) {
	casos := []struct {
		host  string
		regra string
		sev   check.Severity
		porqu string
	}{
		{"web01", "ops ALL,!web01=(root) NOPASSWD: ALL", check.SevInfo,
			"a exclusão vem depois do ALL e é ela que decide"},
		{"web02", "ops ALL,!web01=(root) NOPASSWD: ALL", check.SevCritical,
			"a exclusão não alcança este host, e o ALL vale"},
		{"web01", "ops !web01,ALL=(root) NOPASSWD: ALL", check.SevCritical,
			"aqui o ALL é a última que casa — a ordem inverte a resposta, e é assim " +
				"que o sudo resolve"},
		{"web01", "ops SERVIDORES,!web01=(root) NOPASSWD: ALL", check.SevInfo,
			"a exclusão é posterior ao alias e decide sozinha, casando ou não o alias"},
		{"web01", "ops !web01,SERVIDORES=(root) NOPASSWD: ALL", check.SevCritical,
			"o alias é POSTERIOR e pode casar: o desconhecido apaga a exclusão em " +
				"vez de herdá-la, porque supor que não casa seria inventar absolvição"},
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

// AS QUATRO FORMAS DO RUNAS_SPEC, e duas delas eu li ao contrário.
//
// O sudoers(5) separa uma a uma, e a diferença entre elas é a diferença entre
// "root inteiro sem senha" e "o próprio usuário com um grupo a mais".
func TestSudoQuatroFormasDoRunas(t *testing.T) {
	casos := []struct {
		runas      string
		root, invo bool
		porqu      string
	}{
		{"(root)", true, false, "usuário explícito"},
		{"(ALL)", true, false, "ALL na lista de usuários alcança root"},
		{"(#0)", true, false, "root por uid numérico"},
		{"(ALL:ALL)", true, false, "usuário e grupo, os dois ALL"},
		{"(postgres)", false, false, "outra conta não é root"},
		{"(postgres:postgres)", false, false, "conta e grupo nomeados"},
		{"(:www-data)", false, true, "lista de usuários VAZIA: roda como o invocador"},
		{"(:adm)", false, true, "idem"},
		{"()", false, true, "as duas vazias: só o próprio invocador"},
	}
	for _, c := range casos {
		reg := parseRegraSudo("ana ALL=" + c.runas + " NOPASSWD: /bin/ls")
		if len(reg.Specs) != 1 {
			t.Errorf("%s: %+v", c.runas, reg.Specs)
			continue
		}
		sp := reg.Specs[0]
		if sp.ComoRoot != c.root {
			t.Errorf("%s: ComoRoot=%v, queria %v — %s", c.runas, sp.ComoRoot, c.root, c.porqu)
		}
		if sp.RunasInvocador != c.invo {
			t.Errorf("%s: RunasInvocador=%v, queria %v — %s",
				c.runas, sp.RunasInvocador, c.invo, c.porqu)
		}
	}
	// E a ausência continua sendo root — é o padrão do sudo.
	reg := parseRegraSudo("ana ALL=NOPASSWD: /bin/ls")
	if !reg.Specs[0].ComoRoot || reg.Specs[0].RunasDeclarado {
		t.Errorf("sem Runas_Spec o padrão é root: %+v", reg.Specs[0])
	}
}

// O `runas_default` é do ARQUIVO: trocá-lo muda o que a AUSÊNCIA de `(runas)`
// significa, e afirmar root ali vira um crítico sobre uma regra que não concede
// root nenhum.
func TestSudoRunasDefaultTrocado(t *testing.T) {
	f := regraNoHost("web01",
		"Defaults runas_default=postgres",
		"ops ALL=NOPASSWD: ALL",
	)
	r := sudoSemSenha.Run(sudoSemSenha, f, testEnv())
	if len(r.Findings) != 1 {
		t.Fatalf("%+v", r.Findings)
	}
	if r.Findings[0].Sev != check.SevWarn {
		t.Errorf("a ausência de runas não é root neste arquivo: %v", r.Findings[0].Sev)
	}
	if ev := strings.Join(r.Findings[0].Evidence, " "); !strings.Contains(ev, "runas_default") {
		t.Errorf("e a evidência precisa dizer POR QUE deixou de ser root:\n%s", ev)
	}

	// ESCOPADO não muda a leitura: o escopo não é resolvido, e supor que ele
	// alcança esta regra inventaria uma absolvição.
	f = regraNoHost("web01",
		"Defaults:ana runas_default=postgres",
		"ops ALL=NOPASSWD: ALL",
	)
	r = sudoSemSenha.Run(sudoSemSenha, f, testEnv())
	if r.Findings[0].Sev != check.SevCritical {
		t.Errorf("Defaults escopado a OUTRO usuário não absolve esta regra: %v",
			r.Findings[0].Sev)
	}
	if ev := strings.Join(r.Findings[0].Evidence, " "); !strings.Contains(ev, "ESCOPADO") {
		t.Errorf("mas a ressalva precisa aparecer:\n%s", ev)
	}
}

// O `\\` escapa o metacaractere, e o sudoers(5) diz isso. A regra que escapou de
// propósito — a de quem sabia do problema — não pode sair com a severidade de
// quem não escapou.
func TestSudoCuringaEscapadoNaoReabre(t *testing.T) {
	comEscape := parseRegraSudo(`ops ALL=(root) NOPASSWD: /usr/bin/find /var/log -name \*.gz -delete`)
	if comEscape.Specs[0].Cmd.Curinga {
		t.Error("`\\*` é asterisco literal, não curinga")
	}
	semEscape := parseRegraSudo(`ops ALL=(root) NOPASSWD: /usr/bin/find /var/log -name *.gz -delete`)
	if !semEscape.Specs[0].Cmd.Curinga {
		t.Error("e sem a barra ele continua sendo curinga")
	}
}
