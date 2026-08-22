package drift

import (
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/facts"
)

// OBSERVABILIDADE POR CAMPO E POR FONTE: os oito casos, um teste cada.
//
// Todos têm a mesma forma, e é a que sobreviveu às catracas anteriores: uma
// fonte falha e a comparação de OUTRA — perfeitamente lida — some junto. A
// diferença desta rodada é que a fonte já não é a família: ela é o campo de uma
// entidade, ou o subconjunto de entidades que veio de uma varredura.

func semTipo(t *testing.T, d facts.Drift, tipo, oque string) {
	t.Helper()
	for _, m := range d.Mudancas {
		if m.Tipo == tipo {
			t.Errorf("%s: %s (%s %s %s)", tipo, oque, m.Kind, m.ID, m.Campo)
		}
	}
}

func exigeMudanca(t *testing.T, d facts.Drift, tipo, campo, oque string) {
	t.Helper()
	for _, m := range d.Mudancas {
		if m.Tipo == tipo && m.Campo == campo {
			return
		}
	}
	t.Fatalf("%s/%s: %s\nmudanças: %+v", tipo, campo, oque, d.Mudancas)
}

func comparar(antes, depois *facts.Facts) facts.Drift {
	return Comparar(lado(antes, tudoVisivel),
		Lado{F: depois, Caps: tudoVisivel, Host: "h", Quando: "2026-01-02T00:00:00Z"})
}

// UNIT1: um authorized_keys ilegível NÃO pode calar um ExecStart alterado.
//
// A chave `persist` é escrita por dezenove coletores — o denyPersist a alimenta
// SEMPRE —, e a família de unit dependia dela. Bastava um arquivo de chave de
// outro usuário sem permissão para o `ExecStart=/tmp/.agent` sumir.
func TestUNIT1LacunaDeSSHNaoCalaExecStart(t *testing.T) {
	comExec := func(cmd string) *facts.Facts {
		return &facts.Facts{Units: []facts.Unit{unit("agent.service", cmd)}}
	}
	antes := comExec("/usr/bin/agent")
	depois := comExec("/tmp/.agent")
	// a lacuna é de OUTRO coletor, e cai na chave larga
	depois.PersistDenied = map[string][]string{"ssh": {"authorized_keys ilegível"}}
	depois.Partial = map[string][]string{"persist": {"authorized_keys ilegível"}}

	exigeMudanca(t, comparar(antes, depois), "systemd.unit", "exec",
		"o ExecStart mudou e a comparação calou por causa de uma lacuna de SSH")
}

// UNIT2: um EnvironmentFile= ilegível cega o `environment` DAQUELA unit, e não
// o `exec` dela nem as outras units.
func TestUNIT2EnvFileIlegivelCegaSoOCampoEnvironment(t *testing.T) {
	comEnv := func(cmd, val string, ilegivel bool) *facts.Facts {
		u := unit("agent.service", cmd)
		u.Environment = []facts.EnvSetting{{File: "/etc/agent.env", Key: "X", Value: val}}
		if ilegivel {
			u.EnvFilesIlegiveis = []string{"/etc/agent.env"}
		}
		return &facts.Facts{Units: []facts.Unit{u, unit("outra.service", "/usr/bin/outra")}}
	}
	antes := comEnv("/usr/bin/agent", "a", false)
	depois := comEnv("/tmp/.agent", "b", true)

	d := comparar(antes, depois)
	exigeMudanca(t, d, "systemd.unit", "exec",
		"o EnvironmentFile ilegível não podia cegar o ExecStart, que veio do arquivo da unit")
	for _, m := range d.Mudancas {
		if m.Tipo == "systemd.unit" && m.Campo == "environment" {
			t.Errorf("o `environment` foi afirmado com um EnvironmentFile= ilegível: %+v", m)
		}
	}
}

// TRIG1: uma árvore de git ilegível não pode fazer o /etc/profile sumir, nem
// fazer o hook dela sair como REMOVIDO.
func TestTRIG1LacunaDeGitNaoAlcancaOsOutrosGatilhos(t *testing.T) {
	trig := func(file, kind, linha string) facts.Trigger {
		return facts.Trigger{File: file, Kind: kind,
			Lines: []facts.TriggerLine{{N: 1, Text: linha}}}
	}
	antes := &facts.Facts{Triggers: []facts.Trigger{
		trig("/etc/profile", "profile", "export PATH=/usr/bin"),
		trig("/srv/app/.git/hooks/post-merge", "git_hook", "#!/bin/sh"),
	}}
	// o repositório ficou ilegível: o hook não foi visto, o /etc/profile sim
	depois := &facts.Facts{Triggers: []facts.Trigger{
		trig("/etc/profile", "profile", "export PATH=/usr/bin\n. /tmp/.p"),
	}}
	depois.PersistDenied = map[string][]string{"githook": {"a árvore do repo não pôde ser varrida"}}
	depois.Partial = map[string][]string{"persist": {"idem"}}

	d := comparar(antes, depois)
	exigeMudanca(t, d, "startup.trigger", "linhas",
		"o /etc/profile mudou e a comparação calou por causa de uma lacuna de git hook")
	for _, m := range d.Mudancas {
		if m.Tipo == "startup.trigger" && m.Kind == Sumiu {
			t.Errorf("o hook de git saiu como REMOVIDO, e a varredura dele é que "+
				"declarou lacuna: %+v", m)
		}
	}
}

// MAC1: o securityfs ilegível não pode calar a mudança PERSISTENTE no arquivo.
//
// `configurado` vale no próximo boot e é o que sobrevive ao reboot; `ativo` é
// runtime. Duas fontes, uma entidade — e enquanto a lacuna era da família, o
// segundo apagava o primeiro.
func TestMAC1SecurityFSIlegivelNaoCalaOArquivo(t *testing.T) {
	antes := &facts.Facts{MAC: facts.MAC{
		Configurado: "enforcing", Ativo: "1", ConfigLido: true, RuntimeLido: true}}
	depois := &facts.Facts{MAC: facts.MAC{
		Configurado: "permissive", ConfigLido: true, RuntimeLido: false}}
	depois.Partial = map[string][]string{"mac": {"/sys/fs/selinux/enforce ilegível"}}

	d := comparar(antes, depois)
	exigeMudanca(t, d, "mac", "configurado",
		"o SELinux saiu de enforcing no ARQUIVO e a mudança sumiu porque o securityfs não abriu")
	for _, m := range d.Mudancas {
		if m.Tipo == "mac" && m.Campo == "ativo" {
			t.Errorf("o `ativo` foi afirmado sem ter sido lido de um dos lados: %+v", m)
		}
	}
}

// NSS1: o ld.so.conf ilegível cega o `libs`, e não o `servicos`.
//
// Localizar a lib usa os diretórios de busca do loader; a lista de databases
// que a fonte atende vem só do nsswitch.conf. Uma fonte NSS passando a
// responder TAMBÉM pelo `shadow` é a mudança que interessa, e ela não tem nada
// com o loader.
func TestNSS1LacunaDoLoaderCegaSoAsLibs(t *testing.T) {
	nss := func(paths, servicos []string, loaderOK bool) *facts.Facts {
		return &facts.Facts{
			NSSLido: true, LoaderPathCompleto: loaderOK,
			NSSModules: []facts.NSSModule{{Fonte: "impl", Paths: paths, Servicos: servicos}},
		}
	}
	antes := nss([]string{"/opt/.lib/libnss_impl.so.2"}, []string{"passwd"}, true)
	depois := nss(nil, []string{"passwd", "shadow"}, false)

	d := comparar(antes, depois)
	exigeMudanca(t, d, "nss", "servicos",
		"a fonte NSS passou a responder pelo shadow e a mudança sumiu porque o loader não abriu")
	for _, m := range d.Mudancas {
		if m.Tipo == "nss" && m.Campo == "libs" {
			t.Errorf("`libs` foi afirmado com a cadeia do loader incompleta: %+v", m)
		}
	}
}

// PROT1: o /proc/sys/kernel/tainted ilegível não pode calar o ptrace_scope.
func TestPROT1LacunaDeTaintNaoCalaOEndurecimento(t *testing.T) {
	prot := func(scope string) *facts.Facts {
		return &facts.Facts{Protecao: facts.ProtecaoKernel{
			PtraceScope: scope, KptrRestrict: "2", Lockdown: "none"}}
	}
	antes := prot("1")
	depois := prot("0")
	depois.Partial = map[string][]string{"taint": {"/proc/sys/kernel/tainted ilegível"}}

	exigeMudanca(t, comparar(antes, depois), "kernel.protecao", "ptrace_scope",
		"a trava que impede um processo de ler a memória de outro foi desligada, "+
			"e a mudança sumiu por causa de um arquivo sem relação")
}

// UNITENV1: um EnvironmentFile= ilegível de UMA unit não pode pôr em dúvida o
// /etc/environment nem as outras units.
func TestUNITENV1IncertezaEhPorUnit(t *testing.T) {
	u1 := unit("a.service", "/usr/bin/a")
	u1.EnvFilesIlegiveis = []string{"/etc/a.env"}
	u2 := unit("b.service", "/usr/bin/b")
	base := func(comA bool) *facts.Facts {
		f := &facts.Facts{
			Units:             []facts.Unit{u1, u2},
			LoaderEnvCompleto: true, LoaderPathCompleto: true,
		}
		f.Loader.EnvVars = []facts.EnvSetting{
			{File: "/etc/environment", Key: "LD_PRELOAD", Value: "/tmp/.g.so"}}
		f.Loader.EnvDeUnit = []facts.EnvDeUnit{
			{Unit: "b.service", Key: "LD_PRELOAD", Value: "/tmp/.b.so"}}
		if comA {
			f.Loader.EnvDeUnit = append(f.Loader.EnvDeUnit, facts.EnvDeUnit{
				Unit: "a.service", Key: "LD_PRELOAD", Value: "/tmp/.a.so", Incerto: true})
		}
		return f
	}
	antes := base(true)
	depois := base(false)
	// e o global muda, no mesmo retrato
	depois.Loader.EnvVars[0].Value = "/tmp/.novo.so"

	d := comparar(antes, depois)
	exigeMudanca(t, d, "loader.env", "valor",
		"o LD_PRELOAD do /etc/environment mudou e a comparação calou por causa "+
			"do EnvironmentFile de uma unit")
	for _, m := range d.Mudancas {
		if m.Tipo == "unit.env" && strings.HasPrefix(m.ID, "a.service") {
			t.Errorf("a unit com EnvironmentFile= ILEGÍVEL produziu afirmação: %+v", m)
		}
	}
}

// A CATRACA DO MECANISMO NOVO: chave de NaoObservado que não existe em Campos
// não faz nada, e não faz nada em SILÊNCIO.
//
// `NaoObservado["ativo"]` escrito como `NaoObservado["active"]` compila, roda,
// e a comparação segue afirmando o campo que ninguém leu — a mesma classe de
// falha que a catraca de extração pegou no `binds`. Aqui a conferência é a
// mesma: o mapa de cegueira só pode nomear campo que o extrator emite.
func TestNaoObservadoSoNomeiaCampoQueExiste(t *testing.T) {
	f := fixtureDeTodasAsFamilias()
	for _, c := range classes {
		for _, e := range c.Extrair(f) {
			for campo := range e.NaoObservado {
				if _, ok := e.Campos[campo]; !ok {
					t.Errorf("%s: a entidade %s marca `%s` como não observado, e o "+
						"extrator não emite esse campo — a cegueira não alcança "+
						"nada e ninguém percebe", c.Tipo, e.ID, campo)
				}
			}
		}
	}
}

// E o irmão: entidade com Fonte só faz sentido em família que sabe responder
// quais fontes ficaram incertas.
func TestFonteDeEntidadeTemQuemResponda(t *testing.T) {
	f := fixtureDeTodasAsFamilias()
	for _, c := range classes {
		for _, e := range c.Extrair(f) {
			if e.Fonte != "" && c.FontesIncertas == nil {
				t.Errorf("%s: a entidade %s declara a fonte `%s` e a classe não tem "+
					"FontesIncertas — a fonte não é consultada por ninguém, e a "+
					"supressão por fonte nunca acontece", c.Tipo, e.ID, e.Fonte)
			}
		}
	}
}
