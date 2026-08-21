package facts

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/lex0c/aletheia/internal/env"
)

// A SEÇÃO decide se a diretiva existe, e ignorá-la era um bypass de três linhas.
//
// O parser pulava o cabeçalho e aplicava qualquer diretiva reconhecida viesse
// ela de onde viesse. Como `ExecStart=` vazio RESETA a lista, bastava
// acrescentar uma seção que o systemd ignora para o Exec sumir dos olhos desta
// ferramenta enquanto o systemd continuava executando o implante — silêncio com
// cobertura completa, que é a única classe de erro que esta base não pode
// cometer.
//
// Medido contra o binário antes do conserto: a unit de controle saía CRITICAL e
// a com `[X-Aletheia]\nExecStart=` saía nada.
func TestUnitSecaoDecideSeADiretivaVale(t *testing.T) {
	casos := []struct {
		nome      string
		conteudo  string
		querExecs int
		querCmd   string
	}{
		{
			nome:      "controle: só [Service], o Exec fica",
			conteudo:  "[Service]\nExecStart=/tmp/.implant\n",
			querExecs: 1, querCmd: "/tmp/.implant",
		},
		{
			// Seções X- são ignoradas POR CONTRATO pelo systemd — é o lugar
			// documentado para metadado de terceiros.
			nome:      "reset em [X-Qualquer] não tem efeito",
			conteudo:  "[Service]\nExecStart=/tmp/.implant\n\n[X-Qualquer]\nExecStart=\n",
			querExecs: 1, querCmd: "/tmp/.implant",
		},
		{
			// Não precisa nem de X-: [Install] não aceita ExecStart.
			nome:      "reset em [Install] não tem efeito",
			conteudo:  "[Service]\nExecStart=/tmp/.implant\n\n[Install]\nExecStart=\n",
			querExecs: 1, querCmd: "/tmp/.implant",
		},
		{
			nome:      "reset em [Unit] não tem efeito",
			conteudo:  "[Service]\nExecStart=/tmp/.implant\n\n[Unit]\nExecStart=\n",
			querExecs: 1, querCmd: "/tmp/.implant",
		},
		{
			// E o outro lado: plantar Exec numa seção que o systemd ignora não
			// pode virar achado, senão o conserto trocaria FN por FP.
			nome:      "Exec plantado em [X-] não vira achado",
			conteudo:  "[Unit]\nDescription=x\n\n[X-Qualquer]\nExecStart=/tmp/.implant\n",
			querExecs: 0,
		},
		{
			// Sem cabeçalho nenhum o systemd recusa o arquivo; honrar a linha
			// seria aceitar o que o alvo não aceita.
			nome:      "diretiva antes de qualquer seção não vale",
			conteudo:  "ExecStart=/tmp/.implant\n",
			querExecs: 0,
		},
		{
			// O reset LEGÍTIMO continua funcionando: é assim que um drop-in
			// substitui o comando da unit original.
			nome:      "reset dentro de [Service] continua resetando",
			conteudo:  "[Service]\nExecStart=/tmp/.implant\nExecStart=\n",
			querExecs: 0,
		},
		// A SEGUNDA METADE do bypass, e ela sobreviveu ao primeiro conserto.
		//
		// Olhar a seção isolada fechava X-, Unit e Install — e deixava abertas
		// as seções de OUTROS TIPOS, que também carregam contexto de execução.
		// O atacante só trocou `[X-Aletheia]` por `[Socket]`. Numa .service,
		// `[Socket]` é tão ignorado pelo systemd quanto `[X-Foo]`: opção
		// específica de um tipo vive na seção DAQUELE tipo.
		{
			nome:      "reset em [Socket] dentro de .service não tem efeito",
			conteudo:  "[Service]\nExecStart=/tmp/.implant\n\n[Socket]\nExecStart=\n",
			querExecs: 1, querCmd: "/tmp/.implant",
		},
		{
			nome:      "reset em [Mount] dentro de .service não tem efeito",
			conteudo:  "[Service]\nExecStart=/tmp/.implant\n\n[Mount]\nExecStart=\n",
			querExecs: 1, querCmd: "/tmp/.implant",
		},
		{
			nome:      "reset em [Timer] dentro de .service não tem efeito",
			conteudo:  "[Service]\nExecStart=/tmp/.implant\n\n[Timer]\nExecStart=\n",
			querExecs: 1, querCmd: "/tmp/.implant",
		},
	}
	for _, c := range casos {
		raiz := t.TempDir()
		if err := os.WriteFile(filepath.Join(raiz, "svc.service"), []byte(c.conteudo), 0o644); err != nil {
			t.Fatal(err)
		}
		e := env.Probe(env.Options{Root: raiz, Version: "test"})
		u := parseUnitFile(&Facts{}, e, "/svc.service", "system", "service", false)
		e.Close()

		if len(u.Exec) != c.querExecs {
			t.Errorf("[%s] %d Exec, queria %d: %+v", c.nome, len(u.Exec), c.querExecs, u.Exec)
			continue
		}
		if c.querCmd != "" && u.Exec[0].Cmd != c.querCmd {
			t.Errorf("[%s] Cmd=%q, queria %q", c.nome, u.Exec[0].Cmd, c.querCmd)
		}
	}
}

// O mesmo corte vale para o resto do contexto de execução: Environment= numa
// seção ignorada não pode entrar no modelo, senão um LD_PRELOAD plantado em
// [X-] viraria achado que o systemd nunca aplicaria — FP —, e um
// `Environment=` de reset ali viraria a via de sumir com um preload real.
func TestUnitEnvironmentRespeitaSecao(t *testing.T) {
	raiz := t.TempDir()
	os.WriteFile(filepath.Join(raiz, "svc.service"), []byte(
		"[Service]\nExecStart=/bin/true\n\n[X-Qualquer]\nEnvironment=LD_PRELOAD=/tmp/.so\n"), 0o644)
	e := env.Probe(env.Options{Root: raiz, Version: "test"})
	t.Cleanup(func() { e.Close() })

	u := parseUnitFile(&Facts{}, e, "/svc.service", "system", kindOf("/svc.service"), false)
	if len(u.Environment) != 0 {
		t.Errorf("Environment de seção ignorada entrou no modelo: %+v", u.Environment)
	}
}

// E as seções que NÃO são de execução continuam contribuindo com o que é delas
// — o conserto não pode cegar o timer nem o path.
func TestUnitSecoesProprias(t *testing.T) {
	raiz := t.TempDir()
	os.WriteFile(filepath.Join(raiz, "t.timer"), []byte(
		"[Timer]\nOnCalendar=*:0/5\n\n[Install]\nWantedBy=timers.target\n"), 0o644)
	os.WriteFile(filepath.Join(raiz, "p.path"), []byte(
		"[Path]\nPathChanged=/etc/cron.d\n"), 0o644)
	e := env.Probe(env.Options{Root: raiz, Version: "test"})
	t.Cleanup(func() { e.Close() })

	if u := parseUnitFile(&Facts{}, e, "/t.timer", "system", kindOf("/t.timer"), false); len(u.OnCalendar) != 1 ||
		len(u.WantedBy) != 1 {
		t.Errorf("timer perdeu agenda ou habilitação: %+v", u)
	}
	if u := parseUnitFile(&Facts{}, e, "/p.path", "system", kindOf("/p.path"), false); len(u.WatchPaths) != 1 {
		t.Errorf("path perdeu o alvo observado: %+v", u)
	}
}

// E o outro lado do corte por tipo: a seção do PRÓPRIO tipo continua valendo
// inteira. Sem esta metade o conserto cegaria .socket, .mount e .swap, que têm
// contexto de execução legítimo — trocar um FN por outro.
func TestUnitSecaoDoProprioTipoContinuaValendo(t *testing.T) {
	casos := []struct{ arquivo, tipo, conteudo string }{
		{"/x.socket", "socket", "[Socket]\nListenStream=1234\nExecStartPre=/tmp/.i\n"},
	}
	for _, c := range casos {
		raiz := t.TempDir()
		if err := os.WriteFile(filepath.Join(raiz, filepath.Base(c.arquivo)), []byte(c.conteudo), 0o644); err != nil {
			t.Fatal(err)
		}
		e := env.Probe(env.Options{Root: raiz, Version: "test"})
		u := parseUnitFile(&Facts{}, e, c.arquivo, "system", c.tipo, false)
		e.Close()
		if len(u.Exec) != 1 {
			t.Errorf("[%s] a seção do próprio tipo tem de valer: %+v", c.arquivo, u.Exec)
		}
	}
	// E a .socket ganha o Listen, que só existe nela.
	raiz := t.TempDir()
	os.WriteFile(filepath.Join(raiz, "x.socket"), []byte("[Socket]\nListenStream=1234\n"), 0o644)
	e := env.Probe(env.Options{Root: raiz, Version: "test"})
	defer e.Close()
	if u := parseUnitFile(&Facts{}, e, "/x.socket", "system", "socket", false); len(u.Listen) != 1 {
		t.Errorf("Listen* na .socket: %+v", u.Listen)
	}
}

// Drop-in herda o tipo do DIRETÓRIO (`foo.service.d/`), não do nome do .conf.
// Sem isso todo drop-in cairia no caminho de tipo desconhecido, e o bypass
// voltaria pela porta mais usada de todas.
func TestUnitDropinHerdaTipoDoDiretorio(t *testing.T) {
	raiz := t.TempDir()
	dir := filepath.Join(raiz, "etc/systemd/system/agent.service.d")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "10-x.conf"), []byte(
		"[Service]\nExecStart=/tmp/.implant\n\n[Socket]\nExecStart=\n"), 0o644)
	e := env.Probe(env.Options{Root: raiz, Version: "test"})
	defer e.Close()

	u := parseUnitFile(&Facts{}, e, "/etc/systemd/system/agent.service.d/10-x.conf",
		"system", kindOf("agent.service"), false)
	if len(u.Exec) != 1 || u.Exec[0].Cmd != "/tmp/.implant" {
		t.Errorf("drop-in de .service não pode aceitar reset em [Socket]: %+v", u.Exec)
	}
}

// .mount e .swap NÃO têm comandos de execução, e o teste anterior travava o
// contrário.
//
// Eles compartilham o ExecContext — Environment, RootDirectory, BindPaths,
// ExecSearchPath —, mas quem monta é o systemd, não um ExecStart. Medido contra
// o systemd-analyze: `ExecStartPre` numa .mount sai como "Unknown key
// 'ExecStartPre' in section [Mount], ignoring". Aceitá-lo fazia a ferramenta
// afirmar execução de um caminho que o alvo descarta.
//
// O caso anterior exigia o oposto: eu escrevi um teste que cimentava um falso
// positivo, ao generalizar "os quatro tipos têm contexto de execução" para "os
// quatro aceitam Exec*".
func TestMountSwapNaoTemComandoDeExec(t *testing.T) {
	for _, c := range []struct{ arquivo, tipo, secao string }{
		{"/x.mount", "mount", "Mount"},
		{"/x.swap", "swap", "Swap"},
	} {
		raiz := t.TempDir()
		os.WriteFile(filepath.Join(raiz, filepath.Base(c.arquivo)),
			[]byte("["+c.secao+"]\nExecStartPre=/tmp/.i\nExecSearchPath=/tmp/bin\n"), 0o644)
		e := env.Probe(env.Options{Root: raiz, Version: "test"})
		u := parseUnitFile(&Facts{}, e, c.arquivo, "system", c.tipo, false)
		e.Close()

		if len(u.Exec) != 0 {
			t.Errorf("[%s] comando de exec não existe neste tipo: %+v", c.tipo, u.Exec)
		}
		// Mas o CONTEXTO continua valendo, e ExecSearchPath é contexto apesar do
		// prefixo — cortar por HasPrefix("Exec") cegaria a resolução de nome nu.
		if len(u.ExecSearchPath) != 1 {
			t.Errorf("[%s] ExecSearchPath é ExecContext e tem de valer: %+v",
				c.tipo, u.ExecSearchPath)
		}
	}
}
