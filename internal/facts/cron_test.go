package facts

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/lex0c/aletheia/internal/env"
)

// O /etc/crontab que o pacote `cron` instala no Debian separa o usuário do
// comando com TAB, e o parser cortava só em espaço. O resultado era o usuário
// virar "root\tcd" e o comando virar "/ && run-parts …", cujo primeiro token é
// `/`. O diretório raiz entrava na pergunta de propriedade e todo servidor
// Debian de fábrica com cron instalado saía com aviso e exit code 1.
//
// Nenhum contêiner da matriz tem cron instalado, e por isso isto passou.
func TestCrontabDeSistemaSeparaUsuarioPorTab(t *testing.T) {
	f := imagem(t, map[string]string{
		"etc/crontab": "SHELL=/bin/sh\n" +
			"17 *\t* * *\troot\tcd / && run-parts --report /etc/cron.hourly\n" +
			"30 3\t* * *\tdeploy\t/opt/app/backup.sh --full\n" +
			// e com ESPAÇO, que é igualmente válido e não pode regredir
			"0 4 * * * root /usr/bin/limpeza\n",
	})

	quer := []struct{ user, cmd string }{
		{"root", "cd / && run-parts --report /etc/cron.hourly"},
		{"deploy", "/opt/app/backup.sh --full"},
		{"root", "/usr/bin/limpeza"},
	}
	var i int
	for j := range f.Cron {
		c := &f.Cron[j]
		if c.Schedule == "(atribuição)" {
			continue
		}
		if i >= len(quer) {
			t.Fatalf("entrada a mais: user=%q cmd=%q", c.User, c.Cmd)
		}
		if c.User != quer[i].user {
			t.Errorf("entrada %d: user=%q, queria %q", i, c.User, quer[i].user)
		}
		if c.Cmd != quer[i].cmd {
			t.Errorf("entrada %d: cmd=%q, queria %q", i, c.Cmd, quer[i].cmd)
		}
		i++
	}
	if i != len(quer) {
		t.Errorf("li %d entradas de agendamento, esperava %d", i, len(quer))
	}
}

// Crontab de USUÁRIO não tem campo de usuário, e o comando começa logo depois
// do horário. Cortar um token ali comeria o binário.
func TestCrontabDeUsuarioNaoTemCampoDeUsuario(t *testing.T) {
	f := imagem(t, map[string]string{
		"var/spool/cron/crontabs/deploy": "*/5 * * * *\t/opt/app/beacon\n",
	})
	var achou bool
	for i := range f.Cron {
		if f.Cron[i].Cmd == "/opt/app/beacon" {
			achou = true
		}
	}
	if !achou {
		t.Errorf("o comando do crontab de usuário não sobreviveu: %+v", f.Cron)
	}
}

// Diretório nunca é binário, e linha de agendamento ou de unit cita caminho o
// tempo todo sem que ele seja executável: `cd /srv/app`, `--report
// /etc/cron.hourly`, unit quebrada apontando para uma pasta. A pergunta "quem
// empacotou este diretório" não tem resposta útil, e a resposta que ela dava —
// nenhum pacote reivindica `/` — virava aviso num host de fábrica.
//
// A asserção é sobre os CANDIDATOS, e não sobre f.Ownership: a coleta de
// propriedade sai cedo quando não há base de pacote, e um rootfs de mentira não
// tem uma. Afirmar sobre o resultado final faria o teste passar sem medir nada.
func TestPropriedadeIgnoraDiretorio(t *testing.T) {
	raiz := t.TempDir()
	if err := os.MkdirAll(filepath.Join(raiz, "srv/app"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(raiz, "srv/app/run.sh"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	e := env.Probe(env.Options{Root: raiz})
	t.Cleanup(func() { e.Close() })

	f := &Facts{Units: []Unit{{
		Name: "quebrada.service",
		Exec: []ExecLine{
			{Key: "ExecStart", Cmd: "/srv/app"},           // diretório: fora
			{Key: "ExecStartPre", Cmd: "/srv/app/run.sh"}, // arquivo: dentro
		},
	}}}
	cs := candidatosDePropriedade(f, e)

	if _, tem := cs["/srv/app"]; tem {
		t.Error("diretório entrou na pergunta de propriedade")
	}
	if _, tem := cs["/srv/app/run.sh"]; !tem {
		t.Errorf("o arquivo de verdade tinha que entrar: %v", cs)
	}
}

// Os hooks de interpretador são o LD_PRELOAD de quem não é ELF, e a lacuna veio
// de um corpus EXTERNO: a ferramenta tratava LD_PRELOAD como quebra de
// confiança e nunca fez a mesma pergunta a python, node, perl ou bash.
func TestHooksDeInterpretador(t *testing.T) {
	f := imagem(t, map[string]string{
		"etc/environment": "PATH=/usr/bin\n" +
			"BASH_ENV=/opt/.cache/x.sh\n" +
			"NAO_E_HOOK=/tmp/qualquer\n",
		"etc/security/pam_env.conf":        "PYTHONSTARTUP DEFAULT=/tmp/.p.py\n",
		"etc/systemd/system/app.service":   "[Service]\nEnvironment=\"NODE_OPTIONS=--require /opt/app/t.js\"\n",
		"etc/systemd/system/limpa.service": "[Service]\nEnvironment=LANG=pt_BR.UTF-8\n",
	})

	achado := map[string]string{}
	for _, h := range f.HooksInterp {
		achado[h.Key] = h.Fonte
	}
	for _, k := range []string{"BASH_ENV", "PYTHONSTARTUP", "NODE_OPTIONS"} {
		if achado[k] == "" {
			t.Errorf("%s não foi coletada: %+v", k, f.HooksInterp)
		}
	}
	if _, tem := achado["NAO_E_HOOK"]; tem {
		t.Error("variável que não executa código não pode entrar na lista")
	}
	if _, tem := achado["LANG"]; tem {
		t.Error("Environment=LANG numa unit não é hook de interpretador")
	}

	// GLOBAL é a diferença de peso: /etc/environment vale para toda sessão do
	// host; Environment= de unit vale para um serviço.
	for _, h := range f.HooksInterp {
		global := h.Fonte == "/etc/environment" || h.Fonte == "/etc/security/pam_env.conf"
		if h.Global != global {
			t.Errorf("%s em %s: Global=%v, queria %v", h.Key, h.Fonte, h.Global, global)
		}
	}
}

// O ALVO precisa chegar à pergunta de propriedade — é ela que separa "deploy
// com biblioteca própria" de implante, e é a única coisa que separa.
func TestAlvoDoHookEntraNaPerguntaDePropriedade(t *testing.T) {
	raiz := t.TempDir()
	for _, d := range []string{"opt/app", "etc"} {
		if err := os.MkdirAll(filepath.Join(raiz, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(raiz, "opt/app/t.js"), []byte("//\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(raiz, "etc/environment"),
		[]byte("NODE_OPTIONS=--require /opt/app/t.js\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	e := env.Probe(env.Options{Root: raiz})
	t.Cleanup(func() { e.Close() })

	f := &Facts{HooksInterp: []HookInterp{
		{Fonte: "/etc/environment", Key: "NODE_OPTIONS", Value: "--require /opt/app/t.js"},
	}}
	cs := candidatosDePropriedade(f, e)
	if _, tem := cs["/opt/app/t.js"]; !tem {
		t.Errorf("o alvo do hook não virou candidato a propriedade: %v", cs)
	}
}

func TestCaminhosDoValor(t *testing.T) {
	casos := []struct {
		v    string
		quer []string
	}{
		{"--require /opt/app/t.js", []string{"/opt/app/t.js"}},
		{"/a:/b:/c", []string{"/a", "/b", "/c"}},              // PYTHONPATH
		{"-javaagent:/opt/apm.jar", []string{"/opt/apm.jar"}}, // JAVA_TOOL_OPTIONS
		{"-Mevil", nil},                    // PERL5OPT sem caminho
		{"--max-old-space-size=4096", nil}, // o falso positivo comum
		{"", nil},
	}
	for _, c := range casos {
		got := CaminhosDoValor(c.v)
		if len(got) != len(c.quer) {
			t.Errorf("CaminhosDoValor(%q) = %v, queria %v", c.v, got, c.quer)
			continue
		}
		for i := range got {
			if got[i] != c.quer[i] {
				t.Errorf("CaminhosDoValor(%q)[%d] = %q, queria %q", c.v, i, got[i], c.quer[i])
			}
		}
	}
}
