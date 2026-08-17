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
