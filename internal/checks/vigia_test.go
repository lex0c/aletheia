package checks

import (
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/facts"
)

func rodaVigia(t *testing.T, f *facts.Facts) *check.Report {
	t.Helper()
	f.Index()
	return check.Run([]check.Check{vigiaDeArquivo}, f, testEnv())
}

// A frase que o check existe para explicar: "removi o backdoor e ele voltou".
// Quem recria o arquivo apagado precisa saber que ele sumiu — e o jeito de
// saber é vigiar o diretório, que sobrevive ao `rm`.
func TestVigiaSemDonoSobrePersistenciaAcusa(t *testing.T) {
	f := &facts.Facts{
		Processes: []facts.Process{{PID: 900, Exe: "/usr/local/sbin/.sync", Comm: "sync"}},
		Ownership: []facts.Ownership{{Path: "/usr/local/sbin/.sync", Owned: false}},
		Vigias: []facts.Vigia{{
			PID: 900, Comm: "sync", Exe: "/usr/local/sbin/.sync", Tipo: "inotify",
			Watches: 2, SemNome: 1,
			Alvos: []facts.AlvoVigiado{
				{Caminho: "/etc/cron.d", Persistencia: true},
				{Caminho: "/var/cache/app", Persistencia: false},
			},
		}},
	}
	r := rodaVigia(t, f)
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevCritical {
		t.Fatalf("achados = %+v", r.Findings)
	}
	if !temEvidencia(r, "/etc/cron.d") {
		t.Errorf("o caminho de persistência precisa aparecer: %v", evidencias(r))
	}
	// O alvo que NÃO é persistência não entra na contagem que justifica o achado.
	if temEvidencia(r, "/var/cache/app") {
		t.Errorf("cache não é persistência: %v", evidencias(r))
	}
	// E o que não pôde ser nomeado é DITO, não descartado.
	if !temEvidencia(r, "NÃO puderam ser nomeados") {
		t.Errorf("o alvo sem nome precisa ser declarado: %v", evidencias(r))
	}
	// A ordem da §19 é o passo que evita o "voltou".
	var ordem bool
	for _, s := range r.Findings[0].NextSteps {
		if strings.Contains(s, "ANTES de apagar") {
			ordem = true
		}
	}
	if !ordem {
		t.Errorf("o primeiro passo é a ORDEM: %v", r.Findings[0].NextSteps)
	}
}

// Metade nenhuma sozinha basta. systemd vigia /etc por desenho, e acusá-lo
// encheria o relatório em todo host do mundo.
func TestVigiaComDonoDePacoteNaoAcusa(t *testing.T) {
	f := &facts.Facts{
		Processes: []facts.Process{{PID: 1, Exe: "/usr/lib/systemd/systemd"}},
		Ownership: []facts.Ownership{{Path: "/usr/lib/systemd/systemd", Owned: true, Pacote: "systemd"}},
		Vigias: []facts.Vigia{{
			PID: 1, Exe: "/usr/lib/systemd/systemd", Tipo: "inotify", Watches: 1,
			Alvos: []facts.AlvoVigiado{{Caminho: "/etc/passwd", Persistencia: true}},
		}},
	}
	if r := rodaVigia(t, f); len(r.Findings) != 0 {
		t.Errorf("binário de pacote vigiando /etc é o funcionamento normal: %+v", r.Findings)
	}
}

// E a outra metade: binário sem dono vigiando cache é um programa qualquer
// observando arquivo qualquer.
func TestVigiaSemDonoForaDePersistenciaNaoAcusa(t *testing.T) {
	f := &facts.Facts{
		Processes: []facts.Process{{PID: 900, Exe: "/opt/app/agent"}},
		Ownership: []facts.Ownership{{Path: "/opt/app/agent", Owned: false}},
		Vigias: []facts.Vigia{{
			PID: 900, Exe: "/opt/app/agent", Tipo: "inotify", Watches: 1,
			Alvos: []facts.AlvoVigiado{{Caminho: "/var/log/app", Persistencia: false}},
		}},
	}
	if r := rodaVigia(t, f); len(r.Findings) != 0 {
		t.Errorf("vigiar log não é vigiar persistência: %+v", r.Findings)
	}
}

// fanotify com classe de PERMISSÃO não observa: ele decide. Remover o arquivo
// pode simplesmente falhar, e o operador precisa saber disso antes de tentar.
func TestFanotifyQueBloqueiaEhDito(t *testing.T) {
	f := &facts.Facts{
		Processes: []facts.Process{{PID: 900, Exe: "/opt/x"}},
		Ownership: []facts.Ownership{{Path: "/opt/x", Owned: false}},
		Vigias: []facts.Vigia{{
			PID: 900, Exe: "/opt/x", Tipo: "fanotify", Watches: 1,
			Bloqueia: true, MontagemInteira: true,
			Alvos: []facts.AlvoVigiado{{Caminho: "/etc/ssh", Persistencia: true}},
		}},
	}
	r := rodaVigia(t, f)
	if !temEvidencia(r, "DECIDE se a operação acontece") {
		t.Errorf("o veto precisa ser dito: %v", evidencias(r))
	}
	if !temEvidencia(r, "MONTAGEM inteira") {
		t.Errorf("o watch de montagem inteira precisa ser dito: %v", evidencias(r))
	}
}
