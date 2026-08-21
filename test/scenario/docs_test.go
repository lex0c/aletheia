package scenario_test

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/check"
	_ "github.com/lex0c/aletheia/internal/checks"
	"github.com/lex0c/aletheia/test/scenario"
)

// docs/SCENARIOS.md é GERADO, e este teste é o que impede que ele apodreça.
//
// Um catálogo escrito à mão descreve o produto do dia em que foi escrito. Este
// sai dos mesmos dois registros que a ferramenta usa em runtime — o de checks e
// o de cenários —, então check novo sem cenário, cenário renomeado ou lacuna
// declarada aparecem no documento no mesmo commit em que entram no código.
//
//	go test ./test/scenario -run TestDocumentoDeCenarios -update
const caminhoDoDoc = "../../docs/SCENARIOS.md"

var atualizar = flag.Bool("update", false, "reescreve docs/SCENARIOS.md")

func TestDocumentoDeCenarios(t *testing.T) {
	novo := geraDocumento()
	if *atualizar {
		if err := os.WriteFile(caminhoDoDoc, []byte(novo), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	atual, err := os.ReadFile(caminhoDoDoc)
	if err != nil {
		t.Fatalf("%v — gere com: go test ./test/scenario -run TestDocumentoDeCenarios -update", err)
	}
	if string(atual) != novo {
		t.Errorf("docs/SCENARIOS.md está desatualizado.\n\n"+
			"Ele é GERADO dos registros de check e de cenário; editar à mão não "+
			"adianta, e deixar velho é pior que não ter — um catálogo que descreve "+
			"outra versão do produto engana quem consulta.\n\n"+
			"    go test ./test/scenario -run TestDocumentoDeCenarios -update\n\n"+
			"(atual: %d bytes; gerado: %d)", len(atual), len(novo))
	}
}

func geraDocumento() string {
	var b strings.Builder
	checks := check.All()
	cenarios := scenario.All()

	// check -> cenários que o afirmam
	porCheck := map[string][]string{}
	for _, s := range cenarios {
		for _, e := range s.Expect {
			porCheck[e.ID] = append(porCheck[e.ID], s.ID)
		}
		for _, id := range s.UntestableChecks {
			porCheck[id] = append(porCheck[id], s.ID+" (não reproduzível)")
		}
	}
	for k := range porCheck {
		porCheck[k] = unicos(porCheck[k])
	}

	fmt.Fprintf(&b, "# O que a Aletheia detecta\n\n")
	fmt.Fprintf(&b, "GERADO de `internal/checks` e `test/scenario`. Não edite à mão:\n")
	fmt.Fprintf(&b, "`go test ./test/scenario -run TestDocumentoDeCenarios -update`.\n\n")
	fmt.Fprintf(&b, "%d checks, %d cenários.\n\n", len(checks), len(cenarios))
	fmt.Fprintf(&b, "Um **check** é uma pergunta que a ferramenta faz ao host. Um **cenário** é um\n")
	fmt.Fprintf(&b, "host montado de propósito — em contêiner, imagem ou microVM — que prova a\n")
	fmt.Fprintf(&b, "resposta. Check sem cenário não entra no catálogo: o portão em\n")
	fmt.Fprintf(&b, "`registro_test.go` recusa.\n\n")

	// --- checks por grupo
	porGrupo := map[string][]check.Check{}
	for _, c := range checks {
		porGrupo[c.Group] = append(porGrupo[c.Group], c)
	}
	grupos := make([]string, 0, len(porGrupo))
	for g := range porGrupo {
		grupos = append(grupos, g)
	}
	sort.Strings(grupos)

	fmt.Fprintf(&b, "## Checks\n\n")
	for _, g := range grupos {
		fmt.Fprintf(&b, "### `%s` (%d)\n\n", g, len(porGrupo[g]))
		fmt.Fprintf(&b, "| check | § | o que acusa | provado por |\n|---|---|---|---|\n")
		for _, c := range porGrupo[g] {
			prova := "—"
			if v := porCheck[c.ID]; len(v) > 0 {
				prova = "`" + strings.Join(primeiros(v, 3), "`, `") + "`"
				if len(v) > 3 {
					prova += fmt.Sprintf(" +%d", len(v)-3)
				}
			}
			marca := ""
			if c.Mode == check.ModeManual {
				marca = " *(manual)*"
			}
			fmt.Fprintf(&b, "| `%s`%s | %s | %s | %s |\n",
				c.ID, marca, c.Ref, escapa(c.Title), prova)
		}
		fmt.Fprintln(&b)
	}

	// --- cenários
	fmt.Fprintf(&b, "## Cenários\n\n")
	fmt.Fprintf(&b, "`live` roda a CLI dentro do contêiner; `image` exporta o rootfs e varre de\n")
	fmt.Fprintf(&b, "fora com `--root`; `vm` sobe uma microVM com kernel próprio, para o que\n")
	fmt.Fprintf(&b, "contêiner não alcança — hidepid, sysctl, módulo, cgroup, eBPF.\n\n")
	fmt.Fprintf(&b, "| cenário | modo | o que monta |\n|---|---|---|\n")
	for _, s := range cenarios {
		nota := ""
		switch {
		case s.Untestable != "":
			nota = " ⚠ não reproduzível: " + escapa(primeiraFrase(s.Untestable))
		case s.KnownGap != "":
			nota = " ⚠ lacuna conhecida: " + escapa(primeiraFrase(s.KnownGap))
		}
		fmt.Fprintf(&b, "| `%s` | %s | %s%s |\n", s.ID, modo(s), escapa(s.Desc), nota)
	}
	fmt.Fprintln(&b)

	// --- limites declarados
	var limites []scenario.Scenario
	for _, s := range cenarios {
		if s.Untestable != "" || s.KnownGap != "" {
			limites = append(limites, s)
		}
	}
	fmt.Fprintf(&b, "## Limites declarados (%d)\n\n", len(limites))
	fmt.Fprintf(&b, "O que a ferramenta NÃO alcança, dito por escrito. Um cenário que declara o\n")
	fmt.Fprintf(&b, "próprio limite vale mais que a ausência dele: a lacuna fica medida em vez de\n")
	fmt.Fprintf(&b, "ser descoberta no incidente.\n\n")
	for _, s := range limites {
		motivo := s.Untestable
		rotulo := "não reproduzível aqui"
		if motivo == "" {
			motivo, rotulo = s.KnownGap, "lacuna conhecida"
		}
		fmt.Fprintf(&b, "- **`%s`** (%s) — %s\n", s.ID, rotulo, escapa(primeiraFrase(motivo)))
	}
	return b.String()
}

func modo(s scenario.Scenario) string {
	switch s.Mode {
	case scenario.VM:
		return "vm"
	case scenario.Image:
		return "image"
	}
	return "live"
}

func primeiraFrase(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	for _, fim := range []string{". ", " — "} {
		if i := strings.Index(s, fim); i > 40 {
			return s[:i]
		}
	}
	if len(s) > 180 {
		return strings.TrimSpace(s[:180]) + "…"
	}
	return s
}

func escapa(s string) string { return strings.ReplaceAll(s, "|", "\\|") }

func primeiros(v []string, n int) []string {
	if len(v) <= n {
		return v
	}
	return v[:n]
}

func unicos(v []string) []string {
	seen := map[string]bool{}
	out := v[:0]
	for _, s := range v {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
