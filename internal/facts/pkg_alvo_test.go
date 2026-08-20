package facts

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/lex0c/aletheia/internal/env"
)

// END-TO-END (item 1 da revisão): unit com wrapper. O alvo efetivo do ExecStart
// tem de entrar na PERGUNTA DE PROPRIEDADE — senão unit_unowned calcula o alvo
// certo e semDono nunca o teve. O teste unitário mascarava isso injetando
// Ownership à mão; este roda a coleta de units e a montagem de candidatos.
func TestAlvoDeWrapperViraCandidato(t *testing.T) {
	raiz := t.TempDir()
	os.MkdirAll(filepath.Join(raiz, "etc/systemd/system"), 0o755)
	os.MkdirAll(filepath.Join(raiz, "bin"), 0o755)
	os.WriteFile(filepath.Join(raiz, "bin/.backdoor"), []byte("x"), 0o755)
	os.WriteFile(filepath.Join(raiz, "etc/systemd/system/x.service"),
		[]byte("[Service]\nExecStart=/usr/bin/env /bin/.backdoor\n"), 0o644)
	e := env.Probe(env.Options{Root: raiz, Version: "test"})
	t.Cleanup(func() { e.Close() })

	f := &Facts{}
	collectUnits(f, e)
	cand := candidatosDePropriedade(f, e)
	if _, ok := cand["/bin/.backdoor"]; !ok {
		var ks []string
		for k := range cand {
			ks = append(ks, k)
		}
		t.Fatalf("/bin/.backdoor (alvo efetivo do env) devia ser candidato; candidatos: %v", ks)
	}
}
