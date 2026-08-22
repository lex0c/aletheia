package dump

import (
	"errors"
	"testing"

	"github.com/lex0c/aletheia/internal/env"
)

// O SELO NASCE DO ARTEFATO, e não de quem chama lembrar de pedir.
//
// As duas origens importam, e por motivos opostos: a de IMAGEM já era recusada
// por ErrSemRaiz desde sempre, e por isso o defeito passou despercebido — a de
// HOST VIVO tem Root vazio e Source=live, então caía no os.ReadFile do próprio
// processo. Medido antes da correção: d.Env(nil).ReadFile("/etc/hostname")
// devolveu o hostname da máquina do ANALISTA, sete bytes, err=nil.
func TestEnvDoArtefatoNasceSelado(t *testing.T) {
	for _, origem := range []env.Source{env.SourceLive, env.SourceImage} {
		d := &Dump{}
		d.Ambiente.Source = origem.String()
		d.Ambiente.Caps = []string{"filesystem"}

		e, err := d.Env(nil)
		if err != nil {
			t.Fatalf("%s: %v", origem, err)
		}
		if !e.Selado() {
			t.Errorf("%s: o ambiente do artefato não nasceu selado", origem)
		}
		b, err := e.ReadFile("/etc/hostname")
		if !errors.Is(err, env.ErrSelado) {
			t.Errorf("%s: ReadFile devolveu (%d bytes, %v); um dump descreve uma "+
				"coleta ENCERRADA e não pode ler o host de agora — %q",
				origem, len(b), err, string(b))
		}
	}
}
