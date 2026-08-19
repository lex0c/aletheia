package facts

import (
	"os"
	"syscall"
	"testing"

	"github.com/lex0c/aletheia/internal/env"
)

// O mesmo invariante do lacuna_test.go, para os coletores LIVE-ONLY.
//
// Eles leem /proc e /sys direto, fora do env.Env — e com razão: não há raiz
// travada num host vivo. A consequência é que o harness de raiz ilegível não
// alcança nenhum deles, e a pergunta "você declara quando não consegue ler?"
// nunca chegou aqui. Este harness injeta a falha no ponto único de leitura e
// faz a pergunta.
//
// EACCES e não ENOENT, de propósito: "não existe" é resposta legítima — um
// host sem BPF não tem /sys/fs/bpf, e um contêiner tem /proc mascarado. O que
// não pode virar silêncio é "existe e eu não pude ler".
func comLeituraNegada(t *testing.T, fn func(*Facts, *env.Env)) *Facts {
	t.Helper()
	original := lerArquivoDoHost
	lerArquivoDoHost = func(string) ([]byte, error) {
		return nil, &os.PathError{Op: "open", Err: syscall.EACCES}
	}
	t.Cleanup(func() { lerArquivoDoHost = original })

	e := env.Probe(env.Options{Version: "test"})
	t.Cleanup(func() { e.Close() })
	f := &Facts{}
	fn(f, e)
	return f
}

func TestColetorVivoComLeituraNegadaDeclaraLacuna(t *testing.T) {
	casos := []struct {
		nome  string
		rodar func(*Facts, *env.Env)
	}{
		{"taint", collectTaint},
		{"helpers", collectHelpers},
		{"modulosCarregados", collectModulosCarregados},
		{"ftrace", collectFtrace},
	}
	// FORA daqui, e por razões diferentes:
	//
	//	mounts, limitesDeRede,   leem por e.ReadFile, que esta injeção não
	//	protecaoKernel           alcança — ela troca o leitor do HOST. O
	//	                         instrumento certo para eles é o harness de raiz
	//	                         travada (lacuna_test.go), onde o env aplica.
	//	host                     é METADADO de cabeçalho, não superfície de
	//	                         achado. O invariante vale onde a ausência de
	//	                         achado pode ser lida como ausência de problema;
	//	                         um hostname em branco no relatório é
	//	                         auto-evidente, e exigir Partial ali seria
	//	                         aplicar a regra onde ela não diz nada.
	for _, c := range casos {
		t.Run(c.nome, func(t *testing.T) {
			f := comLeituraNegada(t, c.rodar)
			ls := lacunasDe(f)
			if len(ls) == 0 {
				t.Errorf("o coletor %q não conseguiu ler NADA e não declarou lacuna: "+
					"ausência afirmada a partir de leitura negada", c.nome)
				return
			}
			t.Logf("%-18s %d lacuna(s): %s", c.nome, len(ls), primeira(ls))
		})
	}
}
