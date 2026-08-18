package checks

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/check"
)

// O `§ref` é impresso em TODO achado, e é como o operador pula do relatório
// para o runbook. Um número errado ali manda a pessoa ler a seção errada no meio
// do incidente — e o erro é silencioso, porque a seção existe e o texto abre.
//
// Isto não era conferido, e uma auditoria contra o runbook achou dezesseis
// refs errados de uma vez. Dois deles apontavam para seções que NÃO EXISTEM
// (§4.2 e §4.3, num runbook cuja §4 não tem subseção nenhuma); os outros
// catorze apontavam para a seção errada — os cinco checks de anti-forense
// mandavam para "Remover/quarentenar arquivo", e quem os seguisse leria
// instruções de `rm` esperando ler sobre auditoria.
//
// A verificação SEMÂNTICA continua humana: nenhum teste sabe se a §11 é o lugar
// certo do auditd. O que dá para automatizar é o outro erro, que é o barato de
// cometer: citar um número que não existe.
//
// # Por que ele pula quando não acha o runbook
//
// O runbook não mora neste repositório — ele é o documento de origem, e a CLI é
// derivada dele. Copiá-lo para cá criaria uma segunda cópia para envelhecer.
// Então: quando o arquivo está por perto, o teste roda; quando não está, ele
// PULA com o motivo e o caminho esperado. É a mesma regra dos cenários que
// dependem de imagem ou de qemu — nunca passar em silêncio.
func TestTodoRefExisteNoRunbook(t *testing.T) {
	texto, caminho := lerRunbook(t)

	secoes := map[string]string{}
	re := regexp.MustCompile(`(?m)^#{1,2} (\d+(?:\.\d+)?)\. (.+)$`)
	for _, m := range re.FindAllStringSubmatch(texto, -1) {
		secoes[m[1]] = strings.TrimSpace(m[2])
	}
	if len(secoes) < 50 {
		t.Fatalf("%s: só %d seções reconhecidas — o formato do runbook mudou, "+
			"e este teste passaria a aprovar qualquer coisa", caminho, len(secoes))
	}

	for _, c := range check.All() {
		if c.Ref == "" {
			t.Errorf("%s sem Ref", c.ID)
			continue
		}
		if _, existe := secoes[c.Ref]; !existe {
			t.Errorf("%s cita §%s, que NÃO EXISTE no runbook. O operador que "+
				"seguir esse número não acha nada — e o erro é silencioso, "+
				"porque nada no relatório denuncia um ref inventado", c.ID, c.Ref)
		}
	}
	t.Logf("runbook: %s · %d seções · %d checks conferidos",
		caminho, len(secoes), len(check.All()))
}

// lerRunbook procura o documento de origem. A variável de ambiente vence; sem
// ela, tenta o lugar onde ele costuma estar em relação a este repositório.
func lerRunbook(t *testing.T) (texto, caminho string) {
	t.Helper()
	candidatos := []string{os.Getenv("ALETHEIA_RUNBOOK")}
	if raiz, err := filepath.Abs("../.."); err == nil {
		candidatos = append(candidatos,
			filepath.Join(filepath.Dir(raiz), "blablabla", "VM_SCAN.md"),
			filepath.Join(raiz, "VM_SCAN.md"))
	}
	for _, p := range candidatos {
		if p == "" {
			continue
		}
		if b, err := os.ReadFile(p); err == nil {
			return string(b), p
		}
	}
	t.Skipf("runbook não encontrado: aponte ALETHEIA_RUNBOOK para o VM_SCAN.md "+
		"para conferir que todo §ref existe. Procurei em: %v", candidatos[1:])
	return "", ""
}
