package baseline

import (
	"testing"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/facts"
)

// Dois achados DIFERENTES do mesmo check sobre o mesmo sujeito precisam gerar
// chaves diferentes.
//
// A chave era `ID|Subject`, e ela colide sempre que um check emite mais de um
// achado por sujeito — priv.sudo_nopasswd usa o USUÁRIO como Subject, e
// ioc.match usa o mesmo pid para indicadores distintos. O erro é para o lado
// perigoso: a regra recém-inserida em sudoers.d que dá root irrestrito saía
// marcada `baseline=true`, SEM a marca ✳NOVO, sob uma linha de evidência
// afirmando "já estava presente na baseline de …" — uma frase falsa sobre uma
// regra que nunca esteve lá.
func TestChaveNaoColideEntreAchadosDoMesmoSujeito(t *testing.T) {
	f := &facts.Facts{}

	antiga := check.Finding{
		ID: "priv.sudo_nopasswd", Subject: "deploy",
		Chave: "deploy ALL=(root) NOPASSWD: /usr/bin/systemctl",
	}
	nova := check.Finding{
		ID: "priv.sudo_nopasswd", Subject: "deploy",
		Chave: "deploy ALL=(root) NOPASSWD: ALL",
	}

	ka, kn := Chave(f, antiga), Chave(f, nova)
	if ka == "" || kn == "" {
		t.Fatalf("chave vazia: antiga=%q nova=%q", ka, kn)
	}
	if ka == kn {
		t.Fatalf("as duas regras geraram a MESMA chave (%q): a regra nova herda "+
			"a presença da antiga na baseline e sai sem a marca ✳NOVO, com uma "+
			"linha de evidência afirmando que já estava lá", ka)
	}
}

// E a baseline capturada com a regra antiga NÃO pode abençoar a nova.
func TestBaselineComRegraAntigaNaoAbencoaRegraNova(t *testing.T) {
	f := &facts.Facts{}
	antiga := check.Finding{
		ID: "priv.sudo_nopasswd", Subject: "deploy",
		Chave: "deploy ALL=(root) NOPASSWD: /usr/bin/systemctl",
	}
	nova := check.Finding{
		ID: "priv.sudo_nopasswd", Subject: "deploy",
		Chave: "deploy ALL=(root) NOPASSWD: ALL",
	}

	b := &Baseline{Schema: Schema, Keys: []string{Chave(f, antiga)}}
	conhecidas := map[string]bool{}
	for _, k := range b.Keys {
		conhecidas[k] = true
	}

	if !conhecidas[Chave(f, antiga)] {
		t.Error("a regra que ESTAVA na baseline precisa ser reconhecida")
	}
	if conhecidas[Chave(f, nova)] {
		t.Error("a regra NOVA foi reconhecida como presente na baseline: é o " +
			"falso 'já estava assim' sobre uma concessão de root irrestrito")
	}
}

// Sem discriminador, o comportamento antigo continua valendo — a maior parte
// dos checks emite um achado por sujeito, e para eles `ID|Subject` basta.
func TestSemDiscriminadorAChaveContinuaSendoIDMaisSujeito(t *testing.T) {
	f := &facts.Facts{}
	fd := check.Finding{ID: "persist.unit_unowned", Subject: "/etc/systemd/system/x.service"}
	if got, quer := Chave(f, fd), "persist.unit_unowned|/etc/systemd/system/x.service"; got != quer {
		t.Errorf("Chave=%q, queria %q", got, quer)
	}
}
