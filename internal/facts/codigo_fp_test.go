package facts

import "testing"

func pior(src string) (int, string) {
	p, r := 0, ""
	for _, m := range analisarConteudo(src, "php") {
		if m.Tier > p {
			p, r = m.Tier, m.Regra
		}
	}
	return p, r
}

func TestFPStringNaoEhChamada(t *testing.T) {
	for _, c := range []struct{ nome, src string }{
		{"apm_aspa_simples", `<?php
$msg = 'requestInitStartTime - $_SERVER[\'REQUEST_TIME_FLOAT\'] (seconds)';
echo $msg;`},
		{"apm_aspa_dupla", `<?php
$s = "usa $_GET['f'] (nao executa)";
echo $s;`},
		{"comentario", "<?php\n// mede $_SERVER['REQUEST_TIME_FLOAT'] (segundos)\n$x=1;"},
	} {
		if p, r := pior(c.src); p >= 2 {
			t.Errorf("%s: FP tier %d (%s)", c.nome, p, r)
		}
	}
}

func TestChamadaDinamicaRealContinuaPegando(t *testing.T) {
	for _, s := range []string{
		`<?php $_GET['f']();`,
		`<?php $_POST['cmd']();`,
		`<?php $f = $_GET['f']; $f();`,
		`<?php $_REQUEST['x']();`,
	} {
		if p, _ := pior(s); p < 2 {
			t.Errorf("chamada dinâmica REAL saiu tier %d: %q", p, s)
		}
	}
}

// A aspa dupla precisa continuar VISÍVEL para o taint: em PHP ela interpola.
func TestAspaDuplaContinuaSendoFonteParaOTaint(t *testing.T) {
	if p, _ := pior(`<?php system("ls $_GET[x]");`); p < 2 {
		t.Errorf("interpolação em aspa dupla é fonte real, saiu tier %d", p)
	}
}
