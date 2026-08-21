package facts

import (
	"testing"
	"time"
)

// PID RECICLADO NÃO É O CRIADOR, e casar por número bastava para inventar um.
//
// O segmento SysV sobrevive à morte de quem o criou — o próprio coletor diz
// isso. O PID some junto e o kernel o reaproveita: horas depois, um processo
// novo com o mesmo número abre um socket de escuta, e um segmento órfão de
// 3 MiB vira "perfil do canal do Ebury" — CRITICAL, direto, sem atacante
// nenhum. Em servidor com uptime longo é questão de tempo.
//
// A prova é temporal e o teste é sobre ela: quem começou depois do segmento não
// pode tê-lo criado.
func TestProcessoComecouDepois(t *testing.T) {
	// O instante do segmento vem calculado, não chutado: constante de epoch
	// escrita à mão foi o que fez a primeira versão deste teste falhar.
	criado := must(t, "2026-08-20T10:00:00Z")

	casos := []struct {
		nome     string
		start    string
		criadoEm int
		depois   bool
		deuPara  bool
	}{
		{"processo nasceu ANTES: pode ser o criador",
			"2026-08-20T10:00:00Z", criado, false, true},
		{"processo nasceu DEPOIS: o número foi reciclado",
			"2026-08-20T12:00:00Z", criado, true, true},
		// Granularidade de segundo nos dois lados: um processo que começou em
		// t=10,9 e criou o segmento em t=11,0 aparece como (10, 11). Acusar
		// reciclagem por arredondamento seria trocar um FP por outro.
		{"um segundo antes: NÃO é reciclagem",
			"2026-08-20T09:59:59Z", criado, false, true},
		{"sem hora de início: não dá para provar em direção nenhuma",
			"", criado, false, false},
		{"sem ctime do segmento: idem",
			"2026-08-20T10:00:00Z", 0, false, false},
		{"hora de início ilegível: idem",
			"ontem", criado, false, false},
	}
	for _, c := range casos {
		depois, deuPara := processoComecouDepois(&Process{StartUTC: c.start}, c.criadoEm)
		if depois != c.depois || deuPara != c.deuPara {
			t.Errorf("[%s] (%v, %v), queria (%v, %v)", c.nome, depois, deuPara, c.depois, c.deuPara)
		}
	}
}

func must(t *testing.T, s string) int {
	t.Helper()
	v, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return int(v.Unix())
}
