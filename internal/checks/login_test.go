package checks

import (
	"strconv"
	"testing"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/facts"
)

// O limiar de força bruta é contado POR ORIGEM, e quem lê o código fica
// abaixo dele: nove falhas de cada um de cem endereços somam novecentas
// tentativas sem cruzar o limiar em origem nenhuma. Não é a forma exótica — é
// a comum, porque todo mundo limita por IP.
func TestForcaBrutaEspalhadaPorMuitasOrigens(t *testing.T) {
	f := &facts.Facts{}
	// Seis origens, NOVE falhas cada uma: nenhuma cruza o limiar de dez.
	for o := 0; o < 6; o++ {
		for i := 0; i < 9; i++ {
			f.Logins = append(f.Logins, facts.Login{
				Tipo: facts.TipoLoginUsuario, User: "deploy", Falhou: true,
				Origem: "203.0.113." + strconv.Itoa(10+o), QuandoU: "2026-08-18T01:00:00Z",
			})
		}
	}
	// E então alguém entra.
	f.Logins = append(f.Logins, facts.Login{
		Tipo: facts.TipoLoginUsuario, User: "deploy",
		Origem: "203.0.113.10", QuandoU: "2026-08-18T02:00:00Z",
	})
	f.Index()

	r := check.Run([]check.Check{forcaBrutaComSucesso}, f, testEnv())
	if len(r.Findings) != 1 {
		t.Fatalf("achados = %+v — nenhuma origem cruza o limiar, e mesmo assim "+
			"seis endereços atacaram a MESMA conta e alguém entrou", r.Findings)
	}
	fd := r.Findings[0]
	if fd.Sev != check.SevCritical || fd.Subject != "deploy" {
		t.Errorf("o sujeito é a CONTA quando o ataque veio espalhado: %+v", fd)
	}
	if !temEvidencia(r, "6 endereços diferentes") {
		t.Errorf("o número de origens é o sinal: %v", evidencias(r))
	}
	if !temEvidencia(r, "NENHUMA das origens sozinha cruzou o limiar") {
		t.Errorf("e por que o primeiro eixo não pegou: %v", evidencias(r))
	}
}

// Um usuário legítimo erra a senha do celular, do laptop e da VPN. Três
// origens não é ataque espalhado, e acusar aí seria trocar um ponto cego por
// ruído em todo host com gente que viaja.
func TestPoucasOrigensNaoSaoAtaqueEspalhado(t *testing.T) {
	f := &facts.Facts{}
	for o := 0; o < 3; o++ {
		f.Logins = append(f.Logins, facts.Login{
			Tipo: facts.TipoLoginUsuario, User: "ana", Falhou: true,
			Origem: "10.0.0." + strconv.Itoa(10+o), QuandoU: "2026-08-18T01:00:00Z",
		})
	}
	f.Logins = append(f.Logins, facts.Login{
		Tipo: facts.TipoLoginUsuario, User: "ana", Origem: "10.0.0.10",
		QuandoU: "2026-08-18T02:00:00Z",
	})
	f.Index()
	if r := check.Run([]check.Check{forcaBrutaComSucesso}, f, testEnv()); len(r.Findings) != 0 {
		t.Errorf("três origens é gente errando a senha: %+v", r.Findings)
	}
}
