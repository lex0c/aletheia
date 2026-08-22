package env

import (
	"errors"
	"reflect"
	"testing"
)

// O AMBIENTE RECONSTRUÍDO NÃO LÊ O HOST DE AGORA.
//
// A catraca não confere os acessores de hoje: ela enumera por reflexão TODO
// método exportado de *Env que recebe um caminho, e exige que cada um esteja
// declarado aqui. Um acessor novo que esqueça o portão não passa despercebido —
// ele nem compila a expectativa, porque não existe.
//
// O motivo de ser assim: raizIndisponivel é o gargalo único, mas quatro dos
// acessores atuais não o chamam direto (chegam nele por ReadFile, Stat ou
// ReadDir). Um quinto escrito daqui a seis meses pode abrir o arquivo sozinho, e
// aí a fronteira some sem ninguém mexer numa linha deste arquivo.
func TestEnvSeladoRecusaTodoAcessoAFilesystem(t *testing.T) {
	// O que cada acessor tem de responder num Env selado.
	//
	// "recusa" = devolve ErrSelado. "vazio" = não tem por onde devolver erro,
	// então tem de responder a negativa, nunca o estado do host. "indeterminada"
	// é o caso em que a negativa seria ela mesma uma afirmação falsa.
	espera := map[string]string{
		"ReadFile":        "recusa",
		"Stat":            "recusa",
		"Lstat":           "recusa",
		"Readlink":        "recusa",
		"Open":            "recusa",
		"OpenFD":          "recusa",
		"ReadDir":         "recusa",
		"ReadDirNamesErr": "recusa",
		"ReadDirNames":    "vazio",
		"IsDir":           "vazio",
		"Exists":          "vazio",

		// EstadoDeMontagem é o único que NÃO pode responder o zero: ali o zero
		// é MontagemAusente, "o ponto não existe neste host". Um ambiente selado
		// não sabe disso — ele não olhou. A resposta certa é a quarta, e o enum
		// de quatro estados existe exatamente para essa diferença.
		"EstadoDeMontagem": "indeterminada",

		// Path monta string para EXIBIÇÃO e nunca toca o filesystem — o próprio
		// comentário dele diz para não usá-lo para abrir nada.
		"Path": "nao_le",
		// Ignorado responde sobre a lista de exclusão do operador, que é
		// configuração deste processo e não estado do alvo.
		"Ignorado": "nao_le",
		// Stage e Detalhe recebem o nome de um estágio de coleta e o mandam para
		// o indicador de progresso. Recebem string, não caminho.
		"Stage":   "nao_le",
		"Detalhe": "nao_le",
	}

	e := &Env{Source: SourceLive, Caps: CapFilesystem}
	e.Selar()

	tipo := reflect.TypeOf(e)
	vazio := reflect.TypeOf("")
	vistos := map[string]bool{}

	for i := 0; i < tipo.NumMethod(); i++ {
		m := tipo.Method(i)
		if m.Type.NumIn() != 2 || m.Type.In(1) != vazio {
			continue
		}
		vistos[m.Name] = true
		quer, declarado := espera[m.Name]
		if !declarado {
			t.Errorf("%s recebe um caminho e NÃO está declarado em selado_test.go.\n"+
				"Diga o que ele faz num ambiente selado: se lê filesystem, tem de\n"+
				"recusar; se não lê, diga por quê.", m.Name)
			continue
		}
		if quer == "nao_le" {
			continue
		}

		saidas := m.Func.Call([]reflect.Value{reflect.ValueOf(e), reflect.ValueOf("/etc/hostname")})
		conferir(t, m.Name, quer, saidas)
	}

	for nome := range espera {
		if !vistos[nome] {
			t.Errorf("%s está declarado aqui e não existe mais em *Env: "+
				"remova a linha, para a tabela não virar decoração", nome)
		}
	}
}

func conferir(t *testing.T, nome, quer string, saidas []reflect.Value) {
	t.Helper()

	var erro error
	if n := len(saidas); n > 0 {
		if e, ok := saidas[n-1].Interface().(error); ok {
			erro = e
		}
	}

	if quer == "indeterminada" {
		if len(saidas) != 1 || saidas[0].Interface() != MontagemIndeterminada {
			t.Errorf("%s devolveu %v num ambiente selado; queria "+
				"MontagemIndeterminada — responder ausência sobre um ponto que "+
				"ninguém olhou é trocar recusa por fato", nome, saidas)
		}
		return
	}

	if quer == "recusa" {
		if !errors.Is(erro, ErrSelado) {
			t.Errorf("%s devolveu err=%v; um ambiente selado tem de recusar com "+
				"ErrSelado, e não responder sobre o host de quem investiga", nome, erro)
		}
		return
	}

	// "vazio": sem canal de erro, a resposta tem de ser a negativa.
	for _, s := range saidas {
		if _, ok := s.Interface().(error); ok {
			continue
		}
		if !s.IsZero() {
			t.Errorf("%s devolveu %#v num ambiente selado — isso é o estado do "+
				"host de agora vazando por um acessor sem canal de erro",
				nome, s.Interface())
		}
	}
}

// E o selo nasce do artefato, não de quem chama lembrar de pedir. A prova de
// que ele importa está no par de origens: a de IMAGEM já era recusada por
// ErrSemRaiz, a de HOST VIVO não era recusada por nada.
func TestEnvVivoNaoNasceSelado(t *testing.T) {
	e := &Env{Source: SourceLive, Caps: CapFilesystem}
	if e.Selado() {
		t.Fatal("um Env construído para coletar não pode nascer selado")
	}
	if _, err := e.ReadFile("/etc/hostname"); errors.Is(err, ErrSelado) {
		t.Fatal("a coleta precisa conseguir ler")
	}
}
