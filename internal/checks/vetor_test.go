package checks

import (
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/facts"
)

func escuta(porta int, ip string, pid int) facts.Socket {
	return facts.Socket{Proto: "tcp", State: "LISTEN", LocalIP: ip, LocalPort: porta,
		Inode: uint64(9000 + porta), PID: pid, Comm: "node"}
}

func conexaoEntrando(porta int, de string, pid int, escopo facts.Scope) facts.Socket {
	return facts.Socket{Proto: "tcp", State: "ESTAB", LocalIP: "10.0.0.5", LocalPort: porta,
		PeerIP: de, PeerPort: 50000, Inode: uint64(8000 + porta), PID: pid,
		Dir: facts.DirIn, PeerScope: escopo}
}

// A segunda armadilha do proxy (§15): o backend em 0.0.0.0 que só o nginx local
// usa. Quem vier de fora fala direto com ele, e todo filtro que mora no proxy
// deixa de existir.
func TestBackendUsadoSoPeloProxyLocalEExposto(t *testing.T) {
	f := &facts.Facts{
		Processes: []facts.Process{{PID: 100, Comm: "node", Exe: "/usr/local/bin/node"}},
		Sockets: []facts.Socket{
			escuta(4100, "0.0.0.0", 100),
			conexaoEntrando(4100, "127.0.0.1", 100, facts.ScopeLoopback),
			conexaoEntrando(4100, "127.0.0.1", 100, facts.ScopeLoopback),
		},
	}
	r := backendExposto.Run(backendExposto, f, testEnv())
	if len(r.Findings) != 1 {
		t.Fatalf("achados = %v", r.Findings)
	}
	ev := strings.Join(r.Findings[0].Evidence, " ")
	for _, trecho := range []string{"não é loopback", "vêm todas do LOOPBACK", "127.0.0.1"} {
		if !strings.Contains(ev, trecho) {
			t.Errorf("faltou %q: %v", trecho, r.Findings[0].Evidence)
		}
	}
}

// As três formas de NÃO ser este achado. A do meio é a que decide se o check é
// usável: metade dos serviços de um host legítimo escuta em 0.0.0.0 de
// propósito, e "escuta em 0.0.0.0" sozinho não é sinal de nada.
func TestQuandoOBackendExpostoNaoDispara(t *testing.T) {
	casos := map[string]*facts.Facts{
		"escuta só no loopback": {
			Processes: []facts.Process{{PID: 100, Comm: "node"}},
			Sockets: []facts.Socket{
				escuta(4100, "127.0.0.1", 100),
				conexaoEntrando(4100, "127.0.0.1", 100, facts.ScopeLoopback),
			},
		},
		"tem conexão de FORA: é servidor mesmo": {
			Processes: []facts.Process{{PID: 100, Comm: "nginx"}},
			Sockets: []facts.Socket{
				escuta(443, "0.0.0.0", 100),
				conexaoEntrando(443, "127.0.0.1", 100, facts.ScopeLoopback),
				conexaoEntrando(443, "203.0.113.80", 100, facts.ScopePublic),
			},
		},
		"sem conexão nenhuma: não há evidência de uso": {
			Processes: []facts.Process{{PID: 100, Comm: "node"}},
			Sockets:   []facts.Socket{escuta(4100, "0.0.0.0", 100)},
		},
	}
	for nome, f := range casos {
		if r := backendExposto.Run(backendExposto, f, testEnv()); len(r.Findings) != 0 {
			t.Errorf("%s: não podia disparar: %v", nome, r.Findings[0].Evidence)
		}
	}
}

// A heurística do §14, que ELIMINA hipótese: o backdoor roda como um usuário, e
// só serviço daquele usuário pode ser a entrada.
func TestVetorEstreitaPeloUsuario(t *testing.T) {
	f := &facts.Facts{
		Processes: []facts.Process{
			{PID: 900, UID: 1001, Comm: "x", Exe: "/tmp/.x"},               // o suspeito
			{PID: 100, UID: 1001, Comm: "app", Exe: "/opt/app/app"},        // mesmo uid, escuta
			{PID: 200, UID: 33, Comm: "php-fpm", Exe: "/usr/sbin/php-fpm"}, // outro uid
		},
		Sockets: []facts.Socket{escuta(8080, "0.0.0.0", 100), escuta(9000, "127.0.0.1", 200)},
	}
	r := vetorPorUsuario.Run(vetorPorUsuario, f, testEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevInfo {
		t.Fatalf("achados = %v", r.Findings)
	}
	ev := strings.Join(r.Findings[0].Evidence, " ")
	if !strings.Contains(ev, "app em 0.0.0.0:8080") {
		t.Errorf("o serviço do MESMO uid precisa ser nomeado: %v", r.Findings[0].Evidence)
	}
	if strings.Contains(ev, "php-fpm") {
		t.Errorf("o serviço de OUTRO uid não pode entrar: seria o contrário de "+
			"estreitar o vetor: %v", r.Findings[0].Evidence)
	}
}

// Sem achado no host não há pergunta a fazer, e o check fica calado — senão
// todo scan limpo ganharia um bloco de hipótese sobre nada.
func TestSemSuspeitoNaoHaVetorAEstreitar(t *testing.T) {
	f := &facts.Facts{
		Processes: []facts.Process{{PID: 100, UID: 33, Comm: "nginx", Exe: "/usr/sbin/nginx"}},
		Sockets:   []facts.Socket{escuta(443, "0.0.0.0", 100)},
	}
	if r := vetorPorUsuario.Run(vetorPorUsuario, f, testEnv()); len(r.Findings) != 0 {
		t.Errorf("sem suspeito não há vetor a estreitar: %v", r.Findings)
	}
}

// E quando NENHUM serviço roda com aquele uid, a resposta é o contrário — e é
// informação: a entrada provavelmente não foi por rede local.
func TestSemServicoDoMesmoUsuarioAEntradaNaoFoiPorRede(t *testing.T) {
	f := &facts.Facts{
		Processes: []facts.Process{
			{PID: 900, UID: 1001, Comm: "x", Exe: "/dev/shm/.x"},
			{PID: 100, UID: 33, Comm: "nginx", Exe: "/usr/sbin/nginx"},
		},
		Sockets: []facts.Socket{escuta(443, "0.0.0.0", 100)},
	}
	r := vetorPorUsuario.Run(vetorPorUsuario, f, testEnv())
	if len(r.Findings) != 1 {
		t.Fatalf("achados = %v", r.Findings)
	}
	if !strings.Contains(strings.Join(r.Findings[0].Evidence, " "), "NENHUM serviço escuta") {
		t.Errorf("evidência = %v", r.Findings[0].Evidence)
	}
}
