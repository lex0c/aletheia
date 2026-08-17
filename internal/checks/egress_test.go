package checks

import (
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/facts"
)

// factsDeRede monta o mínimo para os dois checks: um processo, seu socket e a
// resposta da base de pacotes sobre o executável.
func factsDeRede(exe string, dono bool, s facts.Socket) *facts.Facts {
	s.PID = 7
	return &facts.Facts{
		Processes: []facts.Process{{PID: 7, Comm: "x", Exe: exe}},
		Sockets:   []facts.Socket{s},
		Ownership: []facts.Ownership{{Path: exe, Owned: dono}},
		Pkg:       facts.PkgDB{Kind: "dpkg"},
	}
}

// O discriminador é a PROPRIEDADE, não o endereço: o mesmo socket, vindo de um
// binário que um pacote entregou, não é achado.
func TestSaidaSoDisparaSemDonoDePacote(t *testing.T) {
	sock := facts.Socket{
		Proto: "tcp", State: "ESTAB", Dir: facts.DirOut,
		PeerIP: "51.91.190.241", PeerPort: 443, PeerScope: facts.ScopePublic,
	}

	comDono := factsDeRede("/usr/bin/curl", true, sock)
	if r := saidaSemDono.Run(saidaSemDono, comDono, testEnv()); len(r.Findings) != 0 {
		t.Fatalf("binário de pacote falando com a internet é rotina: %v", r.Findings)
	}

	semDono := factsDeRede("/usr/local/sbin/agente", false, sock)
	r := saidaSemDono.Run(saidaSemDono, semDono, testEnv())
	if len(r.Findings) != 1 {
		t.Fatalf("achados = %v", r.Findings)
	}
	// /usr/local é território de instalação manual: sem dono ali é a norma.
	if r.Findings[0].Sev != check.SevWarn {
		t.Errorf("sev = %v, /usr/local sem dono é AVISO", r.Findings[0].Sev)
	}
	if !strings.Contains(strings.Join(r.Findings[0].Evidence, " "), "51.91.190.241:443") {
		t.Error("o destino precisa aparecer: é o que vale como IOC de frota")
	}
}

// Endereço privado não é saída para a internet, e o pivô já cobre movimento
// lateral: contar aqui de novo inflaria a triagem sem acrescentar informação.
func TestSaidaIgnoraDestinoPrivado(t *testing.T) {
	f := factsDeRede("/usr/local/sbin/agente", false, facts.Socket{
		Proto: "tcp", State: "ESTAB", Dir: facts.DirOut,
		PeerIP: "10.0.0.9", PeerPort: 443, PeerScope: facts.ScopePrivate,
	})
	if r := saidaSemDono.Run(saidaSemDono, f, testEnv()); len(r.Findings) != 0 {
		t.Fatalf("achados = %v", r.Findings)
	}
}

// Escutar em loopback não expõe nada: o achado é sobre estar aberto PARA FORA.
func TestEscutaIgnoraLoopback(t *testing.T) {
	f := factsDeRede("/usr/local/sbin/agente", false, facts.Socket{
		Proto: "tcp", State: "LISTEN", Dir: facts.DirListen,
		LocalIP: "127.0.0.1", LocalPort: 41337,
	})
	if r := escutaSemDono.Run(escutaSemDono, f, testEnv()); len(r.Findings) != 0 {
		t.Fatalf("achados = %v", r.Findings)
	}
}

// Porta alta é aplicação que alguém não empacotou; a porta de um serviço
// conhecido é o serviço SUBSTITUÍDO, e a diferença muda a severidade inteira.
func TestEscutaPesaPortaDeServico(t *testing.T) {
	alta := factsDeRede("/usr/local/sbin/agente", false, facts.Socket{
		Proto: "tcp", State: "LISTEN", Dir: facts.DirListen,
		LocalIP: "0.0.0.0", LocalPort: 41337,
	})
	r := escutaSemDono.Run(escutaSemDono, alta, testEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevWarn {
		t.Fatalf("porta alta em /usr/local é AVISO: %v", r.Findings)
	}

	ssh := factsDeRede("/usr/local/sbin/sshd", false, facts.Socket{
		Proto: "tcp", State: "LISTEN", Dir: facts.DirListen,
		LocalIP: "0.0.0.0", LocalPort: 22,
	})
	r = escutaSemDono.Run(escutaSemDono, ssh, testEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevCritical {
		t.Fatalf("porta de serviço conhecido é CRÍTICO: %v", r.Findings)
	}
	if !strings.Contains(strings.Join(r.Findings[0].Evidence, " "), "SSH") {
		t.Error("o nome do serviço precisa aparecer: é o que explica a severidade")
	}
}

// Base de pacotes ilegível não pode virar silêncio: sem a resposta, "nenhuma
// conexão de binário sem dono" significa apenas que ninguém perguntou.
func TestRedeNaoCalaQuandoNaoPodePerguntar(t *testing.T) {
	f := &facts.Facts{
		Processes:     []facts.Process{{PID: 7, Comm: "x", Exe: "/opt/a/b"}},
		Sockets:       []facts.Socket{{PID: 7, Dir: facts.DirOut, PeerScope: facts.ScopePublic}},
		Pkg:           facts.PkgDB{Kind: "rpm"},
		PersistDenied: map[string][]string{"pkg": {"base rpm é binária: não foi consultada"}},
	}
	r := saidaSemDono.Run(saidaSemDono, f, testEnv())
	if len(r.Partial) == 0 {
		t.Fatal("sem a base de pacotes a lacuna precisa ser declarada, não engolida")
	}
}

// SO_REUSEPORT: o MESMO processo com dois sockets na mesma porta.
//
// Medido num desktop real, com root: o mdns do `adb` mantém dois sockets em
// 0.0.0.0:5353, e o check emitia um achado por SOCKET — duas linhas com texto
// idêntico, mesmo pid, mesmo endereço, mesma porta. Duas linhas iguais não são
// dois fatos, e no JSONL que a frota agrega elas contavam duas escutas onde há
// uma.
//
// O número não some: ele vira evidência, porque vários descritores dividindo
// uma escuta diz algo sobre a forma do serviço.
func TestEscutaNaMesmaPortaNaoDuplica(t *testing.T) {
	escuta := func(inode uint64) facts.Socket {
		return facts.Socket{
			Proto: "udp", State: "", Dir: facts.DirListen,
			LocalIP: "0.0.0.0", LocalPort: 5353, Inode: inode, PID: 7,
		}
	}
	f := factsDeRede("/opt/sdk/adb", false, escuta(9955173))
	f.Sockets = append(f.Sockets, escuta(9955174))

	r := escutaSemDono.Run(escutaSemDono, f, testEnv())
	if len(r.Findings) != 1 {
		t.Fatalf("dois sockets na mesma escuta são UM achado, veio %d: %v",
			len(r.Findings), r.Findings)
	}
	junto := strings.Join(r.Findings[0].Evidence, " | ")
	if !strings.Contains(junto, "2 sockets deste processo na MESMA porta") {
		t.Errorf("a contagem precisa aparecer como evidência: %q", junto)
	}
}

// E a outra direção continua valendo: portas DIFERENTES do mesmo processo são
// escutas diferentes, e agrupar por pid teria escondido a segunda.
func TestEscutasEmPortasDiferentesNaoSeFundem(t *testing.T) {
	escuta := func(porta int, inode uint64) facts.Socket {
		return facts.Socket{
			Proto: "tcp", Dir: facts.DirListen,
			LocalIP: "0.0.0.0", LocalPort: porta, Inode: inode, PID: 7,
		}
	}
	f := factsDeRede("/opt/app/server", false, escuta(8080, 1))
	f.Sockets = append(f.Sockets, escuta(9090, 2))

	r := escutaSemDono.Run(escutaSemDono, f, testEnv())
	if len(r.Findings) != 2 {
		t.Fatalf("duas portas são dois achados, veio %d: %v", len(r.Findings), r.Findings)
	}
}
