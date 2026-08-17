package checks

import (
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/facts"
)

// sock monta um socket sintético.
func sock(inode uint64, pid int, dir facts.Direction, scope facts.Scope, peer string) facts.Socket {
	host, port := peer, 443
	if i := strings.LastIndex(peer, ":"); i > 0 {
		host = peer[:i]
	}
	return facts.Socket{
		Proto: "tcp", State: "ESTAB", Inode: inode, PID: pid,
		Dir: dir, PeerScope: scope, PeerIP: host, PeerPort: port,
		LocalIP: "10.0.0.5", LocalPort: 44120,
	}
}

// sockFDs liga o processo aos sockets pelo DESCRITOR, que é como o kernel de
// fato relaciona os dois. O índice é construído por aí — e é o que faz um
// socket herdado por fork aparecer nos DOIS processos.
func sockFDs(inodes ...uint64) []facts.FD {
	var out []facts.FD
	for i, in := range inodes {
		out = append(out, facts.FD{N: 10 + i, Socket: true, SocketInode: in})
	}
	return out
}

func stdio(inode uint64) []facts.FD {
	var out []facts.FD
	for n := 0; n < 3; n++ {
		out = append(out, facts.FD{N: n, Socket: true, SocketInode: inode, Target: "socket:[x]"})
	}
	return out
}

// --- correlate.revshell (runbook §17) ---

func TestRevshellDisparaEmSaidaParaIPPublico(t *testing.T) {
	f := &facts.Facts{
		Processes: []facts.Process{{PID: 6574, Comm: "sh", Exe: "/tmp/.x", FDs: stdio(999)}},
		Sockets:   []facts.Socket{sock(999, 6574, facts.DirOut, facts.ScopePublic, "51.91.190.241")},
	}
	r := revshell.Run(revshell, f, testEnv())
	if len(r.Findings) != 1 {
		t.Fatalf("achados = %d, quer 1", len(r.Findings))
	}
	if r.Findings[0].Sev != check.SevCritical {
		t.Errorf("severidade = %s, quer CRITICAL: é a DEFINIÇÃO de reverse shell", r.Findings[0].Sev)
	}
	if !r.Findings[0].Irreversible {
		t.Error("preservar antes de matar é irreversível se pulado")
	}
}

// O falso positivo que a revisão de código identificou: ativação por socket do
// systemd (StandardInput=socket) e inetd têm EXATAMENTE a mesma forma — fd 0,1,2
// no mesmo socket. Sem descartá-los, o check dispara em sshd.socket e afins.
//
// O que separa: a DIREÇÃO. Neles o socket é de ENTRADA; num reverse shell o
// processo SAIU para o operador.
func TestRevshellNaoDisparaEmSocketActivation(t *testing.T) {
	f := &facts.Facts{
		Processes: []facts.Process{{PID: 700, PPID: 1, Comm: "sshd", Exe: "/usr/sbin/sshd", FDs: stdio(555)}},
		Sockets:   []facts.Socket{sock(555, 700, facts.DirIn, facts.ScopePublic, "203.0.113.9")},
	}
	r := revshell.Run(revshell, f, testEnv())
	if len(r.Findings) != 0 {
		t.Errorf("disparou em ativação por socket: %v", r.Findings[0].Evidence)
	}
}

// Saída para destino interno tem a mesma forma mas não é o canal com o
// operador: pode ser movimento lateral a partir de outra máquina já tomada.
// Vale o achado, não vale a mesma confiança.
func TestRevshellParaDestinoInternoEhWarn(t *testing.T) {
	f := &facts.Facts{
		Processes: []facts.Process{{PID: 42, Comm: "sh", FDs: stdio(999)}},
		Sockets:   []facts.Socket{sock(999, 42, facts.DirOut, facts.ScopePrivate, "10.0.0.9")},
	}
	r := revshell.Run(revshell, f, testEnv())
	if len(r.Findings) != 1 {
		t.Fatalf("achados = %d, quer 1", len(r.Findings))
	}
	if r.Findings[0].Sev != check.SevWarn {
		t.Errorf("severidade = %s, quer WARN", r.Findings[0].Sev)
	}
}

func TestRevshellExigeOsTresDescritores(t *testing.T) {
	// Dois iguais e um ausente não é a forma: o shell precisa LER e ESCREVER
	// pela rede.
	f := &facts.Facts{
		Processes: []facts.Process{{PID: 10, FDs: []facts.FD{
			{N: 0, Socket: true, SocketInode: 999},
			{N: 1, Socket: true, SocketInode: 999},
			{N: 2, Target: "/dev/null"},
		}}},
		Sockets: []facts.Socket{sock(999, 10, facts.DirOut, facts.ScopePublic, "1.2.3.4")},
	}
	if r := revshell.Run(revshell, f, testEnv()); len(r.Findings) != 0 {
		t.Error("fd 2 fora do socket não é a assinatura")
	}
}

func TestRevshellRegistraPTYComoInterativo(t *testing.T) {
	fds := append(stdio(999), facts.FD{N: 7, PTY: true, Target: "/dev/pts/3"})
	f := &facts.Facts{
		Processes: []facts.Process{{PID: 6574, Comm: "bash", Exe: "/bin/bash", FDs: fds}},
		Sockets:   []facts.Socket{sock(999, 6574, facts.DirOut, facts.ScopePublic, "51.91.190.241")},
	}
	r := revshell.Run(revshell, f, testEnv())
	if !strings.Contains(strings.Join(r.Findings[0].Evidence, " "), "INTERATIVO") {
		t.Errorf("PTY significa operador digitando do outro lado: %v", r.Findings[0].Evidence)
	}
}

// --- net.pivot (runbook §12.2) ---

// O defeito que a revisão encontrou: sem DIREÇÃO, o check disparava em todo
// proxy reverso — nginx público tem socket com peer público (o cliente) e
// socket para o backend interno.
func TestPivotNaoDisparaEmProxyReverso(t *testing.T) {
	f := &facts.Facts{
		Processes: []facts.Process{{PID: 900, Comm: "nginx", Exe: "/usr/sbin/nginx",
			FDs: sockFDs(1, 2)}},
		Sockets: []facts.Socket{
			sock(1, 900, facts.DirIn, facts.ScopePublic, "203.0.113.9"), // cliente
			sock(2, 900, facts.DirOut, facts.ScopePrivate, "10.0.0.9"),  // backend
		},
	}
	if r := pivot.Run(pivot, f, testEnv()); len(r.Findings) != 0 {
		t.Errorf("proxy reverso NÃO é pivô: entrada externa + saída interna.\n%v",
			r.Findings[0].Evidence)
	}
}

func TestPivotDisparaComSaidaNosDoisLados(t *testing.T) {
	f := &facts.Facts{
		Processes: []facts.Process{{PID: 3311, Comm: "node", Exe: "/usr/bin/node",
			FDs: sockFDs(1, 2, 3)}},
		Sockets: []facts.Socket{
			sock(1, 3311, facts.DirOut, facts.ScopePublic, "51.91.190.241"), // operador
			sock(2, 3311, facts.DirOut, facts.ScopePrivate, "10.0.0.9"),     // alvo interno
			sock(3, 3311, facts.DirOut, facts.ScopePrivate, "10.0.0.11"),
		},
	}
	r := pivot.Run(pivot, f, testEnv())
	if len(r.Findings) != 1 {
		t.Fatalf("achados = %d, quer 1", len(r.Findings))
	}
	ev := strings.Join(r.Findings[0].Evidence, " ")
	for _, want := range []string{"saída externa", "saída interna", "10.0.0.9"} {
		if !strings.Contains(ev, want) {
			t.Errorf("evidência sem %q: %s", want, ev)
		}
	}
}

func TestPivotExigeOsDoisLados(t *testing.T) {
	só := func(ss ...facts.Socket) *facts.Facts {
		inodes := make([]uint64, 0, len(ss))
		for _, s := range ss {
			inodes = append(inodes, s.Inode)
		}
		return &facts.Facts{
			Processes: []facts.Process{{PID: 1, Comm: "x", FDs: sockFDs(inodes...)}},
			Sockets:   ss,
		}
	}
	casos := map[string]*facts.Facts{
		"só externo": só(sock(1, 1, facts.DirOut, facts.ScopePublic, "1.2.3.4")),
		"só interno": só(sock(1, 1, facts.DirOut, facts.ScopePrivate, "10.0.0.9")),
		"loopback":   só(sock(1, 1, facts.DirOut, facts.ScopeLoopback, "127.0.0.1")),
	}
	for nome, f := range casos {
		if r := pivot.Run(pivot, f, testEnv()); len(r.Findings) != 0 {
			t.Errorf("%s não é pivô", nome)
		}
	}
}

// Um socket herdado por fork pertence aos DOIS processos. Modelar um dono só —
// o último a escrever no join — fazia um pivô cujo filho ficou com uma das
// pernas não disparar em ninguém.
func TestSocketHerdadoPorForkApareceNosDoisProcessos(t *testing.T) {
	ext := sock(1, 100, facts.DirOut, facts.ScopePublic, "51.91.190.241")
	int1 := sock(2, 100, facts.DirOut, facts.ScopePrivate, "10.0.0.9")
	f := &facts.Facts{
		Processes: []facts.Process{
			{PID: 100, Comm: "pai", Exe: "/tmp/.x", FDs: sockFDs(1, 2)},
			{PID: 101, PPID: 100, Comm: "filho", Exe: "/tmp/.x", FDs: sockFDs(1, 2)},
		},
		Sockets: []facts.Socket{ext, int1},
	}
	r := pivot.Run(pivot, f, testEnv())
	if len(r.Findings) != 2 {
		t.Fatalf("achados = %d, quer 2: os dois processos detêm as duas pernas", len(r.Findings))
	}
}

// E dup2 do mesmo socket sobre vários descritores não pode contar como vários
// sockets: seria inventar conexão que não existe.
func TestDupDoMesmoSocketNaoDuplica(t *testing.T) {
	f := &facts.Facts{
		Processes: []facts.Process{{PID: 10, Comm: "x", FDs: sockFDs(7, 7, 7)}},
		Sockets:   []facts.Socket{sock(7, 10, facts.DirOut, facts.ScopePublic, "1.2.3.4")},
	}
	if n := len(f.SocketsOf(10)); n != 1 {
		t.Errorf("SocketsOf devolveu %d sockets para três fds do mesmo, quer 1", n)
	}
}

// Socket sem dono identificado significa que o check não pôde avaliar aquele
// processo. Sem virar cobertura parcial, uma execução sem root reportaria
// cobertura completa tendo enxergado só os próprios sockets.
func TestSocketSemDonoViraCoberturaParcial(t *testing.T) {
	f := &facts.Facts{Sockets: []facts.Socket{
		{State: "ESTAB", Inode: 1, PID: 0},
		{State: "ESTAB", Inode: 2, PID: 0},
	}}
	for _, c := range []check.Check{revshell, pivot} {
		if r := c.Run(c, f, testEnv()); len(r.Partial) == 0 {
			t.Errorf("%s: conexão sem dono precisa virar cobertura parcial", c.ID)
		}
	}
}
