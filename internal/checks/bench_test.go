package checks

import (
	"strconv"
	"testing"
	"time"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/facts"
)

// bigFacts monta o retrato de um servidor grande de verdade: muitos processos,
// muitas conexões. É o tamanho que revela custo quadrático — num host de 300
// processos tudo parece rápido.
func bigFacts(nproc, nsock int) *facts.Facts {
	f := &facts.Facts{}
	for i := 0; i < nproc; i++ {
		p := facts.Process{
			PID: i + 1, PPID: 1, UID: 1000, EUID: 1000,
			Comm: "svc", Exe: "/usr/bin/svc", Cgroup: "/system.slice/svc.service",
			NS: map[string]string{"mnt": "mnt:[4026531840]"},
		}
		for n := 0; n < 8; n++ {
			p.FDs = append(p.FDs, facts.FD{
				N: n, Socket: true, SocketInode: uint64(i*8 + n),
				Target: "socket:[" + strconv.Itoa(i*8+n) + "]",
			})
		}
		f.Processes = append(f.Processes, p)
	}
	for i := 0; i < nsock; i++ {
		f.Sockets = append(f.Sockets, facts.Socket{
			Proto: "tcp", State: "ESTAB", Inode: uint64(i),
			PID: (i / 8) + 1, Dir: facts.DirOut, PeerScope: facts.ScopePrivate,
			LocalIP: "10.0.0.5", LocalPort: 40000 + i%20000,
			PeerIP: "10.0.0.9", PeerPort: 443,
		})
	}
	return f
}

func benchAll(b *testing.B, nproc, nsock int) {
	f := bigFacts(nproc, nsock)
	e := testEnv()
	all := check.All()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		check.Run(all, f, e)
	}
}

func BenchmarkChecks_500proc_2ksock(b *testing.B)  { benchAll(b, 500, 2000) }
func BenchmarkChecks_2kproc_16ksock(b *testing.B)  { benchAll(b, 2000, 16000) }
func BenchmarkChecks_5kproc_40ksock(b *testing.B)  { benchAll(b, 5000, 40000) }
func BenchmarkChecks_2kproc_100ksock(b *testing.B) { benchAll(b, 2000, 100000) }

// TestCustoNaoEhQuadratico é uma trava, não uma medição. O número vem de um
// defeito real: `net.pivot` perguntava "quais sockets são deste processo" para
// CADA processo, varrendo a tabela inteira toda vez. Com 5 mil processos e 40
// mil conexões isso media 962ms — só de laço, antes da coleta, e mais que o
// orçamento inteiro do `wtf`.
//
// Com índice por chave, o mesmo caso mede ~10ms. O limite de 300ms tem 30× de
// folga sobre o valor bom e 3× de margem sob o valor ruim: não vai piscar em
// máquina carregada, e não deixa passar a volta do custo quadrático.
func TestCustoNaoEhQuadratico(t *testing.T) {
	if testing.Short() {
		t.Skip("teste de custo: pulado em -short")
	}
	f := bigFacts(5000, 40000)
	e := testEnv()

	inicio := time.Now()
	check.Run(check.All(), f, e)
	levou := time.Since(inicio)

	if levou > 300*time.Millisecond {
		t.Errorf("checks levaram %v para 5000 processos e 40000 conexões.\n"+
			"Isso é o perfil do custo QUADRÁTICO que o índice de facts.Index() "+
			"existe para evitar — procure por varredura de f.Sockets dentro de "+
			"um laço sobre f.Processes.", levou)
	}
}
