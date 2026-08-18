package info

import (
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/facts"
)

// sockOut monta uma conexão de saída já classificada.
func sockOut(pid int, peer string, porta int, escopo facts.Scope) facts.Socket {
	return facts.Socket{
		Proto: "tcp", State: "ESTAB", LocalIP: "10.0.0.5", LocalPort: 40000 + porta,
		PeerIP: peer, PeerPort: porta, Dir: facts.DirOut, PeerScope: escopo, PID: pid,
	}
}

func hostComRede(socks []facts.Socket, procs []facts.Process) *facts.Facts {
	f := &facts.Facts{Sockets: socks, Processes: procs}
	f.Index()
	return f
}

// O padrão que nenhum `ss` dá: um destino por host, sempre na MESMA porta.
// É a forma de varredura e de movimento lateral, e ela some numa lista de
// quarenta linhas idênticas exceto pelo IP.
func TestLequeDeSaidaEhReconhecidoENomeado(t *testing.T) {
	var socks []facts.Socket
	for i := 0; i < 40; i++ {
		socks = append(socks, sockOut(900, "10.0.9."+itoaT(i), 22, facts.ScopePrivate))
	}
	f := hostComRede(socks, []facts.Process{
		{PID: 900, Exe: "/usr/bin/python3", Comm: "python3"},
	})

	c := CensoDaRede(f)
	var achou *Padrao
	for i := range c.Padroes {
		if c.Padroes[i].Tipo == "leque de saída" {
			achou = &c.Padroes[i]
		}
	}
	if achou == nil {
		t.Fatalf("quarenta destinos distintos na porta 22 é leque: %+v", c.Padroes)
	}
	if achou.N != 40 {
		t.Errorf("N = %d, queria 40", achou.N)
	}
	if !strings.Contains(achou.Detalhe, "SSH") {
		t.Errorf("a porta é o que dá o sentido, e ela precisa aparecer: %q", achou.Detalhe)
	}
	// E o agrupamento: quarenta conexões de um processo são UMA linha.
	if len(c.Saida) != 1 || c.Saida[0].Conexoes != 40 || c.Saida[0].Destinos != 40 {
		t.Errorf("saída = %+v", c.Saida)
	}
}

// O leque em 443 CONTINUA sendo reportado, e a primeira versão deste arquivo o
// descartava.
//
// Descartar estava errado por construção: a porta é exatamente o campo que o
// atacante escolhe. C2 moderno usa 443 de propósito, e filtrar por porta é
// filtrar pelo que o adversário controla — a ferramenta ficaria cega
// justamente onde ele decidiu se esconder. O que a porta muda é a RESSALVA,
// não a existência da linha.
func TestLequeEmPortaDeWebEhReportadoComRessalva(t *testing.T) {
	var socks []facts.Socket
	for i := 0; i < 40; i++ {
		socks = append(socks, sockOut(700, "93.184.216."+itoaT(i), 443, facts.ScopePublic))
	}
	f := hostComRede(socks, []facts.Process{
		{PID: 700, Exe: "/usr/lib/firefox/firefox", Comm: "firefox"},
	})
	c := CensoDaRede(f)
	var achou *Padrao
	for i := range c.Padroes {
		if c.Padroes[i].Tipo == "leque de saída" {
			achou = &c.Padroes[i]
		}
	}
	if achou == nil {
		t.Fatal("o leque em 443 não pode sumir: é a porta que C2 escolhe")
	}
	if !achou.Comum {
		t.Error("mas precisa vir marcado: em 443 esta forma também é a de " +
			"navegador e de atualizador")
	}
	if !strings.Contains(achou.Detalhe, "NÃO separa") {
		t.Errorf("e a ressalva precisa dizer o que separa os dois: %q", achou.Detalhe)
	}
}

// E a ordem: leque em porta de SERVIÇO vem antes do leque em porta de web. Num
// desktop o de web aparece toda vez, e pô-lo no topo enterraria o que muda o
// que o operador faz em seguida. Ordenar não é esconder.
func TestLequeDeServicoVemAntesDoDeWeb(t *testing.T) {
	var socks []facts.Socket
	for i := 0; i < 40; i++ {
		socks = append(socks, sockOut(700, "93.184.216."+itoaT(i), 443, facts.ScopePublic))
	}
	for i := 0; i < 10; i++ {
		socks = append(socks, sockOut(900, "10.0.9."+itoaT(i), 22, facts.ScopePrivate))
	}
	f := hostComRede(socks, []facts.Process{
		{PID: 700, Exe: "/usr/lib/firefox/firefox"},
		{PID: 900, Exe: "/usr/bin/python3"},
	})
	ps := CensoDaRede(f).Padroes
	if len(ps) != 2 {
		t.Fatalf("padrões = %+v", ps)
	}
	if ps[0].Comum || !ps[1].Comum {
		t.Errorf("o de porta 22 vem primeiro mesmo tendo N MENOR: %+v", ps)
	}
}

// SO_REUSEPORT: um serviço divide a porta entre vários descritores, e o `ss`
// imprime uma linha por descritor. Um nginx com doze workers parecia doze
// portas abertas.
func TestReusePortEhUmaEscutaSo(t *testing.T) {
	var socks []facts.Socket
	for i := 0; i < 12; i++ {
		socks = append(socks, facts.Socket{
			Proto: "tcp", State: "LISTEN", LocalIP: "0.0.0.0", LocalPort: 443,
			Dir: facts.DirListen, PID: 500,
		})
	}
	f := hostComRede(socks, []facts.Process{{PID: 500, Exe: "/usr/sbin/nginx", Comm: "nginx"}})
	c := CensoDaRede(f)
	if len(c.Escutas) != 1 {
		t.Fatalf("%d escutas para uma porta dividida: %+v", len(c.Escutas), c.Escutas)
	}
	if c.Escutas[0].Sockets != 12 {
		t.Errorf("sockets = %d: o número precisa sobreviver, ou some a explicação "+
			"de por que a linha não se repete", c.Escutas[0].Sockets)
	}
	if !c.Escutas[0].Exposta {
		t.Error("0.0.0.0 não é loopback: a porta está aberta para fora")
	}
}

// Escuta em loopback NÃO é superfície de ataque, e misturar as duas faz o
// operador olhar para a linha errada primeiro.
func TestLoopbackNaoContaComoExposta(t *testing.T) {
	f := hostComRede([]facts.Socket{
		{Proto: "tcp", State: "LISTEN", LocalIP: "127.0.0.1", LocalPort: 5432,
			Dir: facts.DirListen, PID: 1},
		{Proto: "tcp", State: "LISTEN", LocalIP: "0.0.0.0", LocalPort: 22,
			Dir: facts.DirListen, PID: 2},
	}, []facts.Process{
		{PID: 1, Exe: "/usr/bin/postgres"}, {PID: 2, Exe: "/usr/sbin/sshd"},
	})
	c := CensoDaRede(f)
	// A EXPOSTA vem primeiro: a ordem é a da urgência.
	if len(c.Escutas) != 2 || !c.Escutas[0].Exposta || c.Escutas[1].Exposta {
		t.Fatalf("escutas = %+v", c.Escutas)
	}
}

// Socket sem dono identificado é LACUNA, não ausência: sem root o fd de
// processo alheio é ilegível, e o socket existe do mesmo jeito.
func TestSocketSemDonoEhContado(t *testing.T) {
	f := hostComRede([]facts.Socket{
		{Proto: "tcp", State: "LISTEN", LocalIP: "0.0.0.0", LocalPort: 8080,
			Dir: facts.DirListen, PID: 0},
	}, nil)
	c := CensoDaRede(f)
	if c.SemDono != 1 {
		t.Errorf("semDono = %d", c.SemDono)
	}
	if !c.Escutas[0].DonoDesconhecido {
		t.Error("'ninguém segura' e 'não pude ver quem segura' são respostas opostas")
	}
}

// Teto NÃO LIDO fica de fora: uma linha "0 de 0" é pior que a ausência dela,
// porque tem cara de medida.
func TestTetoNaoLidoNaoViraLinha(t *testing.T) {
	c := CensoDaRede(hostComRede(nil, nil))
	if len(c.Tetos) != 0 {
		t.Errorf("sem limites lidos não há teto a mostrar: %+v", c.Tetos)
	}
}

// E com os limites lidos, a ocupação é medida contra eles.
func TestTetoDePortaEfemeraContaTimeWait(t *testing.T) {
	f := &facts.Facts{
		LimitesRede: facts.LimitesDeRede{
			PortaEfemeraMin: 32768, PortaEfemeraMax: 60999, FaixaLida: true,
		},
	}
	for i := 0; i < 28000; i++ {
		f.Sockets = append(f.Sockets, facts.Socket{
			Proto: "tcp", State: "TIME-WAIT", Dir: facts.DirOut,
			PeerIP: "10.0.0.1", PeerPort: 80,
		})
	}
	f.Index()
	c := CensoDaRede(f)
	var achou bool
	for _, t2 := range c.Tetos {
		if t2.Nome == "portas efêmeras" {
			achou = true
			if t2.Teto != 28232 {
				t.Errorf("faixa = %d, queria 60999-32768+1", t2.Teto)
			}
			if !t2.Perto {
				t.Error("28000 TIME-WAIT numa faixa de 28232 é o motivo de o " +
					"connect estar falhando com EADDRNOTAVAIL")
			}
		}
	}
	if !achou {
		t.Errorf("tetos = %+v", c.Tetos)
	}
}

func itoaT(n int) string {
	if n < 10 {
		return string(rune('0' + n))
	}
	return string(rune('0'+n/10)) + string(rune('0'+n%10))
}

// A varredura de PORTAS entrava como "pool" — o rótulo BENIGNO.
//
// A condição do pool olhava só o número de ENDEREÇOS distintos, e dezesseis
// portas do mesmo host somam um endereço. A ferramenta dava nome de cliente de
// banco para a forma exata de um scanner. Foi achado rodando um scan de portas
// contra o próprio loopback e lendo a saída.
func TestVarreduraDePortasNaoEhChamadaDePool(t *testing.T) {
	portas := []int{1521, 2375, 3306, 3389, 5432, 5601, 5900, 6379, 7001, 8080,
		9200, 9300, 11211, 15672, 27017, 8443}
	var socks []facts.Socket
	for _, p := range portas {
		socks = append(socks, sockOut(900, "10.0.0.9", p, facts.ScopePrivate))
	}
	f := hostComRede(socks, []facts.Process{{PID: 900, Exe: "/opt/scanner/bin/explorer"}})

	c := CensoDaRede(f)
	var varredura, pool *Padrao
	for i := range c.Padroes {
		switch c.Padroes[i].Tipo {
		case "varredura de portas":
			varredura = &c.Padroes[i]
		case "pool":
			pool = &c.Padroes[i]
		}
	}
	if pool != nil {
		t.Errorf("dezesseis PORTAS de um host não são pool de conexão: %+v", pool)
	}
	if varredura == nil {
		t.Fatalf("padrões = %+v", c.Padroes)
	}
	if varredura.N != len(portas) {
		t.Errorf("N = %d, queria %d", varredura.N, len(portas))
	}
	// As portas alcançadas dizem o que a varredura PROCURAVA, e é isso que
	// separa inventário de caça a banco exposto.
	if !strings.Contains(varredura.Detalhe, "3306") {
		t.Errorf("a amostra de portas precisa aparecer: %q", varredura.Detalhe)
	}
	// E o agrupamento continua: um destino, mesmo com dezesseis endpoints.
	if c.Saida[0].Destinos != 1 || c.Saida[0].Endpoints != len(portas) {
		t.Errorf("destinos=%d endpoints=%d — são os dois números que separam as "+
			"três formas", c.Saida[0].Destinos, c.Saida[0].Endpoints)
	}
}

// E o pool de verdade continua sendo pool: mesmo endereço E mesma porta.
func TestPoolDeVerdadeEhMesmoEndpoint(t *testing.T) {
	var socks []facts.Socket
	for i := 0; i < 30; i++ {
		socks = append(socks, sockOut(800, "10.0.0.9", 5432, facts.ScopePrivate))
	}
	f := hostComRede(socks, []facts.Process{{PID: 800, Exe: "/usr/bin/app"}})
	c := CensoDaRede(f)
	if len(c.Padroes) != 1 || c.Padroes[0].Tipo != "pool" {
		t.Fatalf("padrões = %+v", c.Padroes)
	}
	if !c.Padroes[0].Comum {
		t.Error("pool é a forma normal de cliente de banco: precisa vir marcado")
	}
}
