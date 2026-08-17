package checks

import (
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/facts"
)

// Agrupar por DETENTOR é o que mantém o inventário legível: um processo com
// quatro sockets é um fato, não quatro linhas.
func TestPacketSocketAgrupaPorDetentor(t *testing.T) {
	f := &facts.Facts{SocketsBrutos: []facts.SocketBruto{
		{Familia: "packet", Proto: "ARP", ProtoNum: 0x0806, Inode: 1, PID: 40, Comm: "dhcpcd", IfaceNome: "eth0", Ativo: true},
		{Familia: "packet", Proto: "IPv4", ProtoNum: 0x0800, Inode: 2, PID: 40, Comm: "dhcpcd", IfaceNome: "eth0", Ativo: true},
		{Familia: "raw6", Proto: "ICMPv6", ProtoNum: 58, Inode: 3, PID: 41, Comm: "NetworkManager", Ativo: true},
	}}
	r := socketDeCaptura.Run(socketDeCaptura, f, testEnv())
	if len(r.Findings) != 2 {
		t.Fatalf("achados = %d, queria um por detentor: %v", len(r.Findings), r.Findings)
	}
	for _, fd := range r.Findings {
		if fd.Sev != check.SevManual {
			t.Errorf("%s: sev = %v — inventário não acusa", fd.Subject, fd.Sev)
		}
	}
	if !strings.Contains(strings.Join(r.Findings[0].Evidence, " "), "2 socket(s)") {
		t.Errorf("o detentor com dois sockets precisa aparecer contado: %v", r.Findings[0].Evidence)
	}
}

// Sem root o socket aparece e o DONO não. Dizer "4 sockets de captura" sem
// dizer que ninguém foi identificado deixaria o operador achar que a lista tem
// nome.
func TestPacketSocketSemDonoDeclara(t *testing.T) {
	f := &facts.Facts{
		SocketsBrutos: []facts.SocketBruto{
			{Familia: "packet", Proto: "ETH_P_ALL (TODO o tráfego)", ProtoNum: 3, Inode: 9, Ativo: true},
		},
		Partial: map[string][]string{"pacote": {"1 de 1 sockets sem dono identificado"}},
	}
	r := socketDeCaptura.Run(socketDeCaptura, f, testEnv())
	if len(r.Findings) != 1 || r.Findings[0].Subject != "dono não identificado" {
		t.Fatalf("achados = %v", r.Findings)
	}
	junto := strings.Join(r.Findings[0].Evidence, " | ")
	if !strings.Contains(junto, "NÃO foi identificado") {
		t.Errorf("a evidência precisa dizer que o dono não foi identificado: %q", junto)
	}
	// ETH_P_ALL é a distinção objetiva do check, e a asserção precisa ser na
	// FRASE que a decisão produz — não em "TODO o tráfego", que também está no
	// nome do protocolo e passaria com o `if` inteiro apagado. Foi um
	// sobrevivente de mutação que mostrou isso: o teste era decorativo.
	if !strings.Contains(junto, "recebe o que passa pela interface") {
		t.Errorf("a consequência da captura ampla precisa ser dita: %q", junto)
	}
	if len(r.Partial) == 0 {
		t.Error("a falta de dono precisa degradar a cobertura")
	}
}

// Interface promíscua é CONTEXTO — ponte de contêiner e de VM ligam isso por
// desenho. Tratá-la como achado faria a ferramenta acusar todo host com docker.
func TestPacketSocketPromiscuaEhContexto(t *testing.T) {
	f := &facts.Facts{
		SocketsBrutos: []facts.SocketBruto{{Familia: "packet", Proto: "ARP", Inode: 1, PID: 7, Comm: "x", Ativo: true}},
		Interfaces: []facts.Interface{
			{Nome: "eth0", Index: 2},
			{Nome: "br-1a2b", Index: 3, Promisc: true},
		},
	}
	r := socketDeCaptura.Run(socketDeCaptura, f, testEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevManual {
		t.Fatalf("promíscuo não pode mudar a severidade: %v", r.Findings)
	}
	junto := strings.Join(r.Findings[0].Evidence, " | ")
	if !strings.Contains(junto, "br-1a2b") || !strings.Contains(junto, "contexto, não achado") {
		t.Errorf("a interface promíscua precisa entrar como contexto: %q", junto)
	}
}

// Host sem socket de captura não produz inventário: uma linha dizendo "zero"
// seria ruído em todo contêiner da matriz.
func TestPacketSocketCalaSemSockets(t *testing.T) {
	r := socketDeCaptura.Run(socketDeCaptura, &facts.Facts{}, testEnv())
	if len(r.Findings) != 0 {
		t.Errorf("sem socket de captura não há inventário: %v", r.Findings)
	}
}

// O falso positivo que a suíte inteira pegou: o socket que o runtime de
// contêiner deixa no namespace não lê nada, e a §2.6 pergunta por quem LÊ.
func TestPacketSocketIgnoraInerte(t *testing.T) {
	f := &facts.Facts{SocketsBrutos: []facts.SocketBruto{
		{Familia: "packet", Proto: "nenhum (bind sem protocolo)", ProtoNum: 0, Inode: 15015108},
	}}
	r := socketDeCaptura.Run(socketDeCaptura, f, testEnv())
	if len(r.Findings) != 0 {
		t.Errorf("socket inerte não lê tráfego e não entra no inventário: %v", r.Findings)
	}
}
