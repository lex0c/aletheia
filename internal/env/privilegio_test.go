package env

import (
	"os"
	"strconv"
	"strings"
	"testing"
)

// CapRoot É ALCANCE, NÃO euid.
//
// A concessão era `os.Geteuid() == 0`. Num processo uid=1000 com
// CAP_DAC_READ_SEARCH e CAP_SYS_PTRACE — que é como um serviço de coleta
// costuma ser empacotado, justamente para NÃO rodar como root — as quatro
// superfícies que a razão de CapRoot nomeia estão todas alcançáveis, e mesmo
// assim os coletores que consultam e.Has(CapRoot) pulavam o trabalho e
// declaravam lacuna.
//
// Lacuna fabricada é o espelho do erro que esta ferramenta combate. Ela nunca
// parece errada — "não olhei" soa sempre prudente —, e por isso ninguém a
// procura.
func TestCapRootOlhaCapabilityENaoSoEuid(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("como root a concessão é trivial; o caso que importa é uid != 0")
	}

	const (
		dac    = uint64(1) << capDACReadSearch
		ptrace = uint64(1) << capSysPtrace
		admin  = uint64(1) << 21 // CAP_SYS_ADMIN
		chown  = uint64(1) << 0
	)

	casos := []struct {
		nome    string
		eff     uint64
		lidas   bool
		concede bool
		naRazao string
	}{
		{"sem capability nenhuma", 0, true, false, "environ, dono de socket"},
		{"só CAP_CHOWN (não é de observação)", chown, true, false, "environ, dono de socket"},
		{"só leitura de arquivo", dac, true, false, "falta CAP_SYS_PTRACE"},
		{"só ptrace", ptrace, true, false, "falta capability de leitura"},
		{"leitura + ptrace", dac | ptrace, true, true, ""},
		// CAP_SYS_ADMIN é a capability mais larga do Linux e NÃO é atalho para
		// as duas checagens desta pergunta: o kernel não a consulta no bypass de
		// permissão DAC nem no acesso ao /proc alheio. Um processo só com ela
		// continua levando EACCES em /etc/shadow.
		//
		// Esta linha já esteve escrita com `true`, e o teste travava o erro no
		// lugar. Conceder CapRoot sem alcance faz o check rodar como se tivesse
		// observado — e aí a ausência que ele reporta vira evidência.
		{"CAP_SYS_ADMIN sozinha", admin, true, false, "environ, dono de socket"},
		{"CAP_SYS_ADMIN + ptrace, sem DAC", admin | ptrace, true, false, "falta capability de leitura"},
		{"não deu para ler o /proc", 0, false, false, "não foi possível ler as capabilities"},
	}

	original := lerCapsEfetivas
	t.Cleanup(func() { lerCapsEfetivas = original })

	for _, c := range casos {
		t.Run(c.nome, func(t *testing.T) {
			lerCapsEfetivas = func() (uint64, bool) { return c.eff, c.lidas }

			alcanca, razao := alcancaSuperficiePrivilegiada()
			if alcanca != c.concede {
				t.Fatalf("concedeu=%v, queria %v — razão: %s", alcanca, c.concede, razao)
			}
			if c.concede {
				if razao != "" {
					t.Errorf("concedeu E deu razão de recusa: %s", razao)
				}
				return
			}
			if !strings.Contains(razao, c.naRazao) {
				t.Errorf("a recusa precisa dizer o que FALTA e o que fica invisível.\n"+
					"queria %q em: %s", c.naRazao, razao)
			}

			// E a recusa tem de chegar ao Env como razão, não como silêncio: é
			// ela que vira a lacuna declarada no relatório.
			e := &Env{Source: SourceLive, CapReason: map[string]string{}}
			e.probeCaps()
			if e.Has(CapRoot) {
				t.Error("o Env concedeu CapRoot contra o alcance medido")
			}
			if e.CapReason["root"] == "" {
				t.Error("CapRoot negada sem razão: a lacuna chega ao relatório muda")
			}
		})
	}
}

// E o caminho inteiro: com as duas capabilities, o Env CONCEDE.
func TestEnvConcedeCapRootComAsDuasCapabilities(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("como root a concessão é trivial")
	}
	original := lerCapsEfetivas
	t.Cleanup(func() { lerCapsEfetivas = original })
	lerCapsEfetivas = func() (uint64, bool) {
		return uint64(1)<<capDACReadSearch | uint64(1)<<capSysPtrace, true
	}

	e := &Env{Source: SourceLive, CapReason: map[string]string{}}
	e.probeCaps()
	if !e.Has(CapRoot) {
		t.Fatalf("uid=%d com CAP_DAC_READ_SEARCH e CAP_SYS_PTRACE alcança "+
			"environ, dono de socket, /etc/shadow e /root — negar CapRoot ali "+
			"faz o coletor pular trabalho que ele conseguiria fazer e declarar "+
			"uma lacuna que não existe. Razão dada: %q",
			os.Geteuid(), e.CapReason["root"])
	}
	if r := e.CapReason["root"]; r != "" {
		t.Errorf("concedeu e deixou razão de recusa: %q", r)
	}
}

// capget(2) E /proc/self/status RESPONDEM A MESMA COISA.
//
// capget é o caminho primário porque não depende de /proc estar montado — um
// shell de resgate, um initramfs ou um contêiner mínimo são exatamente onde
// /proc pode faltar e onde esta ferramenta é usada. O /proc fica como segundo
// caminho.
//
// Dois caminhos para o mesmo fato divergem em silêncio, e aqui a divergência
// seria entre o privilégio que o servidor ANUNCIA e o alcance que a coleta
// ASSUME. A catraca compara os dois sempre que ambos respondem — e vale de
// verdade quando roda como root num contêiner, onde CapEff não é zero.
func TestCapgetEProcConcordam(t *testing.T) {
	pelaSyscall, okSys := capgetEfetivas()
	if !okSys {
		t.Skip("capget indisponível neste kernel")
	}

	b, err := os.ReadFile(statusDoProprioProcesso)
	if err != nil {
		t.Skip("sem /proc/self/status para comparar")
	}
	var peloProc uint64
	achou := false
	for _, ln := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(ln, ":")
		if !ok || k != "CapEff" {
			continue
		}
		peloProc, err = strconv.ParseUint(strings.TrimSpace(v), 16, 64)
		if err != nil {
			t.Fatalf("CapEff ilegível: %v", err)
		}
		achou = true
		break
	}
	if !achou {
		t.Skip("/proc/self/status sem CapEff")
	}

	if pelaSyscall != peloProc {
		t.Fatalf("capget(2) devolveu %016x e /proc/self/status devolveu %016x.\n"+
			"Os dois caminhos descrevem o MESMO conjunto: divergir aqui é o "+
			"servidor anunciar um privilégio e a coleta assumir outro.",
			pelaSyscall, peloProc)
	}
	// Os bits ALTOS são a metade que se perde ao ler só data[0] do capget:
	// CAP_SYSLOG (34), CAP_PERFMON (38) e CAP_BPF (39) moram lá, e são
	// capabilities de observação.
	t.Logf("CapEff=%016x (bits altos: %08x)", pelaSyscall, uint32(pelaSyscall>>32))
}
