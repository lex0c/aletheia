package mcp

import (
	"os"
	"strconv"
	"strings"
)

// O privilégio DESTE processo, declarado em voz alta.
//
// # Por que euid não basta
//
// "Não estou como root" é a resposta que quase todo mundo dá, e ela é
// incompleta. Um processo `uid=1000` com CAP_DAC_READ_SEARCH lê /etc/shadow;
// com CAP_SYS_PTRACE lê a memória de qualquer processo; com CAP_BPF enumera
// programas eBPF. Nada disso aparece num `id`. Um servidor que anuncia
// "euid=1000, não privilegiado" enquanto carrega essas capabilities está
// descrevendo errado o próprio alcance — e é o operador que decide, com base
// nessa descrição, o que autorizar.
//
// A lista abaixo é deliberadamente CURTA: só as capabilities que mudam o que
// este servidor consegue OBSERVAR. Um dump completo das 40+ seria inventário,
// e inventário longo é o que ninguém lê.

// A leitura é de /proc/self/status com os.ReadFile, e não com env.Env, de
// propósito: o Env em modo snapshot é o ambiente DA COLETA — travado na raiz da
// imagem, quando houver — e a pergunta aqui é sobre ESTE processo, na máquina
// onde ele roda. Passar pelo Env leria o /proc de outro host.
const statusDoProprioProcesso = "/proc/self/status"

var capsDeObservacao = []struct {
	bit    uint
	nome   string
	efeito string
}{
	{0, "CAP_CHOWN", ""},
	{1, "CAP_DAC_OVERRIDE", "ignora permissão de arquivo: lê qualquer coisa"},
	{2, "CAP_DAC_READ_SEARCH", "ignora permissão de LEITURA e de travessia de diretório"},
	{3, "CAP_FOWNER", "age como dono de qualquer arquivo (inclusive O_NOATIME alheio)"},
	{12, "CAP_NET_ADMIN", "administra rede: enumera tc, XDP e qdisc"},
	{16, "CAP_SYS_MODULE", "carrega e descarrega módulo de kernel"},
	{17, "CAP_SYS_RAWIO", "acessa /dev/mem e portas de I/O"},
	{19, "CAP_SYS_PTRACE", "lê a memória e o /proc de qualquer processo"},
	{21, "CAP_SYS_ADMIN", "praticamente root para efeito de observação"},
	{34, "CAP_SYSLOG", "lê o ring buffer do kernel (dmesg)"},
	{38, "CAP_PERFMON", "abre perf_event e lê contadores"},
	{39, "CAP_BPF", "enumera e carrega programas eBPF"},
}

// Privilegio é o que este processo pode ver, e é reportado em session.status e
// no server/discover.
type Privilegio struct {
	UID  int  `json:"uid"`
	EUID int  `json:"euid"`
	Root bool `json:"root"`

	// CapsLidas separa "nenhuma capability" de "não consegui olhar". Sem ela, um
	// /proc não montado produziria a lista vazia — e a lista vazia se leria como
	// "processo sem privilégio nenhum", que é a afirmação mais tranquilizadora
	// possível a partir de uma leitura que não aconteceu.
	CapsLidas    bool     `json:"caps_read"`
	CapsEfetivas []string `json:"effective_caps,omitempty"`

	// Elevado é root OU qualquer capability de observação presente. É o campo
	// que responde a pergunta que o operador de fato faz.
	Elevado bool `json:"elevated"`

	// Explicacao diz o que a elevação SIGNIFICA, no formato do resto da
	// ferramenta: o número vem com o que ele quer dizer.
	Explicacao []string `json:"elevation_notes,omitempty"`
}

// LerPrivilegio sonda este processo.
func LerPrivilegio() Privilegio {
	p := Privilegio{UID: os.Getuid(), EUID: os.Geteuid()}
	p.Root = p.EUID == 0

	b, err := os.ReadFile(statusDoProprioProcesso)
	if err != nil {
		// Sem /proc não há como saber, e "não sei" é a resposta. Root continua
		// verdadeiro pelo euid, que veio de uma syscall e não do filesystem.
		p.Elevado = p.Root
		if p.Root {
			p.Explicacao = []string{"euid 0: root"}
		}
		return p
	}
	for _, ln := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(ln, ":")
		if !ok || k != "CapEff" {
			continue
		}
		eff, err := strconv.ParseUint(strings.TrimSpace(v), 16, 64)
		if err != nil {
			break
		}
		p.CapsLidas = true
		for _, c := range capsDeObservacao {
			if eff&(1<<c.bit) == 0 {
				continue
			}
			p.CapsEfetivas = append(p.CapsEfetivas, c.nome)
			if c.efeito != "" {
				p.Explicacao = append(p.Explicacao, c.nome+": "+c.efeito)
			}
		}
		break
	}
	p.Elevado = p.Root || len(p.Explicacao) > 0
	if p.Root {
		p.Explicacao = append([]string{"euid 0: root"}, p.Explicacao...)
	}
	return p
}
