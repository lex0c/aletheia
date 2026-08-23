package mcp

import (
	"os"

	"github.com/lex0c/aletheia/internal/env"
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

// Toda entrada tem `efeito` preenchido, e isso não é estilo: é o critério de
// pertencer à lista. Havia um CAP_CHOWN aqui, com efeito vazio — e ele não é
// capability de OBSERVAÇÃO, é de mutação: trocar o dono de um arquivo não
// mostra nada que já não se veja. A tabela se chama capsDeObservacao, e ele não
// era uma.
//
// A presença dele acoplava a resposta à prosa: Elevado saía de `efeito != ""`,
// então um processo só com CAP_CHOWN reportava elevated:false porque eu não
// tinha escrito descrição para aquela linha. A resposta estava certa por
// acidente, e acidente não é decisão.
var capsDeObservacao = []struct {
	bit    uint
	nome   string
	efeito string
}{
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

	// O leitor de CapEff mora em internal/env porque é LÁ que ele decide algo:
	// a concessão de env.CapRoot passou a olhar capability, e não só euid. Duas
	// cópias do mesmo parser divergiriam em silêncio — e a divergência seria
	// entre o que o servidor ANUNCIA de privilégio e o que a coleta ASSUME dele.
	eff, lidas := env.CapsEfetivasDoProcesso()
	if !lidas {
		// Sem /proc não há como saber, e "não sei" é a resposta. Root continua
		// verdadeiro pelo euid, que veio de uma syscall e não do filesystem.
		p.Elevado = p.Root
		if p.Root {
			p.Explicacao = []string{"euid 0: root"}
		}
		return p
	}
	p.CapsLidas = true
	for _, c := range capsDeObservacao {
		if eff&(1<<c.bit) == 0 {
			continue
		}
		p.CapsEfetivas = append(p.CapsEfetivas, c.nome)
		p.Explicacao = append(p.Explicacao, c.nome+": "+c.efeito)
	}
	// Da LISTA, e não do texto: estar na tabela é o critério, e toda entrada
	// dela muda o que este servidor consegue observar.
	p.Elevado = p.Root || len(p.CapsEfetivas) > 0
	if p.Root {
		p.Explicacao = append([]string{"euid 0: root"}, p.Explicacao...)
	}
	return p
}

// ExigeConsentimento decide se este processo precisa do --allow-root, e diz por
// quê.
//
// # "Não sei" não é "não tenho"
//
// A decisão era `priv.Elevado`, e Elevado é falso quando as capabilities não
// puderam ser lidas — de modo que a incerteza virava a resposta mais
// tranquilizadora possível, exatamente na direção que este projeto combate em
// todo lugar menos aqui. capget(2) tornou a leitura quase infalível, e é
// justamente por isso que a falha dela merece desconfiança: se nem o kernel
// respondeu, este processo não sabe o que consegue ver.
//
// A recusa vale só em modo de AQUISIÇÃO. Servindo um artefato, o servidor não
// lê o host: o privilégio não muda uma linha do que chega ao modelo, e recusar
// ali tiraria o `--snapshot` de ambientes de resgate sem ganhar nada.
func ExigeConsentimento(p Privilegio, modo Modo) (bool, string) {
	if p.Root {
		return true, "este processo é root (euid 0)."
	}
	if len(p.CapsEfetivas) > 0 {
		return true, "este processo carrega capability de observação, e euid não " +
			"é a medida: elas alcançam superfície que um uid comum não alcança."
	}
	if modo != ModoSnapshot && !p.CapsLidas {
		return true, "NÃO foi possível determinar o privilégio deste processo: " +
			"capget(2) falhou e /proc/self/status não respondeu.\n" +
			"Este servidor vai LER o host, e não sabe com que alcance. Tratar " +
			"'não sei' como 'não tenho' seria a leitura mais tranquilizadora de " +
			"uma verificação que não aconteceu — que é o erro que esta ferramenta " +
			"inteira existe para não cometer."
	}
	return false, ""
}
