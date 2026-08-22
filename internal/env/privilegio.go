package env

import (
	"os"
	"strconv"
	"strings"
)

// As capabilities que decidem se este processo alcança as superfícies
// privilegiadas — e que euid sozinho não responde.
//
// Os números são os do <linux/capability.h> e não mudam: eles são ABI.
const (
	capDACOverride   = 1
	capDACReadSearch = 2
	capSysPtrace     = 19
	capSysAdmin      = 21
)

// statusDoProprioProcesso é lido com os.ReadFile, e NÃO por este Env, de
// propósito: em modo image o Env está travado na raiz da imagem, e a pergunta
// aqui é sobre ESTE processo, na máquina onde ele roda. Passar pelo Env leria o
// /proc de outro host.
const statusDoProprioProcesso = "/proc/self/status"

// lerCapsEfetivas é substituível em teste: sem isso, a única forma de exercitar
// a concessão seria dar capability de verdade ao binário de teste.
var lerCapsEfetivas = capsEfetivasDoProcesso

// CapsEfetivasDoProcesso devolve o CapEff deste processo e se deu para lê-lo.
//
// O segundo retorno separa "nenhuma capability" de "não consegui olhar" — sem
// ele, um /proc não montado produziria zero, e zero se leria como "processo sem
// privilégio nenhum", que é a afirmação mais tranquilizadora possível a partir
// de uma leitura que não aconteceu.
func CapsEfetivasDoProcesso() (uint64, bool) { return lerCapsEfetivas() }

func capsEfetivasDoProcesso() (uint64, bool) {
	b, err := os.ReadFile(statusDoProprioProcesso)
	if err != nil {
		return 0, false
	}
	for _, ln := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(ln, ":")
		if !ok || k != "CapEff" {
			continue
		}
		eff, err := strconv.ParseUint(strings.TrimSpace(v), 16, 64)
		if err != nil {
			return 0, false
		}
		return eff, true
	}
	return 0, false
}

// alcancaSuperficiePrivilegiada responde se este processo lê o que CapRoot
// promete: environ alheio, dono de socket, /etc/shadow e /root.
//
// # Por que não basta ser root
//
// Não basta o CONTRÁRIO: euid 0 concede, mas não ser root NÃO nega. Um processo
// uid=1000 com CAP_DAC_READ_SEARCH lê /etc/shadow e /root; com CAP_SYS_PTRACE
// lê o /proc de qualquer processo, que é onde moram environ e o dono de socket.
// Quem tem as duas alcança as QUATRO superfícies que a razão de CapRoot nomeia.
//
// O portão anterior era `os.Geteuid() == 0` e só. Num host assim ele SUB-CONCEDE:
// os coletores que consultam e.Has(CapRoot) pulam trabalho que conseguiriam
// fazer, e a resposta sai com uma lacuna declarada que não existe. É o espelho
// exato do erro que esta ferramenta inteira combate — só que na direção que
// ninguém percebe, porque "não olhei" nunca parece errado.
//
// A conjunção é deliberada. Conceder com UMA das duas marcaria como COMPLETO um
// check que não cobriu metade da superfície, e sobre-conceder é a direção
// perigosa: ela transforma lacuna em silêncio. Com as duas, ou sem nenhuma, a
// resposta é exata.
//
// CAP_SYS_ADMIN e CAP_DAC_OVERRIDE entram como equivalentes do que cada uma
// substitui: a primeira é praticamente root para efeito de observação, e a
// segunda ignora permissão de arquivo do mesmo jeito que a de leitura.
func alcancaSuperficiePrivilegiada() (bool, string) {
	if os.Geteuid() == 0 {
		return true, ""
	}
	eff, lidas := lerCapsEfetivas()
	if !lidas {
		return false, "não estamos como root, e não foi possível ler as " +
			"capabilities deste processo (/proc/self/status ilegível): environ, " +
			"dono de socket, /etc/shadow e /root ficam invisíveis, e não dá para " +
			"saber se seria diferente"
	}
	tem := func(bits ...uint) bool {
		for _, b := range bits {
			if eff&(1<<b) != 0 {
				return true
			}
		}
		return false
	}
	le := tem(capDACReadSearch, capDACOverride, capSysAdmin)
	espia := tem(capSysPtrace, capSysAdmin)
	switch {
	case le && espia:
		return true, ""
	case le:
		return false, "não estamos como root: há capability de LEITURA de " +
			"arquivo (/etc/shadow e /root são alcançáveis), mas falta " +
			"CAP_SYS_PTRACE — environ e dono de socket dos outros processos " +
			"continuam invisíveis"
	case espia:
		return false, "não estamos como root: há CAP_SYS_PTRACE (environ e dono " +
			"de socket são alcançáveis), mas falta capability de leitura de " +
			"arquivo — /etc/shadow e /root continuam invisíveis"
	}
	return false, "não estamos como root: environ, dono de socket, /etc/shadow " +
		"e /root ficam invisíveis"
}
