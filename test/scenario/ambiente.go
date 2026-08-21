package scenario

import "strings"

// Lacunas que o AMBIENTE DA SUÍTE impõe, e que a ferramenta está CERTA em
// declarar.
//
// # Por que esta lista existe
//
// Um cenário afirma coisas sobre o HOST QUE ELE MONTA: que o implante é pego,
// que o host limpo cala, que a cobertura fecha. Nenhum deles quer afirmar nada
// sobre a máquina de quem roda a suíte — mas parte da cobertura depende dela,
// porque contêiner compartilha o kernel do host e microVM sobe um kernel
// mínimo. Se `udp_diag` não está carregado na máquina do desenvolvedor, a
// ferramenta diz que não consultou UDP por netlink, e ela está certa: a segunda
// testemunha não existiu.
//
// Sem esta lista, `Exit: 0` e `MustBeComplete` viravam loteria sobre quem rodou
// `ss -u` por último na máquina. Com ela, o cenário afirma o que sempre quis
// afirmar — "não há achado, e nenhuma lacuna ALÉM das que este ambiente impõe".
//
// # O que ela NÃO é
//
// Não é lugar para esconder check que esqueceu o guarda de ambiente. A diferença
// é objetiva: aqui só entra lacuna que a ferramenta declara CORRETAMENTE, e cuja
// causa está fora do repositório. Lacuna que aparece em todo host de um tipo
// porque o check confundiu "não existe aqui" com "não consegui olhar" é DEFEITO,
// e o lugar dela é o conserto — foi assim com o bootloader em contêiner, com a
// sondagem de PID e com o nsswitch em musl, os três corrigidos em vez de
// listados.
//
// # A lista não pode apodrecer
//
// Entrada que nunca casa em execução nenhuma é lixo que dá a impressão de
// cobertura. O TestGapsDoAmbienteSaoUsados reclama das que sobrarem.
var GapsDoAmbiente = []GapAmbiental{
	{
		Contem: "netlink NÃO consultou udp",
		Porque: "os módulos de diagnóstico de socket UDP (udp_diag) não estão " +
			"carregados no kernel de quem roda a suíte, e consultar autocarregaria " +
			"— alteração de estado do host, que a ferramenta se recusa a fazer. " +
			"Contêiner usa o kernel do host, então isto não é escolha do cenário",
	},
	{
		Contem: "consulta por netlink NÃO feita",
		Porque: "o mesmo, do lado do check: sem NENHUM módulo de diagnóstico " +
			"disponível o cross.socket_view não roda. Acontece nas microVMs, cujo " +
			"kernel mínimo não traz inet_diag",
	},
	{
		Contem: "cgroup v2 não encontrado em /sys/fs/cgroup",
		Porque: "as microVMs sobem sem cgroup2 montado, a menos que o cenário o " +
			"monte de propósito (o P6 monta). Onde ele não existe, não há anexo " +
			"de cgroup para enumerar",
	},
}

// GapAmbiental é uma lacuna esperada, com o motivo escrito.
//
// O Porque não é decoração: é o que separa esta lista de uma lista de exceções.
// Quem acrescentar uma entrada tem de conseguir explicar por que a causa está
// fora do repositório — e quem revisar tem de conseguir discordar.
type GapAmbiental struct {
	Contem string
	Porque string
}

// EhDoAmbiente diz se uma lacuna declarada é uma das esperadas.
func EhDoAmbiente(lacuna string) bool {
	for _, g := range GapsDoAmbiente {
		if strings.Contains(lacuna, g.Contem) {
			return true
		}
	}
	return false
}

// FiltraAmbientais devolve só as lacunas que NÃO são do ambiente — as que um
// cenário tem o direito de cobrar.
func FiltraAmbientais(lacunas []string) []string {
	var out []string
	for _, l := range lacunas {
		if !EhDoAmbiente(l) {
			out = append(out, l)
		}
	}
	return out
}
