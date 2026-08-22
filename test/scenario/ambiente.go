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
		SoEmVM: true,
		Contem: "consulta por netlink NÃO feita",
		Porque: "o mesmo, do lado do check: sem NENHUM módulo de diagnóstico " +
			"disponível o cross.socket_view não roda. Acontece nas microVMs, cujo " +
			"kernel mínimo não traz inet_diag",
	},
	{
		SoEmVM:     true,
		SoNoKernel: "3.18",
		Contem:     "não há tracefs montado",
		Porque: "o /init do guest monta tracefs e debugfs desde que o kernel os " +
			"ofereça, e nos kernels modernos da suíte ele monta. O 3.18 desta " +
			"matriz foi compilado SEM ftrace: tem debugfs, e dentro dele não há " +
			"`tracing` para montar. Não há o que a suíte possa fazer no guest, e " +
			"declarar a lacuna é a resposta certa. O recorte por kernel é o que " +
			"importa aqui: em qualquer outro kernel esta lacuna volta a ser falha",
	},
	{
		SoEmVM: true,
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
	// SoEmVM marca a entrada que só se forma no tier de microVM.
	//
	// Existe para o anti-apodrecimento não cobrar o que não teve chance de
	// acontecer: rodar só o tier de contêiner — que é o que cabe numa CI sem
	// KVM — deixaria essas entradas sem uso e a suíte falharia acusando lista
	// podre onde há apenas execução parcial. Falha por motivo errado é a mesma
	// doença que este arquivo inteiro combate.
	SoEmVM bool

	// SoNoKernel restringe a entrada aos cenários que bootam AQUELE kernel.
	//
	// Sem o recorte, uma entrada nascida de uma limitação de kernel antigo
	// passaria a perdoar a mesma lacuna em toda a matriz — inclusive onde ela
	// significaria regressão (o /init parou de montar tracefs, e ninguém viu).
	// A tolerância tem de ser tão estreita quanto a causa.
	SoNoKernel string
}

// ValeNoKernel diz se esta entrada se aplica ao kernel de um cenário.
func (g GapAmbiental) ValeNoKernel(kernel string) bool {
	return g.SoNoKernel == "" || g.SoNoKernel == kernel
}

// EhDoAmbiente diz se uma lacuna declarada é uma das esperadas NAQUELE cenário.
//
// O cenário entra porque parte das entradas é recortada por kernel: a mesma
// frase é ambiente num guest 3.18 e defeito num guest moderno.
func EhDoAmbiente(sc Scenario, lacuna string) bool {
	for _, g := range GapsDoAmbiente {
		if g.ValeNoKernel(sc.Kernel) && strings.Contains(lacuna, g.Contem) {
			return true
		}
	}
	return false
}

// FiltraAmbientais devolve só as lacunas que NÃO são do ambiente — as que um
// cenário tem o direito de cobrar.
func FiltraAmbientais(sc Scenario, lacunas []string) []string {
	var out []string
	for _, l := range lacunas {
		if !EhDoAmbiente(sc, l) {
			out = append(out, l)
		}
	}
	return out
}
