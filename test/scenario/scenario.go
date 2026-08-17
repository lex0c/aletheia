// Package scenario descreve situações que a CLI precisa reconhecer, e o que ela
// precisa dizer sobre cada uma.
//
// Cenário é arquivo Go, não YAML: acrescentar um cenário é criar um arquivo com
// um init() — mesmo padrão dos checks. Sem parser, sem dependência, e o script
// de plantio é literal de crase, que aguenta shell multilinha sem escapar nada.
//
// O que os testes unitários NÃO cobrem e isto cobre:
//
//	coleta de verdade      parsing de /proc real, permissão, corrida
//	matriz de userland     debian, rocky, alpine — o "sonde, não detecte" da spec
//	modo image             rootfs exportado, com symlink absoluto como em imagem real
//	degradação             sem root a cobertura precisa cair, e o exit NÃO pode ser 0
//
// O que ele NÃO cobre, e é importante não confundir: contêiner compartilha o
// KERNEL do host. Um centos:6 aqui testa o layout de userland, não o procfs do
// 2.6.32 — e /proc/sys/kernel/osrelease reporta o kernel do host. Kernel antigo,
// hidepid, ptrace_scope, systemd e eBPF exigem VM (fase 8).
package scenario

import "sort"

// Mode é como o cenário executa a CLI.
type Mode int

const (
	// Live: a CLI roda DENTRO do contêiner, vendo o /proc dele.
	Live Mode = iota
	// Image: o rootfs do contêiner é exportado e varrido de fora com --root.
	Image
	// VM: microVM com KERNEL PRÓPRIO, para o que contêiner não alcança —
	// hidepid, ptrace_scope, sysctl, módulo, cgroup v1 x v2, eBPF. Boot em
	// ~0,5s via initramfs, sem rede, sem disco compartilhado: o único canal é
	// o console serial.
	VM
)

// Expect é um achado que precisa aparecer.
type Expect struct {
	ID      string
	Sev     string // "CRITICAL" | "WARN" | "MANUAL" | ""=qualquer
	Subject string // substring; ""=qualquer
}

// Scenario é uma situação e o contrato de saída correspondente.
type Scenario struct {
	ID     string
	Desc   string
	Images []string
	Mode   Mode

	// User != "" roda como usuário sem privilégio. É o cenário mais
	// importante da suíte: a maior parte dos defeitos da primeira revisão só
	// aparecia sem root.
	User string

	// Plant roda antes da varredura, dentro do contêiner.
	Plant string
	// Setup é o equivalente do Plant em modo VM: roda como root no guest,
	// antes da varredura. Pode mexer em sysctl, mount e módulo — é o ponto
	// de existir uma VM.
	Setup string
	// Args extras para o comando.
	Args []string

	// Cmd é o subcomando exercitado; vazio = "scan". O `wtf` tem seleção,
	// orçamento e renderização próprios, e precisa de cenário próprio: o
	// contrato de JSONL e de exit code é o mesmo, e é justamente isso que
	// tem de continuar valendo.
	Cmd string

	// Caps são capabilities extras do contêiner (--cap-add). Só os cenários que
	// PRECISAM de privilégio para montar a situação as pedem: NET_ADMIN para
	// criar apelido de endereço, SYS_ADMIN para o unshare.
	Caps []string

	// NoNetwork tira a rede do contêiner (--network=none). Os cenários de rede
	// precisam de endereço de escopo PÚBLICO para exercitar a classificação, e a
	// forma honesta de conseguir isso é criar apelidos em `lo` dentro de um
	// namespace isolado: o endereço é público para quem classifica, e nenhum
	// pacote jamais sai da máquina.
	NoNetwork bool

	// Expect precisa aparecer; Forbid não pode aparecer. As proibições são
	// tão valiosas quanto as expectativas: elas travam confusão entre checks
	// e ruído em host limpo.
	Expect []Expect
	Forbid []string

	// Exit é o código esperado. -1 = não verificar.
	Exit int

	// Coverage exige que a execução termine reportando cobertura incompleta —
	// é o invariante central da ferramenta e precisa de teste próprio.
	MustBeIncomplete bool
	MustBeComplete   bool

	// Untestable explica por que este cenário não roda NEM em contêiner NEM em
	// VM com o kernel do host. Quando preenchido, o cenário é pulado e serve de
	// documentação do limite.
	Untestable string
}

var registry = map[string]Scenario{}

// Register valida e registra.
func Register(s Scenario) {
	switch {
	case s.ID == "":
		panic("cenário sem ID")
	case s.Desc == "":
		panic("cenário " + s.ID + " sem Desc")
	case len(s.Images) == 0 && s.Untestable == "" && s.Mode != VM:
		panic("cenário " + s.ID + " sem Images")
	}
	if _, dup := registry[s.ID]; dup {
		panic("cenário duplicado: " + s.ID)
	}
	registry[s.ID] = s
}

// All devolve os cenários, ordenados por ID.
func All() []Scenario {
	out := make([]Scenario, 0, len(registry))
	for _, s := range registry {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// CoveredCheckIDs devolve os IDs de check que algum cenário afirma disparar.
// É o que permite recusar um check que ninguém provou que dispara — mesma
// lógica do FalsePositives obrigatório no Register do check.
func CoveredCheckIDs() map[string]bool {
	out := map[string]bool{}
	for _, s := range All() {
		for _, e := range s.Expect {
			out[e.ID] = true
		}
	}
	return out
}
