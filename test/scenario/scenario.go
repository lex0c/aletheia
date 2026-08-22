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

// SemAvisos é o orçamento de ruído ZERO: o cenário exige que a ferramenta
// fique calada. Não é `MaxWarn: 0`, que é o valor zero do campo e significa
// "não declarado".
const SemAvisos = -1

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

	// Evidence é uma substring que precisa aparecer na evidência do achado.
	// Existe para travar PARSING, não severidade: "o cgroup v1 nomeado virou
	// /legado.service" só é verificável olhando o que foi impresso.
	Evidence string

	// Title e NextStep completam o conteúdo do achado, e existem para tirar do
	// ExpectOutput o que nunca foi sobre o relatório.
	//
	// O título diz O QUE é o achado e o próximo passo diz o que FAZER com ele —
	// os dois são contrato com quem lê o JSONL, e nenhum dos dois depende de
	// como o texto humano decide se apresentar hoje. Afirmá-los pelo relatório
	// amarrava o contrato à renderização: quando o nível 0 virou decisão
	// compacta, dezenove asserções caíram sem nada ter regredido no produto.
	Title    string
	NextStep string
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

	// Kernel fixa a versão do kernel do guest — "3.18", "4.14". Vazio usa o do
	// HOST, que é o caso comum.
	//
	// É o único eixo que contêiner nenhum alcança: contêiner compartilha o
	// kernel de quem o roda, então a matriz de imagens prova layout de
	// userland e não procfs de época. "Roda em VM legada?" só tem resposta
	// honesta bootando um kernel legado.
	Kernel string

	// Arch é "386" ou vazio (nativo). Servidor legado de 32 bits ainda existe,
	// e é onde tamanho de int e número de syscall divergem.
	//
	// Em contêiner troca só o BINÁRIO — o kernel continua sendo o do host.
	// Em VM troca o ambiente inteiro: emulador, kernel e initramfs de 32 bits,
	// que é o i686 de verdade.
	Arch string

	// RequerModulo diz que o cenário precisa carregar um MÓDULO DE KERNEL de
	// verdade no guest.
	//
	// Não dá para plantar esse fato: ele vem de /proc/modules, que é o kernel
	// falando. O `make vm-image` prepara um `dummy.ko` do host quando consegue
	// — o guest boota o kernel do host, então serve —, e quando não consegue o
	// cenário é PULADO com o motivo, nunca passa em silêncio.
	RequerModulo bool

	// ModulosOcultacao diz que o cenário carrega os módulos de OCULTAÇÃO —
	// socknd (hooka tcp4_seq_show, esconde socket de /proc/net) e/ou modhide
	// (some de /proc/modules mas o ftrace o delata). São o que prova
	// cross.socket_view e cross.module_view contra kernel real.
	//
	// Não dá para plantar esses fatos: hook de ftrace e módulo escondido vêm do
	// KERNEL, não de arquivo em disco. E, ao contrário do dummy.ko do
	// RequerModulo (levantado dos módulos do host), estes são COMPILADOS contra o
	// linux-lts do Alpine e só carregam sob ele — por isso o cenário usa
	// Kernel:"lts". O `make vm-modulos` os compila e extrai o kernel casado; o
	// `make vm-image` os enfia no initramfs e escreve o marcador. Sem isso o
	// cenário é PULADO com o motivo, nunca passa em silêncio.
	//
	// Por que não em contêiner: um hook em tcp4_seq_show no /proc/net do HOST
	// esconderia conexão do host inteiro. Só é seguro dentro do QEMU descartável,
	// com o kernel do próprio guest — a mesma recusa que o vm-matrix já respeita.
	ModulosOcultacao bool

	// Caps são capabilities extras do contêiner (--cap-add). Só os cenários que
	// PRECISAM de privilégio para montar a situação as pedem: NET_ADMIN para
	// criar apelido de endereço, SYS_ADMIN para o unshare.
	Caps []string

	// CPUs limita a CPU do contêiner (--cpus). Existe para exercitar a leitura
	// da COTA de cgroup, que o runtime do Go não enxerga: num contêiner de meia
	// CPU ele continua reportando as do host inteiro.
	CPUs string

	// NoNetwork tira a rede do contêiner (--network=none). Os cenários de rede
	// precisam de endereço de escopo PÚBLICO para exercitar a classificação, e a
	// forma honesta de conseguir isso é criar apelidos em `lo` dentro de um
	// namespace isolado: o endereço é público para quem classifica, e nenhum
	// pacote jamais sai da máquina.
	NoNetwork bool

	// ExpectOutput são substrings que precisam sair no relatório HUMANO. É
	// para o que não vira achado — cabeçalho, contexto, cobertura. Sem isso,
	// nada garante que o operador enxergue o que a ferramenta descobriu.
	ExpectOutput []string

	// ForbidOutput são substrings que NÃO podem sair. Existe pelo mesmo motivo
	// do `Forbid`: a negativa vale tanto quanto a afirmativa.
	//
	// O caso que a criou: um cenário planta o esconderijo E os hooks de exemplo
	// do git ao lado, e precisa provar que só o primeiro apareceu. Sem uma
	// negativa sobre a SAÍDA, a única alternativa era afirmar a contagem de
	// achados — que quebra à primeira mudança de formatação e não diz o que
	// está sendo protegido.
	ForbidOutput []string

	// Expect precisa aparecer; Forbid não pode aparecer. As proibições são
	// tão valiosas quanto as expectativas: elas travam confusão entre checks
	// e ruído em host limpo.
	Expect []Expect
	Forbid []string

	// ForbidFinding é como Forbid, mas casa por ID **e** Subject/Sev/Evidence —
	// a mesma chave do Expect. Forbid recusa TODO achado de um ID; ForbidFinding
	// recusa UM achado específico sem proibir os legítimos do mesmo ID no mesmo
	// cenário. O caso que a pede: um host com um `app.code_backdoor` legítimo
	// (Elastic APM olhado por regra estrutural) ao lado de um sequestro real —
	// proibir o ID inteiro apagaria a distinção que o cenário existe para provar.
	// É também a forma de AFIRMAR uma lacuna conhecida (ver KnownGap).
	ForbidFinding []Expect

	// ExpectGap são substrings que precisam aparecer em alguma LACUNA declarada
	// — de check ou de coletor, tanto faz qual das duas.
	//
	// É o par do Expect para o outro lado do contrato. "A ferramenta DIZ que não
	// pôde perguntar" é uma afirmação tão verificável quanto um achado, e ela
	// também estava sendo cobrada pelo texto do relatório, onde o motivo da
	// lacuna só aparece com --coverage ou -v.
	ExpectGap []string

	// ForbidGap é o simétrico, e vale tanto quanto: nenhuma lacuna declarada
	// pode conter estas substrings.
	//
	// Existe para separar as DUAS razões de silêncio, que é a distinção central
	// desta ferramenta. Um check que não acusa porque ATRIBUIU o objeto e um que
	// não acusa porque não conseguiu olhar produzem a mesma saída vazia, e só a
	// cobertura os distingue. Onde um cenário afirma que o silêncio é por
	// conhecimento, ele precisa poder afirmar também que não há lacuna ali.
	ForbidGap []string

	// MCP é a conversa com o servidor MCP, quando Cmd == "mcp".
	//
	// O contrato deste modo é OUTRO: não há achado nem linha de cobertura no
	// stdout — há JSON-RPC. Ver mcp.go.
	MCP []Chamada

	// Exit é o código esperado. -1 = não verificar.
	Exit int

	// MaxWarn é o ORÇAMENTO DE RUÍDO: o máximo de avisos que este cenário pode
	// produzir.
	//
	// Existe por causa de um cenário: um servidor de produção legítimo, com dois
	// anos de acúmulo — binário instalado à mão, agente de APM com preload,
	// backup por rclone, CA corporativa, gente no grupo docker. Nada ali é
	// ataque, e a ferramenta tem coisas verdadeiras a dizer sobre quase tudo.
	//
	// O ponto é que "quantos avisos um host limpo produz" decide se a
	// ferramenta é usável numa frota. Acima de uma dúzia o operador aprende a
	// ignorar a saída, e aí o achado que importa se perde junto. Sem este
	// campo isso seria opinião; com ele é regressão.
	//
	// ZERO É "NÃO DECLARADO", e essa distinção custou um defeito silencioso:
	// três cenários escreviam `MaxWarn: 0` achando que exigiam silêncio, e o
	// harness — que testava `if sc.MaxWarn > 0` — não conferia nada. Um
	// orçamento que não é conferido é pior que orçamento nenhum, porque parece
	// proteção. Para exigir silêncio existe SemAvisos.
	MaxWarn int

	// Coverage exige que a execução termine reportando cobertura incompleta —
	// é o invariante central da ferramenta e precisa de teste próprio.
	MustBeIncomplete bool
	MustBeComplete   bool

	// Untestable explica por que este cenário não roda NEM em contêiner NEM em
	// VM com o kernel do host. Quando preenchido, o cenário é pulado e serve de
	// documentação do limite.
	Untestable string

	// UntestableChecks são os checks que este cenário DECLARA impossíveis de
	// demonstrar, e vale só junto de Untestable.
	//
	// Existe porque a alternativa é pior. O invariante "todo check tem cenário"
	// recusa check que ninguém provou disparar — mas alguns só disparam contra
	// um rootkit de verdade, e a suíte não vai carregar um para se testar.
	// Sem este campo, a saída seria relaxar o invariante ou fingir um cenário;
	// com ele, a impossibilidade fica ESCRITA, com motivo, e o pulo aparece na
	// saída do teste.
	UntestableChecks []string

	// KnownGap declara uma LACUNA CONHECIDA: o cenário REPRODUZ um ataque que a
	// ferramenta HOJE não detecta. É a terceira coisa, entre as duas que já
	// existiam:
	//
	//	Untestable   não consigo reproduzir           pulado, documenta o limite
	//	KnownGap     reproduzo e a ferramenta PERDE   roda, dívida explícita
	//	Expect       reproduzo e a ferramenta PEGA    roda, vira cobertura
	//
	// Uma lacuna conhecida NÃO conta em CoveredCheckIDs — é dívida, não
	// cobertura. A ausência da detecção é AFIRMADA por ForbidFinding/Forbid/
	// ForbidOutput, e é isso que a torna uma catraca no sentido certo: quando a
	// lacuna FECHA (a ferramenta passa a pegar), essa afirmação falha e obriga a
	// promover o cenário para Expect, apagando a dívida. Uma lacuna reproduzível
	// e medida vale quase tanto quanto uma detecção — ela diz onde a ferramenta
	// perde, em vez de deixar isso para o operador descobrir no incidente.
	KnownGap string
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
	// Cenário que não afirma achado nenhum existe para provar SILÊNCIO — e
	// silêncio sem número é opinião.
	//
	// É o mesmo invariante do FalsePositives obrigatório no Register do check, e
	// pela mesma razão: sem ele, "quantos avisos um host legítimo produz" fica
	// sendo descoberto pelo operador no meio do incidente. Com ele, cresce o
	// ruído e a suíte quebra.
	//
	// Dois subcomandos ficam de fora, por razões diferentes.
	//
	// O `watch`: ali a contagem NÃO é determinística. O relatório de vigília
	// imprime o que MUDOU a cada ciclo, e um implante que vai e volta reaparece
	// um número de vezes que depende do ritmo da amostragem — o K4 mediu 2 numa
	// execução e 4 na seguinte. Um orçamento fixo ali seria teste instável, que
	// é pior que teste nenhum.
	//
	// O `preserve`: ele não produz achado NENHUM — a saída dele é manifesto de
	// coleta. Um `SemAvisos` ali seria verdadeiro por vacuidade, que é
	// exatamente a armadilha do `MaxWarn: 0` descrita acima: parece proteção e
	// não confere nada. O que um cenário de preserve afirma vai em ExpectOutput.
	//
	// O `mcp`: pela mesma vacuidade, por outro caminho. O orçamento é contado
	// sobre o JSONL de achados, e o modo MCP não produz um — o que sai no
	// stdout é JSON-RPC, e a contagem de avisos viaja DENTRO da resposta de uma
	// tool. Declarar `SemAvisos` ali seria um número que o harness nunca lê.
	//
	// O que aquele modo afirma no lugar é mais forte, e está no M1: a lista de
	// críticos vem VAZIA e o veredito NÃO diz OK. É a mesma pergunta — "o
	// silêncio aqui significa o quê?" — feita nos termos do canal.
	if s.Untestable == "" && orcamentoDeRuidoFazSentido(s.Cmd) {
		if _, declarado := s.Orcamento(); !declarado && len(s.Expect) == 0 {
			panic("cenário " + s.ID + ": não afirma achado nenhum, então ele existe " +
				"para provar SILÊNCIO — e precisa declarar o orçamento de ruído " +
				"(MaxWarn: N, medido; ou SemAvisos, para exigir silêncio)")
		}
	}
	// CAMPO INERTE NÃO PASSA.
	//
	// O modo MCP tem outro contrato de saída, e assertMCP não lê nada da
	// família de achados — Expect, Forbid, ExpectGap, o orçamento, a exigência
	// de cobertura. Declará-los ali seria escrever asserção que ninguém avalia.
	//
	// E o Expect é PIOR que inerte: CoveredCheckIDs credita todo Expect de todo
	// cenário, então um check citado num cenário de MCP contaria como
	// demonstrado sem que nada o tivesse demonstrado — o invariante "todo check
	// tem cenário" passaria a mentir. É a mesma armadilha do MaxWarn: 0, num
	// lugar novo: parece proteção, e não confere nada.
	if s.Cmd == "mcp" {
		inertes := map[string]bool{
			"Expect": len(s.Expect) > 0, "Forbid": len(s.Forbid) > 0,
			"ForbidFinding": len(s.ForbidFinding) > 0,
			"ExpectGap":     len(s.ExpectGap) > 0, "ForbidGap": len(s.ForbidGap) > 0,
			"MaxWarn":          s.MaxWarn != 0,
			"MustBeIncomplete": s.MustBeIncomplete, "MustBeComplete": s.MustBeComplete,
		}
		for campo, usado := range inertes {
			if usado {
				panic("cenário " + s.ID + ": " + campo + " não é lido no modo mcp — " +
					"o contrato ali é a resposta JSON-RPC (ver o campo MCP). " +
					"Uma asserção que ninguém avalia é pior que nenhuma, e um " +
					"Expect aqui ainda creditaria cobertura que ninguém demonstrou")
			}
		}
	}

	// Uma lacuna conhecida sem prova da ausência não documenta nada: ela precisa
	// AFIRMAR que a ferramenta ficou calada sobre o artefato do ataque, senão
	// "known gap" vira comentário não verificado — e não falha quando a lacuna
	// fecha, que é justamente a catraca que dá valor ao campo.
	if s.KnownGap != "" && len(s.ForbidFinding) == 0 && len(s.Forbid) == 0 && len(s.ForbidOutput) == 0 {
		panic("cenário " + s.ID + ": KnownGap sem prova da ausência — afirme o " +
			"silêncio da ferramenta com ForbidFinding, Forbid ou ForbidOutput, " +
			"para que o cenário FALHE quando a lacuna fechar")
	}
	if _, dup := registry[s.ID]; dup {
		panic("cenário duplicado: " + s.ID)
	}
	registry[s.ID] = s
}

// orcamentoDeRuidoFazSentido: ver as duas exceções acima. O `watch` conta o que
// muda, e a contagem depende do ritmo da amostragem; o `preserve` não conta
// nada, porque não produz achado.
func orcamentoDeRuidoFazSentido(cmd string) bool {
	return cmd != "watch" && cmd != "preserve" && cmd != "info" && cmd != "mcp"
}

// Varredura diz se o cenário ANALISA o host. Só quem analisa tem cobertura a
// declarar: o `preserve` copia bytes e vai embora, e o `info` responde sobre UM
// alvo sem concluir nada. Uma linha de cobertura em qualquer um dos dois
// afirmaria uma conclusão que ninguém tirou.
// Varredura diz se este cenário produz um relatório com cobertura.
//
// `preserve` COPIA e `info` RESPONDE — nenhum dos dois roda check, e uma linha
// de cobertura ali afirmaria uma conclusão que ninguém tirou.
//
// `mcp` NÃO entra nesta lista, e a ausência dele é deliberada: aquele modo tem
// um caminho de asserção próprio (assertMCP), e nunca chega em assertScenario,
// que é o único lugar de onde isto é consultado. Um `&& s.Cmd != "mcp"` aqui
// seria um braço que nenhum teste alcança — a mesma decoração que a conferência
// de newline do transporte era antes de sair.
func (s Scenario) Varredura() bool {
	return s.Cmd != "preserve" && s.Cmd != "info"
}

// Orcamento devolve o teto de avisos e se ele foi DECLARADO. É a função que
// separa "este cenário aceita até N avisos" de "ninguém disse nada sobre ruído
// aqui" — e ela existe porque o campo sozinho não conseguia dizer isso.
func (s Scenario) Orcamento() (int, bool) {
	switch {
	case s.MaxWarn == SemAvisos:
		return 0, true
	case s.MaxWarn > 0:
		return s.MaxWarn, true
	}
	return 0, false
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
		// Impossibilidade DECLARADA conta como cobertura: o motivo está escrito
		// e sai na mensagem de pulo do teste.
		for _, id := range s.UntestableChecks {
			out[id] = true
		}
	}
	return out
}
