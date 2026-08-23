package mcp

import (
	"time"

	"github.com/lex0c/aletheia/internal/env"
)

// Modo é COMO este servidor obtém fato, e é fixado no lançamento do processo.
//
// Ele não é o mesmo eixo que `env.Source`, e confundir os dois é fácil:
//
//	Modo         de onde o fato VEM agora   snapshot | live | imagem
//	env.Source   o que o retrato DESCREVE   live | image
//
// Um dump coletado com `--root` é servido em ModoSnapshot e declara
// `source: image`. Um servidor em ModoImagem lê filesystem montado AGORA. Os
// dois respondem "image" na procedência, e só um deles pode adquirir fato novo.
type Modo uint8

const (
	// ModoSnapshot serve dumps selados. Nenhuma leitura do host acontece —
	// nem /proc, nem filesystem, nem netlink.
	ModoSnapshot Modo = iota
	// ModoLive adquire do host vivo.
	ModoLive
	// ModoImagem adquire de uma imagem montada (`--root`). Não tem /proc, não
	// tem processo, não tem socket: ali o kernel é o do analista, e ocultamento
	// de arquivo por rootkit não acontece (runbook §35.6).
	ModoImagem
)

func (m Modo) String() string {
	switch m {
	case ModoLive:
		return "live"
	case ModoImagem:
		return "image"
	}
	return "snapshot"
}

// Perfil é QUANTO se pode inspecionar.
//
// Completo é inspeção ampla, NÃO execução arbitrária. A fronteira é a regra do
// pacote: nem no perfil completo existe tool que escreva, execute ou modifique.
type Perfil uint8

const (
	PerfilPadrao Perfil = iota
	PerfilCompleto
)

func (p Perfil) String() string {
	if p == PerfilCompleto {
		return "full"
	}
	return "standard"
}

// Policy é o que este processo pode fazer, decidido uma vez, no lançamento.
//
// # Por que ela é do PROCESSO e não da sessão
//
// A 2026-07-28 diz que `tools/list` não varia por conexão — as listas passaram
// a ser cacheáveis e não dependem mais de estado de sessão. Isso poderia
// parecer conflito com "o registry nasce da policy", e não é: a policy vem das
// flags do lançamento e não muda enquanto o processo vive. Um servidor
// `--profile full` é OUTRO processo, com outra lista, e o cliente que fala com
// ele sabe disso porque foi o operador quem o iniciou assim.
type Policy struct {
	Modo   Modo
	Perfil Perfil

	// PermitirRoot é CONSENTIMENTO, nunca elevação. Este servidor não ganha
	// privilégio: ele herda o do processo. A flag existe para que rodar como
	// root seja uma decisão dita em voz alta, e não um acidente de `sudo`.
	PermitirRoot bool

	// PermitirSegredos desliga a projeção de redação. Importa porque o Aletheia
	// não tem egress — mas o CLIENTE MCP quase certamente manda o resultado
	// para um modelo remoto, e essa segunda metade não está sob controle desta
	// ferramenta.
	PermitirSegredos bool

	MaxLinha     int64
	MaxResultado int64

	// Budget é o teto de tempo de uma AQUISIÇÃO, e ele volta agora com o
	// mecanismo que o faz valer.
	//
	// Ele já existiu, preenchido com um padrão e lido por ninguém — e foi
	// removido por isso: orçamento declarado e não conferido é a armadilha do
	// MaxWarn: 0, que parece proteção e não confere nada. Em modo snapshot não
	// havia o que cronometrar.
	//
	// Agora há. Ele vira env.WalkDeadline, que é o mesmo teto cooperativo que o
	// `wtf` usa: a varredura de filesystem PARA no prazo e DECLARA o que não
	// examinou, em vez de estourar o tempo que o operador reservou. O que não
	// couber vira lacuna, nunca "nada encontrado".
	//
	// Ele NÃO interrompe a coleta no meio: não existe context.Context no
	// domínio, e fingir cancelamento fino seria mentira. O que ele faz é o que
	// o mecanismo existente sustenta, e a descrição da tool diz isso.
	Budget time.Duration

	// OrcamentoDeColeta é o orçamento COOPERATIVO de trabalho em aquisição,
	// acumulado por processo.
	//
	// O teto de retratos vivos limita MEMÓRIA, e só. Capturar e liberar em laço
	// mantém um retrato vivo o tempo todo e nunca esbarra nele — enquanto cada
	// volta cobra uma varredura completa do host INVESTIGADO, que é a máquina
	// em pior estado da sala. Um modelo em laço de correção ("o resultado veio
	// estranho, deixa eu capturar de novo") transforma um servidor de
	// observação num gerador de carga.
	//
	// # O que ele é, exatamente
	//
	// Duas coisas, e nenhuma delas é um relógio de parede rígido:
	//
	//  1. um PORTÃO DE ADMISSÃO: sem saldo, snapshot.capture recusa antes de
	//     tocar no host;
	//  2. um TETO nas varreduras que respeitam prazo: o env.WalkDeadline de cada
	//     captura é o MENOR entre Budget e o saldo restante.
	//
	// O que ele NÃO é: uma captura já admitida pode passar do saldo nas etapas
	// que não são interrompíveis. Não existe context.Context neste domínio, e
	// fingir corte fino seria mentira — a mesma que a descrição de
	// snapshot.capture já recusa contar sobre cancelamento.
	//
	// A versão anterior admitia com 10ms de saldo e então entregava dois minutos
	// de WalkDeadline, porque o prazo saía de Budget sem olhar o que restava.
	//
	// Liberar NÃO devolve orçamento: memória volta, trabalho já feito não.
	OrcamentoDeColeta time.Duration

	// SemTetoDeColeta é o operador dizendo, explicitamente, que não quer teto.
	//
	// Ele existe porque zero já significava "não disse nada" — Padroes() o
	// trocava pelo padrão, e `--capture-budget=0` imprimia "desliga o teto" e
	// subia com dez minutos. Uma flag que diz uma coisa e faz outra é pior que
	// flag nenhuma, mesmo quando erra para o lado seguro.
	SemTetoDeColeta bool
}

// Padroes preenche o que o operador não disse.
func (p Policy) Padroes() Policy {
	if p.MaxLinha <= 0 {
		p.MaxLinha = MaxLinhaPadrao
	}
	if p.MaxResultado <= 0 {
		p.MaxResultado = MaxResultadoPadrao
	}
	if p.Budget <= 0 {
		p.Budget = BudgetPadrao
	}
	if !p.SemTetoDeColeta && p.OrcamentoDeColeta <= 0 {
		p.OrcamentoDeColeta = OrcamentoDeColetaPadrao
	}
	return p
}

const (
	// MaxResultadoPadrao é o teto de UMA resposta, em bytes de JSON.
	//
	// Ele NÃO corta bytes: quem chega perto reduz a PÁGINA e declara a
	// truncagem em observability. Cortar JSON serializado produz documento
	// inválido, e um cliente que recebe metade de uma resposta não tem como
	// saber que era metade.
	MaxResultadoPadrao int64 = 4 << 20 // 4 MiB

	// BudgetPadrao é o teto da varredura de filesystem numa captura completa.
	//
	// Generoso: uma coleta completa num host normal fica em ~1,5s, e o que
	// estoura dois minutos é um filesystem grande — exatamente o caso em que a
	// lacuna declarada vale mais que a espera.
	BudgetPadrao = 2 * time.Minute

	// OrcamentoDeColetaPadrao é quanto tempo de coleta uma sessão inteira pode
	// gastar no host investigado.
	//
	// A conta, com os números certos: 600 segundos são ~400 capturas completas
	// num host normal (~1,5s cada) ou ~3.600 voláteis (~164ms). Uma investigação
	// humana faz dezenas, não centenas.
	//
	// O outro extremo é o que decide o número: num filesystem grande, cada
	// captura completa pode encostar no Budget de 2 minutos, e aí dez minutos
	// dão CINCO capturas. É por causa desse extremo que o padrão não é um
	// minuto — e é por isso que a recusa ensina o --capture-budget em vez de só
	// dizer não.
	//
	// Um laço autônomo consome os dez minutos em dez minutos de relógio, tenha o
	// host o tamanho que tiver. O padrão separa uso de acidente; não raciona.
	OrcamentoDeColetaPadrao = 10 * time.Minute
)

// FonteDoModo é o que um servidor DE AQUISIÇÃO descreve. Em ModoSnapshot não
// há resposta: quem decide é cada dump carregado.
func (p Policy) FonteDoModo() (env.Source, bool) {
	switch p.Modo {
	case ModoLive:
		return env.SourceLive, true
	case ModoImagem:
		return env.SourceImage, true
	}
	return 0, false
}
