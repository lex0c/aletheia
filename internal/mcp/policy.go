package mcp

import "github.com/lex0c/aletheia/internal/env"

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
}

// Padroes preenche o que o operador não disse.
func (p Policy) Padroes() Policy {
	if p.MaxLinha <= 0 {
		p.MaxLinha = MaxLinhaPadrao
	}
	if p.MaxResultado <= 0 {
		p.MaxResultado = MaxResultadoPadrao
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
)

// Aqui havia um `Budget time.Duration`, teto de tempo por tool. Ele foi
// removido porque NADA o aplicava: era preenchido com um padrão e lido por
// ninguém.
//
// É a armadilha do `MaxWarn: 0` da suíte de cenários, num lugar novo — um
// orçamento declarado e não conferido parece proteção e não confere nada, e
// pior, convida quem lê a policy a acreditar que existe um limite. Em modo
// snapshot não há o que cronometrar: toda tool responde de memória sobre um
// retrato imutável, e a mais cara é memoizada.
//
// Ele volta com a aquisição live, junto do mecanismo que o faz valer — os
// deadlines cooperativos que env.WalkExpired e check.RunOptions já sustentam.

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
