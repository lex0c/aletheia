// Package dump é o artefato que separa COLETAR de ANALISAR.
//
// # Por que existe
//
// Até aqui a ferramenta só respondia na máquina comprometida, ao vivo, com os
// checks que existiam naquele dia. Isso custa três coisas:
//
//	tempo no host    a varredura completa gasta segundos no alvo, e cada segundo
//	                 ali é ruído na timeline e risco de o implante reagir
//	uma chance só    a VM é destruída, o disco é rotacionado, e a pergunta que
//	                 aparece no terceiro dia não tem mais onde ser feita
//	nenhum acervo    cada host analisado some, quando poderia virar fixture
//
// Com o dump, a coleta é curta e o resto acontece do lado limpo: a mesma
// máquina de checks, quantas vezes for preciso, com regras mais novas e com a
// lista de indicadores que só apareceu depois.
//
// # A regra que não pode ser quebrada
//
// A análise HERDA a cobertura da coleta. Não pode melhorá-la.
//
// É a tentação óbvia: o `analyze` roda numa estação com root, com debugfs
// montado, com base de pacotes — e seria trivial sondar o ambiente local e
// declarar 79/79. O relatório sairia dizendo que verificou coisas que ninguém
// olhou, sobre um host que talvez nem exista mais. Por isso o ambiente da coleta
// viaja DENTRO do artefato, e o `analyze` nunca sonda a máquina onde roda.
//
// A checagem é fácil de perder de vista porque o efeito é silencioso: números
// maiores, veredito melhor, nenhum erro.
package dump

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
	"github.com/lex0c/aletheia/internal/redact"
)

// Schema muda quando a FORMA do artefato muda. Um dump de esquema diferente é
// recusado em vez de interpretado torto: analisar um retrato mal lido produz
// conclusão sobre um host que não existe.
//
// Ele é separado do facts.SchemaVersion de propósito — os dois podem mudar por
// razões diferentes, e o dump carrega os dois números.
const Schema = 1

// Dump é o que sai do host: o retrato E as condições em que ele foi tirado.
type Dump struct {
	Schema   int          `json:"schema"`
	Ambiente Ambiente     `json:"env"`
	Facts    *facts.Facts `json:"facts"`
}

// Ambiente é o `env.Env` na forma que atravessa o tempo.
//
// Só o que a ANÁLISE precisa: o que a coleta pôde ver, o que não pôde e por quê,
// de onde olhou e quando. O que fica de fora fica por decisão — a raiz travada
// (`os.Root`) é um descritor que não se serializa, e a lista de indicadores é da
// execução, não do host: quem analisa traz a sua.
type Ambiente struct {
	Source string `json:"source"` // live | image
	Root   string `json:"root,omitempty"`

	// Caps é o que a coleta CONSEGUIU. CapReason é por que o resto faltou — e é
	// o texto que vai aparecer, meses depois, no rodapé de cobertura da análise.
	Caps      []string          `json:"caps"`
	CapReason map[string]string `json:"cap_reasons,omitempty"`

	// BPFSemMecanismo separa "o kernel não tem bpf(2)" de "não me deixaram
	// olhar", e a diferença decide se a ausência degrada a cobertura.
	BPFSemMecanismo bool `json:"bpf_unavailable,omitempty"`

	CollectedAt string `json:"collected_at"` // RFC3339 UTC
	Clock       int    `json:"clock"`
	ClockTexto  string `json:"clock_text,omitempty"` // legível sem a ferramenta

	// Quem coletou. Sem isso o dump é um retrato anônimo, e a §39.3 pede o
	// contrário: cada achado precisa saber que ferramenta o produziu.
	Tool     string `json:"tool"`
	ToolSHA  string `json:"tool_sha256,omitempty"`
	ToolPath string `json:"tool_path,omitempty"`

	NumCPU int `json:"cpus,omitempty"`
}

// De monta o dump a partir de uma coleta viva.
//
// A REDAÇÃO acontece aqui, e não no coletor: o `Facts` em memória continua
// completo — os checks precisam do argv inteiro para casar indicador e para
// julgar linhagem —, e o que sai para o disco é a versão que pode virar
// fixture, anexo de ticket e arquivo em repositório (SPEC 5.4).
func De(e *env.Env, f *facts.Facts) *Dump {
	return &Dump{Schema: Schema, Ambiente: ambienteDe(e), Facts: redigir(f)}
}

func ambienteDe(e *env.Env) Ambiente {
	return Ambiente{
		Source: e.Source.String(), Root: e.Root,
		Caps: e.Caps.Names(), CapReason: e.CapReason,
		BPFSemMecanismo: e.BPFSemMecanismo,
		CollectedAt:     e.Now.UTC().Format(time.RFC3339),
		Clock:           int(e.Clock), ClockTexto: e.Clock.String(),
		Tool: e.ToolVersion, ToolSHA: e.ToolSHA256, ToolPath: e.ToolPath,
		NumCPU: e.NumCPU,
	}
}

// redigir tira do artefato o que não pode sair do host.
//
// O environ já sai redigido do coletor — só os NOMES das variáveis, e o valor
// apenas de uma allowlist. O que faltava era o argv: `mysqldump -pS3cr3t` está
// na linha de comando de qualquer host que faça backup, e o relatório já o
// redigia enquanto o dump o levaria inteiro para o repositório.
//
// A cópia é rasa de propósito: só o slice de processos é clonado, porque é o
// único lugar alterado. O resto compartilha memória com o Facts vivo, que
// continua servindo à execução em curso.
func redigir(f *facts.Facts) *facts.Facts {
	if f == nil {
		return nil
	}
	c := *f
	c.Processes = make([]facts.Process, len(f.Processes))
	copy(c.Processes, f.Processes)
	for i := range c.Processes {
		c.Processes[i].Argv = redact.Cmdline(c.Processes[i].Argv)
	}
	return &c
}

// Escrever emite o dump. Indentado: ele é lido por gente no meio de um
// incidente, e `jq` nem sempre está instalado do lado limpo.
func (d *Dump) Escrever(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", " ")
	return enc.Encode(d)
}

var (
	// ErrEsquema recusa o que este binário não sabe ler. Recusar é a resposta
	// certa: interpretar um retrato torto produz conclusão sobre um host que não
	// existe, e ninguém revisa a conclusão de um arquivo que "abriu".
	ErrEsquema = errors.New("dump de esquema incompatível")
	// ErrVazio protege do caso em que o arquivo abriu e não havia fato nenhum —
	// analisar isso produziria um relatório limpo sobre nada.
	ErrVazio = errors.New("dump sem fatos: não há o que analisar")
)

// Carregar lê um dump do disco, ou de "-" para a entrada padrão.
func Carregar(caminho string) (*Dump, error) {
	var b []byte
	var err error
	if caminho == "-" {
		b, err = io.ReadAll(os.Stdin)
	} else {
		b, err = os.ReadFile(caminho)
	}
	if err != nil {
		return nil, err
	}
	var d Dump
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, err
	}
	if d.Schema != Schema {
		return nil, fmt.Errorf("%w: o arquivo é do esquema %d e este binário lê o %d — "+
			"recolete com esta versão, ou analise com a versão que coletou",
			ErrEsquema, d.Schema, Schema)
	}
	if d.Facts == nil {
		return nil, ErrVazio
	}
	if d.Facts.SchemaVersion != facts.SchemaVersion {
		return nil, fmt.Errorf("%w: os fatos são do esquema %d e este binário lê o %d",
			ErrEsquema, d.Facts.SchemaVersion, facts.SchemaVersion)
	}
	return &d, nil
}

// Env reconstrói o ambiente DA COLETA.
//
// O `local` é o ambiente de quem está analisando, e dele vem exatamente duas
// coisas: a lista de indicadores (que é da execução, não do host) e a identidade
// da ferramenta que analisa — para que o relatório possa dizer que são duas
// ferramentas diferentes. TUDO o mais vem do dump.
//
// Nenhuma capacidade é sondada aqui. Se fosse, uma análise rodando como root
// declararia cobertura que a coleta sem root nunca teve.
func (d *Dump) Env(local *env.Env) (*env.Env, error) {
	a := d.Ambiente
	caps, estranhas := env.CapsDeNomes(a.Caps)

	razoes := map[string]string{}
	for k, v := range a.CapReason {
		razoes[k] = v
	}
	// Capacidade que ESTE binário conhece e que o dump não menciona de jeito
	// nenhum: a coleta é de outra versão, que não sondava isso. "indisponível"
	// seco se confundiria com "sondei e não tinha" — que é a distinção que a
	// ferramenta inteira existe para manter.
	for _, n := range env.TodasAsCaps() {
		if c, _ := env.CapDeNome(n); caps&c != 0 {
			continue
		}
		if _, dito := razoes[n]; dito {
			continue
		}
		razoes[n] = "a coleta não sondou esta capacidade (dump gerado por outra " +
			"versão da ferramenta): trate como NÃO verificada"
	}

	origem, conhecida := env.SourceDeNome(a.Source)
	if !conhecida {
		return nil, fmt.Errorf(
			"o dump declara origem %q, que este binário não conhece.\n"+
				"A origem decide quais checks rodam: tratá-la como host vivo faria a\n"+
				"análise concluir ausência sobre um modo que nunca foi olhado.\n"+
				"Use a versão da ferramenta que fez a coleta.", a.Source)
	}

	e := &env.Env{
		Root:            a.Root,
		Source:          origem,
		Caps:            caps,
		CapReason:       razoes,
		Now:             quando(a.CollectedAt),
		Clock:           env.ClockDeCodigo(a.Clock),
		ToolVersion:     a.Tool,
		ToolSHA256:      a.ToolSHA,
		ToolPath:        a.ToolPath,
		NumCPU:          a.NumCPU,
		BPFSemMecanismo: a.BPFSemMecanismo,
	}
	if local != nil {
		e.IOC = local.IOC
	}
	// A capacidade que este binário não conhece fica REGISTRADA, não descartada:
	// ela é a pista de que o dump veio de uma versão mais nova, e quem lê o
	// relatório precisa saber que existe um eixo aqui que esta análise ignorou.
	for _, n := range estranhas {
		e.CapReason["dump:"+n] = "a coleta declarou a capacidade " + n +
			", que este binário não conhece: use a versão que coletou"
	}
	return e, nil
}

// Estranhas devolve as capacidades declaradas pelo dump que este binário não
// conhece. É o sinal de que a análise está sendo feita por uma versão MAIS
// VELHA que a coleta — e o relatório precisa dizer isso em voz alta.
func (d *Dump) Estranhas() []string {
	_, estranhas := env.CapsDeNomes(d.Ambiente.Caps)
	return estranhas
}

// quando devolve o instante da coleta. Data ilegível não vira "agora": vira
// zero, e o relatório mostra o campo vazio em vez de fingir uma data.
func quando(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}
