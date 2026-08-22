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
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"syscall"
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
const Schema = 2

// Dump é o que sai do host: o retrato E as condições em que ele foi tirado.
type Dump struct {
	Schema int `json:"schema"`
	// Redacao é a PROVA de que este artefato passou pela redação.
	//
	// Ela existe porque a afirmação estava sendo feita sem lastro: o servidor
	// MCP publicava `redacted_at_source: true` em toda procedência, derivado de
	// nada além do modo em que ele foi lançado. Um arquivo montado à mão com
	// `{"schema":N,"facts":{"processes":[{"argv":["mysql","--password=x"]}]}}`
	// é estruturalmente válido, e o servidor o anunciava como redigido — uma
	// afirmação de segurança falsa sobre um artefato de procedência desconhecida.
	//
	// dump.Carregar já provava que o esquema é compatível; agora prova também
	// que a redação aconteceu, e em que versão.
	Redacao  Redacao      `json:"redaction"`
	Ambiente Ambiente     `json:"env"`
	Facts    *facts.Facts `json:"facts"`
}

// Redacao é o carimbo da redação no artefato.
type Redacao struct {
	Aplicada bool `json:"applied"`
	Versao   int  `json:"version"`
}

// RedacaoVersao é a versão da POLÍTICA de redação que este binário aplica.
//
//	(sem carimbo)  a lista curada de quatro campos — argv, cron, ExecStart.
//	               Vazava setenta chaves de topo, e não deixava rastro de si
//	1              redação PROFUNDA: toda string do Facts, com opt-out por
//	               `redact:"-"` no campo
//
// Ela é separada do Schema porque as duas mudam por razões diferentes: a forma
// do artefato e a política aplicada a ele.
const RedacaoVersao = 1

// EstadoDaRedacao é o que o artefato PROVA sobre a própria redação.
type EstadoDaRedacao string

const (
	// RedacaoAplicada: carimbo presente, na versão que este binário conhece.
	RedacaoAplicada EstadoDaRedacao = "applied"
	// RedacaoAusente: nenhum carimbo. O artefato NÃO prova ter sido redigido —
	// o que é diferente de provar que não foi.
	RedacaoAusente EstadoDaRedacao = "absent"
	// RedacaoDesconhecida: carimbo de uma versão que este binário não conhece.
	// O dump é de uma versão mais nova, e a política aplicada nele pode não ser
	// a que este binário assumiria.
	RedacaoDesconhecida EstadoDaRedacao = "unknown_version"
)

// Estado devolve o que o artefato prova sobre a própria redação.
func (r Redacao) Estado() EstadoDaRedacao {
	switch {
	case !r.Aplicada:
		return RedacaoAusente
	case r.Versao == RedacaoVersao:
		return RedacaoAplicada
	}
	return RedacaoDesconhecida
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

	// NetlinkSemMecanismo é o mesmo para o sock_diag. Dump antigo não tem o
	// campo e ele vem false — que é o comportamento ANTERIOR (ausência conta
	// como lacuna). Errar para o lado de degradar a cobertura é o lado seguro,
	// e por isso isto não força re-coleta.
	NetlinkSemMecanismo bool `json:"netlink_unavailable,omitempty"`

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
	return &Dump{
		Schema:   Schema,
		Redacao:  Redacao{Aplicada: true, Versao: RedacaoVersao},
		Ambiente: ambienteDe(e),
		Facts:    redigir(f),
	}
}

func ambienteDe(e *env.Env) Ambiente {
	return Ambiente{
		Source: e.Source.String(), Root: e.Root,
		Caps: e.Caps.Names(), CapReason: e.CapReason,
		BPFSemMecanismo:     e.BPFSemMecanismo,
		NetlinkSemMecanismo: e.NetlinkSemMecanismo,
		CollectedAt:         e.Now.UTC().Format(time.RFC3339),
		Clock:               int(e.Clock), ClockTexto: e.Clock.String(),
		Tool: e.ToolVersion, ToolSHA: e.ToolSHA256, ToolPath: e.ToolPath,
		NumCPU: e.NumCPU,
	}
}

// redigir tira do artefato o que não pode sair do host.
//
// # Por que ela deixou de ser uma lista de campos
//
// Ela redigia QUATRO superfícies escolhidas a dedo: o argv do processo, o
// comando e as variáveis de uma linha de cron, e o ExecStart de uma unit. A
// escolha estava certa para as quatro, e o método estava errado — porque a
// lista precisa ser mantida, e não foi.
//
// Medido, enchendo toda superfície textual do Facts com uma linha que carrega
// credencial e conferindo o que sobrevive à escrita: SETENTA chaves de topo
// atravessavam. Entre elas o `.bashrc` do usuário (Trigger.Lines[].Text, que um
// check põe na evidência verbatim), o histórico de shell, o `Environment=` de
// unit, o `ProxyCommand` do cliente SSH. O caminho até o modelo é curto:
//
//	~/.bashrc -> TriggerLine.Text -> dump -> check -> Finding.Evidence
//	          -> finding.get -> a IA
//
// E o servidor MCP declara essas tools como DadosRedigidosNaOrigem, que promete
// "não contém segredo em claro". A promessa era falsa.
//
// Agora a redação é PROFUNDA e a direção do erro é a outra: toda string do
// Facts passa por redact.Texto, e quem NÃO quer isso se declara com
// `redact:"-"`. Um coletor novo nasce protegido, e o modo de falha vira
// "redigiu demais" — visível e reversível — no lugar de "vazou", que é
// invisível.
//
// A cópia é PROFUNDA, e a anterior era rasa de propósito para não dobrar o pico
// de memória no host suspeito. O preço mudou de lado: um Facts real de um host
// grande tem dezenas de MB, e dobrá-los por um instante na escrita custa menos
// que publicar credencial num artefato que vai para ticket, repositório e para
// dentro de um modelo remoto. Os campos não exportados ficam para trás, e é o
// que se quer: nada deles é serializado.
func redigir(f *facts.Facts) *facts.Facts {
	if f == nil {
		return nil
	}
	c := redigirValor(reflect.ValueOf(f).Elem(), "").Interface().(facts.Facts)
	return &c
}

// TagRedacao classifica o campo. O valor decide QUAL redator se aplica.
//
//	(ausente)  texto livre — redact.TextoLivre, sem estado entre tokens
//	cmdline    uma sequência argv: redact.Cmdline sobre a FATIA inteira
//	linha      uma linha de comando como string: redact.Texto
//	valor      um par nome/valor: redact.Valor, que mascara pelo NOME
//	-          intocado; os bytes exatos importam
const TagRedacao = "redact"

// redigirValor devolve uma cópia redigida do valor.
//
// # Por que a classe do campo importa
//
// A primeira versão desta caminhada aplicava o redator de LINHA DE COMANDO a
// toda string, e ele tem estado entre tokens — `-p` manda mascarar o token
// seguinte, `Authorization:` manda mascarar até fechar o cabeçalho. Aplicado
// string a string, esse estado se perde; aplicado a texto que não é comando,
// ele estraga o que não é segredo. Medido, os dois sentidos:
//
//	["mysql","-p","S3cr3t"]           o segredo saía EM CLARO
//	"-w /etc/passwd -p wa -k identity"  virava "-w <redacted> -p <redacted> …"
//
// A classe restaura o contexto onde ele existe. O padrão continua sendo
// redigir — um coletor novo nasce protegido —, e o que ele perde em relação ao
// redator de comando é só a forma PARTIDA (`-p` e o valor em tokens
// separados), que só existe em linha de comando e portanto só nos campos que
// se declaram.
//
// Ela constrói em vez de mutar porque o Facts vivo continua servindo à execução
// em curso: os checks precisam do argv inteiro para casar indicador e para
// julgar linhagem, e redigir no lugar os cegaria.
func redigirValor(v reflect.Value, classe string) reflect.Value {
	switch v.Kind() {
	case reflect.String:
		if classe == "linha" {
			return reflect.ValueOf(redact.Texto(v.String())).Convert(v.Type())
		}
		return reflect.ValueOf(redact.TextoLivre(v.String())).Convert(v.Type())

	case reflect.Struct:
		out := reflect.New(v.Type()).Elem()
		if classe == "valor" {
			return redigirPar(v)
		}
		for i := 0; i < v.NumField(); i++ {
			campo := v.Type().Field(i)
			if !campo.IsExported() {
				continue // não serializa, e o reflect não o alcançaria
			}
			c := campo.Tag.Get(TagRedacao)
			if c == "-" {
				out.Field(i).Set(v.Field(i))
				continue
			}
			out.Field(i).Set(redigirValor(v.Field(i), c))
		}
		return out

	case reflect.Slice:
		if v.IsNil() {
			return v
		}
		// ARGV é uma SEQUÊNCIA, e só ela liga uma flag ao token seguinte.
		if classe == "cmdline" && v.Type().Elem().Kind() == reflect.String {
			return reflect.ValueOf(redact.Cmdline(paraStrings(v))).Convert(v.Type())
		}
		out := reflect.MakeSlice(v.Type(), v.Len(), v.Len())
		for i := 0; i < v.Len(); i++ {
			out.Index(i).Set(redigirValor(v.Index(i), classe))
		}
		return out

	case reflect.Map:
		if v.IsNil() {
			return v
		}
		out := reflect.MakeMapWithSize(v.Type(), v.Len())
		iter := v.MapRange()
		mapaNomeValor := v.Type().Key().Kind() == reflect.String &&
			v.Type().Elem().Kind() == reflect.String
		for iter.Next() {
			// A CHAVE também: um mapa de lacunas por caminho tem o caminho na
			// chave, e um caminho pode carregar segredo tanto quanto um valor.
			k := redigirValor(iter.Key(), classe)
			if mapaNomeValor {
				// map[string]string é, quase sempre, NOME -> VALOR: o environ de
				// um processo, as variáveis de uma crontab. O nome é o que
				// denuncia o segredo (`AWS_SECRET_ACCESS_KEY`), e é a proteção
				// que a lista curada tinha e a caminhada por string perdeu.
				out.SetMapIndex(k, reflect.ValueOf(
					redigirNomeValor(iter.Key().String(), iter.Value().String()),
				).Convert(v.Type().Elem()))
				continue
			}
			out.SetMapIndex(k, redigirValor(iter.Value(), classe))
		}
		return out

	case reflect.Pointer:
		if v.IsNil() {
			return v
		}
		out := reflect.New(v.Type().Elem())
		out.Elem().Set(redigirValor(v.Elem(), classe))
		return out

	case reflect.Interface:
		if v.IsNil() {
			return v
		}
		out := reflect.New(v.Type()).Elem()
		out.Set(redigirValor(v.Elem(), classe))
		return out
	}
	return v
}

// redigirPar trata a struct que é um par nome/valor — o EnvSetting de uma
// crontab. O NOME é o que denuncia o segredo.
//
// Ela redige TODOS os campos, e não só o Value. A primeira versão fazia
// `out.Set(v)` — cópia da struct inteira — e reescrevia apenas o Value; o
// EnvSetting tem também um `File`, e ele saía CRU. A catraca global pegou, que
// é exatamente para isso que ela existe: perguntar "o segredo saiu?" em vez de
// "os campos que eu lembrei foram redigidos?".
func redigirPar(v reflect.Value) reflect.Value {
	out := reflect.New(v.Type()).Elem()
	var nome string
	for i := 0; i < v.NumField(); i++ {
		if v.Type().Field(i).Name == "Key" && v.Field(i).Kind() == reflect.String {
			nome = v.Field(i).String()
		}
	}
	for i := 0; i < v.NumField(); i++ {
		campo := v.Type().Field(i)
		if !campo.IsExported() {
			continue
		}
		if campo.Tag.Get(TagRedacao) == "-" {
			out.Field(i).Set(v.Field(i))
			continue
		}
		if campo.Name == "Value" && campo.Type.Kind() == reflect.String {
			out.Field(i).SetString(redigirNomeValor(nome, v.Field(i).String()))
			continue
		}
		out.Field(i).Set(redigirValor(v.Field(i), campo.Tag.Get(TagRedacao)))
	}
	return out
}

// redigirNomeValor aplica a redação por NOME e, se ela não disse nada, a de
// texto livre — que ainda pega a forma embutida.
func redigirNomeValor(nome, valor string) string {
	if r := redact.Valor(nome, valor); r != valor {
		return r
	}
	return redact.TextoLivre(valor)
}

func paraStrings(v reflect.Value) []string {
	out := make([]string, v.Len())
	for i := range out {
		out[i] = v.Index(i).String()
	}
	return out
}

// Escrever emite o dump, em fluxo e SEM indentação.
//
// A indentação custava uma segunda materialização do documento INTEIRO na
// memória do host suspeito: o Encoder já monta tudo num buffer interno, e o
// SetIndent monta um segundo, maior, antes de qualquer byte sair. Num host com
// dezenas de milhares de arquivos de código, milhares de units e de sockets,
// isso é duas a três vezes o tamanho do dump de pico transitório — no exato
// momento em que a ferramenta prometeu passar pouco tempo e pouco recurso no
// alvo, e possivelmente com a memória já comida pelo incidente. O caminho de
// LEITURA tem teto declarado (MaxDump); o de escrita não tinha nenhum.
//
// O que se perde é legibilidade a olho nu de um arquivo que ninguém lê a olho
// nu: o dump é consumido pelo `aletheia analyze`, e do lado limpo `jq .` e
// `python -m json.tool` resolvem a formatação sem custar nada ao alvo.
func (d *Dump) Escrever(w io.Writer) error {
	bw := bufio.NewWriterSize(w, 256<<10)
	if err := json.NewEncoder(bw).Encode(d); err != nil {
		return err
	}
	return bw.Flush()
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

// MaxDump é o teto do dump inteiro lido no lado limpo. O dump vem de um host
// possivelmente comprometido, então tamanho é entrada não confiável: sem teto,
// um arquivo gigante (malicioso ou acidental) estoura a memória do analisador
// por OOM antes de qualquer erro controlado — e o json.Unmarshal ainda mantém
// uma segunda cópia. É o análogo, na fronteira de replay, do env.MaxLeitura que
// já protege cada arquivo coletado. Generoso: os coletores já são limitados
// (40k arquivos de código etc.), então um dump real fica muito abaixo disto.
var MaxDump int64 = 512 << 20

// AbrirArtefato abre um arquivo que veio de FORA — dump ou sidecar — tratando-o
// como entrada hostil.
//
// O `env` já evoluiu para isto do lado do host investigado: abre com O_NONBLOCK,
// faz fstat no DESCRITOR realmente aberto e recusa o que não é arquivo comum.
// A razão está escrita lá: um `mkfifo` no caminho que a ferramenta sempre lê
// pendura a varredura para sempre, e decidir pelo CAMINHO em vez de pelo
// descritor deixa uma janela de troca que não precisa de privilégio nenhum.
//
// O artefato tinha a mesma exposição e nenhuma dessas defesas: `os.Open` seco.
// Um `mkfifo incident.json` travava o servidor MCP antes de ele responder a
// primeira mensagem — e o arquivo vem de um host comprometido, de um pendrive,
// de um caso de IR. É a mesma classe de entrada, e agora tem a mesma porta.
func AbrirArtefato(caminho string) (*os.File, error) {
	fh, err := os.OpenFile(caminho, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	fi, err := fh.Stat()
	if err != nil {
		fh.Close()
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		fh.Close()
		return nil, fmt.Errorf("%s não é arquivo comum (fifo, socket ou "+
			"dispositivo): RECUSADO, porque abrir isto bloqueia ou consome sem fim",
			caminho)
	}
	return fh, nil
}

// CarregarComDigest lê o dump UMA VEZ e devolve o digest DOS MESMOS BYTES.
//
// # Por que uma leitura só
//
// O servidor MCP abria o caminho duas vezes: uma para hashear e outra para
// interpretar. Entre as duas existe uma janela em que o arquivo pode ser
// trocado — e o resultado é o pior possível para um servidor que deixa uma IA
// CITAR evidência: o snapshot_id identifica o conteúdo A, e os fatos servidos
// são o conteúdo B. A citação aponta para bytes que ninguém analisou.
//
// O `collect` já resolve isto do outro lado, e a razão está escrita lá: ele
// calcula o hash DURANTE a escrita, justamente para não haver janela entre
// conteúdo e digest. Aqui é a mesma regra na leitura — um descritor, um
// TeeReader, os mesmos bytes para o hash e para o decodificador.
//
// E o teto entra ANTES do trabalho: o hash antigo era um io.Copy sem limite, e
// um artefato de 80 GB era lido e hasheado por inteiro para só então o
// MaxDump o recusar. O teto só valia depois de o dano que ele existe para
// impedir já ter acontecido.
func CarregarComDigest(caminho string) (*Dump, string, error) {
	if caminho == "-" {
		return nil, "", errors.New("CarregarComDigest não lê da entrada padrão: " +
			"o digest identifica um ARQUIVO, e um fluxo não tem identidade a citar")
	}
	fh, err := AbrirArtefato(caminho)
	if err != nil {
		return nil, "", err
	}
	defer fh.Close()

	h := sha256.New()
	b, err := lerComTeto(io.TeeReader(fh, h))
	if err != nil {
		return nil, "", err
	}
	d, err := interpretar(b)
	if err != nil {
		return nil, "", err
	}
	return d, hex.EncodeToString(h.Sum(nil)), nil
}

// Carregar lê um dump do disco, ou de "-" para a entrada padrão.
func Carregar(caminho string) (*Dump, error) {
	var r io.Reader = os.Stdin
	if caminho != "-" {
		fh, err := AbrirArtefato(caminho)
		if err != nil {
			return nil, err
		}
		defer fh.Close()
		r = fh
	}
	b, err := lerComTeto(r)
	if err != nil {
		return nil, err
	}
	return interpretar(b)
}

// lerComTeto lê no máximo um byte além do teto — o suficiente para saber que
// ESTOUROU sem carregar o resto. Vale para stdin (que não dá para statar) e
// para arquivo, sem corrida entre statar e ler.
func lerComTeto(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, MaxDump+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > MaxDump {
		return nil, fmt.Errorf("dump grande demais: passa de %d MiB — recusado "+
			"para não estourar a memória do analisador", MaxDump>>20)
	}
	return b, nil
}

func interpretar(b []byte) (*Dump, error) {
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
		Root:                a.Root,
		Source:              origem,
		Caps:                caps,
		CapReason:           razoes,
		Now:                 quando(a.CollectedAt),
		Clock:               env.ClockDeCodigo(a.Clock),
		ToolVersion:         a.Tool,
		ToolSHA256:          a.ToolSHA,
		ToolPath:            a.ToolPath,
		NumCPU:              a.NumCPU,
		BPFSemMecanismo:     a.BPFSemMecanismo,
		NetlinkSemMecanismo: a.NetlinkSemMecanismo,
	}
	// Restaura o conjunto de "escopo, não lacuna" — ver env.MarcarSemMecanismo.
	if a.BPFSemMecanismo {
		e.MarcarSemMecanismo(env.CapBPF)
	}
	if a.NetlinkSemMecanismo {
		e.MarcarSemMecanismo(env.CapNetlink)
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
