// Package baseline responde a pergunta que nenhum check faz sozinho:
//
//	isso deveria existir NESTE host?
//
// Os checks respondem "isto é suspeito?" olhando forma, procedência e
// integridade. Todos os três são propriedades do artefato. Nenhum deles sabe
// que o `rclone` daquele servidor é o backup noturno que roda desde 2023, nem
// que o binário sem dono de pacote em /usr/local é a aplicação da casa.
//
// Quem sabe isso é a HISTÓRIA do host, ou a dos irmãos dele na frota. Esta
// ferramenta não fala com outros hosts de propósito — é um binário estático,
// local, sem rede —, então a história precisa ser TRAZIDA: um arquivo capturado
// antes, ou de uma imagem de referência, ou agregado da frota.
//
// # A propriedade que não pode ser violada
//
// Baseline é a funcionalidade mais perigosa desta ferramenta, e a razão é
// simples: se o host JÁ ESTAVA comprometido quando a captura foi feita, o
// implante entra na baseline e passa a ser abençoado para sempre.
//
// Por isso, aqui, casar com a baseline NUNCA apaga um achado. Ele desce um
// nível de severidade, continua no relatório, e ganha uma linha dizendo desde
// quando está lá — junto com a frase que o operador precisa ler: estar na
// baseline não prova que é legítimo, prova apenas que não é novo.
//
// A distinção entre "não é novo" e "é legítimo" é a mesma que separa "não
// achei" de "não consegui olhar". É a espinha desta ferramenta, e a baseline é
// onde ela é mais fácil de trair.
package baseline

import (
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/facts"
	"github.com/lex0c/aletheia/internal/safeio"
)

// Schema muda quando a forma da chave muda. Uma baseline de esquema anterior é
// RECUSADA em vez de interpretada torto: casar chave errada abençoaria achado
// que ninguém aprovou.
const Schema = 2

// Baseline é o que se sabia deste host — ou da referência — num momento dado.
type Baseline struct {
	Schema int `json:"schema"`

	// Proveniência. Sem ela o operador não tem como julgar o que a baseline
	// vale, e uma baseline sem julgamento é pior que nenhuma.
	Host       string `json:"host"`
	Tool       string `json:"tool"`
	CapturedAt string `json:"captured_at"`

	// Completa diz se a captura viu tudo. Baseline montada numa execução
	// degradada descreve menos do que parece: o que não foi olhado não entrou,
	// e depois vira "novo" sem ter nascido.
	Completa       bool     `json:"complete"`
	CoberturaTxt   string   `json:"coverage"`
	LacunasCaptura []string `json:"capture_gaps,omitempty"`

	// Keys são os achados conhecidos. É a lista do que ESTAVA lá — não uma
	// lista de aprovação.
	Keys []string `json:"keys"`
}

// Chave identifica um achado de forma estável entre execuções.
//
// Três partes: o ID do check, o sujeito (com o PID trocado pelo executável) e,
// quando o check o fornece, o discriminador do achado — ver
// check.Finding.Chave, e a razão de ele existir.
//
// `ID|Subject` resolve a maioria, porque a maior parte dos sujeitos é caminho,
// nome de unit ou usuário — coisas que não mudam entre reboots.
//
// O caso que exige tratamento é o PID: ele muda a cada execução, e uma chave
// com PID nunca casaria. Para esses, a identidade estável é o EXECUTÁVEL do
// processo, que sai dos fatos — os mesmos fatos existem na captura e na
// comparação, então os dois lados calculam a mesma chave.
//
// Processo sem exe legível não recebe chave: sem identidade estável, entrar na
// baseline seria abençoar qualquer processo que aparecesse naquele PID depois.
func Chave(f *facts.Facts, fd check.Finding) string {
	s := fd.Subject
	if pid, ok := strings.CutPrefix(s, "pid="); ok {
		n, err := strconv.Atoi(pid)
		if err != nil {
			return ""
		}
		p := f.ProcessByPID(n)
		if p == nil || p.Exe == "" {
			return ""
		}
		s = "exe=" + p.Exe
	}
	// O discriminador do achado entra na chave quando o check o fornece. Sem
	// ele, dois achados distintos do mesmo check sobre o mesmo sujeito geram a
	// MESMA chave, e o segundo é abençoado pela presença do primeiro na
	// baseline — ver check.Finding.Chave.
	if fd.Chave != "" {
		return fd.ID + "|" + s + "|" + fd.Chave
	}
	return fd.ID + "|" + s
}

// Capturar monta a baseline a partir de uma execução.
func Capturar(r *check.Report, f *facts.Facts, host, tool string, quando time.Time) *Baseline {
	b := &Baseline{
		Schema:     Schema,
		Host:       host,
		Tool:       tool,
		CapturedAt: quando.UTC().Format(time.RFC3339),
		Completa:   r.Coverage.Complete >= r.Coverage.Total && len(r.Coverage.CollectorGaps) == 0,
		CoberturaTxt: strconv.Itoa(r.Coverage.Complete) + "/" +
			strconv.Itoa(r.Coverage.Total),
		LacunasCaptura: r.Coverage.CollectorGaps,
	}

	visto := map[string]bool{}
	for i := range r.Findings {
		k := Chave(f, r.Findings[i])
		if k == "" || visto[k] {
			continue
		}
		visto[k] = true
		b.Keys = append(b.Keys, k)
	}
	// Ordem estável: uma baseline que muda de forma entre capturas idênticas
	// não é comparável por diff, e diff de baseline é como se audita frota.
	sort.Strings(b.Keys)
	return b
}

// Escrever emite a baseline em JSON.
func (b *Baseline) Escrever(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(b)
}

// ErrEsquema é devolvido quando a baseline é de outra versão de chave.
var ErrEsquema = errors.New("baseline de esquema incompatível: recapture")

// MaxBaseline é o teto do arquivo de baseline.
//
// Ele é apontado pelo operador e, num IR real, mora no diretório de incidente
// DO HOST INVESTIGADO — quem tem escrita ali escolhe o tamanho. Um
// `truncate -s 8G baseline.json` (esparso, 0 byte de disco) fazia o os.ReadFile
// alocar os 8 GB e o processo sair com `fatal error: out of memory`, status 2 —
// que o contrato desta ferramenta lê como "CRITICAL: indicador de alta
// confiança". É o mesmo raciocínio de env.MaxLeitura e de dump.MaxDump, que
// este caminho não tinha.
var MaxBaseline int64 = 64 << 20

// ErrGrandeDemais recusa uma baseline acima do teto, em vez de tentar lê-la.
var ErrGrandeDemais = errors.New("baseline maior que o teto de leitura: NÃO foi lida")

// Carregar lê uma baseline do disco.
func Carregar(caminho string) (*Baseline, error) {
	// safeio pelo mesmo motivo do teto logo abaixo: o arquivo mora no diretório
	// de incidente DO HOST INVESTIGADO, e quem tem escrita ali escolhe o que ele
	// é. O teto defende contra tamanho; ele não defende contra um fifo, que faz
	// o open não voltar nunca — e a baseline é carregada ANTES da varredura,
	// então o `scan` inteiro não sai do lugar.
	fh, err := safeio.AbrirArtefato(caminho)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	// LimitReader a MaxBaseline+1: um byte além do teto é o que distingue
	// "coube" de "estourou" sem precisar confiar no tamanho declarado.
	b, err := io.ReadAll(io.LimitReader(fh, MaxBaseline+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > MaxBaseline {
		return nil, ErrGrandeDemais
	}
	var bl Baseline
	if err := json.Unmarshal(b, &bl); err != nil {
		return nil, err
	}
	if bl.Schema != Schema {
		return nil, ErrEsquema
	}
	return &bl, nil
}

// Aplicar marca os achados conhecidos e rebaixa a severidade deles.
//
// Devolve quantos foram rebaixados e quantos NÃO PUDERAM ser comparados. Nada
// é removido: o achado continua no relatório com a data em que já estava
// presente.
func (b *Baseline) Aplicar(r *check.Report, f *facts.Facts) (rebaixados, semChave int) {
	conhecido := make(map[string]bool, len(b.Keys))
	for _, k := range b.Keys {
		conhecido[k] = true
	}

	desde := b.CapturedAt
	for i := range r.Findings {
		fd := &r.Findings[i]
		k := Chave(f, *fd)
		if k == "" {
			// Sem chave estável não dá para dizer NADA sobre a baseline, e
			// ✳NOVO é a coluna mais lida do relatório justamente porque é a que
			// aponta o que mudou. Marcá-lo aqui era afirmar por ignorância — e
			// pior, para sempre: a captura também não consegue guardar chave
			// vazia, então o mesmo achado sairia como novidade em toda execução,
			// todo dia, até ninguém mais acreditar na coluna.
			semChave++
			continue
		}
		if !conhecido[k] {
			// Sem baseline não há novidade; COM baseline, o que não estava lá é
			// a informação mais valiosa da execução.
			fd.Novo = true
			continue
		}
		fd.Baseline = true
		fd.Sev = rebaixar(fd.Sev)
		fd.Evidence = append(fd.Evidence,
			"já estava presente na baseline de "+b.Host+", capturada em "+desde+
				" — isso NÃO prova que é legítimo, prova apenas que não é novo")
		rebaixados++
	}
	return rebaixados, semChave
}

// rebaixar desce um nível e PARA em INFO.
//
// O piso existe para que a baseline nunca faça um achado desaparecer. Um
// implante que já estava lá na captura continua impresso, com a data; some da
// urgência, não do relatório.
func rebaixar(s check.Severity) check.Severity {
	switch s {
	case check.SevCritical:
		return check.SevWarn
	case check.SevWarn, check.SevManual:
		return check.SevInfo
	default:
		return s
	}
}

// Idade é quanto tempo passou desde a captura.
func (b *Baseline) Idade(agora time.Time) (time.Duration, bool) {
	t, err := time.Parse(time.RFC3339, b.CapturedAt)
	if err != nil {
		return 0, false
	}
	return agora.Sub(t), true
}

// maxIdade é quando uma baseline passa a merecer aviso. Três meses de deriva
// normal de um servidor — pacote atualizado, aplicação implantada, chave
// rotacionada — bastam para que a lista descreva um host que já não existe.
const maxIdade = 90 * 24 * time.Hour

// Ressalvas são as razões para desconfiar DESTA baseline, em texto pronto para
// o cabeçalho.
//
// Existem porque uma baseline silenciosa é uma autoridade não examinada: ela
// rebaixa achado, e quem lê o relatório precisa saber com que direito.
func (b *Baseline) Ressalvas(hostAtual string, agora time.Time) []string {
	var out []string
	if b.Host != "" && hostAtual != "" && b.Host != hostAtual {
		out = append(out, "capturada em OUTRO host ("+b.Host+"): serve como imagem "+
			"de referência, e o que for específico deste host aparecerá como novo")
	}
	if d, ok := b.Idade(agora); ok && d > maxIdade {
		out = append(out, "capturada há "+strconv.Itoa(int(d.Hours()/24))+
			" dias: deriva normal de servidor já basta para ela descrever um host "+
			"que não existe mais")
	}
	if !b.Completa {
		out = append(out, "capturada com cobertura "+b.CoberturaTxt+
			", incompleta: o que não foi olhado na captura NÃO entrou nela, e vai "+
			"aparecer como novo sem ter nascido")
	}
	return out
}
