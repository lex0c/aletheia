// Package preserve guarda a evidência ANTES que ela suma.
//
// # Por que existe
//
// Esta ferramenta manda preservar dezenas de vezes. Todo achado crítico começa
// com uma linha assim:
//
//	sudo cp /proc/812/exe "$IR/"   # a amostra, antes de qualquer coisa
//	                               ← irreversível se pulado
//
// E até aqui era só isso: uma frase. O operador montava o comando na mão, no
// meio do incidente, que é exatamente quando a janela se perde. A §19 diz que a
// ordem é irreversível — matar o processo destrói a única cópia de um binário
// em memfd ou já apagado do disco.
//
// # As quatro coisas que somem
//
//	exe apagado    /proc/<pid>/exe ainda abre o arquivo depois do unlink. É a
//	               única cópia, e ela morre com o processo
//	memfd          nunca houve arquivo. O binário existe só como descritor
//	memória        região anônima gravável e executável: código injetado que
//	               não tem arquivo em lugar nenhum
//	eBPF           bytecode que vive dentro do kernel e some no reboot
//
// Nenhuma delas sobrevive a um `kill`, e três delas não sobrevivem a um reboot.
//
// # As travas
//
// Este é o único lugar do projeto que ESCREVE, e por isso as regras são
// explícitas: nada fora de `--out`, nada sobrescrito, nada executado. O
// manifesto registra o hash da ORIGEM e o da CÓPIA — se divergirem, o arquivo
// mudou durante a leitura, e isso é evidência e não erro de cópia.
package preserve

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/kbpf"
	"github.com/lex0c/aletheia/internal/pcap"
)

// Item é uma linha do manifesto: uma peça de evidência guardada, com a cadeia
// de custódia junto.
type Item struct {
	ID   string `json:"id"` // sempre "preserve"
	TS   string `json:"ts"`
	Tipo string `json:"kind"` // exe | file | mem | bpf

	// Origem é de onde veio, como o operador precisa citar depois.
	Origem string `json:"source"`
	// OrigemReal é o caminho que o /proc revelou — para um exe apagado, é o
	// caminho que o arquivo TINHA.
	OrigemReal string `json:"source_path,omitempty"`
	Destino    string `json:"out"`

	PID   int    `json:"pid,omitempty"`
	BPFID uint32 `json:"bpf_id,omitempty"`

	Bytes int64 `json:"bytes"`
	// HashOrigem é calculado enquanto se lê; HashCopia relendo o que foi
	// escrito. Iguais é o normal; diferentes é achado.
	HashOrigem string `json:"sha256_source"`
	HashCopia  string `json:"sha256_copy"`

	// Stat guarda o que o inode dizia, quando ainda havia inode.
	//
	// UID e GID são PONTEIRO por um motivo que só aparece depois: com
	// `omitempty` num int, o dono root — uid 0 — desaparece do JSON, e o leitor
	// não consegue separar "era do root" de "não foi possível statear". É a
	// mesma distinção que a ferramenta inteira defende, na escala de um campo.
	Modo    string `json:"mode,omitempty"`
	UID     *int   `json:"uid,omitempty"`
	GID     *int   `json:"gid,omitempty"`
	ModUTC  string `json:"mtime_utc,omitempty"`
	MetaUTC string `json:"ctime_utc,omitempty"`

	// Nota carrega o que a peça tem de particular — região de memória, tipo de
	// programa eBPF, exe apagado.
	Nota string `json:"note,omitempty"`
}

// Falha é o que NÃO pôde ser preservado, com o motivo. Existe pela mesma razão
// que a cobertura existe no scan: um artefato que ficou de fora em silêncio é a
// pior saída possível de uma coleta de evidência.
type Falha struct {
	ID     string `json:"id"` // "preserve_failed"
	TS     string `json:"ts"`
	Tipo   string `json:"kind"`
	Alvo   string `json:"target"`
	Motivo string `json:"reason"`
}

// Coletor escreve num diretório e nunca fora dele.
type Coletor struct {
	Dir   string
	Env   *env.Env
	Itens []Item
	Erros []Falha

	// MaxMem é o teto do dump de memória, em bytes. Zero usa o padrão.
	MaxMem int64
}

// Limites. O de memória existe porque um processo grande tem gigabytes de
// região anônima, e uma coleta que enche o disco do respondedor no meio do
// incidente é pior que uma coleta parcial declarada.
const (
	maxMemPadrao  = 512 << 20
	maxRegioes    = 4096
	maxArquivoBin = 4 << 30
)

var (
	// ErrExiste é a recusa que protege a evidência já coletada. Sobrescrever
	// silenciosamente destruiria a primeira cópia — que costuma ser a boa.
	ErrExiste = errors.New("o destino já existe: preservar de novo por cima " +
		"apagaria a evidência anterior")
	ErrSemDir = errors.New("--out precisa ser um diretório que já existe")
)

// Novo valida o destino. Falhar aqui é falhar antes de tocar em qualquer coisa.
func Novo(dir string, e *env.Env) (*Coletor, error) {
	fi, err := os.Stat(dir)
	if err != nil || !fi.IsDir() {
		return nil, ErrSemDir
	}
	return &Coletor{Dir: dir, Env: e, MaxMem: maxMemPadrao}, nil
}

// Exe preserva o executável de um processo VIVO.
//
// É a peça mais importante do conjunto, e a razão é o /proc: o link
// `/proc/<pid>/exe` abre o arquivo mesmo depois de `unlink`, e mesmo quando
// nunca houve arquivo (memfd). Enquanto o processo existir, existe cópia; um
// `kill` a destrói.
func (c *Coletor) Exe(pid int) error {
	origem := "/proc/" + strconv.Itoa(pid) + "/exe"
	real, _ := os.Readlink(origem)

	item, err := c.copiar(origem, "exe-"+strconv.Itoa(pid)+".bin", "exe")
	if err != nil {
		c.falhar("exe", origem, err)
		return err
	}
	item.PID, item.OrigemReal, item.Nota = pid, real, notaDoExe(real)
	c.Itens = append(c.Itens, item)
	return nil
}

// notaDoExe diz por que ESTA cópia é insubstituível — e as duas respostas
// mandam o respondedor a lugares diferentes.
//
// A ordem foi um defeito, achado por cenário: o kernel resolve o link de um
// memfd como "/memfd:<nome> (deleted)", com o sufixo de apagado JUNTO. Testar o
// sufixo primeiro rotulava execução fileless como "arquivo apagado" — e mandava
// procurar em backup, em log de pacote e no MFT um caminho que nunca existiu.
func notaDoExe(link string) string {
	caminho := strings.TrimSuffix(link, " (deleted)")
	switch {
	case strings.HasPrefix(caminho, "/memfd:"):
		return "execução fileless: nunca houve arquivo em disco, e o binário só " +
			"existe como descritor deste processo"
	case strings.HasSuffix(link, " (deleted)"):
		return "o arquivo foi APAGADO do disco: esta é a única cópia, e ela " +
			"morre junto com o processo"
	}
	return ""
}

// Arquivo preserva um caminho comum.
func (c *Coletor) Arquivo(p string) error {
	item, err := c.copiar(p, "file-"+nomeSeguro(p)+".bin", "file")
	if err != nil {
		c.falhar("file", p, err)
		return err
	}
	c.Itens = append(c.Itens, item)
	return nil
}

// BPF preserva o bytecode de um programa eBPF.
//
// É a única peça deste pacote que não é uma cópia de arquivo: não existe
// arquivo. O que se guarda são as instruções que o kernel de fato executa,
// pedidas pela própria bpf(2) — e elas somem no próximo boot.
func (c *Coletor) BPF(id uint32) error {
	insns, err := kbpf.BytecodeDePrograma(id)
	if err != nil {
		c.falhar("bpf", "prog id="+strconv.Itoa(int(id)), err)
		return err
	}
	nome := "bpf-" + strconv.Itoa(int(id)) + ".xlated.bin"
	item, err := c.escrever(nome, insns, "bpf", "bpf(2) prog id="+strconv.Itoa(int(id)))
	if err != nil {
		c.falhar("bpf", "prog id="+strconv.Itoa(int(id)), err)
		return err
	}
	item.BPFID = id
	item.Nota = "bytecode VERIFICADO, como o kernel o executa. Não há arquivo " +
		"em disco para copiar, e ele some no próximo boot"
	if p, err := kbpf.ProgramaPorID(id); err == nil {
		item.Nota += " · tipo=" + p.Tipo + " tag=" + p.Tag + " nome=" + p.Nome
	}
	c.Itens = append(c.Itens, item)
	return nil
}

// PCAP captura tráfego direto do kernel, sem tcpdump e sem libpcap.
//
// É a única peça deste pacote que não copia nada: ela ESPERA o que ainda vai
// acontecer. As outras preservam o que já existe e some; esta preserva o que só
// existe enquanto passa.
//
// O que ela não pode prometer está no pacote pcap: um eBPF hostil em xdp/tc
// esconde o pacote antes do socket, e captura confiável é espelhamento fora da
// máquina (§2.6, §35.4).
func (c *Coletor) PCAP(o pcap.Opcoes) (pcap.Estatisticas, error) {
	var st pcap.Estatisticas
	iface, err := pcap.AbrirInterface(o.Iface)
	if err != nil {
		c.falhar("pcap", o.Iface, err)
		return st, err
	}
	if !iface.Ativa {
		// Não é recusa: interface administrativamente DOWN pode subir no meio da
		// captura, e capturar zero pacote nela é resultado, não erro. Mas quem
		// lê o manifesto precisa saber que a placa estava caída.
		c.falhar("pcap", o.Iface, errors.New("a interface estava DOWN quando a "+
			"captura começou: zero pacote aqui não significa ausência de tráfego"))
	}

	nome := "captura-" + nomeSeguro(o.Iface) + ".pcap"
	destino, err := c.destino(nome)
	if err != nil {
		c.falhar("pcap", o.Iface, err)
		return st, err
	}
	fh, err := os.OpenFile(destino, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		c.falhar("pcap", o.Iface, err)
		return st, err
	}

	h := sha256.New()
	st, capErr := pcap.Capturar(fh, h, iface, o)
	if cerr := fh.Close(); capErr == nil {
		capErr = cerr
	}
	if capErr != nil {
		// Sem socket não há arquivo: um pcap de zero byte no diretório de
		// evidência se lê como "capturei e não passou nada".
		if st.Gravados == 0 {
			os.Remove(destino)
		}
		c.falhar("pcap", o.Iface, capErr)
		return st, capErr
	}

	item := Item{
		ID: "preserve", TS: c.agora(), Tipo: "pcap",
		Origem:  "AF_PACKET em " + o.Iface,
		Destino: nome, Bytes: st.Bytes,
		HashOrigem: hex.EncodeToString(h.Sum(nil)),
		Nota:       notaDaCaptura(iface, o, st),
	}
	item.HashCopia, err = hashDoArquivo(destino)
	if err != nil {
		c.falhar("pcap", o.Iface, err)
		return st, err
	}
	c.Itens = append(c.Itens, item)

	// O DESCARTE DO KERNEL É LACUNA DE EVIDÊNCIA, e entra como tal: é o único
	// número desta captura que não dá para recuperar depois. Sem ele declarado,
	// "não vi tráfego daquele IP" fica indistinguível de "não coube no buffer".
	if st.Descartados > 0 {
		c.falhar("pcap", o.Iface, fmt.Errorf(
			"o KERNEL descartou %d de %d pacotes por falta de buffer: esta captura "+
				"está INCOMPLETA, e o que faltou não passa de novo",
			st.Descartados, st.VistosPeloKernel))
	}
	if st.NaoEntendidos > 0 {
		c.falhar("pcap", o.Iface, fmt.Errorf(
			"%d pacote(s) não puderam ser decodificados até onde o filtro precisava "+
				"e ficaram de fora: não é o mesmo que não terem casado", st.NaoEntendidos))
	}
	return st, nil
}

func notaDaCaptura(i pcap.Interface, o pcap.Opcoes, st pcap.Estatisticas) string {
	n := "filtro: " + o.Filtro.Descricao() +
		" · " + strconv.Itoa(st.Gravados) + " gravados, " +
		strconv.Itoa(st.Filtrados) + " fora do filtro, " +
		strconv.Itoa(st.Descartados) + " descartados pelo kernel"
	n += " · " + st.Parou
	if i.Promiscua {
		n += " · a interface JÁ ESTAVA em modo promíscuo antes desta captura (§2.6): " +
			"isto não foi feito por esta ferramenta"
	}
	if st.SemRelogioDoKernel {
		n += " · horário de LEITURA, não de chegada: o kernel não forneceu o " +
			"carimbo por pacote"
	}
	if st.Truncados > 0 {
		n += " · " + strconv.Itoa(st.Truncados) + " pacote(s) cortados pelo snaplen"
	}
	if st.Duplicados > 0 {
		n += " · " + strconv.Itoa(st.Duplicados) + " cópia(s) de transmissão descartadas: " +
			"na loopback cada quadro é entregue duas vezes, e gravar as duas " +
			"dobraria a contagem"
	}
	return n
}

// Memoria dumpa as regiões ANÔNIMAS do processo, sem ptrace.
//
// Sem ptrace é a diferença que importa: ler /proc/<pid>/mem não faz attach,
// então não seta TracerPid e não para o processo. O `gcore`, que esta
// ferramenta recomendava, faz as duas coisas — e um processo parado no meio de
// uma coleta muda o que se está medindo.
//
// Só as regiões ANÔNIMAS: o que tem arquivo por trás está no disco e se copia
// com `Arquivo`. O que não tem arquivo é o código injetado, e é a única coisa
// ali que não existe em outro lugar.
func (c *Coletor) Memoria(pid int) error {
	alvo := "pid=" + strconv.Itoa(pid)
	mapas, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/maps")
	if err != nil {
		c.falhar("mem", alvo, err)
		return err
	}
	mem, err := os.Open("/proc/" + strconv.Itoa(pid) + "/mem")
	if err != nil {
		// Duas coisas negam este open, e dizer só uma manda o operador para o
		// lado errado: falta de privilégio, ou o yama recusando attach a quem
		// não é ancestral do processo — que nega até para o mesmo uid.
		c.falhar("mem", alvo, fmt.Errorf("%w — abrir a memória de outro processo "+
			"exige privilégio de ptrace: rode como root, e confira "+
			"/proc/sys/kernel/yama/ptrace_scope", err))
		return err
	}
	defer mem.Close()

	regioes := porInteresse(regioesAnonimas(string(mapas)))

	// O orçamento não corta pelo fim da lista, corta pelo que sobrou: uma arena
	// de alocador de 400 MB no meio do caminho não pode consumir a coleta
	// inteira e enterrar as quatro páginas RWX que vêm depois — que são,
	// justamente, a evidência.
	var gasto, perdido int64
	var n, pulados int
	for _, r := range regioes {
		if n >= maxRegioes {
			c.falhar("mem", alvo, fmt.Errorf(
				"teto de %d regiões atingido: as demais NÃO foram dumpadas", maxRegioes))
			break
		}
		tam := int64(r.fim - r.ini)
		if gasto+tam > c.orcamentoMem() {
			perdido += tam
			pulados++
			continue
		}
		item, err := c.escreverFaixa("mem-"+strconv.Itoa(pid)+"-"+r.rotulo()+".bin",
			mem, r.ini, tam, "/proc/"+strconv.Itoa(pid)+"/mem @"+r.rotulo())
		if err != nil {
			// Região que some entre o maps e a leitura é rotina num processo
			// vivo; declarar e seguir é o certo.
			c.falhar("mem", r.rotulo(), err)
			continue
		}
		item.PID = pid
		item.Nota = "região anônima " + r.perms + " — sem arquivo por trás: o que " +
			"estiver aqui não existe em disco em lugar nenhum"
		if r.rwx() {
			item.Nota = "região anônima GRAVÁVEL E EXECUTÁVEL (" + r.perms + ") — " +
				"a assinatura clássica de código injetado, e não há arquivo " +
				"por trás dela em lugar nenhum"
		}
		if item.Bytes < tam {
			item.Nota += " · dump PARCIAL: a leitura parou em " +
				strconv.FormatInt(item.Bytes, 10) + " de " + strconv.FormatInt(tam, 10) + " bytes"
		}
		c.Itens = append(c.Itens, item)
		gasto += tam
		n++
	}
	if pulados > 0 {
		c.falhar("mem", alvo, fmt.Errorf(
			"orçamento de %d MB esgotado: %d região(ões) somando %d MB NÃO foram "+
				"dumpadas. Suba --mem-max se precisar delas",
			c.orcamentoMem()>>20, pulados, perdido>>20))
	}
	return nil
}

// porInteresse ordena as regiões pelo que vale mais num incidente, porque o
// orçamento pode não cobrir todas e a ORDEM decide o que sobrevive ao corte.
//
//  1. gravável E executável — código injetado se escreve e depois se executa
//  2. [heap] e [stack] — onde payload em dado costuma parar
//  3. o resto, em ordem de endereço
func porInteresse(rs []regiao) []regiao {
	out := append([]regiao(nil), rs...)
	sort.SliceStable(out, func(i, j int) bool {
		return classe(out[i]) < classe(out[j])
	})
	return out
}

func classe(r regiao) int {
	switch {
	case r.rwx():
		return 0
	case r.rotuloFS != "":
		return 1
	}
	return 2
}

func (c *Coletor) orcamentoMem() int64 {
	if c.MaxMem > 0 {
		return c.MaxMem
	}
	return maxMemPadrao
}

// copiar lê a origem em FLUXO e escreve no destino, hasheando os dois lados.
func (c *Coletor) copiar(origem, nome, tipo string) (Item, error) {
	destino, err := c.destino(nome)
	if err != nil {
		return Item{}, err
	}
	src, err := os.Open(origem)
	if err != nil {
		return Item{}, err
	}
	defer src.Close()

	dst, err := os.OpenFile(destino, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return Item{}, err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(dst, h), io.LimitReader(src, maxArquivoBin))
	if cerr := dst.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return Item{}, err
	}

	item := Item{
		ID: "preserve", TS: c.agora(), Tipo: tipo,
		Origem: origem, Destino: nome, Bytes: n,
		HashOrigem: hex.EncodeToString(h.Sum(nil)),
	}
	// O stat sai do DESCRITOR que acabou de ser lido, não do caminho.
	//
	// A SPEC 6.3 pede stat antes da cópia porque `cp -a` não preserva ctime; o
	// descritor resolve melhor as duas pontas. Statear o caminho depois pode
	// descrever OUTRO inode — o atacante troca o arquivo entre a leitura e o
	// stat, e o manifesto casa os bytes de um com os metadados do outro. E
	// statear antes tem o problema simétrico. O fstat descreve exatamente o
	// inode de onde os bytes vieram, inclusive quando ele já foi apagado.
	item.comStat(src)
	item.HashCopia, err = hashDoArquivo(destino)
	if err != nil {
		return Item{}, err
	}
	return item, nil
}

// escreverFaixa copia [ini, ini+tam) sem materializar a faixa inteira em RAM.
//
// Isso importa mais do que parece: o respondedor pode estar num host com pouca
// memória livre — às vezes porque o próprio incidente a comeu — e alocar 500 MB
// para dumpar 500 MB transformaria a coleta em parte do problema.
func (c *Coletor) escreverFaixa(nome string, r io.ReaderAt, ini uint64, tam int64, origem string) (Item, error) {
	destino, err := c.destino(nome)
	if err != nil {
		return Item{}, err
	}
	dst, err := os.OpenFile(destino, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return Item{}, err
	}
	h := sha256.New()
	n, cerr := io.Copy(io.MultiWriter(dst, h), io.NewSectionReader(r, int64(ini), tam))
	if err := dst.Close(); cerr == nil {
		cerr = err
	}
	if cerr != nil && n == 0 {
		// Nada saiu: não deixa arquivo vazio no diretório de evidência, onde
		// ele seria lido como "região dumpada e vazia".
		os.Remove(destino)
		return Item{}, cerr
	}

	item := Item{
		ID: "preserve", TS: c.agora(), Tipo: "mem",
		Origem: origem, Destino: nome, Bytes: n,
		HashOrigem: hex.EncodeToString(h.Sum(nil)),
	}
	item.HashCopia, err = hashDoArquivo(destino)
	return item, err
}

// escrever guarda bytes que já estão em memória — o bytecode e as regiões.
func (c *Coletor) escrever(nome string, dados []byte, tipo, origem string) (Item, error) {
	destino, err := c.destino(nome)
	if err != nil {
		return Item{}, err
	}
	if err := os.WriteFile(destino, dados, 0o600); err != nil {
		return Item{}, err
	}
	soma := sha256.Sum256(dados)
	item := Item{
		ID: "preserve", TS: c.agora(), Tipo: tipo,
		Origem: origem, Destino: nome, Bytes: int64(len(dados)),
		HashOrigem: hex.EncodeToString(soma[:]),
	}
	item.HashCopia, err = hashDoArquivo(destino)
	return item, err
}

// destino monta o caminho e RECUSA sobrescrever. É a trava que protege a
// primeira cópia, que costuma ser a boa.
func (c *Coletor) destino(nome string) (string, error) {
	p := filepath.Join(c.Dir, filepath.Base(nome))
	if _, err := os.Lstat(p); err == nil {
		return "", fmt.Errorf("%w: %s", ErrExiste, p)
	}
	return p, nil
}

// comStat registra o que o inode dizia, quando ainda havia inode.
func (item *Item) comStat(f *os.File) {
	fi, err := f.Stat()
	if err != nil {
		return
	}
	item.Modo = fi.Mode().String()
	item.ModUTC = fi.ModTime().UTC().Format(time.RFC3339)
	if uid, gid, ctime, ok := donoEDatas(fi); ok {
		item.UID, item.GID = &uid, &gid
		item.MetaUTC = ctime
	}
}

func (c *Coletor) falhar(tipo, alvo string, err error) {
	c.Erros = append(c.Erros, Falha{
		ID: "preserve_failed", TS: c.agora(), Tipo: tipo, Alvo: alvo,
		Motivo: err.Error(),
	})
}

func (c *Coletor) agora() string {
	if c.Env != nil && !c.Env.Now.IsZero() {
		return c.Env.Now.UTC().Format(time.RFC3339)
	}
	return time.Now().UTC().Format(time.RFC3339)
}

// Integro confere que cada cópia bate com a origem. Divergência aqui não é erro
// de cópia: é o arquivo tendo MUDADO durante a leitura, e num incidente isso é
// achado.
func (c *Coletor) Integro() []string {
	var out []string
	for _, i := range c.Itens {
		if i.HashOrigem != i.HashCopia {
			out = append(out, i.Destino+": o hash da origem e o da cópia diferem — "+
				"o arquivo mudou enquanto era lido")
		}
	}
	return out
}

func hashDoArquivo(p string) (string, error) {
	fh, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer fh.Close()
	h := sha256.New()
	if _, err := io.Copy(h, fh); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// nomeSeguro transforma um caminho em nome de arquivo, sem perder o que ele
// era. `/usr/local/sbin/x` vira `usr_local_sbin_x`.
func nomeSeguro(p string) string {
	s := strings.TrimPrefix(p, "/")
	s = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		case r == '.', r == '-', r == '_':
			return r
		}
		return '_'
	}, s)
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}
