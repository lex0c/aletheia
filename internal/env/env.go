// Package env descobre o que este processo consegue ver, e a partir de onde.
//
// É o primeiro passo do fluxo (SPEC 5.1) e alimenta duas coisas: o motor, que
// decide se um check pode rodar, e o rodapé de cobertura, que diz o que NÃO foi
// verificado e por quê. Nada aqui adivinha: capacidade ausente vira motivo
// escrito, nunca silêncio.
package env

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/lex0c/aletheia/internal/ioc"
	"github.com/lex0c/aletheia/internal/kbpf"
)

// Cap é uma capacidade do ambiente. O check declara o que precisa (Requires) e
// o que gostaria (Optional); o motor confere aqui antes de rodar.
type Cap uint32

const (
	CapRoot Cap = 1 << iota
	CapProcfs
	CapDebugfs
	CapBPF
	CapSystemd
	CapPkgDB
	CapNetlink
	CapFilesystem
)

var capNames = []struct {
	c Cap
	n string
}{
	{CapRoot, "root"},
	{CapProcfs, "procfs"},
	{CapDebugfs, "debugfs"},
	{CapBPF, "bpf"},
	{CapSystemd, "systemd"},
	{CapPkgDB, "pkgdb"},
	{CapNetlink, "netlink"},
	{CapFilesystem, "filesystem"},
}

// Names devolve os nomes das capacidades presentes no conjunto.
func (c Cap) Names() []string {
	var out []string
	for _, e := range capNames {
		if c&e.c != 0 {
			out = append(out, e.n)
		}
	}
	return out
}

func (c Cap) String() string { return strings.Join(c.Names(), ",") }

// Source é a origem dos dados: host vivo ou imagem montada.
type Source uint8

const (
	// SourceLive: /proc, netlink, systemd em runtime, processos vivos.
	SourceLive Source = 1 << iota
	// SourceImage: apenas filesystem, sob --root. Aqui o kernel é o do
	// analista, então ocultamento de arquivo por hook em getdents64 não
	// acontece (runbook §35.6).
	SourceImage
)

func (s Source) String() string {
	if s == SourceImage {
		return "image"
	}
	return "live"
}

// ClockState registra se a datação desta execução é confiável. Sem NTP
// sincronizado, todo achado datado é frágil (runbook §9) — e isso precisa estar
// no relatório, não ser descoberto depois.
type ClockState int

const (
	ClockUnknown ClockState = iota
	ClockSynced
	ClockUnsynced
)

func (c ClockState) String() string {
	switch c {
	case ClockSynced:
		return "sincronizado"
	case ClockUnsynced:
		return "NÃO sincronizado"
	default:
		return "desconhecido"
	}
}

// Env é o resultado do probe. Imutável depois de Probe.
type Env struct {
	Root      string // prefixo de caminho; "" = host vivo
	Source    Source
	Caps      Cap
	CapReason map[string]string // capacidade ausente -> motivo

	// WalkDeadline limita as varreduras de filesystem (SUID e git-hooks) no
	// tempo. Zero = sem limite, o padrão do scan. O wtf a define para a
	// varredura caber no orçamento: ela para no prazo e DECLARA o que não
	// examinou, em vez de estourar o "~2s" que o wtf promete. É a mesma lacuna
	// da truncagem por contagem, disparada pelo relógio.
	WalkDeadline time.Time

	// CodigoTudo liga a varredura de código sobre a FS montada INTEIRA (a
	// partir de /), no lugar da lista de web roots. Pseudo-FS e montagem de
	// rede são pulados e DECLARADOS. É o --all-fs do scan: cobertura máxima da
	// FS montada, ao custo de tempo, com os limites (contêiner, >2 MB) ditos.
	CodigoTudo bool

	// ignorados são prefixos de caminho absoluto que NENHUMA varredura de
	// filesystem percorre — o --ignore. Excluir uma árvore gigante e
	// irrelevante (/data/xmls) do custo é escolha do operador, e como o --root,
	// atravessa todo coletor. A exclusão é DECLARADA: esquecer que se ignorou
	// algo e ler "limpo" é a cegueira silenciosa que a ferramenta combate.
	ignorados []string

	// stageMarks registra QUANDO cada estágio de coleta começou, para o CLI
	// poder dizer onde o tempo foi quando a coleta é lenta. Só a goroutine da
	// coleta chama Stage (ela é sequencial), então não precisa de lock.
	stageMarks []stageMark

	// Progress recebe o nome do estágio de coleta atual, para o CLI mostrar que
	// a varredura longa não travou. nil = silêncio, e é o padrão: nada em
	// `facts` ou nos testes precisa de um. Vive aqui porque `e` já atravessa
	// todo coletor.
	Progress ProgressSink

	Now   time.Time // sempre UTC
	Clock ClockState

	ToolPath    string
	ToolSHA256  string
	ToolVersion string

	// NumCPU vem do runtime, que já respeita AFINIDADE (taskset, cpuset).
	NumCPU int

	// CPUQuota é a cota do cgroup em CPUs — 0,5 num `docker run --cpus=0.5`.
	// Zero significa sem limite, ou não determinado. É o que o runtime NÃO
	// enxerga, e é o que decide quantos leitores de /proc abrir.
	CPUQuota float64

	// IOC são os indicadores DESTE incidente, quando o operador os informou
	// (SPEC 6.4). Ficam aqui e não em Facts por uma razão de contrato: Facts é
	// o retrato do HOST, e a lista não é fato do host — é o que esta execução
	// está procurando, do mesmo jeito que --root é de onde ela olha.
	IOC *ioc.Lista

	// BPFSemMecanismo diz que este kernel não tem O QUE enumerar — a bpf(2) não
	// existe. É diferente de "não me deixaram olhar", e a diferença decide se a
	// ausência degrada a cobertura ou não.
	BPFSemMecanismo bool

	// root é a raiz travada em modo image. Ver fs.go: prefixar string não
	// impede symlink absoluto de escapar da imagem.
	root *os.Root
	// RootErr guarda a falha de abrir a raiz, se houver.
	RootErr error
}

// Close libera a raiz travada.
func (e *Env) Close() {
	if e.root != nil {
		e.root.Close()
		e.root = nil
	}
}

// Path é APENAS para exibição: monta o caminho como ele aparece para o
// operador. Não use para abrir arquivo — o acesso real vai por ReadFile/Stat/
// ReadDir/Readlink (fs.go), que são travados na raiz. Prefixo de string não
// impede symlink absoluto de escapar da imagem.
func (e *Env) Path(p string) string {
	if e.Root == "" {
		return p
	}
	return filepath.Join(e.Root, filepath.Join("/", p))
}

// Has diz se todas as capacidades do conjunto estão presentes.
func (e *Env) Has(c Cap) bool { return e.Caps&c == c }

// Missing devolve as capacidades de c que faltam.
func (e *Env) Missing(c Cap) Cap { return c &^ e.Caps }

// Reason explica por que as capacidades do conjunto faltam. Devolve TODAS as
// razões: colapsar para a primeira faz o rodapé citar "sem root" e omitir
// "debugfs não montado", e o operador conclui que basta rodar com sudo.
func (e *Env) Reason(c Cap) string {
	var rs []string
	for _, n := range c.Names() {
		if r, ok := e.CapReason[n]; ok {
			rs = append(rs, r)
		}
	}
	if len(rs) == 0 {
		return "indisponível"
	}
	return strings.Join(rs, " · ")
}

// Options são as escolhas do operador que afetam o probe.
type Options struct {
	Root    string
	Version string
	IOC     *ioc.Lista
}

// Probe inspeciona o ambiente uma única vez.
func Probe(o Options) *Env {
	e := &Env{
		Root:        o.Root,
		Now:         time.Now().UTC(),
		CapReason:   map[string]string{},
		ToolVersion: o.Version,
		IOC:         o.IOC,
		NumCPU:      runtime.NumCPU(),
		CPUQuota:    probeCPUQuota(),
	}

	if o.Root != "" {
		e.Source = SourceImage
		r, err := os.OpenRoot(o.Root)
		if err != nil {
			e.RootErr = err
		} else {
			e.root = r
		}
	} else {
		e.Source = SourceLive
	}

	e.probeSelf()
	e.probeCaps()
	e.probeClock()
	return e
}

// Workers devolve quantos leitores concorrentes abrir, respeitando teto,
// afinidade E cota de cgroup.
//
// Arredonda a cota para cima: com 0,5 CPU o certo é UM leitor, não zero — e um
// leitor sequencial é exatamente o comportamento anterior. Nunca devolve menos
// que 1.
func (e *Env) Workers(cap int) int {
	n := e.NumCPU
	if e.CPUQuota > 0 {
		q := int(e.CPUQuota)
		if float64(q) < e.CPUQuota {
			q++ // teto
		}
		if q < n {
			n = q
		}
	}
	if n > cap {
		n = cap
	}
	if n < 1 {
		n = 1
	}
	return n
}

func (e *Env) probeSelf() {
	p, err := os.Executable()
	if err != nil {
		return
	}
	if r, err := filepath.EvalSymlinks(p); err == nil {
		p = r
	}
	e.ToolPath = p

	f, err := os.Open(p)
	if err != nil {
		return
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return
	}
	e.ToolSHA256 = hex.EncodeToString(h.Sum(nil))
}

func (e *Env) grant(c Cap, ok bool, reason string) {
	if ok {
		e.Caps |= c
		return
	}
	for _, n := range c.Names() {
		e.CapReason[n] = reason
	}
}

func (e *Env) probeCaps() {
	// root
	e.grant(CapRoot, os.Geteuid() == 0,
		"não estamos como root: environ, dono de socket, /etc/shadow e /root ficam invisíveis")

	// filesystem — em image depende da raiz travada ter aberto.
	if e.Source == SourceImage && e.root == nil {
		e.grant(CapFilesystem, false, "não foi possível abrir --root com raiz travada: "+errStr(e.RootErr))
	} else {
		e.grant(CapFilesystem, true, "")
	}

	// procfs — só existe no host vivo. Em imagem montada não há processo.
	if e.Source == SourceImage {
		e.grant(CapProcfs, false, "modo image: não há processo vivo numa imagem montada")
	} else {
		_, err := os.Stat("/proc/self/status")
		e.grant(CapProcfs, err == nil, "/proc não montado ou ilegível")
	}

	// debugfs — o caminho mudou entre kernels; sondar os dois. E a sondagem é
	// de MONTAGEM: /sys/kernel/tracing existe em todo kernel com o Kconfig
	// ligado, e o `IsDir` de antes concedia a capacidade sobre um diretório
	// vazio. O motivo acompanha o estado, porque "não está montado" manda
	// montar e "não consigo listar" manda rodar como root.
	dbg, indeterminado := false, false
	motivoDbg := "debugfs/tracefs não montado: ftrace e kprobes não foram verificados"
	for _, c := range []string{"/sys/kernel/tracing", "/sys/kernel/debug/tracing"} {
		switch e.EstadoDeMontagem(c) {
		case MontagemAtiva:
			dbg = true
		case MontagemIndeterminada:
			// O PRIMEIRO candidato indeterminado, não o último: /sys/kernel/tracing
			// é o caminho dos kernels atuais, e nomear o legado confundiria.
			if !indeterminado {
				indeterminado = true
				motivoDbg = c + " está montado e não pôde ser listado (exige " +
					"privilégio): ftrace e kprobes não foram verificados — rode como root"
			}
		}
		if dbg {
			break
		}
	}
	e.grant(CapDebugfs, dbg, motivoDbg)

	// systemd — presença por diretório, não por binário: precisa funcionar
	// sobre imagem montada.
	sysd := false
	for _, c := range []string{"/usr/lib/systemd/system", "/lib/systemd/system", "/etc/systemd/system"} {
		if e.IsDir(c) {
			sysd = true
			break
		}
	}
	e.grant(CapSystemd, sysd, "host sem systemd: checks de unit não se aplicam")

	// base de pacotes
	pkg := false
	// O pacman FALTAVA nesta lista, e o coletor tem backend para ele desde
	// sempre: em todo host Arch a coleta declarava "sem base de pacotes
	// legível" enquanto lia a base normalmente. A capacidade dizia uma coisa e
	// o coletor fazia outra — e quem lê o rodapé acredita na capacidade.
	for _, c := range []string{
		"/var/lib/dpkg/status", "/var/lib/rpm", "/usr/lib/sysimage/rpm",
		"/lib/apk/db", "/var/lib/pacman/local",
	} {
		if e.Exists(c) {
			pkg = true
			break
		}
	}
	e.grant(CapPkgDB, pkg, "sem base de pacotes legível: integridade não foi verificada")

	// eBPF — perguntado à própria bpf(2), não presumido.
	//
	// Esta capacidade passou por um período declarada como "não implementada", e
	// isso tinha um efeito que só apareceu quando alguém foi procurar: como
	// NENHUM check a exigia, o motivo nunca chegava ao rodapé. O ponto cego
	// estava escrito no código e invisível na saída — que é a única forma de
	// lacuna que esta ferramenta não pode ter.
	if e.Source == SourceImage {
		e.BPFSemMecanismo = true
		e.grant(CapBPF, false, "modo image: não há kernel vivo para enumerar programa eBPF")
	} else if err := kbpf.Sonda(); err != nil {
		var es *kbpf.ErroSonda
		if errors.As(err, &es) {
			e.BPFSemMecanismo = es.SemMecanismo
			e.grant(CapBPF, false, es.Motivo)
		} else {
			e.grant(CapBPF, false, "enumeração de eBPF indisponível: "+err.Error())
		}
	} else {
		e.grant(CapBPF, true, "")
	}

	// Ainda não implementado. Declarar ausência é melhor que fingir cobertura.
	e.grant(CapNetlink, false, "netlink ainda não implementado (fase 3): sem a divergência do runbook §35.5")
}

func (e *Env) probeClock() {
	if e.Source == SourceImage {
		e.Clock = ClockUnknown
		return
	}
	// systemd-timesyncd cria este arquivo quando o relógio sincroniza.
	if _, err := os.Stat("/run/systemd/timesync/synchronized"); err == nil {
		e.Clock = ClockSynced
		return
	}
	// Sem o marcador, não afirmamos nada: pode haver chrony ou ntpd, e
	// determinar isso exigiria falar com eles.
	e.Clock = ClockUnknown
}

func errStr(err error) string {
	if err == nil {
		return "motivo desconhecido"
	}
	return err.Error()
}

// ProgressSink recebe o rótulo do estágio corrente da coleta e, opcionalmente, o
// DETALHE do que está sendo feito agora (o caminho sendo lido). O CLI passa um
// escritor de terminal; um dump ou teste passa nil e tudo cala.
type ProgressSink interface {
	Stage(name string)
	Detalhe(s string)
}

// Ignorar registra os caminhos do --ignore, normalizados para caminho absoluto
// e limpo. Ignorar "/" seria esvaziar a varredura inteira e é recusado — quem
// quer isso não passa --ignore.
func (e *Env) Ignorar(paths []string) {
	for _, p := range paths {
		for _, item := range strings.Split(p, ",") {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			if !strings.HasPrefix(item, "/") {
				item = "/" + item
			}
			item = filepath.Clean(item)
			if item == "/" || e.jaIgnora(item) {
				continue
			}
			e.ignorados = append(e.ignorados, item)
		}
	}
}

func (e *Env) jaIgnora(p string) bool {
	for _, ig := range e.ignorados {
		if ig == p {
			return true
		}
	}
	return false
}

// Ignorado diz se um caminho absoluto está sob um prefixo do --ignore. O
// casamento respeita a fronteira de componente: --ignore /data/x não pega
// /data/xmls, só /data/x e o que estiver embaixo dele.
func (e *Env) Ignorado(p string) bool {
	if e == nil {
		return false
	}
	for _, ig := range e.ignorados {
		if p == ig || strings.HasPrefix(p, ig+"/") {
			return true
		}
	}
	return false
}

// Ignorados devolve os prefixos do --ignore, para o relatório DECLARAR o que
// foi excluído da varredura.
func (e *Env) Ignorados() []string { return e.ignorados }

// WalkExpired diz se a varredura de filesystem já passou do prazo. Falso quando
// não há prazo (WalkDeadline zero), que é o caso do scan.
func (e *Env) WalkExpired() bool {
	return e != nil && !e.WalkDeadline.IsZero() && time.Now().After(e.WalkDeadline)
}

// stageMark é o instante em que um estágio de coleta começou.
type stageMark struct {
	nome string
	em   time.Time
}

// StageDur é a duração medida de um estágio.
type StageDur struct {
	Nome string
	Dur  time.Duration
}

// Stage anuncia o estágio atual da coleta: marca o tempo (para o relatório de
// onde o tempo foi) e avisa o progresso, se houver.
func (e *Env) Stage(name string) {
	if e == nil {
		return
	}
	e.stageMarks = append(e.stageMarks, stageMark{name, time.Now()})
	if e.Progress != nil {
		e.Progress.Stage(name)
	}
}

// Detalhe informa ao progresso o que está sendo lido AGORA (um caminho). É
// chamado no laço quente das varreduras, então precisa ser barato: o reporter só
// guarda a string, e o tique decide quando desenhar. No-op sem terminal.
func (e *Env) Detalhe(s string) {
	if e != nil && e.Progress != nil {
		e.Progress.Detalhe(s)
	}
}

// Timings devolve quanto cada estágio levou, usando fim como o término do
// último. Ordenado do mais caro para o mais barato: o gargalo vem primeiro.
func (e *Env) Timings(fim time.Time) []StageDur {
	if e == nil || len(e.stageMarks) == 0 {
		return nil
	}
	out := make([]StageDur, 0, len(e.stageMarks))
	for i, m := range e.stageMarks {
		termino := fim
		if i+1 < len(e.stageMarks) {
			termino = e.stageMarks[i+1].em
		}
		out = append(out, StageDur{m.nome, termino.Sub(m.em)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Dur > out[j].Dur })
	return out
}
