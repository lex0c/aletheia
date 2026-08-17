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
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
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

	Now   time.Time // sempre UTC
	Clock ClockState

	ToolPath    string
	ToolSHA256  string
	ToolVersion string

	NumCPU int

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
}

// Probe inspeciona o ambiente uma única vez.
func Probe(o Options) *Env {
	e := &Env{
		Root:        o.Root,
		Now:         time.Now().UTC(),
		CapReason:   map[string]string{},
		ToolVersion: o.Version,
		NumCPU:      runtime.NumCPU(),
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

	// debugfs — o caminho mudou entre kernels; sondar os dois.
	dbg := ""
	for _, c := range []string{"/sys/kernel/tracing", "/sys/kernel/debug/tracing"} {
		if e.IsDir(c) {
			dbg = c
			break
		}
	}
	e.grant(CapDebugfs, dbg != "",
		"debugfs/tracefs não montado: ftrace e kprobes não foram verificados")

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
	for _, c := range []string{"/var/lib/dpkg/status", "/var/lib/rpm", "/usr/lib/sysimage/rpm", "/lib/apk/db"} {
		if e.Exists(c) {
			pkg = true
			break
		}
	}
	e.grant(CapPkgDB, pkg, "sem base de pacotes legível: integridade não foi verificada")

	// Ainda não implementados. Declarar ausência é melhor que fingir cobertura.
	e.grant(CapBPF, false, "enumeração de eBPF ainda não implementada (fase 8)")
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
