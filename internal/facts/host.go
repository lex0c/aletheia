package facts

import (
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/lex0c/aletheia/internal/env"
)

// Host é o contexto que enquadra todo o resto do relatório.
type Host struct {
	Hostname string `json:"hostname"`
	Kernel   string `json:"kernel"`
	OS       string `json:"os"`
	Virt     string `json:"virt,omitempty"`

	// Load com o número de CPUs junto: "load 8.02" é catastrófico em 2 cpu e
	// normal em 16. Sem o contexto, o alerta vira ruído — justamente no sinal
	// de minerador, que é o comprometimento nº 1 em VM de nuvem.
	Load1  float64 `json:"load1,omitempty"`
	Load5  float64 `json:"load5,omitempty"`
	Load15 float64 `json:"load15,omitempty"`
	NumCPU int     `json:"num_cpu,omitempty"`

	// CPUQuota é a cota do cgroup em CPUs. Registrada porque muda a leitura do
	// load: 8.0 em 12 CPUs é rotina, e 8.0 sob cota de 0,5 é um host afogado.
	CPUQuota float64 `json:"cpu_quota,omitempty"`
	Uptime   string  `json:"uptime,omitempty"`
	BootUTC  string  `json:"boot_utc,omitempty"`

	bootTime time.Time
	hz       int64
}

func collectHost(f *Facts, e *env.Env) {
	h := &f.Host
	h.NumCPU = e.NumCPU
	h.CPUQuota = e.CPUQuota
	h.hz = 100 // USER_HZ é 100 no Linux por ABI; sysconf exigiria cgo.

	// Leitura TRAVADA na raiz. Usar os.ReadFile(e.Path(...)) aqui era o
	// vazamento: /etc/os-release e /etc/hostname são symlinks absolutos em
	// rootfs real, e o Join só resolve a metade léxica — o scan de uma imagem
	// imprimia o hostname do ANALISTA atribuído a ela.
	if s, ok := readEnvTrim(e, "/etc/hostname"); ok {
		h.Hostname = s
	}
	if s, ok := readEnvTrim(e, "/proc/sys/kernel/osrelease"); ok {
		h.Kernel = s
	} else if s, ok := readEnvTrim(e, "/proc/version"); ok {
		h.Kernel = firstFields(s, 3)
	}
	h.OS = osPretty(e)
	h.Virt = detectVirt(e)

	if e.Source != env.SourceLive {
		// load, uptime, boot e contagem de CPU não pertencem à imagem: são do
		// host do analista. Imprimir "load 0.00 (12 cpu)" seria atribuir à
		// imagem um dado que não é dela.
		h.NumCPU = 0
		h.CPUQuota = 0
		return
	}

	if s, ok := readTrim("/proc/loadavg"); ok {
		fs := strings.Fields(s)
		if len(fs) >= 3 {
			h.Load1, _ = strconv.ParseFloat(fs[0], 64)
			h.Load5, _ = strconv.ParseFloat(fs[1], 64)
			h.Load15, _ = strconv.ParseFloat(fs[2], 64)
		}
	}
	if s, ok := readTrim("/proc/uptime"); ok {
		if secs, err := strconv.ParseFloat(firstFields(s, 1), 64); err == nil {
			d := time.Duration(secs) * time.Second
			h.Uptime = humanDuration(d)
			h.bootTime = e.Now.Add(-d)
			h.BootUTC = h.bootTime.Format(time.RFC3339)
		}
	}
	if h.Hostname == "" {
		if n, err := os.Hostname(); err == nil {
			h.Hostname = n
		}
	}
}

func osPretty(e *env.Env) string {
	b, err := e.ReadFile("/etc/os-release")
	if err != nil {
		return ""
	}
	for _, ln := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(ln, "PRETTY_NAME="); ok {
			return strings.Trim(strings.TrimSpace(v), `"`)
		}
	}
	return ""
}

// detectVirt é best-effort e diz "" quando não sabe. Nunca chuta.
func detectVirt(e *env.Env) string {
	if s, ok := readEnvTrim(e, "/sys/hypervisor/type"); ok && s != "" {
		return s
	}
	for _, p := range []string{"/sys/class/dmi/id/product_name", "/sys/class/dmi/id/sys_vendor"} {
		s, ok := readEnvTrim(e, p)
		if !ok {
			continue
		}
		l := strings.ToLower(s)
		switch {
		case strings.Contains(l, "kvm"), strings.Contains(l, "qemu"):
			return "kvm"
		case strings.Contains(l, "vmware"):
			return "vmware"
		case strings.Contains(l, "virtualbox"), strings.Contains(l, "innotek"):
			return "virtualbox"
		case strings.Contains(l, "google"):
			return "gce"
		case strings.Contains(l, "amazon"), strings.Contains(l, "ec2"):
			return "ec2"
		case strings.Contains(l, "microsoft"):
			return "hyperv"
		}
	}
	return ""
}

// readEnvTrim lê pelo caminho TRAVADO na raiz. Todo acesso a arquivo do alvo
// deve passar por aqui ou pelos acessores de env — nunca por os.ReadFile com
// caminho prefixado.
func readEnvTrim(e *env.Env, p string) (string, bool) {
	b, err := e.ReadFile(p)
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(b)), true
}

// readTrim lê caminho ABSOLUTO do host vivo (/proc). Não aceita alvo sob
// --root: em modo image não há /proc.
func readTrim(p string) (string, bool) {
	s, err := readTrimErr(p)
	return s, err == nil
}

// readTrimErr devolve o ERRO. Quem precisa dele é quem distingue "não existe"
// de "não pude ler" — e essa distinção decide se a cobertura degrada.
func readTrimErr(p string) (string, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func firstFields(s string, n int) string {
	fs := strings.Fields(s)
	if len(fs) < n {
		return s
	}
	return strings.Join(fs[:n], " ")
}

func humanDuration(d time.Duration) string {
	days := int(d.Hours()) / 24
	if days > 0 {
		return strconv.Itoa(days) + "d"
	}
	if h := int(d.Hours()); h > 0 {
		return strconv.Itoa(h) + "h"
	}
	return strconv.Itoa(int(d.Minutes())) + "m"
}
