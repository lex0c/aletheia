package env

import (
	"os"
	"path"
	"strconv"
	"strings"
)

// cgroupRoot é onde a hierarquia unificada (v2) e as hierarquias v1 são
// montadas em praticamente todo Linux moderno.
const cgroupRoot = "/sys/fs/cgroup"

// probeCPUQuota descobre quantas CPUs o cgroup realmente permite.
//
// Por que não basta runtime.NumCPU: ele respeita AFINIDADE (sched_getaffinity),
// então taskset e cpuset já entram na conta. O que ele NÃO enxerga é a cota do
// CFS — `docker run --cpus=0.5`, o limite de CPU de um pod de k8s, a
// CPUQuota= de uma unit de systemd. Num contêiner limitado a meia CPU, o Go
// continua reportando as 12 do host.
//
// A consequência prática é o número de leitores paralelos de /proc: abrir oito
// onde há meia CPU não acelera nada e só entrega mais trabalho ao throttling,
// num host que já está em incidente.
//
// Devolve 0 quando não há limite ou não foi possível determinar — e "não sei"
// aqui significa "use o que o Go diz", que é o comportamento anterior.
func probeCPUQuota() float64 {
	if q := cpuQuotaV2(); q > 0 {
		return q
	}
	return cpuQuotaV1()
}

// cpuQuotaV2 lê cpu.max na hierarquia unificada.
//
// A cota é HERDADA: um pai mais apertado manda no filho, e por isso a caminhada
// vai do cgroup do processo até a raiz pegando o MENOR. Dentro de contêiner o
// namespace de cgroup faz o caminho virar "/", e a caminhada termina no
// primeiro passo — que é exatamente o limite do contêiner.
func cpuQuotaV2() float64 {
	rel, ok := cgroupPathOf("")
	if !ok {
		return 0
	}
	menor := 0.0
	for p := rel; ; p = path.Dir(p) {
		if q := parseCPUMax(readOrEmpty(path.Join(cgroupRoot, p, "cpu.max"))); q > 0 {
			if menor == 0 || q < menor {
				menor = q
			}
		}
		if p == "/" || p == "." || p == "" {
			break
		}
	}
	return menor
}

// cpuQuotaV1 lê cpu.cfs_quota_us/cpu.cfs_period_us. Kernel antigo e host com
// systemd em modo híbrido continuam aqui — é o caso das VMs legadas.
func cpuQuotaV1() float64 {
	rel, ok := cgroupPathOf("cpu")
	if !ok {
		return 0
	}
	menor := 0.0
	for p := rel; ; p = path.Dir(p) {
		dir := path.Join(cgroupRoot, "cpu", p)
		q := parseCFS(
			readOrEmpty(path.Join(dir, "cpu.cfs_quota_us")),
			readOrEmpty(path.Join(dir, "cpu.cfs_period_us")),
		)
		if q > 0 && (menor == 0 || q < menor) {
			menor = q
		}
		if p == "/" || p == "." || p == "" {
			break
		}
	}
	return menor
}

// cgroupPathOf devolve o caminho do cgroup deste processo. controller vazio
// pede a hierarquia unificada (linha "0::").
func cgroupPathOf(controller string) (string, bool) {
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", false
	}
	for _, ln := range strings.Split(string(b), "\n") {
		// formato: hierarquia:controladores:caminho
		parts := strings.SplitN(ln, ":", 3)
		if len(parts) != 3 {
			continue
		}
		if controller == "" {
			if parts[0] == "0" && parts[1] == "" {
				return parts[2], true
			}
			continue
		}
		for _, c := range strings.Split(parts[1], ",") {
			if c == controller {
				return parts[2], true
			}
		}
	}
	return "", false
}

// parseCPUMax entende "50000 100000" (meia CPU) e "max 100000" (sem limite).
func parseCPUMax(s string) float64 {
	fs := strings.Fields(s)
	if len(fs) != 2 || fs[0] == "max" {
		return 0
	}
	quota, err1 := strconv.ParseFloat(fs[0], 64)
	period, err2 := strconv.ParseFloat(fs[1], 64)
	if err1 != nil || err2 != nil || period <= 0 || quota <= 0 {
		return 0
	}
	return quota / period
}

// parseCFS entende o par do cgroup v1. Cota -1 é "sem limite".
func parseCFS(quota, period string) float64 {
	q, err1 := strconv.ParseFloat(strings.TrimSpace(quota), 64)
	p, err2 := strconv.ParseFloat(strings.TrimSpace(period), 64)
	if err1 != nil || err2 != nil || q <= 0 || p <= 0 {
		return 0
	}
	return q / p
}

func readOrEmpty(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return string(b)
}
