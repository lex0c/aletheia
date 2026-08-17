package env

import "testing"

// O formato do cgroup v2. "max" é sem limite — tratá-lo como número faria a
// ferramenta rodar serial em host sem restrição nenhuma.
func TestParseCPUMax(t *testing.T) {
	casos := map[string]float64{
		"50000 100000":    0.5,
		"100000 100000":   1,
		"250000 100000":   2.5,
		"max 100000":      0,
		"max\n":           0,
		"":                0,
		"lixo":            0,
		"100000 0":        0,
		"-1 100000":       0,
		"200000 100000\n": 2,
	}
	for in, want := range casos {
		if got := parseCPUMax(in); got != want {
			t.Errorf("parseCPUMax(%q) = %v, quer %v", in, got, want)
		}
	}
}

// cgroup v1: cota -1 é sem limite, e é o valor padrão em host sem restrição.
func TestParseCFS(t *testing.T) {
	casos := []struct {
		quota, period string
		want          float64
	}{
		{"50000", "100000", 0.5},
		{"-1", "100000", 0},
		{"200000", "100000", 2},
		{"", "100000", 0},
		{"50000", "0", 0},
		{"50000\n", "100000\n", 0.5},
	}
	for _, c := range casos {
		if got := parseCFS(c.quota, c.period); got != c.want {
			t.Errorf("parseCFS(%q,%q) = %v, quer %v", c.quota, c.period, got, c.want)
		}
	}
}

// Workers é o que decide o paralelismo da coleta. Errar para MAIS entrega
// trabalho ao throttling num host já sob incidente; errar para MENOS só deixa
// a varredura mais lenta. Por isso a cota arredonda para cima, mas nunca
// ultrapassa nem o teto nem a afinidade.
func TestWorkers(t *testing.T) {
	casos := []struct {
		nome  string
		cpus  int
		quota float64
		teto  int
		quer  int
	}{
		{"sem cota usa as cpus", 12, 0, 8, 8},
		{"teto manda", 12, 0, 4, 4},
		{"meia cpu vira um leitor", 12, 0.5, 8, 1},
		{"uma cpu e meia vira dois", 12, 1.5, 8, 2},
		{"cota maior que as cpus não inventa", 4, 32, 8, 4},
		{"cota exata", 12, 3, 8, 3},
		{"vm de 1 vcpu é serial", 1, 0, 8, 1},
		{"nunca zero", 0, 0, 8, 1},
	}
	for _, c := range casos {
		e := &Env{NumCPU: c.cpus, CPUQuota: c.quota}
		if got := e.Workers(c.teto); got != c.quer {
			t.Errorf("%s: Workers = %d, quer %d (cpus=%d cota=%v teto=%d)",
				c.nome, got, c.quer, c.cpus, c.quota, c.teto)
		}
	}
}
