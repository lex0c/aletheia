package facts

import (
	"runtime"
	"testing"

	"github.com/lex0c/aletheia/internal/env"
)

// BenchmarkCollect mede a coleta contra o /proc REAL desta máquina. É o número
// que decide se a ferramenta cabe no orçamento de um servidor grande.
func BenchmarkCollect(b *testing.B) {
	e := env.Probe(env.Options{})
	defer e.Close()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		f := Collect(e)
		if len(f.Processes) == 0 {
			b.Fatal("nenhum processo coletado")
		}
	}
}

// Os leitores por processo, isolados: é assim que se descobre qual arquivo
// custa caro em vez de adivinhar.
func benchReader(b *testing.B, fn func(*Process)) {
	e := env.Probe(env.Options{})
	defer e.Close()
	f := Collect(e)
	pids := make([]int, 0, len(f.Processes))
	for _, p := range f.Processes {
		pids = append(pids, p.PID)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, pid := range pids {
			p := &Process{PID: pid, NS: map[string]string{}}
			fn(p)
		}
	}
}

func BenchmarkReadMaps(b *testing.B)   { benchReader(b, readMaps) }
func BenchmarkReadFDs(b *testing.B)    { benchReader(b, readFDs) }
func BenchmarkReadStatus(b *testing.B) { benchReader(b, func(p *Process) { _ = readStatus(p) }) }
func BenchmarkReadEnviron(b *testing.B) {
	benchReader(b, func(p *Process) { readEnviron(p, false) })
}
func BenchmarkReadNS(b *testing.B)  { benchReader(b, readNS) }
func BenchmarkReadExe(b *testing.B) { benchReader(b, readExe) }

// BenchmarkMemoria reporta a memória REALMENTE retida depois de coletar e
// indexar — não a soma do que passou pelo alocador. É o número que decide se a
// ferramenta cabe numa VM pequena junto com o que já está rodando nela.
func BenchmarkMemoria(b *testing.B) {
	e := env.Probe(env.Options{})
	defer e.Close()

	var antes, depois runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&antes)

	f := Collect(e)
	f.Index()

	runtime.GC()
	runtime.ReadMemStats(&depois)
	runtime.KeepAlive(f)

	b.ReportMetric(float64(depois.HeapAlloc-antes.HeapAlloc)/1024, "KiB-retidos")
	b.ReportMetric(float64(len(f.Processes)), "processos")
	b.ReportMetric(float64(depois.HeapAlloc-antes.HeapAlloc)/float64(len(f.Processes)), "B/processo")
}
