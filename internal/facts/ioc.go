package facts

import (
	"sort"
	"strconv"

	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/ioc"
)

// Hash dos arquivos que ESTA varredura examinou, para casar com a lista de
// indicadores (SPEC 6.4).
//
// # Por que fica no coletor e não no check
//
// Hashear é ir ao disco, e check é função pura sobre Facts — a regra que
// permite a suíte inteira rodar sem host de verdade. O coletor calcula; o check
// compara.
//
// # Por que só alguns arquivos, e nesta ordem
//
// Hashear o filesystem inteiro não é triagem, é varredura de antivírus. O
// conjunto é o que a §24 já considera interessante — o que roda, o que está
// agendado e o que tem poder —, e a ORDEM decide o que sobrevive ao corte.
//
// Medido num desktop: 13 mil candidatos, dos quais 12.412 eram o inventário de
// módulos da distribuição, e oito arquivos (navegador, LLVM, driver de vídeo)
// somavam 1,4 GB sozinhos. Sem prioridade, o orçamento morria nos módulos antes
// de chegar no que executa.
//
// # Custo zero quando não se pede
//
// Sem hash na lista, nada disto roda.

// ArquivoHash é o hash de um candidato, com o algoritmo que a lista pediu.
type ArquivoHash struct {
	Path string `json:"path"`
	Algo string `json:"algo"`
	Hash string `json:"hash"`
}

// Níveis de prioridade do candidato. O número aparece no motivo do corte: saber
// que sobrou módulo de distribuição é diferente de saber que sobrou binário em
// execução.
const (
	nivelExecuta = iota + 1 // roda agora ou está agendado
	nivelPoder              // setuid, oculto, artefato de ferramenta, exe de processo
	nivelModulo             // inventário de módulos em disco
)

var nomeDoNivel = map[int]string{
	nivelExecuta: "do que roda ou está agendado",
	nivelPoder:   "do que tem poder ou está escondido",
	nivelModulo:  "do inventário de módulos de kernel",
}

const (
	// Tetos próprios, e declarados quando batem. O da §24 não serve: lá o
	// conjunto vem da base de pacotes, aqui vem do que a varredura achou.
	maxHashIOCArquivos = 20000
	maxHashIOCBytes    = 2 << 30
)

type candidatoHash struct {
	Path  string
	Nivel int
}

func collectHashesIOC(f *Facts, e *env.Env) {
	if e.IOC == nil || !e.IOC.Tem(ioc.Hash) {
		return
	}
	algos := e.IOC.Algoritmos()
	candidatos := candidatosDeHash(f)

	var gastos int64
	cortados := map[int]int{}
	for i, c := range candidatos {
		if i >= maxHashIOCArquivos || gastos > maxHashIOCBytes {
			for _, resto := range candidatos[i:] {
				cortados[resto.Nivel]++
			}
			break
		}
		fi, err := e.Lstat(c.Path)
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		gastos += fi.Size()
		for _, algo := range algos {
			h, err := hashDoArquivo(e, c.Path, algo)
			if err != nil {
				continue
			}
			f.HashesIOC = append(f.HashesIOC, ArquivoHash{Path: c.Path, Algo: algo, Hash: h})
		}
	}
	if len(cortados) > 0 {
		f.partial("ioc", strconv.Itoa(somaCortes(cortados))+" arquivo(s) candidato(s) "+
			"NÃO foram hasheados ("+detalheDosCortes(cortados)+"): o orçamento de "+
			"casamento por hash acabou antes deles")
	}
}

func somaCortes(m map[int]int) int {
	t := 0
	for _, n := range m {
		t += n
	}
	return t
}

// detalheDosCortes diz de QUE nível sobrou, porque as consequências são
// diferentes: módulo de distribuição que ficou de fora é rotina, binário em
// execução que ficou de fora é a pergunta sem resposta.
func detalheDosCortes(m map[int]int) string {
	var partes []string
	for _, n := range []int{nivelExecuta, nivelPoder, nivelModulo} {
		if m[n] > 0 {
			partes = append(partes, strconv.Itoa(m[n])+" "+nomeDoNivel[n])
		}
	}
	return juntar(partes, ", ")
}

func juntar(ss []string, sep string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += sep
		}
		out += s
	}
	return out
}

// candidatosDeHash é o conjunto examinado, em ORDEM DE PRIORIDADE.
//
// A ordem não é estética: ela decide o que sobrevive ao corte. O nível 3 vem
// por último pela mesma razão que a §24 não pergunta pela propriedade de todo
// módulo em disco — um módulo só age depois de carregado, e para carregar no
// boot ele precisa estar configurado, o que o traz de volta para o nível 1.
//
// Dentro de cada nível a ordem é alfabética, para que dois cortes no mesmo host
// caiam nos mesmos arquivos e o resultado continue comparável.
func candidatosDeHash(f *Facts) []candidatoHash {
	visto := map[string]bool{}
	nivel := func(n int, listas ...[]string) []candidatoHash {
		var caminhos []string
		for _, lista := range listas {
			for _, p := range lista {
				if p == "" || p[0] != '/' || visto[p] {
					continue
				}
				visto[p] = true
				caminhos = append(caminhos, p)
			}
		}
		sort.Strings(caminhos)
		out := make([]candidatoHash, 0, len(caminhos))
		for _, p := range caminhos {
			out = append(out, candidatoHash{Path: p, Nivel: n})
		}
		return out
	}

	var donos, suid, ocultos, ferramentas, exes []string
	for _, o := range f.Ownership {
		donos = append(donos, o.Path)
	}
	for _, s := range f.Suid {
		suid = append(suid, s.Path)
	}
	ocultos = append(ocultos, f.ExecOculto...)
	for _, t := range f.ToolArtifacts {
		if !t.IsDir {
			ferramentas = append(ferramentas, t.Path)
		}
	}
	for i := range f.Processes {
		p := &f.Processes[i]
		if !p.ExeDeleted && !p.ExeMemfd {
			exes = append(exes, p.Exe)
		}
	}

	out := nivel(nivelExecuta, donos)
	out = append(out, nivel(nivelPoder, suid, ocultos, ferramentas, exes)...)
	return append(out, nivel(nivelModulo, f.ModuleFiles)...)
}
