package facts

import (
	"os"
	"sort"
	"strings"

	"github.com/lex0c/aletheia/internal/env"
)

// A terceira interface de módulos: o ftrace (runbook §35.3).
//
// O crossview de /proc/modules × /sys/module tem um ponto cego, e ele é
// exatamente a técnica clássica de ocultação. Um LKM que faz
//
//	list_del(&THIS_MODULE->list)
//
// some de /proc/modules — que é gerado percorrendo aquela lista — e CONTINUA em
// /sys/module. Nas duas interfaces isso é indistinguível de um módulo EMBUTIDO
// no kernel, que também está no sysfs e não no /proc/modules. Por isso o
// crossview antigo não podia acusar essa direção: acusaria todo builtin.
//
// available_filter_functions desfaz o empate. O kernel registra as funções
// rastreáveis de cada módulo no CARREGAMENTO (ftrace_module_init), indexadas por
// endereço numa página própria, e só as libera no descarregamento REAL
// (free_module → ftrace_release_mod). Nem o list_del nem o kobject_del que
// escondem das outras duas interfaces tocam nesse registro. E o dono aparece
// anotado entre colchetes — `nf_conntrack_lock [nf_conntrack]` — enquanto
// função de builtin sai SEM tag. Então a tag é a marca de módulo CARREGÁVEL, e
// uma tag que /proc/modules nega é um módulo que carregou e mente sobre isso.
//
// Provado em VM (test/vm/ftrace-hidden-module.sh): um módulo que se desencadeia
// da lista some de /proc/modules e permanece anotado em
// available_filter_functions. E medido em host real: 239 tags, todas presentes
// em /proc/modules — a direção não tem falso positivo de fábrica.
//
// O custo é declarado: o arquivo tem dezenas de milhares de linhas, e a leitura
// guarda só o conjunto de tags distintas.
func cruzarModulosFtrace(f *Facts, e *env.Env) {
	// VAZIO não é ILEGÍVEL, e a diferença é o achado.
	//
	// A guarda ingênua era `len(ModProc) == 0 → volta`. Ela confundia as duas
	// coisas, e a VM da prova pegou: num host mínimo, depois que o módulo se
	// esconde, /proc/modules fica VAZIO — nenhum outro módulo carregado —, e a
	// guarda pulava a comparação exatamente quando o módulo oculto era a única
	// coisa a achar. É a mesma confusão entre "não há" e "não consegui ver" que
	// a ferramenta inteira existe para não cometer.
	//
	// Por isso a leitura é feita AQUI, para saber se /proc/modules pôde ser
	// lido, e não deduzida de a lista estar vazia. Ilegível é lacuna; vazio e
	// legível é uma resposta com a qual se cruza.
	if _, ok := readTrim("/proc/modules"); !ok {
		// O coletor de crossview já declarou esta lacuna; não a duplico.
		return
	}

	var texto string
	var achou, negado bool
	for _, p := range []string{
		"/sys/kernel/tracing/available_filter_functions",
		"/sys/kernel/debug/tracing/available_filter_functions",
	} {
		b, err := e.ReadFile(p)
		if err == nil {
			texto, achou = string(b), true
			break
		}
		if !os.IsNotExist(err) {
			negado = true
		}
	}
	if !achou {
		if negado {
			// AUSENTE é contêiner sem tracing próprio, e não é lacuna — igual ao
			// que o coletor de ftrace já decidiu. ILEGÍVEL com o arquivo
			// presente é falta de privilégio, e aí a comparação não foi feita.
			f.partial("cross", "available_filter_functions existe e não pôde ser "+
				"lido (exige root): a terceira interface de módulos — a que pega o "+
				"LKM que se desencadeia da lista — NÃO foi cruzada")
		}
		return
	}

	f.Cross.ModFtrace = tagsDeModuloDoFtrace(texto)
	f.Cross.ModFtraceDiff = ModulosSoNoFtrace(f.Cross.ModFtrace, f.Cross.ModProc)
}

// tagsDeModuloDoFtrace extrai o conjunto de módulos anotados, sem duplicar. A
// anotação é o último `[nome]` da linha; função de builtin não tem nenhum.
func tagsDeModuloDoFtrace(texto string) []string {
	visto := map[string]bool{}
	for _, ln := range strings.Split(texto, "\n") {
		i := strings.LastIndexByte(ln, '[')
		if i < 0 || !strings.HasSuffix(ln, "]") {
			continue
		}
		nome := ln[i+1 : len(ln)-1]
		// A tag é um nome de módulo: sem espaço e não vazia. O filtro evita que
		// uma linha de formato inesperado invente um "módulo".
		if nome == "" || strings.ContainsAny(nome, " \t") {
			continue
		}
		visto[nome] = true
	}
	out := make([]string, 0, len(visto))
	for m := range visto {
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}

// ModulosSoNoFtrace devolve as tags do ftrace ausentes de /proc/modules.
//
// Separada da leitura porque é a DECISÃO: assim a regra que acusa um rootkit de
// kernel é exercitável sem bootar uma VM. Uma direção só — o ftrace conhece
// menos módulos que /proc/modules (os sem função rastreável não aparecem), e
// "em /proc e não no ftrace" é esse caso normal, não anomalia.
func ModulosSoNoFtrace(emFtrace, emProc []string) []string {
	proc := map[string]bool{}
	for _, m := range emProc {
		proc[normalizaModulo(m)] = true
	}
	var out []string
	for _, m := range emFtrace {
		if !proc[normalizaModulo(m)] {
			out = append(out, m+" tem função rastreável no ftrace e NÃO está em /proc/modules")
		}
	}
	sort.Strings(out)
	return out
}
