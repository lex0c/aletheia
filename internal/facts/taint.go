package facts

import (
	"sort"
	"strings"

	"github.com/lex0c/aletheia/internal/env"
)

// Marcas que o kernel guarda sobre o que já foi carregado nele (runbook §35.3).
//
// # A propriedade que faz isto valer a pena
//
// O taint é MONOTÔNICO. O kernel só acrescenta bits: escrever em
// /proc/sys/kernel/tainted faz OR com o valor atual, e nem o root consegue
// limpar sem reiniciar. Um módulo que se carrega, suja o kernel e depois se
// desencadeia da lista para sumir deixa o bit para trás — e o bit não some.
//
// É evidência que sobrevive ao invasor que fez tudo certo do lado dele. Quase
// nada nesta ferramenta tem essa propriedade: log se apaga, arquivo se remove,
// processo termina, histórico se desliga. O bit de taint, não.
//
// # E a pergunta certa não é "o kernel está sujo?"
//
// Está sujo em quase todo desktop e em muito servidor: driver de vídeo,
// VirtualBox, qualquer coisa vinda de DKMS. Medido num host real, um Manjaro
// com nvidia: bits 12 e 13 ligados, quatro módulos assumindo as duas letras.
// Acusar o ESTADO acusaria esse host, e ele não tem nada de errado.
//
// A pergunta é de ATRIBUIÇÃO: o kernel diz que um módulo fez algo; algum
// módulo carregado ADMITE ter feito? Quando ninguém admite, ou o módulo foi
// removido depois — e removê-lo é o que se faz para não deixar rastro — ou ele
// ainda está lá e não aparece na lista, que é a definição de rootkit.

// Taint é o retrato das marcas.
type Taint struct {
	Lido bool   `json:"read"`
	Bits uint64 `json:"bits"`
	// Letras é o que o kernel imprimiria num oops: "OE".
	Letras  string   `json:"letters,omitempty"`
	Motivos []string `json:"reasons,omitempty"`

	// Modulos são os módulos carregados que ADMITEM alguma marca.
	Modulos []ModuloTaint `json:"tainting_modules,omitempty"`
	// ListaLida diz se /proc/modules pôde ser lido. Sem ele não há atribuição
	// possível, e a ausência de dono não significa nada.
	ListaLida bool `json:"module_list_read"`
}

// ModuloTaint é um módulo carregado e as letras que ele carrega.
type ModuloTaint struct {
	Nome   string `json:"name"`
	Letras string `json:"letters"`
}

// MarcaDeTaint descreve um bit.
type MarcaDeTaint struct {
	Bit   int
	Letra byte
	// DeModulo diz que um módulo CARREGADO exibe esta letra em /proc/modules.
	// É o que torna a atribuição possível — e o que separa "ninguém admite" de
	// "ninguém poderia admitir".
	DeModulo    bool
	Significado string
}

// marcasDeTaint é a tabela do kernel (kernel/panic.c). Só as que dizem algo
// para resposta a incidente têm frase longa; as demais existem para o relatório
// não inventar significado nem omitir bit.
var marcasDeTaint = []MarcaDeTaint{
	{0, 'P', true, "módulo proprietário (sem licença GPL) foi carregado"},
	{1, 'F', true, "módulo carregado À FORÇA (`insmod -f`), contra a checagem de versão do kernel"},
	{2, 'S', false, "CPU fora de especificação"},
	{3, 'R', false, "módulo removido À FORÇA (`rmmod -f`)"},
	{4, 'M', false, "exceção de checagem de máquina (hardware)"},
	{5, 'B', false, "página de memória defeituosa detectada"},
	{6, 'U', false, "taint pedido por programa do espaço de usuário"},
	{7, 'D', false, "o kernel MORREU desde o boot (oops ou BUG)"},
	{8, 'A', false, "tabela ACPI substituída pelo usuário"},
	{9, 'W', false, "o kernel emitiu um aviso (WARN)"},
	{10, 'C', true, "driver de staging (fora da qualidade da árvore) carregado"},
	{11, 'I', false, "contorno para defeito de firmware da plataforma"},
	{12, 'O', true, "módulo FORA DA ÁRVORE do kernel foi carregado"},
	{13, 'E', true, "módulo NÃO ASSINADO foi carregado"},
	{14, 'L', false, "travamento leve (soft lockup) ocorreu"},
	{15, 'K', true, "patch ao vivo (livepatch) aplicado ao kernel"},
	{16, 'X', false, "taint auxiliar, definido pela distribuição"},
	{17, 'T', false, "kernel construído com randomização de struct"},
	{18, 'N', false, "kernel de TESTE"},
}

func collectTaint(f *Facts, e *env.Env) {
	s, err := readTrimErr("/proc/sys/kernel/tainted")
	if err != nil {
		f.partial("taint", "/proc/sys/kernel/tainted ilegível: as marcas que o "+
			"kernel guarda sobre módulo carregado não foram lidas")
		return
	}
	bits, ok := parseUint(s)
	if !ok {
		f.partial("taint", "/proc/sys/kernel/tainted com conteúdo inesperado: "+s)
		return
	}
	f.Taint.Lido = true
	f.Taint.Bits = bits
	f.Taint.Letras, f.Taint.Motivos = decodeTaint(bits)

	// A lista de módulos é lida aqui de propósito, em vez de reaproveitar a da
	// visão cruzada: aquela guarda só o NOME, porque a pergunta dela é
	// "aparece nas duas interfaces?". A pergunta daqui é outra, e o campo é
	// outro — as letras entre parênteses no fim da linha.
	texto, err := readTrimErr("/proc/modules")
	if err != nil {
		f.partial("taint", "/proc/modules ilegível: sem ele não dá para saber "+
			"QUAL módulo respondeu por cada marca do kernel")
		return
	}
	f.Taint.ListaLida = true
	f.Taint.Modulos = modulosComTaint(texto)
}

// decodeTaint traduz o número. Bit desconhecido — kernel mais novo que este
// binário — sai como número, nunca omitido.
func decodeTaint(bits uint64) (string, []string) {
	var letras []byte
	var motivos []string
	conhecidos := uint64(0)
	for _, m := range marcasDeTaint {
		conhecidos |= 1 << m.Bit
		if bits&(1<<m.Bit) == 0 {
			continue
		}
		letras = append(letras, m.Letra)
		motivos = append(motivos, string(m.Letra)+": "+m.Significado)
	}
	if resto := bits &^ conhecidos; resto != 0 {
		motivos = append(motivos, "e bits que este binário não conhece (kernel "+
			"mais novo que ele): 0x"+hexU64(resto))
	}
	return string(letras), motivos
}

// modulosComTaint extrai os módulos que exibem letra. O formato da linha é
//
//	nvidia 76546048 41 nvidia_modeset,nvidia_uvm, Live 0x0000000000000000 (OE)
//
// e o campo entre parênteses só existe quando o módulo carrega alguma marca —
// que é a maioria das linhas NÃO tendo campo nenhum.
func modulosComTaint(texto string) []ModuloTaint {
	var out []ModuloTaint
	for _, ln := range strings.Split(texto, "\n") {
		campos := strings.Fields(ln)
		if len(campos) < 2 {
			continue
		}
		ultimo := campos[len(campos)-1]
		if len(ultimo) < 3 || ultimo[0] != '(' || ultimo[len(ultimo)-1] != ')' {
			continue
		}
		// module_flags() acrescenta '-' (MODULE_STATE_GOING) ou '+'
		// (MODULE_STATE_COMING) DENTRO dos parênteses: "nvidia … (OE+)".
		// Rejeitar a linha inteira por causa desse byte descartava o módulo do
		// inventário, e se ele fosse o único a admitir O/E essas marcas passavam
		// a figurar em TaintSemDono — que a ferramenta lê como "o módulo foi
		// removido para não deixar rastro". Um rmmod lento abria a janela.
		letras := strings.TrimRight(ultimo[1:len(ultimo)-1], "+-")
		if !soLetrasMaiusculas(letras) {
			continue
		}
		out = append(out, ModuloTaint{Nome: campos[0], Letras: letras})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Nome < out[j].Nome })
	return out
}

// TaintSemDono devolve as marcas de MÓDULO que nenhum módulo carregado admite.
//
// Está separada da leitura porque é a DECISÃO — mesma razão de
// DiferencaDeModulos existir sozinha. Sem a separação, a regra que decide se um
// rootkit é acusado só poderia ser exercitada com um rootkit à mão; com ela, a
// regra é testável com os dados que um host real produziu.
//
// Uma marca só entra quando NENHUM módulo carregado exibe a letra. Num host com
// nvidia, as letras O e E têm dono e não entram — que é o falso positivo que
// esta função existe para não cometer.
func TaintSemDono(bits uint64, mods []ModuloTaint) []MarcaDeTaint {
	admitido := map[byte]bool{}
	for _, m := range mods {
		for i := 0; i < len(m.Letras); i++ {
			admitido[m.Letras[i]] = true
		}
	}
	var out []MarcaDeTaint
	for _, m := range marcasDeTaint {
		if !m.DeModulo || bits&(1<<m.Bit) == 0 {
			continue
		}
		// 'P' e 'G' são o mesmo bit visto pelos dois lados: o módulo
		// proprietário exibe 'P', e o kernel imprime 'P' quando algum apareceu.
		if admitido[m.Letra] {
			continue
		}
		out = append(out, m)
	}
	return out
}

// TaintTem responde se um bit está ligado, pela letra.
func TaintTem(bits uint64, letra byte) bool {
	for _, m := range marcasDeTaint {
		if m.Letra == letra {
			return bits&(1<<m.Bit) != 0
		}
	}
	return false
}

// SignificadoDeTaint devolve a frase daquela letra.
func SignificadoDeTaint(letra byte) string {
	for _, m := range marcasDeTaint {
		if m.Letra == letra {
			return m.Significado
		}
	}
	return ""
}

func soLetrasMaiusculas(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 'A' || s[i] > 'Z' {
			return false
		}
	}
	return true
}

func parseUint(s string) (uint64, bool) {
	if s == "" {
		return 0, false
	}
	var n uint64
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
		n = n*10 + uint64(s[i]-'0')
	}
	return n, true
}

func hexU64(v uint64) string {
	const hexa = "0123456789abcdef"
	var b []byte
	for v > 0 {
		b = append([]byte{hexa[v&0xf]}, b...)
		v >>= 4
	}
	if len(b) == 0 {
		return "0"
	}
	return string(b)
}
