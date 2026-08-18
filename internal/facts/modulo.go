package facts

import (
	"strconv"
	"strings"

	"github.com/lex0c/aletheia/internal/env"
)

// Os módulos CARREGADOS, e a pergunta que faltava sobre eles.
//
// A ferramenta já sabia decodificar a marca de taint e comparar as duas
// interfaces do kernel (/proc/modules × /sys/module). Faltava a pergunta mais
// direta, que é a mesma que ela faz para binário em execução desde a fase 7:
//
//	que ARQUIVO entregou isto?
//
// Um módulo carregado sem `.ko` que o explique é a assinatura de
// `insmod /tmp/x.ko && rm /tmp/x.ko` — o arquivo some, o código continua dentro
// do kernel, e o único vestígio em disco é nenhum.

// ModuloCarregado é uma linha de /proc/modules, respondida contra o disco.
type ModuloCarregado struct {
	Nome    string `json:"name"`
	Tamanho int    `json:"size,omitempty"`
	Refs    int    `json:"refs"`
	Estado  string `json:"state,omitempty"` // Live | Loading | Unloading
	// Letras é o taint que ESTE módulo admite: O fora da árvore, E sem
	// assinatura, F carregado à força.
	Letras string `json:"taint,omitempty"`
	// Arquivo é o .ko que explica este módulo, ou vazio.
	Arquivo string `json:"file,omitempty"`
	// NoSys diz que o módulo também aparece em /sys/module. Ausência ali com
	// presença no /proc é divergência, e tem check próprio (cross.module_view).
	NoSys bool `json:"in_sysfs,omitempty"`
}

// SemArquivo é a pergunta que o check faz.
func (m ModuloCarregado) SemArquivo() bool { return m.Arquivo == "" }

// NaoAssinado diz que o próprio kernel marcou este módulo como vindo de fora do
// conjunto assinado da distribuição.
//
//	O  construído fora da árvore do kernel
//	E  sem assinatura, ou com assinatura que não confere
//	F  carregado à força, ignorando a checagem de versão
func (m ModuloCarregado) NaoAssinado() bool {
	return strings.ContainsAny(m.Letras, "OEF")
}

// collectModulosCarregados lê /proc/modules e responde cada linha contra os
// arquivos que collectModuleFiles já encontrou.
//
// A ORDEM importa: este coletor depende de f.ModuleFiles, que vem da varredura
// de filesystem. Rodar antes dela responderia "nenhum módulo tem arquivo" em
// todo host — a pior forma de falso positivo, porque é uniforme e convincente.
func collectModulosCarregados(f *Facts, e *env.Env) {
	texto, err := readTrimErr("/proc/modules")
	if err != nil {
		f.partial("modulo", "/proc/modules ilegível: os módulos carregados não "+
			"foram confrontados com o que existe em disco")
		return
	}

	// A árvore precisa ter sido LIDA para que a ausência signifique alguma
	// coisa. Sem ela, todo módulo pareceria sem arquivo — e essa é exatamente a
	// diferença entre "não achei" e "não consegui olhar".
	f.ArvoreDeModulos = len(f.ModuleFiles) > 0

	porNome := indiceDeModulosEmDisco(f.ModuleFiles)
	noSys := map[string]bool{}
	for _, n := range f.Cross.ModSys {
		noSys[normalizaModulo(n)] = true
	}

	for _, ln := range strings.Split(texto, "\n") {
		campos := strings.Fields(ln)
		if len(campos) < 3 {
			continue
		}
		m := ModuloCarregado{Nome: campos[0]}
		m.Tamanho, _ = strconv.Atoi(campos[1])
		m.Refs, _ = strconv.Atoi(campos[2])
		if len(campos) >= 5 {
			m.Estado = campos[4]
		}
		// As letras vêm entre parênteses no fim da linha: "… Live 0x0 (OE)".
		if i := strings.LastIndex(ln, "("); i >= 0 {
			if j := strings.Index(ln[i:], ")"); j > 1 {
				m.Letras = ln[i+1 : i+j]
			}
		}
		chave := normalizaModulo(m.Nome)
		m.Arquivo = porNome[chave]
		m.NoSys = noSys[chave]
		f.Carregados = append(f.Carregados, m)
	}

	// A lacuna só existe se houver PERGUNTA. Um guest mínimo sem /lib/modules e
	// sem módulo carregado nenhum não tem nada a responder — declarar cobertura
	// degradada ali seria inventar uma dúvida que não existe, e degradar por
	// nada gasta a mesma atenção que uma lacuna de verdade.
	// Em contêiner a lista é a do HOST e a árvore é a da imagem: não há lacuna
	// a declarar porque não há pergunta a fazer daqui (ver o check).
	if !f.ArvoreDeModulos && len(f.Carregados) > 0 && !f.Host.EmContainer {
		f.partial("modulo", strconv.Itoa(len(f.Carregados))+" módulo(s) carregado(s) "+
			"e nenhum arquivo de módulo encontrado em /lib/modules ou "+
			"/usr/lib/modules: sem a árvore não dá para dizer se algum deles tem "+
			"arquivo que o explique")
	}
}

// indiceDeModulosEmDisco mapeia nome de módulo → caminho do arquivo.
//
// Duas armadilhas moram aqui, e as duas produzem falso positivo em massa:
//
//	traço vira sublinhado   o kernel chama de `snd_hda_intel` o que o arquivo
//	                        chama de `snd-hda-intel.ko`. Comparar cru acusaria
//	                        metade dos módulos de todo desktop
//	compressão              .ko, .ko.xz, .ko.gz e .ko.zst são o mesmo módulo.
//	                        Distribuição moderna comprime por padrão
func indiceDeModulosEmDisco(arquivos []string) map[string]string {
	out := make(map[string]string, len(arquivos))
	for _, p := range arquivos {
		base := p
		if i := strings.LastIndex(base, "/"); i >= 0 {
			base = base[i+1:]
		}
		for _, sufixo := range []string{".ko.zst", ".ko.xz", ".ko.gz", ".ko"} {
			if s, achou := strings.CutSuffix(base, sufixo); achou {
				base = s
				break
			}
		}
		n := normalizaModulo(base)
		if _, existe := out[n]; !existe {
			out[n] = p
		}
	}
	return out
}

// A normalização de nome (traço vira sublinhado) já existe em crossview.go, e é
// a mesma regra do kernel: reaproveitar em vez de duplicar mantém as duas
// leituras de /proc/modules concordando entre si.
