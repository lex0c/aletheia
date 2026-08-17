package facts

import (
	"strings"

	"github.com/lex0c/aletheia/internal/env"
)

// Módulos de kernel (runbook §7.12, §35.3).
//
// É a camada mais funda da persistência: um módulo roda no kernel, e a partir
// dali ele mente para tudo que estiver acima — inclusive para esta ferramenta.
// Os checks de visão cruzada dizem isso em voz alta, e o limite continua
// valendo: se o kernel está comprometido, todas as fontes podem mentir juntas.
//
// O que se pode fazer com honestidade é olhar o que fica em DISCO, que é onde a
// resposta a incidente realmente trabalha. Três mecanismos, e o terceiro quase
// não é conhecido:
//
//	/etc/modules-load.d/*.conf   diz ao systemd o que carregar no boot
//	/etc/modules                 o mesmo, na forma antiga
//	/etc/modprobe.d/*.conf       `install <mod> <comando>` NÃO carrega módulo:
//	                             executa o comando, como root

// ModuleConf é uma diretiva de configuração de módulo.
type ModuleConf struct {
	File string `json:"file"`
	Line int    `json:"line"`

	// Kind: "load" (carga automática) ou "install"/"alias" (executa comando).
	Kind   string `json:"kind"`
	Module string `json:"module"`

	// Cmd só existe em "install" e "alias": é o que roda como root.
	Cmd string `json:"cmd,omitempty"`
}

func collectModprobe(f *Facts, e *env.Env) {
	collectModuleFiles(f, e)

	// Carga automática no boot: as duas formas dizem a mesma coisa.
	lerCargaDeModulo(f, e, "/etc/modules")
	for _, n := range e.ReadDirNames("/etc/modules-load.d") {
		if strings.HasSuffix(n, ".conf") {
			lerCargaDeModulo(f, e, "/etc/modules-load.d/"+n)
		}
	}

	// modprobe.d: aqui mora a diretiva que EXECUTA.
	for _, dir := range []string{"/etc/modprobe.d", "/lib/modprobe.d", "/usr/lib/modprobe.d"} {
		for _, n := range e.ReadDirNames(dir) {
			if !strings.HasSuffix(n, ".conf") {
				continue
			}
			lerModprobe(f, e, dir+"/"+n)
		}
	}
}

func lerCargaDeModulo(f *Facts, e *env.Env, p string) {
	b, err := e.ReadFile(p)
	if err != nil {
		return
	}
	for i, raw := range strings.Split(string(b), "\n") {
		ln := strings.TrimSpace(raw)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		// A forma antiga aceita opções depois do nome; só o nome interessa.
		nome := strings.Fields(ln)[0]
		f.Modules = append(f.Modules, ModuleConf{
			File: p, Line: i + 1, Kind: "load", Module: nome,
		})
	}
}

func lerModprobe(f *Facts, e *env.Env, p string) {
	b, err := e.ReadFile(p)
	if err != nil {
		return
	}
	for i, raw := range strings.Split(string(b), "\n") {
		ln := strings.TrimSpace(raw)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		fs := strings.Fields(ln)
		if len(fs) < 3 {
			continue
		}
		// `install` e `alias` são as duas que executam. `blacklist` e `options`
		// não executam nada e não interessam aqui.
		switch fs[0] {
		case "install", "alias":
		default:
			continue
		}
		f.Modules = append(f.Modules, ModuleConf{
			File: p, Line: i + 1, Kind: fs[0], Module: fs[1],
			Cmd: strings.Join(fs[2:], " "),
		})
	}
}

// dkmsOuExterno são as árvores onde módulo compilado LOCALMENTE mora. DKMS —
// nvidia, virtualbox, drivers de placa — instala ali por desenho, e nada disso
// vem de pacote. Sem esta exclusão, toda estação com placa de vídeo dedicada
// vira dezenas de achados.
//
// `/misc/` NÃO entra, apesar de o DKMS às vezes usá-lo: `kernel/drivers/misc`
// é diretório PADRÃO do kernel, e casar por substring excluía a árvore
// legítima inteira. O módulo plantado no cenário 97 caía justamente ali, e a
// varredura o ignorava em silêncio — exclusão larga demais é indistinguível
// de não procurar.
var dkmsOuExterno = []string{"/updates/dkms/", "/extra/", "/weak-updates/"}

// collectModuleFiles lista os módulos em disco para a pergunta de propriedade.
//
// A árvore é grande — alguns milhares de arquivos — mas a pergunta é respondida
// numa passada só sobre as listas do gerenciador, então o custo é a caminhada e
// não a consulta.
func collectModuleFiles(f *Facts, e *env.Env) {
	visitados := 0
	var anda func(dir string, prof int)
	anda = func(dir string, prof int) {
		if prof > 8 || visitados > maxModuleDirs {
			return
		}
		visitados++
		for _, ent := range e.ReadDirNames(dir) {
			p := dir + "/" + ent
			if e.IsDir(p) {
				anda(p, prof+1)
				continue
			}
			if !ehModulo(ent) || ehDKMS(p) {
				continue
			}
			f.ModuleFiles = append(f.ModuleFiles, p)
		}
	}
	for _, raiz := range []string{"/lib/modules", "/usr/lib/modules"} {
		if e.IsDir(raiz) {
			anda(raiz, 0)
		}
	}
	if visitados > maxModuleDirs {
		f.denyPersist("modprobe", "a listagem de módulos parou em "+
			"muitos diretórios: o excedente NÃO foi verificado")
	}
}

const maxModuleDirs = 4000

func ehModulo(n string) bool {
	return strings.HasSuffix(n, ".ko") || strings.HasSuffix(n, ".ko.xz") ||
		strings.HasSuffix(n, ".ko.gz") || strings.HasSuffix(n, ".ko.zst")
}

func ehDKMS(p string) bool {
	for _, d := range dkmsOuExterno {
		if strings.Contains(p, d) {
			return true
		}
	}
	return false
}
