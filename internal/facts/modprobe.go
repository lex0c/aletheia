package facts

import (
	"strings"
	"syscall"

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
	// /run e /usr/local/lib entram porque o systemd os PROCURA (modules-load.d(5)),
	// e é justamente onde vai parar o implante que não quer escrever em disco
	// persistente: /usr costuma ser read-only, e o que está em /run some no
	// reboot sem deixar arquivo para o próximo respondedor achar.
	for _, dir := range []string{
		"/etc/modules-load.d", "/run/modules-load.d",
		"/usr/local/lib/modules-load.d", "/usr/lib/modules-load.d",
	} {
		nomes, err := e.ReadDirNamesErr(dir)
		if env.EhLacuna(err) {
			f.denyPersist("modprobe", dir+" não pôde ser listado ("+
				env.MotivoDoErro(err)+"): os módulos carregados no boot NÃO foram lidos")
			continue
		}
		for _, n := range nomes {
			if strings.HasSuffix(n, ".conf") {
				lerCargaDeModulo(f, e, dir+"/"+n)
			}
		}
	}

	// modprobe.d: aqui mora a diretiva que EXECUTA. Um diretório ilegível aqui
	// silenciava persist.modprobe_install — o `install <mod> /bin/sh -c …` que
	// roda como root na carga do módulo.
	//
	// A lista é a do modprobe.d(5), na ordem em que o kmod procura. /run e
	// /usr/local/lib faltavam, e é ali que um `install` executa como root a cada
	// carga de módulo sem tocar em disco persistente — /usr costuma ser
	// read-only. O coletor de binfmt, neste mesmo pacote, já incluía /run.
	for _, dir := range []string{
		"/etc/modprobe.d", "/run/modprobe.d", "/usr/local/lib/modprobe.d",
		"/lib/modprobe.d", "/usr/lib/modprobe.d",
	} {
		nomes, err := e.ReadDirNamesErr(dir)
		if env.EhLacuna(err) {
			f.denyPersist("modprobe", dir+" não pôde ser listado ("+
				env.MotivoDoErro(err)+"): a diretiva `install`, que EXECUTA como "+
				"root na carga de um módulo, NÃO foi avaliada")
			continue
		}
		for _, n := range nomes {
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
		if env.EhLacuna(err) {
			f.denyPersist("modprobe", p+" existe e não pôde ser lido ("+
				env.MotivoDoErro(err)+"): os módulos que ele manda carregar no boot "+
				"NÃO foram avaliados")
		}
		return
	}
	for _, ll := range linhasLogicas(string(b)) {
		ln := strings.TrimSpace(ll.Texto)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		// A forma antiga aceita opções depois do nome; só o nome interessa.
		nome := strings.Fields(ln)[0]
		f.Modules = append(f.Modules, ModuleConf{
			File: p, Line: ll.Num, Kind: "load", Module: nome,
		})
	}
}

// lerModprobe interpreta um arquivo de modprobe.d.
//
// A continuação por barra invertida passa por linhasLogicas (users.go), a mesma
// do sudoers, e pela mesma razão: o kmod trata `\` no fim da linha como
// continuação, junta DIRETO, e só depois descarta o que começa com `#`.
//
// Sem isso, `install mod /bin/sh -c '…' \` com o resto na linha seguinte deixava
// Cmd truncado em `\` — e soChamaModprobe (checks/modprobe.go) aceita `\` como
// nome de módulo, porque não contém `/`, e devolve true. O resultado era
// persist.modprobe_install SUPRIMINDO o achado enquanto o kmod executava a linha
// inteira como root. A continuação partia o comando exatamente no ponto que o
// tornava invisível, e escrevê-la é grátis para quem planta.
func lerModprobe(f *Facts, e *env.Env, p string) {
	b, err := e.ReadFile(p)
	if err != nil {
		if env.EhLacuna(err) {
			f.denyPersist("modprobe", p+" existe e não pôde ser lido ("+
				env.MotivoDoErro(err)+"): a diretiva `install`, que EXECUTA como root "+
				"na carga de um módulo, NÃO foi avaliada")
		}
		return
	}
	for _, ll := range linhasLogicas(string(b)) {
		ln := strings.TrimSpace(ll.Texto)
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
			File: p, Line: ll.Num, Kind: fs[0], Module: fs[1],
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

// collectModuleFiles lista os módulos em disco.
//
// São DUAS listas, e a distinção importa: ModuleFiles alimenta a pergunta de
// PROPRIEDADE ("que pacote entregou este .ko?"), da qual DKMS está fora por
// desenho; ModuleFilesExternos guarda justamente os excluídos. Quem pergunta
// "existe arquivo em disco para este módulo carregado?" precisa das duas —
// misturar as coisas fazia todo host com nvidia-dkms ou virtualbox-dkms
// reportar SemArquivo() para módulos que estão lá, e como o kernel marca esses
// módulos (OE), NaoAssinado() também era verdade: 4 a 6 CRITICAL irreversíveis
// falsos por estação com placa dedicada.
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
		nomes, err := e.ReadDirNamesErr(dir)
		if env.EhLacuna(err) {
			// Subárvore de módulos ilegível: os .ko dela não entram no índice, e
			// "este módulo não tem arquivo em disco" deixa de ser distinguível de
			// "não consegui listar onde ele estaria" — que vira SemArquivo() e um
			// falso CRÍTICO no check de módulo.
			f.denyPersist("modprobe", dir+" (sob /lib/modules) não pôde ser listado ("+
				env.MotivoDoErro(err)+"): os módulos em disco dali NÃO foram indexados")
			return
		}
		for _, ent := range nomes {
			p := dir + "/" + ent
			if e.IsDir(p) {
				anda(p, prof+1)
				continue
			}
			if !ehModulo(ent) {
				continue
			}
			if ehDKMS(p) {
				f.ModuleFilesExternos = append(f.ModuleFilesExternos, p)
				continue
			}
			f.ModuleFiles = append(f.ModuleFiles, p)
		}
	}
	// Em distribuição usrmerged /lib é symlink para usr/lib, então as duas
	// raízes são a MESMA árvore: andar as duas duplicava cada .ko e gastava
	// metade do teto à toa — com quatro kernels instalados o corte passava a
	// cair DENTRO da primeira raiz, e todo módulo da subárvore não visitada
	// virava SemArquivo. Identidade é dev+ino, não prefixo de string.
	type ident struct{ dev, ino uint64 }
	vistas := map[ident]bool{}
	for _, raiz := range []string{"/lib/modules", "/usr/lib/modules"} {
		if !e.IsDir(raiz) {
			continue
		}
		if fi, err := e.Stat(raiz); err == nil {
			if st, ok := fi.Sys().(*syscall.Stat_t); ok {
				id := ident{uint64(st.Dev), uint64(st.Ino)}
				if vistas[id] {
					continue
				}
				vistas[id] = true
			}
		}
		anda(raiz, 0)
	}
	if visitados > maxModuleDirs {
		f.denyPersist("modprobe", "a listagem de módulos parou em "+
			"muitos diretórios: o excedente NÃO foi verificado")
		// A lacuna também precisa sair na categoria de quem a CONSOME: o
		// check de módulo lê Partial["modulo"], e um índice cortado ali vira
		// SemArquivo() sem que o buraco apareça no check que ele corrompe.
		f.partial("modulo", "o índice de módulos em disco está INCOMPLETO "+
			"(teto de diretórios atingido): 'sem arquivo em disco' não pode "+
			"ser distinguido de 'não indexado'")
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
