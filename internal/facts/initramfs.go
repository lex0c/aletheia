package facts

import (
	"io/fs"
	"strings"

	"github.com/lex0c/aletheia/internal/env"
)

// A geração do initramfs (runbook §7.12).
//
// # A camada antes do userland
//
// Toda a §7 pergunta o que faz o host executar alguma coisa DEPOIS do boot:
// unit, cron, perfil de shell. O initramfs roda ANTES de tudo isso — antes de o
// sistema de arquivos raiz assumir —, como root, e o que ele contém é montado
// por scripts de GERAÇÃO que ficam em disco:
//
//	initramfs-tools  /etc/initramfs-tools/hooks, /etc/initramfs-tools/scripts
//	                 /usr/share/initramfs-tools/{hooks,scripts}
//	dracut           /usr/lib/dracut/modules.d, e install_items em dracut.conf.d
//	mkinitcpio       /etc/initcpio/{hooks,install}, /usr/lib/initcpio/{hooks,install}
//	                 e FILES= em mkinitcpio.conf
//	kernel-install   /etc/kernel/install.d, /usr/lib/kernel/install.d
//
// Pegar a persistência aqui — nos scripts que GERAM o initramfs — é mais barato
// e mais cedo que descompactar a imagem: é filesystem, vale em modo image, e cai
// no mesmo discriminador de propriedade de pacote da §24. O parser da imagem
// compactada é outra pergunta, mais cara, e NÃO está feita.
//
// # O que decide o falso positivo
//
// Admin acrescenta hook de initramfs legitimamente — LUKS, hardware incomum. O
// discriminador é o de sempre: de onde vem o arquivo. Um script sem dono num
// diretório de PACOTE (/usr/lib/dracut) é forte; em /etc é território do
// administrador, e vale menos.

// ArtefatoInitramfs é um arquivo que entra na geração do initramfs.
type ArtefatoInitramfs struct {
	Path      string `json:"path"`
	Mecanismo string `json:"mechanism"`
	// Como diz por que este arquivo importa: um hook executável, ou um caminho
	// REFERENCIADO por uma configuração para ser embutido na imagem.
	Como string `json:"how"`
}

// dirsHookInitramfs são os diretórios de SCRIPT de geração. Recursivo=true entra
// um nível (scripts/ tem subpastas init-top/…, modules.d/ tem uma por módulo).
var dirsHookInitramfs = []struct {
	dir       string
	mecanismo string
	recursivo bool
}{
	{"/etc/initramfs-tools/hooks", "initramfs-tools", false},
	{"/etc/initramfs-tools/scripts", "initramfs-tools", true},
	{"/usr/share/initramfs-tools/hooks", "initramfs-tools", false},
	{"/usr/share/initramfs-tools/scripts", "initramfs-tools", true},
	{"/usr/lib/dracut/modules.d", "dracut", true},
	{"/etc/initcpio/hooks", "mkinitcpio", false},
	{"/etc/initcpio/install", "mkinitcpio", false},
	{"/usr/lib/initcpio/hooks", "mkinitcpio", false},
	{"/usr/lib/initcpio/install", "mkinitcpio", false},
	{"/etc/kernel/install.d", "kernel-install", false},
	{"/usr/lib/kernel/install.d", "kernel-install", false},
}

func collectInitramfs(f *Facts, e *env.Env) {
	for _, d := range dirsHookInitramfs {
		coletaHooksDe(f, e, d.dir, d.mecanismo, d.recursivo)
	}
	coletaDracutConf(f, e)
	coletaMkinitcpioConf(f, e)
}

// participaDaGeracao diz se um arquivo daquele mecanismo entra na geração do
// initramfs — e o critério NÃO é o bit de execução para todos.
//
// O dracut SOURCEIA o module-setup.sh:
//
//	. "$_moddir"/module-setup.sh
//
// e o teste dele é de EXISTÊNCIA, não de `-x`. Arquivo sourceado não precisa de
// bit de execução, então o filtro universal de +x descartava um
// modules.d/99evil/module-setup.sh com modo 0644 ANTES de perguntar quem o
// entregou — e o arquivo participa da geração igual.
//
// O detalhe que torna isso pior: a distribuição entrega todos os module-setup.sh
// com 755. Num host de fábrica o filtro não remove nada; o ÚNICO que ele remove
// é o que alguém plantou sem se dar ao trabalho de dar chmod. O critério estava
// exatamente invertido contra o adversário.
func participaDaGeracao(mecanismo, nome string, modo fs.FileMode) (string, bool) {
	if mecanismo == "dracut" && nome == "module-setup.sh" {
		return "módulo de dracut (sourceado, não executado)", true
	}
	if modo.Perm()&0o111 != 0 {
		return "hook executável", true
	}
	return "", false
}

// coletaHooksDe registra os arquivos que participam da geração do initramfs.
func coletaHooksDe(f *Facts, e *env.Env, dir, mecanismo string, recursivo bool) {
	nomes, err := e.ReadDirNamesErr(dir)
	if env.EhLacuna(err) {
		f.denyPersist("initramfs", dir+" não pôde ser listado ("+env.MotivoDoErro(err)+
			"): os hooks de geração do initramfs NÃO foram avaliados")
		return
	}
	for _, n := range nomes {
		p := dir + "/" + n
		fi, err := e.Lstat(p)
		if err != nil {
			// "não existe" é corrida; "não consegui olhar" é lacuna, e um hook
			// de initramfs roda como root antes do userland.
			if env.EhLacuna(err) {
				f.denyPersist("initramfs", p+" não pôde ser examinado ("+
					env.MotivoDoErro(err)+"): não se sabe se ele participa da geração")
			}
			continue
		}
		if fi.IsDir() {
			if recursivo {
				// Um nível só: modules.d/<modulo>/*.sh, scripts/<fase>/*.
				coletaHooksDe(f, e, p, mecanismo, false)
			}
			continue
		}
		como, ok := participaDaGeracao(mecanismo, n, fi.Mode())
		if !ok {
			continue
		}
		f.Initramfs = append(f.Initramfs, ArtefatoInitramfs{
			Path: p, Mecanismo: mecanismo, Como: como,
		})
	}
}

// coletaDracutConf extrai os caminhos que dracut.conf.d manda EMBUTIR na imagem
// via install_items. Um payload referenciado aqui entra no initramfs e roda como
// root no early boot, sem estar em nenhum hook.
func coletaDracutConf(f *Facts, e *env.Env) {
	for _, dir := range []string{"/etc/dracut.conf.d", "/usr/lib/dracut/dracut.conf.d"} {
		nomes, err := e.ReadDirNamesErr(dir)
		if env.EhLacuna(err) {
			f.denyPersist("initramfs", dir+" não pôde ser listado ("+env.MotivoDoErro(err)+")")
			continue
		}
		for _, n := range nomes {
			if !strings.HasSuffix(n, ".conf") {
				continue
			}
			p := dir + "/" + n
			b, err := e.ReadFile(p)
			if err != nil {
				if env.EhLacuna(err) {
					f.denyPersist("initramfs", p+" não pôde ser lido ("+env.MotivoDoErro(err)+
						"): os arquivos que ele manda EMBUTIR na imagem não foram avaliados")
				}
				continue
			}
			for _, alvo := range caminhosDeAtribuicaoShell(string(b), "install_items") {
				f.Initramfs = append(f.Initramfs, ArtefatoInitramfs{
					Path: alvo, Mecanismo: "dracut", Como: "install_items em " + baseNome(p),
				})
			}
		}
	}
}

// coletaMkinitcpioConf extrai os caminhos de FILES= — os arquivos que o
// mkinitcpio embute na imagem literalmente.
func coletaMkinitcpioConf(f *Facts, e *env.Env) {
	for _, p := range []string{"/etc/mkinitcpio.conf"} {
		b, err := e.ReadFile(p)
		if err != nil {
			if env.EhLacuna(err) {
				f.denyPersist("initramfs", p+" não pôde ser lido ("+env.MotivoDoErro(err)+
					"): os arquivos que ele manda EMBUTIR na imagem não foram avaliados")
			}
			continue
		}
		for _, alvo := range caminhosDeArrayShell(string(b), "FILES") {
			f.Initramfs = append(f.Initramfs, ArtefatoInitramfs{
				Path: alvo, Mecanismo: "mkinitcpio", Como: "FILES em mkinitcpio.conf",
			})
		}
	}
	// mkinitcpio.conf.d é o diretório de drop-in moderno.
	nomes, err := e.ReadDirNamesErr("/etc/mkinitcpio.conf.d")
	if env.EhLacuna(err) {
		f.denyPersist("initramfs", "/etc/mkinitcpio.conf.d não pôde ser listado ("+
			env.MotivoDoErro(err)+")")
		return
	}
	for _, n := range nomes {
		if !strings.HasSuffix(n, ".conf") {
			continue
		}
		p := "/etc/mkinitcpio.conf.d/" + n
		if b, err := e.ReadFile(p); err == nil {
			for _, alvo := range caminhosDeArrayShell(string(b), "FILES") {
				f.Initramfs = append(f.Initramfs, ArtefatoInitramfs{
					Path: alvo, Mecanismo: "mkinitcpio", Como: "FILES em " + baseNome(p),
				})
			}
		}
	}
}

// caminhosDeAtribuicaoShell extrai os caminhos absolutos de uma atribuição de
// shell do tipo `chave="… /a /b …"` ou `chave+=" … "`, que é a forma do
// install_items do dracut.
func caminhosDeAtribuicaoShell(corpo, chave string) []string {
	var out []string
	for _, ln := range strings.Split(corpo, "\n") {
		ln = strings.TrimSpace(ln)
		if strings.HasPrefix(ln, "#") {
			continue
		}
		resto, ok := strings.CutPrefix(ln, chave+"+=")
		if !ok {
			resto, ok = strings.CutPrefix(ln, chave+"=")
		}
		if !ok {
			continue
		}
		out = append(out, absolutosEm(resto)...)
	}
	return out
}

// caminhosDeArrayShell extrai os caminhos absolutos de um array de shell
// `CHAVE=(/a /b)`, que é a forma do FILES do mkinitcpio. O array pode ocupar
// várias linhas até o `)`.
func caminhosDeArrayShell(corpo, chave string) []string {
	var out []string
	linhas := strings.Split(corpo, "\n")
	dentro := false
	for _, ln := range linhas {
		t := strings.TrimSpace(ln)
		if strings.HasPrefix(t, "#") {
			continue
		}
		if !dentro {
			resto, ok := strings.CutPrefix(t, chave+"=(")
			if !ok {
				continue
			}
			dentro = true
			t = resto
		}
		if i := strings.IndexByte(t, ')'); i >= 0 {
			out = append(out, absolutosEm(t[:i])...)
			dentro = false
			continue
		}
		out = append(out, absolutosEm(t)...)
	}
	return out
}

// absolutosEm devolve os tokens que são caminho absoluto, sem aspas. Só o que
// começa com / interessa — a pergunta de propriedade não responde por token
// relativo nem por variável.
func absolutosEm(s string) []string {
	s = strings.NewReplacer("\"", " ", "'", " ", "(", " ", ")", " ").Replace(s)
	var out []string
	for _, tok := range strings.Fields(s) {
		if strings.HasPrefix(tok, "/") {
			out = append(out, tok)
		}
	}
	return out
}
