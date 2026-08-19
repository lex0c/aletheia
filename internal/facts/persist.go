package facts

import (
	"bufio"
	"errors"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/tools"
)

// Coleta de persistência (runbook §7).
//
// Este é o primeiro coletor BASEADO EM ARQUIVO, e a diferença não é de estilo.
// Tudo que veio antes lê /proc, que só existe em host vivo; daqui em diante a
// mesma análise roda sobre uma imagem montada com --root — onde o kernel é o
// DO ANALISTA e ocultamento por rootkit não acontece (runbook §35.6). É a
// resposta para "o host mente": leia o disco de fora.
//
// A outra decisão que atravessa o arquivo: nada aqui chama `systemctl`. Um
// binário do host comprometido responde o que o atacante quiser, e a §7.2
// existe justamente porque a unit no disco é a verdade que o `systemctl list`
// pode esconder. Ler o arquivo custa mais código e vale o custo.

const (
	// Teto de units lidas. Host grande tem ~400; o teto existe para que um
	// diretório envenenado com milhares de arquivos não trave a coleta — e
	// estourá-lo vira cobertura parcial declarada, nunca corte silencioso.
	maxUnits = 3000
)

// Loader é o que o linker dinâmico injeta em TODO processo dinâmico
// (runbook §7.8). É o rootkit de userland mais comum, e cabe em três arquivos.
type Loader struct {
	// PreloadExists: /etc/ld.so.preload normalmente NÃO existe. A existência
	// já é o achado.
	PreloadExists bool     `json:"preload_exists,omitempty"`
	PreloadLibs   []string `json:"preload_libs,omitempty"`
	PreloadErr    string   `json:"preload_err,omitempty"`

	// SearchDirs são os diretórios de busca declarados em ld.so.conf{,.d}.
	// Um deles gravável é a versão persistente do mesmo truque.
	SearchDirs []LoaderDir `json:"search_dirs,omitempty"`

	// EnvVars são definições de LD_PRELOAD/LD_LIBRARY_PATH em arquivo lido pelo
	// PAM a cada sessão — mesmo efeito, num arquivo que ninguém associa a
	// execução de código.
	EnvVars []EnvSetting `json:"env_vars,omitempty"`
}

type LoaderDir struct {
	Dir    string `json:"dir"`
	From   string `json:"from"` // arquivo que declarou
	Exists bool   `json:"exists,omitempty"`
}

type EnvSetting struct {
	File  string `json:"file"`
	Key   string `json:"key"`
	Value string `json:"value"`
}

// Unit é uma unit de systemd lida do ARQUIVO (runbook §7.2).
type Unit struct {
	Name string `json:"name"`
	Path string `json:"path"`
	Kind string `json:"kind"` // service | timer | socket | path | mount | …

	// Scope separa unit de sistema de unit de USUÁRIO: a segunda roda no login
	// e é o esconderijo da §7.3.
	Scope string `json:"scope"` // system | user

	// Vendor marca a unit que veio de pacote (/usr/lib, /lib) contra a que
	// alguém escreveu (/etc, /run). A de /etc tem PRECEDÊNCIA e pode
	// sobrescrever uma legítima de mesmo nome.
	Vendor bool `json:"vendor,omitempty"`

	// DropInFor != "" quando este arquivo é um drop-in: ele ALTERA outra unit
	// sem tocar no arquivo dela, e `cat` na unit original não mostra nada.
	DropInFor string `json:"dropin_for,omitempty"`

	// EnabledBy lista os *.wants/ e *.requires/ que apontam para esta unit —
	// é o que responde "isto vai rodar?" sem chamar systemctl.
	EnabledBy []string `json:"enabled_by,omitempty"`

	Exec     []ExecLine `json:"exec,omitempty"`
	Restart  string     `json:"restart,omitempty"`
	User     string     `json:"user,omitempty"`
	WantedBy []string   `json:"wanted_by,omitempty"`

	// Gatilhos, por tipo de unit.
	OnCalendar      []string `json:"on_calendar,omitempty"`
	OnUnitActiveSec string   `json:"on_unit_active_sec,omitempty"`
	OnBootSec       string   `json:"on_boot_sec,omitempty"`
	Listen          []string `json:"listen,omitempty"`
	WatchPaths      []string `json:"watch_paths,omitempty"`

	// Environment= da unit. Vai para o mesmo lugar que /etc/environment: é a
	// rota da §7.8 que ninguém associa a execução de código.
	Environment []EnvSetting `json:"environment,omitempty"`

	ModUTC string `json:"mod_utc,omitempty"`

	// Truncated diz que o arquivo não foi lido por inteiro.
	Truncated string `json:"truncated,omitempty"`
}

// ExecLine guarda a diretiva junto com o valor: ExecStartPre num drop-in é
// persistência quase perfeita, e perder qual diretiva era apaga o achado.
type ExecLine struct {
	Key string `json:"key"` // ExecStart | ExecStartPre | …
	Cmd string `json:"cmd"`
}

// Enabled diz se algo aponta para esta unit.
func (u Unit) Enabled() bool { return len(u.EnabledBy) > 0 }

// unitDirs são as árvores de unit, na ordem de precedência do systemd. As de
// /etc e /run vencem as de /usr — e é por isso que o atacante escreve nelas.
var unitDirs = []struct {
	dir    string
	scope  string
	vendor bool
}{
	{"/etc/systemd/system", "system", false},
	{"/run/systemd/system", "system", false},
	{"/usr/lib/systemd/system", "system", true},
	{"/lib/systemd/system", "system", true},
	{"/usr/local/lib/systemd/system", "system", false},
	{"/etc/systemd/user", "user", false},
	{"/usr/lib/systemd/user", "user", true},
}

func collectPersist(f *Facts, e *env.Env) {
	collectLoader(f, e)
	collectUnits(f, e)
	collectToolArtifacts(f, e)
	collectCron(f, e)
	collectSSH(f, e)
	collectTriggers(f, e)
	collectServicosLegados(f, e)
	collectTrust(f, e)
	collectConfiancaDeHost(f, e)
	collectGitHooks(f, e)
	collectSuid(f, e)
	collectModprobe(f, e)
	// Antes do pkg: os alvos dos helpers do kernel precisam entrar na pergunta
	// de propriedade, que é o discriminador inteiro deles.
	collectHelpers(f, e)
	// Junto deles, e pela MESMA razão: o `init=` da linha de boot é um programa
	// que o kernel executa como PID 1, e quem responde por ele é o gerenciador
	// de pacotes. Fica aqui, e não no ramo de /proc, porque a metade que
	// importa em imagem montada — a configuração do bootloader — é filesystem.
	collectBoot(f, e)
	// binfmt em DISCO: a configuração que o systemd-binfmt reaplica no boot.
	// Vale em modo image, e o interpretador dela entra na pergunta de
	// propriedade como qualquer outro alvo executado por conta do sistema.
	collectBinfmtConfig(f, e)
	// Os scripts que GERAM o initramfs: persistência antes do userland, em
	// disco. Também alimenta a pergunta de propriedade.
	collectInitramfs(f, e)
	// ANTES do collectPkg: o ALVO de um hook de interpretador é candidato a
	// propriedade, e é a resposta dessa pergunta que separa configuração de
	// deploy de implante. Depois do collectPkg ele nunca era perguntado, e o
	// check pesava tudo como aviso.
	collectInterpretador(f, e)
	// Por último: a pergunta de propriedade precisa dos candidatos que os
	// coletores acima produziram.
	collectPkg(f, e)
	collectUsers(f, e)
	collectLogins(f, e)
	collectCredenciais(f, e)
	collectHistorico(f, e)
	collectAuditoria(f, e)
	collectLogs(f, e)
	collectMAC(f, e)
	collectSegredos(f, e)

	// Environment= de unit tem o MESMO efeito do /etc/environment, e por isso
	// alimenta a mesma lista: um check só, uma leitura só.
	for i := range f.Units {
		for _, s := range f.Units[i].Environment {
			switch s.Key {
			case "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT":
				f.Loader.EnvVars = append(f.Loader.EnvVars, s)
			}
		}
	}
}

// denyPersist registra o que a coleta de persistência não conseguiu LER. É
// separado do partial genérico porque os checks precisam saber a categoria: uma
// negativa em caminho de ferramenta não degrada o check de unit.
func (f *Facts) denyPersist(cat, motivo string) {
	if f.PersistDenied == nil {
		f.PersistDenied = map[string][]string{}
	}
	f.PersistDenied[cat] = append(f.PersistDenied[cat], motivo)
	f.partial("persist", motivo)
}

// ToolArtifact é a presença em DISCO de uma ferramenta conhecida (runbook
// §5.10, rota "nome de config").
//
// Vale mais que a rota de variável de ambiente por dois motivos: a maioria dos
// implantes usa arquivo de config e não env, e disco é legível em IMAGEM
// MONTADA — onde o kernel é o do analista e ocultamento não acontece (§35.6).
type ToolArtifact struct {
	Family string `json:"family"`
	Path   string `json:"path"`
	IsDir  bool   `json:"is_dir,omitempty"`
}

func collectToolArtifacts(f *Facts, e *env.Env) {
	homes := homeDirs(e)
	visto := map[string]bool{}
	var negados []string

	for _, fam := range tools.All {
		for _, pat := range fam.Paths {
			for _, p := range expandHome(pat, homes) {
				if visto[p] {
					continue
				}
				existe, negado := lookup(e, p)
				if negado {
					// "não pude olhar" não é "não existe". Sem esta distinção,
					// uma varredura sem root reporta cobertura completa tendo
					// ficado cega para /root e para o home dos outros.
					visto[p] = true
					negados = append(negados, p)
					continue
				}
				if !existe {
					continue
				}
				visto[p] = true
				f.ToolArtifacts = append(f.ToolArtifacts, ToolArtifact{
					Family: fam.Name, Path: p, IsDir: e.IsDir(p),
				})
			}
		}
	}
	if len(negados) > 0 {
		f.denyPersist("artifact", strconv.Itoa(len(negados))+
			" caminhos de ferramenta conhecida não puderam ser lidos (permissão): "+
			resumoCaminhos(negados))
	}
	sort.Slice(f.ToolArtifacts, func(i, j int) bool {
		return f.ToolArtifacts[i].Path < f.ToolArtifacts[j].Path
	})
}

// lookup separa os três desfechos de um caminho: existe, não existe, e "não
// pude olhar". O terceiro é o único que degrada cobertura.
func lookup(e *env.Env, p string) (existe, negado bool) {
	_, err := e.Lstat(p)
	switch {
	case err == nil:
		return true, false
	case os.IsNotExist(err), errors.Is(err, syscall.ENOTDIR):
		// ENOTDIR precisa contar como "não existe", e não como "não pude
		// olhar": um componente do caminho que não é diretório significa que o
		// caminho não pode existir. O Alpine usa /dev/null como home de conta
		// de sistema, então /dev/null/.config/... cai aqui — e tratar isso
		// como negativa fazia TODO host Alpine reportar lacuna falsa.
		return false, false
	default:
		return false, true
	}
}

func resumoCaminhos(ps []string) string {
	if len(ps) <= 3 {
		return strings.Join(ps, " · ")
	}
	return strings.Join(ps[:3], " · ") + " · … (+" + strconv.Itoa(len(ps)-3) + ")"
}

// expandHome troca "~" por cada home do passwd DO ALVO. Caminho absoluto passa
// direto.
func expandHome(pat string, homes []string) []string {
	rest, temTil := strings.CutPrefix(pat, "~")
	if !temTil {
		return []string{pat}
	}
	out := make([]string, 0, len(homes))
	for _, h := range homes {
		out = append(out, strings.TrimSuffix(h, "/")+rest)
	}
	return out
}

// --- linker dinâmico (runbook §7.8) ---

func collectLoader(f *Facts, e *env.Env) {
	l := &f.Loader

	switch b, err := e.ReadFile("/etc/ld.so.preload"); {
	case err == nil:
		l.PreloadExists = true
		for _, ln := range strings.Split(string(b), "\n") {
			if ln = strings.TrimSpace(ln); ln != "" && !strings.HasPrefix(ln, "#") {
				l.PreloadLibs = append(l.PreloadLibs, ln)
			}
		}
	case isNotExist(err):
		// O caso normal. Ausência aqui é a resposta esperada.
	default:
		// Existe e não pudemos ler: isso NÃO é "não existe".
		l.PreloadExists = true
		l.PreloadErr = err.Error()
		f.denyPersist("loader", "/etc/ld.so.preload existe e não pôde ser lido: "+err.Error())
	}

	confs := []string{"/etc/ld.so.conf"}
	ents, errCD := e.ReadDir("/etc/ld.so.conf.d")
	if env.EhLacuna(errCD) {
		f.denyPersist("loader", "/etc/ld.so.conf.d não pôde ser listado ("+
			env.MotivoDoErro(errCD)+"): um diretório de busca de biblioteca "+
			"injetado ali NÃO foi avaliado")
	}
	for _, ent := range ents {
		if !ent.IsDir() {
			confs = append(confs, "/etc/ld.so.conf.d/"+ent.Name())
		}
	}
	// Índice, não `range`: o laço APPENDA em `confs` ao seguir um include.
	vistosConf := map[string]bool{}
	for i := 0; i < len(confs) && i < maxConfsLoader; i++ {
		c := confs[i]
		if vistosConf[c] {
			continue
		}
		vistosConf[c] = true
		b, err := e.ReadFile(c)
		if err != nil {
			if env.EhLacuna(err) {
				f.denyPersist("loader", c+" não pôde ser lido ("+env.MotivoDoErro(err)+
					"): os diretórios de busca de biblioteca que ele declara NÃO "+
					"foram avaliados")
			}
			continue
		}
		for _, ln := range strings.Split(string(b), "\n") {
			ln = strings.TrimSpace(ln)
			if ln == "" || strings.HasPrefix(ln, "#") {
				continue
			}
			// O ldconfig OBEDECE o include, e quem escreve o alvo é quem edita
			// o /etc/ld.so.conf. Descartar a linha junto com os comentários
			// cobria o caso de fábrica (ld.so.conf.d é lido à parte) e deixava
			// passar um `include /tmp/x.conf`: o diretório de busca injetado
			// nunca chegava a l.SearchDirs, que é sobre o que o check pergunta
			// se algum diretório de busca é gravável.
			if v, ok := strings.CutPrefix(ln, "include"); ok {
				if v == "" || v[0] == ' ' || v[0] == '\t' {
					for _, campo := range strings.Fields(v) {
						confs = append(confs, expandirIncludeLoader(f, e, campo)...)
					}
					continue
				}
			}
			l.SearchDirs = append(l.SearchDirs, LoaderDir{
				Dir: ln, From: c, Exists: e.IsDir(ln),
			})
		}
	}

	// Lidos pelo PAM a cada sessão.
	for _, p := range []string{"/etc/environment", "/etc/security/pam_env.conf"} {
		b, err := e.ReadFile(p)
		if err != nil {
			if env.EhLacuna(err) {
				f.denyPersist("loader", p+" não pôde ser lido ("+env.MotivoDoErro(err)+
					"): um LD_PRELOAD/LD_AUDIT global definido ali NÃO foi avaliado")
			}
			continue
		}
		for _, ln := range strings.Split(string(b), "\n") {
			ln = strings.TrimSpace(ln)
			if ln == "" || strings.HasPrefix(ln, "#") {
				continue
			}
			for _, k := range []string{"LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT"} {
				if v, ok := envAssign(ln, k); ok {
					l.EnvVars = append(l.EnvVars, EnvSetting{File: p, Key: k, Value: v})
				}
			}
		}
	}
}

// envAssign reconhece as formas que esses arquivos aceitam: "K=v", "K v",
// "export K=v" e o formato do pam_env ("K DEFAULT=v").
// maxConfsLoader limita a cadeia de include do ld.so.conf.
const maxConfsLoader = 64

// expandirIncludeLoader resolve o alvo de um include do ld.so.conf. Caminho
// relativo é relativo a /etc, como o ldconfig faz, e o glob é expandido pelo
// diretório — sem filepath.Glob, que resolveria fora da raiz travada em modo
// image.
func expandirIncludeLoader(f *Facts, e *env.Env, padrao string) []string {
	if !strings.HasPrefix(padrao, "/") {
		padrao = "/etc/" + padrao
	}
	if !strings.ContainsAny(padrao, "*?[") {
		return []string{padrao}
	}
	dir, base := path.Split(padrao)
	dir = strings.TrimSuffix(dir, "/")
	if strings.ContainsAny(dir, "*?[") {
		return nil
	}
	var out []string
	nomes, err := e.ReadDirNamesErr(dir)
	if env.EhLacuna(err) {
		f.denyPersist("loader", dir+" (include de ld.so.conf) não pôde ser listado ("+
			env.MotivoDoErro(err)+"): os arquivos incluídos dali NÃO foram lidos")
	}
	for _, n := range nomes {
		if ok, err := path.Match(base, n); err == nil && ok {
			out = append(out, dir+"/"+n)
		}
	}
	sort.Strings(out)
	return out
}

func envAssign(line, key string) (string, bool) {
	s := strings.TrimPrefix(strings.TrimSpace(line), "export ")
	if !strings.HasPrefix(s, key) {
		return "", false
	}
	rest := strings.TrimSpace(s[len(key):])
	switch {
	case strings.HasPrefix(rest, "="):
		return strings.Trim(strings.TrimSpace(rest[1:]), `"'`), true
	case strings.HasPrefix(rest, "DEFAULT="), strings.HasPrefix(rest, "OVERRIDE="):
		_, v, _ := strings.Cut(rest, "=")
		return strings.Trim(strings.TrimSpace(v), `"'`), true
	}
	return "", false
}

// --- systemd (runbook §7.2, §7.3) ---

func collectUnits(f *Facts, e *env.Env) {
	// wants é o mapa "quem aponta para quem": responde se a unit vai rodar,
	// sem perguntar ao systemctl do host.
	wants := map[string][]string{}
	var units []Unit
	truncated := false

	// Diretório já visitado NÃO se lê de novo, e a chave é a identidade do
	// inode — não o caminho.
	//
	// Sob usrmerge /lib é link para usr/lib, e /lib/systemd/system e
	// /usr/lib/systemd/system são LITERALMENTE o mesmo diretório. Os dois estão
	// na lista de propósito: em distribuição sem usrmerge — ubuntu 14.04,
	// centos 7 — eles são diferentes e as duas árvores precisam ser lidas. Em
	// Debian 12 o resultado era toda unit de sistema coletada DUAS VEZES:
	// f.Units com o dobro do tamanho e todo check que emite por unit gerando
	// achado duplicado. Apareceu como "2× ssh.socket" onde havia um socket só.
	//
	// A comparação é por (dev, ino) e não por tabela de caminhos porque a fusão
	// varia entre distribuições — o Arch funde de um jeito, o Debian de outro, e
	// tabela erra. Dois caminhos no mesmo inode são o mesmo diretório em
	// qualquer arranjo.
	vistos := map[[2]uint64]bool{}
	for _, d := range unitDirs {
		if id, ok := idDeDiretorio(e, d.dir); ok {
			if vistos[id] {
				continue
			}
			vistos[id] = true
		}
		ents, err := e.ReadDir(d.dir)
		if err != nil {
			continue
		}
		for _, ent := range ents {
			name := ent.Name()
			full := d.dir + "/" + name

			// *.wants/ e *.requires/ contêm os symlinks que HABILITAM.
			if ent.IsDir() {
				switch {
				case strings.HasSuffix(name, ".wants"), strings.HasSuffix(name, ".requires"):
					for _, ln := range e.ReadDirNames(full) {
						wants[ln] = append(wants[ln], full+"/"+ln)
					}
				case strings.HasSuffix(name, ".d"):
					// drop-ins: alteram a unit sem tocar no arquivo dela
					target := strings.TrimSuffix(name, ".d")
					for _, c := range e.ReadDirNames(full) {
						if !strings.HasSuffix(c, ".conf") {
							continue
						}
						if len(units) >= maxUnits {
							truncated = true
							break
						}
						u := parseUnitFile(e, full+"/"+c, d.scope, d.vendor)
						u.Name = target
						u.DropInFor = target
						u.Kind = kindOf(target)
						units = append(units, u)
					}
				}
				continue
			}
			if !isUnitName(name) {
				continue
			}
			if len(units) >= maxUnits {
				truncated = true
				continue
			}
			u := parseUnitFile(e, full, d.scope, d.vendor)
			u.Name = name
			u.Kind = kindOf(name)
			units = append(units, u)
		}
	}

	// Unit de usuário mora no home, fora das árvores acima (runbook §7.3).
	homes := homeDirs(e)
	if len(homes) == 0 {
		f.denyPersist("unit", "/etc/passwd ilegível ou vazio: nenhum home foi "+
			"vasculhado, e unit de usuário é o esconderijo da §7.3")
	}
	var negados []string
	for _, home := range homes {
		dir := home + "/.config/systemd/user"
		if _, negado := lookup(e, dir); negado {
			negados = append(negados, dir)
			continue
		}
		for _, name := range e.ReadDirNames(dir) {
			if !isUnitName(name) || len(units) >= maxUnits {
				truncated = truncated || len(units) >= maxUnits
				continue
			}
			u := parseUnitFile(e, dir+"/"+name, "user", false)
			u.Name = name
			u.Kind = kindOf(name)
			units = append(units, u)
		}
	}

	if len(negados) > 0 {
		f.denyPersist("unit", strconv.Itoa(len(negados))+
			" diretórios de unit de usuário ilegíveis (permissão): "+resumoCaminhos(negados))
	}

	for i := range units {
		units[i].EnabledBy = wants[units[i].Name]
	}
	sort.Slice(units, func(i, j int) bool {
		if units[i].Name != units[j].Name {
			return units[i].Name < units[j].Name
		}
		return units[i].Path < units[j].Path
	})
	f.Units = units

	if truncated {
		f.partial("persist", "mais de "+strconv.Itoa(maxUnits)+
			" units encontradas; o excedente NÃO foi lido")
	}
	if len(units) == 0 && e.Has(env.CapSystemd) {
		f.partial("persist", "systemd presente e nenhuma unit foi legível: "+
			"os checks de unit não avaliaram nada")
	}
}

// isNotExist trata a ausência como resposta, não como falha: a maioria dos
// caminhos de persistência normalmente NÃO existe, e é a existência que informa.
func isNotExist(err error) bool { return os.IsNotExist(err) }

func isUnitName(n string) bool {
	for _, s := range []string{".service", ".timer", ".socket", ".path", ".mount", ".target"} {
		if strings.HasSuffix(n, s) {
			return true
		}
	}
	return false
}

func kindOf(n string) string {
	if i := strings.LastIndexByte(n, '.'); i >= 0 {
		return n[i+1:]
	}
	return ""
}

// parseUnitFile lê o formato INI do systemd. Chave REPETIDA é normal
// (ExecStart= pode aparecer várias vezes) e continuação com "\" também.
func parseUnitFile(e *env.Env, path, scope string, vendor bool) Unit {
	u := Unit{Path: path, Scope: scope, Vendor: vendor}
	if fi, err := e.Lstat(path); err == nil {
		u.ModUTC = fi.ModTime().UTC().Format(time.RFC3339)
	}
	b, err := e.ReadFile(path)
	if err != nil {
		return u
	}

	var pending string
	for _, raw := range strings.Split(string(b), "\n") {
		ln := strings.TrimSpace(raw)
		if pending != "" {
			ln, pending = pending+" "+ln, ""
		}
		if strings.HasSuffix(ln, `\`) {
			pending = strings.TrimSpace(strings.TrimSuffix(ln, `\`))
			continue
		}
		if ln == "" || strings.HasPrefix(ln, "#") || strings.HasPrefix(ln, ";") ||
			strings.HasPrefix(ln, "[") {
			continue
		}
		k, v, ok := strings.Cut(ln, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)

		switch {
		case strings.HasPrefix(k, "Exec"):
			// "ExecStart=" vazio RESETA a lista — é assim que um drop-in
			// substitui o comando da unit original.
			if v == "" {
				u.Exec = nil
				continue
			}
			u.Exec = append(u.Exec, ExecLine{Key: k, Cmd: v})
		case k == "Restart":
			u.Restart = v
		case k == "User":
			u.User = v
		case k == "WantedBy", k == "RequiredBy":
			u.WantedBy = append(u.WantedBy, strings.Fields(v)...)
		case k == "OnCalendar":
			u.OnCalendar = append(u.OnCalendar, v)
		case k == "OnUnitActiveSec", k == "OnUnitInactiveSec":
			u.OnUnitActiveSec = v
		case k == "OnBootSec", k == "OnStartupSec":
			u.OnBootSec = v
		case strings.HasPrefix(k, "Listen"):
			u.Listen = append(u.Listen, v)
		case k == "PathExists", k == "PathChanged", k == "PathModified",
			k == "PathExistsGlob", k == "DirectoryNotEmpty":
			u.WatchPaths = append(u.WatchPaths, v)
		case k == "Environment":
			// Environment=LD_PRELOAD=… numa unit é a rota da §7.8 que ninguém
			// associa a execução de código: entra no mesmo lugar que o
			// /etc/environment, para o check de preload enxergar.
			for _, as := range camposComAspas(v) {
				kk, vv, ok := strings.Cut(as, "=")
				if !ok {
					continue
				}
				u.Environment = append(u.Environment, EnvSetting{
					File: path, Key: kk, Value: strings.Trim(vv, `"'`),
				})
			}
		}
	}
	// Continuação aberta no fim do arquivo: a última linha some se ela for
	// descartada, e é onde o comando costuma estar.
	if pending != "" {
		u.Truncated = "última linha termina em continuação e ficou incompleta"
	}
	return u
}

// camposComAspas divide respeitando aspas: Environment="A=1" "B=2 3".
func camposComAspas(s string) []string {
	var out []string
	var cur strings.Builder
	var aspa rune
	for _, r := range s {
		switch {
		case aspa != 0 && r == aspa:
			aspa = 0
		case aspa == 0 && (r == '"' || r == '\''):
			aspa = r
		case aspa == 0 && (r == ' ' || r == '\t'):
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// homeDirs devolve os diretórios pessoais, do passwd do ALVO — nunca do host
// do analista.
func homeDirs(e *env.Env) []string {
	b, err := e.ReadFile("/etc/passwd")
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, ln := range strings.Split(string(b), "\n") {
		fs := strings.Split(ln, ":")
		if len(fs) < 6 {
			continue
		}
		h := fs[5]
		if h == "" || h == "/" || h == "/nonexistent" || seen[h] {
			continue
		}
		seen[h] = true
		// Conta de sistema aponta o home para lugar que não é home: /dev/null,
		// /bin, /sbin. Sondar ali é trabalho jogado fora e ruído garantido.
		if !e.IsDir(h) {
			continue
		}
		out = append(out, h)
	}
	return out
}

// listarNegando lista um diretório e registra LACUNA quando não consegue.
//
// `ReadDirNames` devolve nada para "não existe" e nada para "sem permissão", e
// as duas respostas são opostas. É dessa confusão que sai o pior erro que esta
// ferramenta pode cometer: dizer que não há crontab de usuário nenhum quando o
// spool é 1730 root:crontab e a varredura rodou sem root.
func (f *Facts) listarNegando(e *env.Env, cat, dir string) []string {
	ents, err := e.ReadDir(dir)
	if err != nil {
		if env.EhLacuna(err) {
			f.denyPersist(cat, dir+" não pôde ser listado ("+env.MotivoDoErro(err)+
				"): o que estiver lá dentro NÃO entrou na varredura")
		}
		return nil
	}
	nomes := make([]string, 0, len(ents))
	for _, ent := range ents {
		nomes = append(nomes, ent.Name())
	}
	return nomes
}

// lerNegando lê um arquivo e registra LACUNA quando não consegue. O par de
// listarNegando, pela mesma razão: diretório legível com arquivo ilegível
// dentro some tão silenciosamente quanto o diretório inteiro negado.
func (f *Facts) lerNegando(e *env.Env, cat, path string) ([]byte, bool) {
	b, err := e.ReadFile(path)
	if err != nil {
		if env.EhLacuna(err) {
			f.denyPersist(cat, path+" não pôde ser lido ("+env.MotivoDoErro(err)+")")
		}
		return nil, false
	}
	return b, true
}

// scannerFoiAteOFim declara LACUNA quando a leitura por linhas parou ANTES do
// fim do arquivo.
//
// `bufio.Scanner` para em silêncio numa linha maior que o buffer e o laço
// termina como se o arquivo tivesse acabado. Nas bases de referência de pacote
// isso não é detalhe: quem consegue escrever uma linha comprida no
// /var/lib/dpkg/status derruba a verificação de TODOS os arquivos listados
// depois dela, e o resultado sai como "nada divergiu".
func (f *Facts) scannerFoiAteOFim(sc *bufio.Scanner, cat, caminho string) bool {
	if err := sc.Err(); err != nil {
		f.denyPersist(cat, caminho+" não foi lido até o fim ("+err.Error()+
			"): o que vinha depois NÃO entrou na comparação")
		return false
	}
	return true
}
