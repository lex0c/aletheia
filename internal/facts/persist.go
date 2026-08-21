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

// execPathPadrao é o PATH FIXO que o systemd usa para resolver um Exec*= de
// nome NU quando a unit NÃO declara ExecSearchPath nem um PATH próprio — a
// mesma lista embutida do PID 1 (systemd.exec(5), "a fixed value"). Sem ela, um
// ExecStart de nome nu ficava sem alvo concreto e o check de dono não via o
// binário que de fato roda.
var execPathPadrao = []string{
	"/usr/local/sbin", "/usr/local/bin",
	"/usr/sbin", "/usr/bin",
	"/sbin", "/bin",
}

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
	// e é um esconderijo comum.
	Scope string `json:"scope"` // system | user

	// Manager é o DONO da unit de usuário quando ela vem do home dele
	// (~/.config/systemd/user). Vazio para unit de sistema e para as árvores de
	// user COMPARTILHADAS (/etc/systemd/user, /usr/lib/systemd/user). Cada
	// usuário roda seu próprio gerenciador; sem isto, alice/foo.service e
	// bob/foo.service — arquivos DIFERENTES — competiam como se fossem a mesma
	// unit, e a de um sombreava a do outro, deixando o Exec da sombreada sem
	// avaliação. FN.
	Manager string `json:"manager,omitempty"`

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

	Exec []ExecLine `json:"exec,omitempty"`
	// ExecSearchPath são os diretórios onde o systemd procura um Exec*= de nome
	// NU. É um bypass barato: ExecStart=agent com ExecSearchPath=/tmp/.cache/bin
	// resolve para /tmp/.cache/bin/agent, e sem representar isto o parser via só
	// "agent" — nem caminho suspeito nem propriedade eram avaliados.
	ExecSearchPath []string `json:"exec_search_path,omitempty"`

	// RootDirectory= faz o systemd executar num chroot: ExecStart=/usr/bin/x
	// roda /jail/usr/bin/x, NÃO o /usr/bin/x do host. Sem modelar isto, o check
	// avaliava o arquivo ERRADO — o do host, que nem é o que executa.
	RootDirectory string `json:"root_directory,omitempty"`
	// RootImage= monta uma IMAGEM de disco como raiz. O binário vive DENTRO da
	// imagem, que não está montada na varredura — não dá para lê-lo. É lacuna
	// declarada, não um arquivo de host para acusar em falso.
	RootImage string `json:"root_image,omitempty"`
	// Binds são os BindPaths=/BindReadOnlyPaths= da unit. Ver BindDaUnit.
	Binds []BindDaUnit `json:"binds,omitempty"`

	Restart  string   `json:"restart,omitempty"`
	User     string   `json:"user,omitempty"`
	WantedBy []string `json:"wanted_by,omitempty"`

	// Gatilhos, por tipo de unit.
	OnCalendar      []string `json:"on_calendar,omitempty"`
	OnUnitActiveSec string   `json:"on_unit_active_sec,omitempty"`
	OnBootSec       string   `json:"on_boot_sec,omitempty"`
	Listen          []string `json:"listen,omitempty"`
	WatchPaths      []string `json:"watch_paths,omitempty"`

	// Environment= da unit. Vai para o mesmo lugar que /etc/environment: é a
	// rota da §7.8 que ninguém associa a execução de código.
	Environment []EnvSetting `json:"environment,omitempty"`
	// EnvFilesIlegiveis são os EnvironmentFile= que a unit referencia e que não
	// puderam ser lidos — um LD_PRELOAD ali fica sem avaliação.
	EnvFilesIlegiveis []string `json:"env_files_unreadable,omitempty"`
	// EnvFileReset marca que este arquivo teve um `EnvironmentFile=` vazio, que
	// REDEFINE a lista. Num drop-in, isso alcança a unit base de mesmo nome — a
	// fusão pós-coleta usa esta marca.
	EnvFileReset bool `json:"env_file_reset,omitempty"`
	// ExecResetKeys são as diretivas Exec*= que tiveram atribuição vazia (que
	// REDEFINE aquela lista, e SÓ ela — `ExecStart=` vazio não zera
	// ExecStartPre). Num drop-in, alcança os objetos carregados antes.
	ExecResetKeys []string `json:"exec_reset_keys,omitempty"`
	// ExecSearchPathReset marca um `ExecSearchPath=` vazio, que REDEFINE a lista
	// de busca. Num drop-in, alcança a base: a resolução pós-merge usa esta marca
	// para acumular o ExecSearchPath EFETIVO na ordem de carga.
	ExecSearchPathReset bool `json:"exec_search_path_reset,omitempty"`
	// Shadowed: existe uma unit de mesmo nome em árvore de MAIOR precedência —
	// o systemd executa aquela, não esta. Masked: o arquivo é link para
	// /dev/null (a unit está DESLIGADA). Os checks de execução pulam as duas: o
	// que o sistema não roda não é persistência ativa.
	Shadowed bool `json:"shadowed,omitempty"`
	Masked   bool `json:"masked,omitempty"`

	ModUTC string `json:"mod_utc,omitempty"`

	// Truncated diz que o arquivo não foi lido por inteiro.
	Truncated string `json:"truncated,omitempty"`
}

// ExecLine guarda a diretiva junto com o valor: ExecStartPre num drop-in é
// persistência quase perfeita, e perder qual diretiva era apaga o achado.
// BindDaUnit é um BindPaths=/BindReadOnlyPaths= — um mount que só existe DENTRO
// do namespace da unit.
//
// É a irmã do RootDirectory pelo caminho do mount namespace, e a mais perigosa
// das duas: o RootDirectory ao menos desloca o alvo para um prefixo visível no
// host, enquanto isto TROCA o arquivo sob um caminho que continua parecendo
// legítimo. O host mostra /usr/bin/agent com dono de pacote e hash conferindo; a
// unit executa /tmp/.implant. As duas afirmações são verdadeiras e uma delas é
// irrelevante.
type BindDaUnit struct {
	Origem   string `json:"source"`
	Destino  string `json:"dest,omitempty"`
	SomenteL bool   `json:"read_only,omitempty"`
}

type ExecLine struct {
	Key string `json:"key"` // ExecStart | ExecStartPre | …
	Cmd string `json:"cmd"`
	// RawCmd é o comando como escrito no arquivo, ANTES de resolver o nome nu
	// contra qualquer search path. A resolução EFETIVA (com o ExecSearchPath do
	// drop-in e o PATH fixo do systemd) só é possível pós-merge; guardar o cru
	// deixa essa resolução partir sempre da origem, não de um Cmd já mexido por
	// uma resolução por-arquivo que o merge invalidou. Interno à coleta.
	RawCmd string `json:"-"`
	// Target é o ALVO EFETIVO — o programa que de fato roda, desembrulhados os
	// wrappers (env, sudo, sh -c, env -S). Computado UMA vez na coleta para que
	// a pergunta de propriedade e os checks de execução usem a MESMA resposta.
	Target string `json:"target,omitempty"`
	// AlvoIndeterminado diz que a linha EXECUTA algo e não deu para provar o
	// quê — `sh -c` com substituição de comando, subshell, ou só builtin.
	//
	// É diferente de Target vazio por não haver Exec: aqui há execução e não há
	// nome. Sem esta distinção o check calaria igual nos dois casos, e um deles
	// é uma lacuna que o operador precisa ver.
	AlvoIndeterminado bool `json:"target_undetermined,omitempty"`
}

// Enabled diz se algo aponta para esta unit.
func (u Unit) Enabled() bool { return len(u.EnabledBy) > 0 }

// Efetiva diz se o systemd de fato RODA esta unit: nem sombreada por outra de
// maior precedência, nem mascarada (link para /dev/null). Os checks de execução
// e a pergunta de propriedade só olham units efetivas — o que não roda não é
// persistência ativa. Drop-in não é "efetivo" por si (ele modifica a base), mas
// os checks de drop-in olham DropInFor diretamente, não este predicado.
func (u Unit) Efetiva() bool { return !u.Shadowed && !u.Masked }

// execSemKey remove as linhas de uma diretiva Exec*= específica, preservando as
// demais — é o efeito de um `ExecStart=` vazio, que reseta só a lista dele.
func execSemKey(exec []ExecLine, key string) []ExecLine {
	var out []ExecLine
	for _, e := range exec {
		if e.Key != key {
			out = append(out, e)
		}
	}
	return out
}

// unitDirs são as árvores de unit, na ORDEM DE PRECEDÊNCIA REAL do systemd (a
// primeira vence) — a "System Unit Search Path" da systemd.unit(5). A ordem
// importa para valer: control e transient vencem /etc/systemd/system, e
// /usr/local vence /usr/lib. Errar isso faz mesclarUnits() marcar como
// Shadowed a unit que o systemd de fato executa — e como os checks pulam o que
// não é Efetiva(), a implementação criada para tirar FP de unit inativa viraria
// FN da unit ATIVA. É por transient/control que o `systemd-run` e os overrides
// de runtime plantam sem deixar .service em /etc.
//
// generator.* são unidades GERADAS em runtime (/run) — um gerador malicioso é
// vetor de persistência real, e por isso entram, no lugar certo da tabela.
//
// O load path de USER por-home (XDG: ~/.config/systemd/user etc.) ainda não
// está aqui — é dívida declarada, a ser resolvida com a enumeração de homes.
var unitDirs = []struct {
	dir    string
	scope  string
	vendor bool
}{
	{"/etc/systemd/system.control", "system", false},
	{"/run/systemd/system.control", "system", false},
	{"/run/systemd/transient", "system", false},
	{"/run/systemd/generator.early", "system", false},
	{"/etc/systemd/system", "system", false},
	{"/run/systemd/system", "system", false},
	{"/run/systemd/generator", "system", false},
	{"/usr/local/lib/systemd/system", "system", false},
	{"/usr/lib/systemd/system", "system", true},
	{"/lib/systemd/system", "system", true},
	{"/run/systemd/generator.late", "system", false},
	{"/etc/systemd/user", "user", false},
	{"/run/systemd/user.control", "user", false},
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
	// nsswitch.conf: uma fonte NSS com lib sem dono roda em TODA resolução de
	// nome. Antes do collectPkg, para o caminho da lib entrar na propriedade.
	collectNSS(f, e)
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

	// A fusão de precedência, máscara e resets de drop-in roda em collectUnits
	// (mesclarUnits), antes daqui — f.Units já reflete a config EFETIVA.
	//
	// Só as units efetivas alimentam a lista de preload: uma unit sombreada por
	// outra de maior precedência, ou mascarada (link para /dev/null), não roda.
	// Environment= de unit tem o MESMO efeito do /etc/environment, e por isso
	// alimenta a mesma lista: um check só, uma leitura só.
	for i := range f.Units {
		if !f.Units[i].Efetiva() {
			continue // unit sombreada ou mascarada não injeta env: não roda
		}
		for _, s := range f.Units[i].Environment {
			switch s.Key {
			case "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT":
				f.Loader.EnvVars = append(f.Loader.EnvVars, s)
			}
		}
		for _, arq := range f.Units[i].EnvFilesIlegiveis {
			f.denyPersist("loader", "a unit "+f.Units[i].Name+" carrega env de "+arq+
				", que não pôde ser lido: um LD_PRELOAD/LD_AUDIT definido ali NÃO "+
				"foi avaliado")
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
	// O teto de include existe contra um ld.so.conf que se inclui em ciclo ou
	// aponta para uma árvore enorme — mas cortar em silêncio transforma "parei
	// de olhar" em "não há". Se a cadeia passou do teto, um diretório de busca
	// gravável declarado além dele NÃO foi avaliado, e isso precisa constar.
	if len(confs) > maxConfsLoader {
		f.denyPersist("loader", "a cadeia de include do ld.so.conf passou de "+
			strconv.Itoa(maxConfsLoader)+" arquivos e foi cortada no teto: os "+
			"diretórios de busca de biblioteca declarados além dele NÃO foram "+
			"avaliados")
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
		// A varredura de UMA árvore — arquivos de unit, drop-ins .d/ e a
		// habilitação *.wants//*.requires/ — é idêntica para a árvore de sistema
		// e para o load path de user por-home; ver coletarDirDeUnits. Antes o
		// user tinha uma cópia pela metade (só arquivos isUnitName), e por isso
		// não via nem drop-in nem máscara de unit de usuário.
		trunc, lerr := coletarDirDeUnits(f, e, d.dir, d.scope, d.vendor, &units, wants)
		truncated = truncated || trunc
		if env.EhLacuna(lerr) {
			f.denyPersist("unit", d.dir+" não pôde ser listado ("+
				env.MotivoDoErro(lerr)+"): as units declaradas nesta árvore NÃO "+
				"foram avaliadas — uma unit de persistência plantada aqui passaria")
		}
	}

	// Unit de usuário mora no home, fora das árvores acima (runbook §7.3).
	homes := homeDirs(e)
	if len(homes) == 0 {
		f.denyPersist("unit", "/etc/passwd ilegível ou vazio: nenhum home foi "+
			"vasculhado, e unit de usuário é um esconderijo comum")
	}
	// O load path de USER por-home (systemd.unit(5), "User Unit Search Path"):
	// não só ~/.config/systemd/user, mas o user.control ao lado dele e o
	// ~/.local/share/systemd/user (XDG_DATA_HOME). Sem estes, uma unit de usuário
	// plantada nesses cantos passava invisível.
	//
	// LIMITE declarado: a PRECEDÊNCIA exata do user por-home ainda não é honrada
	// (o ~/.config/systemd/user deveria VENCER /etc/systemd/user, e o runtime
	// user.control mora em $XDG_RUNTIME_DIR/…, que depende do UID). Aqui o foco é
	// COLETAR — a unit fica visível aos checks; num conflito de nome entre árvores
	// de user, qual vence pode sair trocado.
	userSubdirs := []string{
		".config/systemd/user.control",
		".config/systemd/user",
		".local/share/systemd/user",
	}
	var negados []string
	for _, home := range homes {
		usuario := home[strings.LastIndexByte(home, '/')+1:]
		for _, sub := range userSubdirs {
			dir := home + "/" + sub
			// MESMA varredura da árvore de sistema: arquivos, drop-in .d/ e
			// máscara. Sem isto o user via só arquivos isUnitName — um
			// ~/.config/systemd/user/foo.service.d/ passava invisível.
			antes := len(units)
			trunc, lerr := coletarDirDeUnits(f, e, dir, "user", false, &units, wants)
			truncated = truncated || trunc
			// Carimba o DONO em tudo que veio deste home: é o que separa o
			// gerenciador de um usuário do de outro no merge.
			for i := antes; i < len(units); i++ {
				units[i].Manager = usuario
			}
			if env.EhLacuna(lerr) {
				// Existe e não listou (permissão/corrida): resume entre os homes,
				// senão escanear sem root vira uma linha por home 0700.
				negados = append(negados, dir)
			}
		}
	}

	if len(negados) > 0 {
		f.denyPersist("unit", strconv.Itoa(len(negados))+
			" diretórios de unit de usuário ilegíveis (permissão): "+resumoCaminhos(negados))
	}
	lacunaDeManagerDeUsuario(f, units)

	for i := range units {
		units[i].EnabledBy = wants[units[i].Name]
	}
	// Drop-in POR PADRÃO: o systemd aplica um drop-in não só de NAME.TYPE.d/, mas
	// de TYPE.d/ (type-wide), TEMPLATE@.TYPE.d/ (instâncias) e PREFIX-.TYPE.d/
	// (por dash). Antes só o exato entrava — um `service.d/50-x.conf` que altera
	// TODA service, ou um `foo-.service.d/`, passava invisível. Expande para as
	// bases que casa ANTES do merge, para o resto da fusão seguir 1:1.
	units = expandirDropins(f, units)

	// Config EFETIVA: precedência por nome (a de maior precedência vence, as
	// demais viram Shadowed), máscara propagada ao grupo, e resets de Exec/Env
	// de drop-in aplicados aos objetos carregados ANTES. Depois disto, os checks
	// de execução veem o que o systemd realmente roda, não cada arquivo cru.
	mesclarUnits(f, units, e)
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

// coletarDirDeUnits varre UM diretório do load path do systemd: os arquivos de
// unit, os drop-ins em *.d/ (que ALTERAM a unit sem tocar no arquivo dela) e a
// habilitação em *.wants//*.requires/. É o mesmo caminho para a árvore de
// sistema e para o load path de user por-home (~/.config/systemd/user etc.) —
// e é justamente por NÃO ser compartilhado antes que o user só via arquivos
// isUnitName: um `~/.config/systemd/user/foo.service.d/10-x.conf` ou uma unit
// de usuário mascarada com /dev/null passavam invisíveis. Ausência do diretório
// é resposta (silêncio); só a listagem NEGADA vira lacuna declarada. Devolve
// true se o teto de units foi atingido nesta árvore.
func coletarDirDeUnits(f *Facts, e *env.Env, dir, scope string, vendor bool, units *[]Unit, wants map[string][]string) (bool, error) {
	ents, err := e.ReadDir(dir)
	if err != nil {
		// Ausência do diretório é resposta (silêncio); existir-e-não-listar é
		// lacuna. QUEM chama decide como reportar: a árvore de sistema tem ~10
		// diretórios e reporta por-diretório; o load path de user tem um por
		// home e RESUME, senão escanear sem root vira uma linha por home 0700.
		return false, err
	}
	truncated := false
	for _, ent := range ents {
		name := ent.Name()
		full := dir + "/" + name

		// *.wants/ e *.requires/ contêm os symlinks que HABILITAM.
		if ent.IsDir() {
			switch {
			case strings.HasSuffix(name, ".wants"), strings.HasSuffix(name, ".requires"):
				nomes, errL := e.ReadDirNamesErr(full)
				if env.EhLacuna(errL) {
					f.denyPersist("unit", full+" não pôde ser listado ("+
						env.MotivoDoErro(errL)+"): quais units esta árvore HABILITA NÃO foi lido")
				}
				for _, ln := range nomes {
					wants[ln] = append(wants[ln], full+"/"+ln)
				}
			case strings.HasSuffix(name, ".d"):
				// drop-ins: alteram a unit sem tocar no arquivo dela
				target := strings.TrimSuffix(name, ".d")
				nomes, errL := e.ReadDirNamesErr(full)
				if env.EhLacuna(errL) {
					f.denyPersist("unit", full+" não pôde ser listado ("+
						env.MotivoDoErro(errL)+"): um drop-in plantado aqui NÃO foi avaliado")
				}
				for _, c := range nomes {
					if !strings.HasSuffix(c, ".conf") {
						continue
					}
					if len(*units) >= maxUnits {
						truncated = true
						break
					}
					u := parseUnitFile(f, e, full+"/"+c, scope, kindOf(target), vendor)
					u.Name = target
					u.DropInFor = target
					u.Kind = kindOf(target)
					*units = append(*units, u)
				}
			}
			continue
		}
		if !isUnitName(name) {
			continue
		}
		if len(*units) >= maxUnits {
			truncated = true
			continue
		}
		// Máscara ANTES do parse: link para /dev/null (clássica) ou arquivo
		// vazio desliga a unit. Detectar aqui, sem chamar o ReadFile, evita
		// que o /dev/null (ErrNaoEhArquivo, que é lacuna) vire gap FALSO — a
		// unit sairia Masked E "não consegui ler" ao mesmo tempo. Máscara é
		// config conhecida, não uma falha de leitura.
		if detectarMascara(e, full) {
			*units = append(*units, Unit{
				Path: full, Name: name, Scope: scope,
				Vendor: vendor, Kind: kindOf(name), Masked: true,
			})
			continue
		}
		u := parseUnitFile(f, e, full, scope, kindOf(name), vendor)
		u.Name = name
		u.Kind = kindOf(name)
		*units = append(*units, u)
	}
	return truncated, nil
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
// temEspecificadorSystemd diz se o caminho tem um especificador `%X` (que não
// seja `%%`, o por-cento literal). O systemd os expande em tempo de execução;
// aqui, sem o contexto da unit, eles não são resolvíveis.
func temEspecificadorSystemd(s string) bool {
	for i := 0; i+1 < len(s); i++ {
		if s[i] == '%' {
			if s[i+1] == '%' {
				i++ // %% é literal, pula os dois
				continue
			}
			return true
		}
	}
	return false
}

// temGlobShell diz se o caminho tem wildcard de shell — o que o systemd expande
// no EnvironmentFile=.
func temGlobShell(s string) bool {
	return strings.ContainsAny(s, "*?[")
}

// incorporarEnvironmentFile resolve um EnvironmentFile= — literal ou com
// wildcard — e incorpora as atribuições na unit. É função de escopo de pacote
// porque `parseUnitFile` sombreia o pacote `path` com um parâmetro homônimo.
func incorporarEnvironmentFile(u *Unit, e *env.Env, arq string) {
	// `%%` é o por-cento literal; qualquer outro `%X` é um ESPECIFICADOR do
	// systemd (%h = home, %i = instância, %t = runtime dir). Sem o contexto de
	// quem roda a unit não dá para expandi-lo com segurança — e ler o literal
	// `%h/.env` daria ENOENT e sumiria um LD_PRELOAD em silêncio. Declara-se a
	// lacuna em vez de silenciar.
	if temEspecificadorSystemd(arq) {
		u.EnvFilesIlegiveis = append(u.EnvFilesIlegiveis, arq+
			" (contém especificador % do systemd, não expandido sem o contexto da unit)")
		return
	}
	if !temGlobShell(arq) {
		lerEnvFileNaUnit(u, e, arq)
		return
	}
	// systemd expande WILDCARD no ÚLTIMO componente. `/etc/app/*.env` virava
	// ReadFile do literal, ENOENT, e um backdoor.env ali era FN silencioso.
	dir, padrao := path.Split(arq)
	dir = strings.TrimSuffix(dir, "/")
	nomes, gerr := e.ReadDirNamesErr(dir)
	if env.EhLacuna(gerr) {
		// Diretório do glob ilegível: não dá para saber se há um arquivo de
		// ambiente casando — lacuna, não silêncio.
		u.EnvFilesIlegiveis = append(u.EnvFilesIlegiveis, arq+" (diretório do glob ilegível)")
		return
	}
	sort.Strings(nomes)
	for _, n := range nomes {
		if ok, _ := path.Match(padrao, n); ok {
			lerEnvFileNaUnit(u, e, dir+"/"+n)
		}
	}
}

// envSemArquivos remove de uma lista de env as entradas que vieram de
// EnvironmentFile= (File != caminho da unit), preservando os Environment= EM
// LINHA. É o efeito de um `EnvironmentFile=` vazio, que redefine a lista.
func envSemArquivos(envs []EnvSetting, unitPath string) []EnvSetting {
	var out []EnvSetting
	for _, es := range envs {
		if es.File == unitPath {
			out = append(out, es)
		}
	}
	return out
}

// lerEnvFileNaUnit lê um arquivo de EnvironmentFile= e incorpora as atribuições.
// Ilegível vira lacuna registrada no Unit (collectUnits a declara); as linhas
// são KEY=value no estilo shell.
func lerEnvFileNaUnit(u *Unit, e *env.Env, arq string) {
	eb, err := e.ReadFile(arq)
	if err != nil {
		if env.EhLacuna(err) {
			u.EnvFilesIlegiveis = append(u.EnvFilesIlegiveis, arq)
		}
		return
	}
	for _, el := range strings.Split(string(eb), "\n") {
		el = strings.TrimSpace(el)
		if el == "" || strings.HasPrefix(el, "#") {
			continue
		}
		el = strings.TrimPrefix(el, "export ")
		kk, vv, ok := strings.Cut(el, "=")
		if !ok {
			continue
		}
		u.Environment = append(u.Environment, EnvSetting{
			File: arq, Key: strings.TrimSpace(kk),
			Value: strings.Trim(strings.TrimSpace(vv), `"'`),
		})
	}
}

// mesclarUnits reconstrói a config EFETIVA a partir dos arquivos crus, sem
// APAGAR os objetos (os checks de drop-in ainda os olham). Faz três coisas:
//
//	precedência  entre bases de mesmo (escopo,nome), a de MAIOR precedência (a
//	             primeira na ordem de coleta = ordem de unitDirs) vence; as
//	             demais viram Shadowed. O systemd roda uma só.
//	máscara      se a base vencedora é link para /dev/null, o grupo INTEIRO está
//	             mascarado — drop-ins não ressuscitam unit mascarada.
//	resets       ExecStart=/EnvironmentFile= vazios num objeto limpam os
//	             carregados ANTES dele (base + drop-ins anteriores). Não se
//	             faz MERGE (isso duplicaria): cada objeto mantém sua própria
//	             contribuição pós-reset, e os checks somam olhando cada um.
func mesclarUnits(f *Facts, units []Unit, e *env.Env) {
	grupos := map[string][]int{}
	var ordem []string
	for i := range units {
		// O Manager entra na chave: a unit do home de um usuário só se funde com
		// drop-in do MESMO usuário. Sem ele, o foo.service de dois usuários caía
		// no mesmo grupo e um sombreava o outro (FN). A árvore de user
		// COMPARTILHADA (Manager="") fica no seu próprio grupo — a precedência
		// exata entre compartilhada e por-home continua declarada como limite,
		// mas nenhuma unit deixa de ser avaliada por causa de outra.
		k := units[i].Scope + "\x00" + units[i].Manager + "\x00" + units[i].Name
		if _, ok := grupos[k]; !ok {
			ordem = append(ordem, k)
		}
		grupos[k] = append(grupos[k], i)
	}
	for _, k := range ordem {
		idxs := grupos[k]
		// Ordem de CARGA: base antes de drop-in; entre bases, a ordem de coleta
		// (precedência); entre drop-ins, por nome de arquivo (como o systemd).
		sort.SliceStable(idxs, func(a, b int) bool {
			ua, ub := &units[idxs[a]], &units[idxs[b]]
			da, db := ua.DropInFor != "", ub.DropInFor != ""
			if da != db {
				return !da
			}
			if !da {
				return false // bases: mantém ordem de coleta
			}
			return baseNome(ua.Path) < baseNome(ub.Path)
		})

		// Precedência de BASE: a primeira (maior precedência) vence; as demais
		// viram Shadowed.
		primeiraBase := -1
		for _, i := range idxs {
			if units[i].DropInFor != "" {
				continue
			}
			if primeiraBase == -1 {
				primeiraBase = i
				continue
			}
			units[i].Shadowed = true
		}

		// Dedup de DROP-IN pelo NOME DO ARQUIVO: para o MESMO basename, o systemd
		// aplica SÓ UM — e qual é decidido por dropinVence (árvore /etc > /run >
		// /usr/lib e, dentro dela, especificidade: exato > prefixo > template >
		// type-wide). Aplicar os dois faz o reset de um apagar o Exec do outro —
		// FN ou FP conforme a ordem. Só nomes DIFERENTES é que se combinam. Os
		// perdedores viram Shadowed e não entram na config efetiva.
		vencedor := map[string]int{}
		for _, i := range idxs {
			if units[i].DropInFor == "" {
				continue
			}
			bn := baseNome(units[i].Path)
			v, ok := vencedor[bn]
			if !ok {
				vencedor[bn] = i
				continue
			}
			if dropinVence(units[i].Path, units[v].Path) {
				units[v].Shadowed = true
				vencedor[bn] = i
			} else {
				units[i].Shadowed = true
			}
		}

		// Máscara: se a base vencedora é link para /dev/null, o grupo INTEIRO
		// está mascarado — drop-in não ressuscita unit mascarada.
		if primeiraBase >= 0 && units[primeiraBase].Masked {
			for _, i := range idxs {
				units[i].Masked = true
			}
		}

		// Resets sequenciais, SÓ entre os efetivos (não-Shadowed), na ordem de
		// carga: um objeto com reset limpa os ANTERIORES. Base sombreada ou
		// drop-in perdedor de basename não roda, então seu reset também não vale.
		var efetivos []int
		for _, i := range idxs {
			if !units[i].Shadowed {
				efetivos = append(efetivos, i)
			}
		}
		for pos, i := range efetivos {
			for _, rk := range units[i].ExecResetKeys {
				for _, j := range efetivos[:pos] {
					units[j].Exec = execSemKey(units[j].Exec, rk)
				}
			}
			if units[i].EnvFileReset {
				for _, j := range efetivos[:pos] {
					units[j].Environment = envSemArquivos(units[j].Environment, units[j].Path)
					units[j].EnvFilesIlegiveis = nil
				}
			}
		}

		// Resolução EFETIVA de ExecSearchPath e Target: SÓ agora, com a
		// EffectiveUnit montada, o ExecSearchPath de um DROP-IN alcança o
		// ExecStart da BASE. Por-arquivo (parseUnitFile), a base não via o
		// searchpath do drop-in — FN do bypass `ExecStart=agent` + drop-in
		// `ExecSearchPath=/tmp/.hidden`. O searchpath acumula na ordem de carga,
		// honrando o reset; um PATH próprio (Environment=) desliga a busca.
		var searchPath []string
		var pathProprio []string // dirs do PATH via Environment=, na ordem
		var rootDir, rootImg string
		temPATH := false
		for _, i := range efetivos {
			if units[i].ExecSearchPathReset {
				searchPath = nil
			}
			searchPath = append(searchPath, units[i].ExecSearchPath...)
			// RootDirectory/RootImage: valor único, a última atribuição não-vazia
			// vence. (Um drop-in que RESETA com valor vazio para tirar o chroot é
			// caso de borda; manter o rootDir da base é o lado SEGURO — verifica
			// dentro do jail, não o host.)
			if units[i].RootDirectory != "" {
				rootDir = units[i].RootDirectory
			}
			if units[i].RootImage != "" {
				rootImg = units[i].RootImage
			}
			for _, s := range units[i].Environment {
				if s.Key == "PATH" {
					// Environment= com a mesma chave: a ÚLTIMA vence (systemd),
					// então sobrescreve.
					temPATH = true
					pathProprio = dirsAbsolutos(strings.Split(s.Value, ":"))
				}
			}
		}
		for _, i := range efetivos {
			// Os diretórios contra os quais o systemd resolve um nome NU, decididos
			// UMA vez para a unit efetiva:
			//   PATH próprio (Environment=)  -> só ele (o systemd não consulta o fixo)
			//   PATH próprio só relativo     -> nil (cwd que não modelamos; não resolve)
			//   ExecSearchPath               -> ele
			//   nada                         -> o PATH fixo do systemd.exec(5)
			var dirs []string
			switch {
			case temPATH && len(pathProprio) > 0:
				dirs = pathProprio
			case temPATH:
				dirs = nil
			case len(searchPath) > 0:
				dirs = searchPath
			default:
				dirs = execPathPadrao
			}
			// RootDirectory=: o systemd resolve e executa DENTRO do chroot. As
			// buscas de nome nu passam a olhar /jail+dir, e o alvo é /jail+path —
			// senão o check avaliava o arquivo do HOST, que nem é o que roda.
			if rootDir != "" {
				dirs = prefixarDirs(rootDir, dirs)
			}
			// RootImage=: a raiz é uma IMAGEM de disco não montada. O binário vive
			// dentro dela e não dá para lê-lo — lacuna declarada uma vez por unit,
			// e sem alvo de host para não acusar o arquivo errado.
			if rootImg != "" {
				f.denyPersist("unit", "unit "+units[i].Name+" roda com RootImage="+rootImg+
					": o ExecStart vive DENTRO da imagem de disco (não montada) e NÃO "+
					"foi analisado — nem dono, nem caminho.")
			}
			for j := range units[i].Exec {
				// Resolve SEMPRE a partir do cru: uma resolução por-arquivo já
				// pode ter mexido o Cmd (base com ExecSearchPath próprio), e o
				// merge invalida essa escolha. Partir do RawCmd cura o FN.
				cru := units[i].Exec[j].RawCmd
				if cru == "" {
					cru = units[i].Exec[j].Cmd // defensivo: unit sem raw (não deve ocorrer)
				}
				cmd := cru
				if len(dirs) > 0 {
					cmd = resolverNomeNu(e, cru, dirs)
				}
				units[i].Exec[j].Cmd = cmd

				// O alvo EFETIVO, DEPOIS de desembrulhar o wrapper. E se o programa
				// embrulhado ainda é NOME NU, resolve-o também: `ExecStart=/usr/bin/env
				// agent` desembrulha para `agent`, e sem resolvê-lo o alvo ficava nome
				// nu — fora do check de dono. `env` roda o programa via PATH, os
				// mesmos `dirs`.
				tgt, indet := AlvoEfetivoDeExec(cmd)
				units[i].Exec[j].AlvoIndeterminado = indet
				if indet {
					// Sem alvo provado não há o que resolver nem o que perguntar
					// ao dono; quem declara a lacuna é o check.
					units[i].Exec[j].Target = ""
					continue
				}
				if len(dirs) > 0 && !strings.ContainsRune(strings.TrimLeft(tgt, "-@+!:"), '/') {
					tgt = resolverNomeNu(e, tgt, dirs)
				}
				if rootDir != "" {
					// O alvo absoluto que não veio pela busca (ExecStart=/usr/bin/x)
					// ainda precisa do prefixo do chroot; o que veio da busca já
					// resolveu sob o root, e sobRoot é idempotente.
					tgt = sobRoot(rootDir, tgt)
				}
				// RootImage= não mexe no alvo: a unit inteira é PULADA pelos checks
				// de arquivo (u.RootImage != ""), com a lacuna já declarada.
				units[i].Exec[j].Target = tgt
			}
		}
	}
}

// prefixarDirs põe cada diretório de busca DENTRO de um root (RootDirectory=).
func prefixarDirs(root string, dirs []string) []string {
	out := make([]string, 0, len(dirs))
	for _, d := range dirs {
		out = append(out, sobRoot(root, d))
	}
	return out
}

// sobRoot prefixa um caminho ABSOLUTO com um root (chroot do RootDirectory=). É
// idempotente: um caminho já sob o root não é prefixado de novo.
func sobRoot(root, p string) string {
	if root == "" || !strings.HasPrefix(p, "/") {
		return p
	}
	r := strings.TrimSuffix(root, "/")
	if p == r || strings.HasPrefix(p, r+"/") {
		return p
	}
	return r + p
}

// precedenciaArvore devolve o índice da árvore de unitDirs a que o caminho
// pertence — menor = maior precedência. Serve para escolher, entre drop-ins de
// mesmo nome em árvores diferentes, o único que o systemd aplica. Caminho fora
// das árvores conhecidas fica com a MENOR precedência (nunca vence).
func precedenciaArvore(caminho string) int {
	for i, d := range unitDirs {
		if strings.HasPrefix(caminho, d.dir+"/") {
			return i
		}
	}
	return len(unitDirs)
}

// especificidadeDropin classifica um drop-in pela pasta .d/ que o contém, na
// ordem do systemd — MAIS específico ganha quando dois drop-ins de MESMO nome
// de arquivo colidem: type-wide (service.d/) < template (foo@.service.d/) <
// prefixo-por-dash (foo-.service.d/, mais longo = mais específico) < nome exato
// (foo.service.d/). É o discriminador que faltava: dois `10-x.conf`, um exato e
// um type-wide na MESMA árvore, tinham o vencedor decidido pela ordem de coleta.
func especificidadeDropin(caminho string) int {
	d := strings.TrimSuffix(path.Base(path.Dir(caminho)), ".d")
	i := strings.LastIndexByte(d, '.')
	if i < 0 {
		return 0 // "service" — só o tipo, o menos específico
	}
	nome := d[:i]
	switch {
	case strings.HasSuffix(nome, "@"):
		return 1 // template@.service
	case strings.HasSuffix(nome, "-"):
		return 1 + len(nome) // prefixo-: foo-bar- é mais específico que foo-
	default:
		return 1_000_000 // nome exato: sempre o mais específico
	}
}

// dropinVence diz se o drop-in `a` é o que o systemd aplica quando `a` e `b`
// têm o MESMO nome de arquivo. Árvore de maior precedência primeiro (/etc >
// /run > /usr/lib, como já era); empate na árvore, o mais específico; empate
// nos dois, o caminho lexical — determinístico, nunca dependente da ordem em
// que os arquivos foram lidos do disco.
func dropinVence(a, b string) bool {
	if pa, pb := precedenciaArvore(a), precedenciaArvore(b); pa != pb {
		return pa < pb
	}
	if sa, sb := especificidadeDropin(a), especificidadeDropin(b); sa != sb {
		return sa > sb
	}
	return a < b
}

// ehPadraoDropin diz se o alvo de um drop-in é um PADRÃO (casa várias units), e
// não um nome exato: só o tipo ("service" = type-wide), um template ("foo@")
// ou um prefixo por dash ("foo-").
func ehPadraoDropin(alvo string) bool {
	i := strings.LastIndexByte(alvo, '.')
	if i < 0 {
		return true // só o tipo: type-wide (service.d/, timer.d/…)
	}
	nome := alvo[:i]
	return strings.HasSuffix(nome, "@") || strings.HasSuffix(nome, "-")
}

// dropinCasaUnit implementa o casamento de drop-in do systemd: o dir P.d/ altera
// a unit NAME.TYPE quando P é TYPE (type-wide), TEMPLATE@.TYPE (a instância de um
// template) ou PREFIX-.TYPE (truncando NAME em cada dash). É a mesma regra da
// systemd.unit(5), "The drop-in files ... are read from directories".
func dropinCasaUnit(padrao, unit string) bool {
	i := strings.LastIndexByte(unit, '.')
	if i < 0 {
		return padrao == unit
	}
	nome, tipo := unit[:i], unit[i+1:]
	switch {
	case padrao == unit: // exato (redundante aqui, mas seguro)
		return true
	case padrao == tipo: // type-wide: "service" casa "*.service"
		return true
	}
	if at := strings.IndexByte(nome, '@'); at >= 0 {
		if padrao == nome[:at+1]+"."+tipo { // "foo@.service" casa "foo@qualquer.service"
			return true
		}
	}
	for j := len(nome) - 1; j >= 0; j-- {
		if nome[j] == '-' {
			if padrao == nome[:j+1]+"."+tipo { // "foo-.service", "foo-bar-.service"
				return true
			}
		}
	}
	return false
}

// expandirDropins troca cada drop-in POR PADRÃO por uma cópia para CADA base que
// ele casa (Name/DropInFor = a base), para o merge seguir 1:1. Um padrão que não
// casa base nenhuma FICA (dormente): é um drop-in plantado que os checks ainda
// devem ver. Drop-in exato e base passam intactos.
func expandirDropins(f *Facts, units []Unit) []Unit {
	basesPorScope := map[string][]string{}
	for _, u := range units {
		if u.DropInFor == "" {
			basesPorScope[u.Scope] = append(basesPorScope[u.Scope], u.Name)
		}
	}
	out := make([]Unit, 0, len(units))
	truncou := false
	for _, u := range units {
		if truncou {
			break
		}
		if u.DropInFor == "" || !ehPadraoDropin(u.DropInFor) {
			out = append(out, u)
			continue
		}
		var casou []string
		for _, base := range basesPorScope[u.Scope] {
			if base != u.DropInFor && dropinCasaUnit(u.DropInFor, base) {
				casou = append(casou, base)
			}
		}
		if len(casou) == 0 {
			out = append(out, u) // dormente: mantém para os checks verem o drop-in plantado
			continue
		}
		for _, base := range casou {
			// Teto: a expansão de PADRÃO × bases é O(N²), e o filesystem é
			// hostil — um `service.d/` type-wide sobre milhares de services
			// materializaria milhões de Unit. O `maxUnits` da coleta não pega
			// isso porque roda ANTES. Estourá-lo vira lacuna DECLARADA, nunca
			// blowup silencioso.
			if len(out) >= maxUnits {
				truncou = true
				break
			}
			cp := u
			cp.Name = base
			cp.DropInFor = base
			cp.Kind = kindOf(base)
			out = append(out, cp)
		}
	}
	if truncou {
		f.partial("persist", "a expansão de drop-ins por padrão (service.d/, template@., "+
			"prefixo-) passou do teto de "+strconv.Itoa(maxUnits)+" units efetivas: o "+
			"excedente NÃO foi avaliado — um host com milhares de units e um drop-in amplo")
	}
	return out
}

// detectarMascara diz se uma unit está MASCARADA sem precisar parseá-la: link
// para /dev/null (a máscara clássica) OU arquivo regular de tamanho ZERO (o
// systemd trata os dois como desligada). Detectar ANTES do parse evita que o
// ReadFile de um /dev/null (ErrNaoEhArquivo, que é lacuna) vire gap FALSO —
// máscara é config CONHECIDA, não "não consegui ler".
func detectarMascara(e *env.Env, path string) bool {
	fi, err := e.Lstat(path)
	if err != nil {
		return false
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		alvo, err := e.Readlink(path)
		return err == nil && alvo == "/dev/null"
	}
	return fi.Mode().IsRegular() && fi.Size() == 0
}

func parseUnitFile(f *Facts, e *env.Env, path, scope, tipo string, vendor bool) Unit {
	u := Unit{Path: path, Scope: scope, Kind: tipo, Vendor: vendor}
	if fi, err := e.Lstat(path); err == nil {
		u.ModUTC = fi.ModTime().UTC().Format(time.RFC3339)
	}
	b, err := e.ReadFile(path)
	if err != nil {
		// "não consegui ler" ≠ "unit vazia". Um .service ilegível (EACCES) sem
		// isto virava unit sem Exec/Env — benigna aos olhos dos checks. FN.
		if env.EhLacuna(err) {
			f.denyPersist("unit", path+" existe e não pôde ser lido ("+
				env.MotivoDoErro(err)+"): o ExecStart/Environment desta unit NÃO foi avaliado")
		}
		return u
	}

	var pending string
	// A SEÇÃO decide se a diretiva vale, e ignorá-la era um bypass de três
	// linhas.
	//
	// O parser pulava o cabeçalho e seguia aplicando qualquer diretiva
	// reconhecida, viesse ela de onde viesse. Como `ExecStart=` VAZIO reseta a
	// lista, bastava acrescentar uma seção que o systemd ignora:
	//
	//	[Service]
	//	ExecStart=/tmp/.implant
	//
	//	[X-Aletheia]
	//	ExecStart=
	//
	// O systemd executa o implante — seções X- são ignoradas por contrato. Esta
	// ferramenta zerava o Exec e saía calada, com a cobertura completa. Medido
	// contra o binário: a unit de controle saía CRITICAL e esta, silêncio.
	// `[Install]` serve igual, porque ali `ExecStart=` também não é opção
	// válida.
	//
	// A regra segue o systemd: diretiva fora da seção dela não existe. Sem
	// seção nenhuma também não — arquivo de unit sem cabeçalho é erro para o
	// systemd, e honrar essas linhas seria aceitar o que o alvo recusa.
	secao := ""
	for _, raw := range strings.Split(string(b), "\n") {
		ln := strings.TrimSpace(raw)
		if pending != "" {
			ln, pending = pending+" "+ln, ""
		}
		if strings.HasSuffix(ln, `\`) {
			pending = strings.TrimSpace(strings.TrimSuffix(ln, `\`))
			continue
		}
		if ln == "" || strings.HasPrefix(ln, "#") || strings.HasPrefix(ln, ";") {
			continue
		}
		if strings.HasPrefix(ln, "[") {
			secao = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(ln, "["), "]"))
			continue
		}
		k, v, ok := strings.Cut(ln, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if !diretivaValeNaSecao(u.Kind, secao, k) {
			continue
		}

		switch {
		case k == "ExecSearchPath":
			// ANTES do HasPrefix(k,"Exec") — senão viraria uma linha de comando.
			// Vazio RESETA a lista (como ExecStart=): sem isto, ExecSearchPath=/tmp/a
			// seguido de ExecSearchPath= mantinha /tmp/a, divergindo do systemd.
			if v == "" {
				u.ExecSearchPath = nil
				u.ExecSearchPathReset = true
				break
			}
			// Lista separada por espaço ou dois-pontos; pode repetir.
			for _, d := range strings.FieldsFunc(v, func(r rune) bool { return r == ' ' || r == ':' }) {
				if d != "" {
					u.ExecSearchPath = append(u.ExecSearchPath, d)
				}
			}
		case strings.HasPrefix(k, "Exec"):
			// "ExecStart=" vazio RESETA a lista — é assim que um drop-in
			// substitui o comando da unit original.
			if v == "" {
				// Reset da lista DAQUELA diretiva só (ExecStart= não zera
				// ExecStartPre — são listas independentes no systemd).
				u.Exec = execSemKey(u.Exec, k)
				u.ExecResetKeys = append(u.ExecResetKeys, k)
				continue
			}
			u.Exec = append(u.Exec, ExecLine{Key: k, Cmd: v, RawCmd: v})
		case k == "RootDirectory":
			// Vazio RESETA (drop-in que tira o chroot). A ÚLTIMA atribuição vence
			// no merge, resolvida em mesclarUnits.
			u.RootDirectory = v
		case k == "RootImage":
			u.RootImage = v
		case k == "BindPaths", k == "BindReadOnlyPaths":
			// Vazio RESETA a lista, como as outras diretivas de lista.
			if v == "" {
				u.Binds = nil
				break
			}
			for _, item := range camposComAspas(v) {
				if b, ok := parseBindDaUnit(item, k == "BindReadOnlyPaths"); ok {
					u.Binds = append(u.Binds, b)
				}
			}
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
		case k == "EnvironmentFile":
			// A unit carrega env de um ARQUIVO à parte, e um LD_PRELOAD ali é a
			// mesma rota da §7.8 escondida um nível abaixo: quem lê a unit vê só
			// `EnvironmentFile=/tmp/.env`, não o preload dentro dela.
			arq := strings.TrimSpace(v)
			if arq == "" {
				// `EnvironmentFile=` vazio REDEFINE a lista: o systemd descarta
				// os arquivos de ambiente acumulados até aqui. Manter old.env
				// depois disso gerava FP — um LD_PRELOAD que o systemd já tinha
				// esquecido virava achado. Os Environment= EM LINHA ficam.
				u.Environment = envSemArquivos(u.Environment, path)
				u.EnvFilesIlegiveis = nil
				// E marca: se ESTE arquivo é um drop-in, o reset alcança a unit
				// BASE de mesmo nome — a fusão pós-coleta aplica isso.
				u.EnvFileReset = true
				break
			}
			// O `-` no começo é "ignore se faltar". (Aqui `path` é o PARÂMETRO —
			// o caminho da unit —, não o pacote: a expansão de glob mora num
			// helper de escopo de pacote.)
			incorporarEnvironmentFile(&u, e, strings.TrimPrefix(arq, "-"))
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
	// Depois de ler o arquivo inteiro: resolve nome NU de Exec*= contra o
	// ExecSearchPath (que pode ter vindo DEPOIS do ExecStart). Feito aqui, os
	// checks de caminho suspeito e propriedade veem o alvo concreto.
	resolverComandosUnit(&u, e)
	for i := range u.Exec {
		u.Exec[i].Target, u.Exec[i].AlvoIndeterminado = AlvoEfetivoDeExec(u.Exec[i].Cmd)
	}
	return u
}

// parseBindDaUnit lê um item de BindPaths: ORIGEM[:DESTINO[:OPÇÕES]].
//
// Sem destino, o mount aparece no MESMO caminho — e aí não há troca de arquivo,
// só disponibilização. O destino é o que interessa: é ele que decide sob qual
// nome o conteúdo da origem vai aparecer para o processo.
func parseBindDaUnit(item string, somenteLeitura bool) (BindDaUnit, bool) {
	item = strings.Trim(strings.TrimSpace(item), `"'`)
	if item == "" {
		return BindDaUnit{}, false
	}
	// O `-` inicial é "ignore se a origem faltar", como no EnvironmentFile.
	item = strings.TrimPrefix(item, "-")
	partes := strings.Split(item, ":")
	b := BindDaUnit{Origem: partes[0], SomenteL: somenteLeitura}
	if len(partes) > 1 && partes[1] != "" {
		b.Destino = partes[1]
	}
	return b, b.Origem != ""
}

// lacunaDeManagerDeUsuario declara o que a configuração efetiva por usuário NÃO
// reconstrói — e declara CIRURGICAMENTE, só onde a colisão existe de verdade.
//
// # O que está por baixo
//
// O `systemd --user` da alice carrega DUAS origens na mesma configuração: a
// árvore compartilhada (/etc/systemd/user, /usr/lib/systemd/user) e a dela
// (~/.config/systemd/user). Esta coleta as mantém separadas — a compartilhada
// fica com Manager vazio, a por-home com o nome do usuário —, e o merge agrupa
// por Scope+Manager+Nome. São chaves diferentes, então não há fusão:
//
//	/usr/lib/systemd/user/agent.service          base, Manager=""
//	~alice/.config/systemd/user/agent.service.d/ drop-in, Manager="alice"
//
// O systemd aplica um sobre o outro; a ferramenta vê dois objetos soltos. Um
// drop-in que só acrescenta ExecSearchPath=/tmp/.hidden nem tem Exec próprio
// para o unit_dropin_exec denunciar, e a base compartilhada continua com
// aparência intacta.
//
// # Por que declarar em vez de consertar
//
// Reconstruir a configuração efetiva de cada manager exige duplicar a árvore
// compartilhada por UID e resolver precedência entre quatro origens. É caro, e
// o ataque depende de uma composição específica. Um scanner de resposta a
// incidente não precisa reproduzir o executor inteiro; precisa saber
// exatamente quando a aproximação dele deixou de bastar.
//
// # Por que só na colisão
//
// Declarar sempre que houvesse as duas árvores faria toda workstation sair com
// lacuna — e lacuna que aparece em toda instância de um ambiente não informa
// nada, só ensina a ignorar o veredito. Já custou caro quatro vezes nesta base.
// A lacuna se forma quando o MESMO nome de unit aparece nos dois domínios, que
// é exatamente a situação em que a precedência decidiria algo e ninguém a
// resolveu.
func lacunaDeManagerDeUsuario(f *Facts, units []Unit) {
	compartilhadas := map[string]bool{}
	for i := range units {
		if units[i].Scope == "user" && units[i].Manager == "" {
			compartilhadas[units[i].Name] = true
		}
	}
	if len(compartilhadas) == 0 {
		return
	}
	// Um par por manager+nome, ordenado: a mesma unit pode vir de vários
	// subdiretórios do mesmo home, e repetir a linha não acrescenta nada.
	vistos := map[string]bool{}
	var colisoes []string
	for i := range units {
		u := &units[i]
		if u.Scope != "user" || u.Manager == "" || !compartilhadas[u.Name] {
			continue
		}
		k := u.Manager + "/" + u.Name
		if vistos[k] {
			continue
		}
		vistos[k] = true
		colisoes = append(colisoes, k)
	}
	if len(colisoes) == 0 {
		return
	}
	sort.Strings(colisoes)
	f.denyPersist("unit", strconv.Itoa(len(colisoes))+" unit(s) de usuário existem "+
		"na árvore COMPARTILHADA e na do próprio usuário ao mesmo tempo ("+
		firstNCaminhos(colisoes, 3)+"): o `systemd --user` funde as duas numa "+
		"configuração só, e esta coleta as mantém separadas. A precedência e os "+
		"drop-ins ENTRE as duas árvores NÃO foram resolvidos — um drop-in por-home "+
		"sobre uma unit compartilhada pode não ser atribuído a ela")
}

// firstNCaminhos resume uma lista longa sem esconder que ela é longa.
func firstNCaminhos(v []string, n int) string {
	if len(v) <= n {
		return strings.Join(v, ", ")
	}
	return strings.Join(v[:n], ", ") + " e mais " + strconv.Itoa(len(v)-n)
}

// diretivaValeNaSecao diz se o systemd aplicaria esta diretiva, NESTA seção, num
// arquivo DESTE tipo.
//
// O tipo entra por um motivo medido: sem ele, o corte fechava só metade do
// bypass. A primeira versão olhava a seção isolada, e como `[Socket]` também
// carrega contexto de execução, bastou ao atacante trocar a seção inventada por
// uma real:
//
//	[Service]
//	ExecStart=/tmp/.implant
//
//	[Socket]
//	ExecStart=
//
// Numa `.service`, `[Socket]` é tão ignorado pelo systemd quanto `[X-Foo]` — as
// opções específicas de um tipo vivem na SEÇÃO DAQUELE TIPO. Medido contra o
// binário depois do primeiro conserto: a unit com `[Socket] ExecStart=` saía em
// silêncio, e a de controle, CRITICAL. Fechar uma porta e deixar quatro do lado
// não é fechar.
//
// A regra passa a ser: a seção precisa ser a do PRÓPRIO tipo (ou [Install],
// que é comum a todos). O que a seção do tipo aceita continua sendo por
// família, porque Service, Socket, Mount e Swap de fato compartilham o contexto
// de execução — cada um na sua seção.
//
// Unit, X-* e seção desconhecida não contribuem com nada do que este parser
// modela. Para X-* isso é o contrato do systemd; para a desconhecida é a escolha
// conservadora — concordar com o alvo, que também a ignora.
//
// Tipo vazio (não deu para deduzir do nome nem do diretório do drop-in) cai no
// comportamento antigo, por seção. É o único caminho em que o bypass sobrevive,
// e ele exige um nome de arquivo que o próprio systemd não carregaria.
func diretivaValeNaSecao(tipo, secao, k string) bool {
	if secao == "Install" {
		return k == "WantedBy" || k == "RequiredBy"
	}
	// A seção do tipo é a única que configura o tipo. Sem tipo conhecido,
	// aceita-se qualquer seção de execução, como antes.
	if tipo != "" && !strings.EqualFold(secao, tipo) {
		return false
	}
	switch secao {
	case "Service", "Mount", "Swap":
		return ehDiretivaDeExecucao(k)
	case "Socket":
		return ehDiretivaDeExecucao(k) || strings.HasPrefix(k, "Listen")
	case "Timer":
		switch k {
		case "OnCalendar", "OnUnitActiveSec", "OnUnitInactiveSec",
			"OnBootSec", "OnStartupSec":
			return true
		}
		return false
	case "Path":
		switch k {
		case "PathExists", "PathChanged", "PathModified", "PathExistsGlob",
			"DirectoryNotEmpty":
			return true
		}
		return false
	}
	return false
}

// ehDiretivaDeExecucao são as opções do contexto de execução que este parser lê.
func ehDiretivaDeExecucao(k string) bool {
	switch k {
	case "ExecSearchPath", "RootDirectory", "RootImage", "Restart", "User",
		"Environment", "EnvironmentFile", "BindPaths", "BindReadOnlyPaths":
		return true
	}
	return strings.HasPrefix(k, "Exec")
}

// resolverComandosUnit resolve os Exec*= de nome NU contra o ExecSearchPath da
// unit, como o systemd faz. O bare name vira caminho concreto para o alvo
// efetivo dos checks; sem isto, `ExecStart=agent` com ExecSearchPath=/tmp/x
// escondia /tmp/x/agent.
func resolverComandosUnit(u *Unit, e *env.Env) {
	if len(u.ExecSearchPath) == 0 {
		return
	}
	// O ExecSearchPath só vale quando $PATH NÃO foi fornecido pela unit
	// (Environment=/EnvironmentFile=). Com um PATH próprio, é ele que o systemd
	// usa — resolver contra o ExecSearchPath aqui acusaria um diretório que o
	// systemd não consultaria. (LIMITE: o PATH de EnvironmentFile e o de drop-in
	// não são vistos neste ponto por-arquivo — é a mesma dívida de config
	// efetiva do resto.)
	for _, s := range u.Environment {
		if s.Key == "PATH" {
			return
		}
	}
	for i := range u.Exec {
		u.Exec[i].Cmd = resolverNomeNu(e, u.Exec[i].Cmd, u.ExecSearchPath)
	}
}

func resolverNomeNu(e *env.Env, cmd string, dirs []string) string {
	toks := strings.Fields(cmd)
	if len(toks) == 0 {
		return cmd
	}
	prim := toks[0]
	nu := strings.TrimLeft(prim, "-@+!:")
	if nu == "" || strings.ContainsRune(nu, '/') {
		return cmd // já é caminho, não nome nu
	}
	for _, dir := range dirs {
		p := strings.TrimSuffix(dir, "/") + "/" + nu
		if _, err := e.Lstat(p); err == nil {
			// Preserva os prefixos do systemd ("-", "@", "+", "!") antes do path.
			toks[0] = prim[:len(prim)-len(nu)] + p
			return strings.Join(toks, " ")
		}
	}
	return cmd
}

// dirsAbsolutos filtra uma lista de componentes de PATH para só os ABSOLUTOS.
// Um PATH pode ter componente vazio (= cwd) ou relativo, que o systemd resolve
// contra um diretório de trabalho que não modelamos — resolver o nome nu contra
// eles acusaria um caminho errado.
func dirsAbsolutos(dirs []string) []string {
	var out []string
	for _, d := range dirs {
		if strings.HasPrefix(d, "/") {
			out = append(out, d)
		}
	}
	return out
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
