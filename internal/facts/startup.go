package facts

import (
	"strconv"
	"strings"

	"github.com/lex0c/aletheia/internal/env"
)

// Gatilhos de execução (runbook §7.6, §7.7 e §7.12).
//
// O que junta coisas tão diferentes quanto um .bashrc, uma regra de udev e um
// hook do apt é a mesma pergunta: QUANDO isto roda. É o quando que decide qual
// arquivo o atacante escolhe — e é o que o operador precisa saber para entender
// o que já rodou desde a invasão.
//
// Por isso `When` é campo, não comentário: um achado em /etc/profile.d vale
// para TODO usuário, e um em ~/.zshenv roda até em shell não interativo. São
// alcances diferentes, e o relatório precisa dizer qual.

// Trigger é um arquivo que executa em algum evento.
type Trigger struct {
	File string `json:"file"`
	Kind string `json:"kind"`
	When string `json:"when"`
	User string `json:"user,omitempty"`

	// Exec importa para rc.local e init.d: sem bit de execução, o arquivo é
	// INERTE. Um chmod +x recente data a ativação (runbook §7.7).
	Exec    bool   `json:"exec,omitempty"`
	Modo    string `json:"mode,omitempty"`
	ModUTC  string `json:"mod_utc,omitempty"`
	Ilegvel bool   `json:"unreadable,omitempty"`

	// Binario marca arquivo que NÃO é texto. Ele continua sendo um gatilho — a
	// existência é o fato —, mas não tem linha para avaliar.
	Binario bool `json:"binary,omitempty"`

	// Lines são as linhas que EXECUTAM algo. Guardar o arquivo inteiro seria
	// carregar ruído; guardar só o que executa é o que os checks avaliam.
	Lines []TriggerLine `json:"lines,omitempty"`
}

// TriggerLine é uma linha executável, com o que decide se ela é suspeita.
type TriggerLine struct {
	N    int    `json:"n"`
	Text string `json:"text"`

	// Added marca a linha que NÃO existe no /etc/skel correspondente. É o
	// baseline de graça da §7.6: o esqueleto é a versão que a distribuição
	// copiou para cada home, e o que sobra foi acrescentado depois.
	Added bool `json:"added,omitempty"`

	// Tail marca linha no fim do arquivo. O .bashrc de distribuição tem
	// dezenas de linhas e ninguém rola até o final — acrescentar lá embaixo,
	// depois de um bloco de linhas em branco, é o padrão (runbook §7.6).
	Tail bool `json:"tail,omitempty"`
}

// gatilhosDeSistema: caminho fixo, alcance de todo mundo.
var gatilhosDeSistema = []struct{ path, kind, when string }{
	{"/etc/profile", "shell", "shell de LOGIN, para todo usuário"},
	{"/etc/bash.bashrc", "shell", "shell INTERATIVO, para todo usuário — roda a cada login SSH"},
	{"/etc/zsh/zshenv", "shell", "SEMPRE em zsh, inclusive shell não interativo"},
	{"/etc/rc.local", "rc", "no BOOT, se tiver bit de execução"},
	{"/etc/rc.d/rc.local", "rc", "no BOOT, se tiver bit de execução"},
	{"/etc/ssh/sshrc", "ssh_rc", "a cada login SSH, antes do shell do usuário"},
}

// gatilhosDeDiretorio: tudo que cair no diretório executa.
var gatilhosDeDiretorio = []struct{ dir, kind, when string }{
	{"/etc/profile.d", "shell", "shell de login, para TODO usuário — um arquivo aqui vale para todos"},
	{"/etc/init.d", "initd", "no boot, convertido em unit pelo systemd-sysv-generator"},
	{"/etc/update-motd.d", "motd", "a cada login, ao montar a mensagem do dia"},
	{"/etc/apt/apt.conf.d", "pkg_hook", "a cada operação do gerenciador de pacotes"},
	{"/etc/dnf/plugins", "pkg_hook", "a cada operação do gerenciador de pacotes"},
	{"/etc/yum/pluginconf.d", "pkg_hook", "a cada operação do gerenciador de pacotes"},
	{"/etc/udev/rules.d", "udev", "em evento de dispositivo"},
	{"/etc/pam.d", "pam", "a cada autenticação"},
	{"/usr/lib/systemd/system-generators", "generator", "em todo boot e reload, ANTES das units"},
	{"/etc/systemd/system-generators", "generator", "em todo boot e reload, ANTES das units"},
}

// gatilhosDeHome: o mesmo arquivo em cada home, e cada um roda num evento
// diferente. É o quadro da §7.6, que decide qual o atacante escolhe.
var gatilhosDeHome = []struct{ nome, when string }{
	{".bashrc", "shell INTERATIVO — roda a CADA login SSH, o favorito"},
	{".bash_profile", "shell de LOGIN"},
	{".bash_login", "shell de LOGIN"},
	{".profile", "shell de LOGIN"},
	{".bash_logout", "ao SAIR do shell"},
	{".zshrc", "shell interativo em zsh"},
	{".zshenv", "SEMPRE em zsh, inclusive não interativo — o mais forte"},
	{".ssh/rc", "a cada login SSH daquele usuário"},
}

func collectTriggers(f *Facts, e *env.Env) {
	for _, g := range gatilhosDeSistema {
		if t, ok := lerTrigger(e, g.path, g.kind, g.when, ""); ok {
			f.Triggers = append(f.Triggers, t)
		}
	}
	for _, g := range gatilhosDeDiretorio {
		for _, n := range e.ReadDirNames(g.dir) {
			p := g.dir + "/" + n
			if e.IsDir(p) {
				continue
			}
			if t, ok := lerTrigger(e, p, g.kind, g.when, ""); ok {
				f.Triggers = append(f.Triggers, t)
			}
		}
	}

	// Home: o esqueleto da distribuição é o baseline de graça.
	skel := map[string]map[string]bool{}
	for _, g := range gatilhosDeHome {
		skel[g.nome] = linhasDe(e, "/etc/skel/"+g.nome)
	}
	var negados []string
	for _, home := range homeDirs(e) {
		u := home[strings.LastIndexByte(home, '/')+1:]
		for _, g := range gatilhosDeHome {
			p := home + "/" + g.nome
			t, ok := lerTrigger(e, p, "shell", g.when, u)
			if !ok {
				if _, negado := lookup(e, p); negado {
					negados = append(negados, p)
				}
				continue
			}
			for i := range t.Lines {
				t.Lines[i].Added = !skel[g.nome][normaliza(t.Lines[i].Text)]
			}
			f.Triggers = append(f.Triggers, t)
		}
	}
	if len(negados) > 0 {
		f.denyPersist("startup", strconv.Itoa(len(negados))+
			" arquivos de inicialização de shell ilegíveis (permissão): "+
			resumoCaminhos(negados))
	}
}

// lerTrigger extrai as linhas EXECUTÁVEIS. Comentário e atribuição simples
// ficam de fora — guardar o arquivo inteiro carregaria ruído, e o que os checks
// avaliam é o que roda.
func lerTrigger(e *env.Env, path, kind, when, user string) (Trigger, bool) {
	fi, err := e.Lstat(path)
	if err != nil {
		return Trigger{}, false
	}
	t := Trigger{
		File: path, Kind: kind, When: when, User: user,
		Exec:   fi.Mode()&0o111 != 0,
		Modo:   fi.Mode().String(),
		ModUTC: fi.ModTime().UTC().Format("2006-01-02T15:04:05Z"),
	}

	b, err := e.ReadFile(path)
	if err != nil {
		t.Ilegvel = true
		return t, true
	}
	// Generator e alguns "hooks" são BINÁRIOS. Fatiar um ELF em linhas produz
	// texto que parece configuração — o systemd-debug-generator tem
	// `TTYPath=/dev/%s` no meio do código, e isso virava achado. O arquivo
	// continua registrado (a existência dele é o fato), sem linhas.
	if ehBinario(b) {
		t.Binario = true
		return t, true
	}
	linhas := strings.Split(string(b), "\n")
	ultimaComConteudo := 0
	for i, ln := range linhas {
		if strings.TrimSpace(ln) != "" {
			ultimaComConteudo = i
		}
	}
	for i, raw := range linhas {
		ln := strings.TrimSpace(raw)
		if ln == "" || strings.HasPrefix(ln, "#") || strings.HasPrefix(ln, ";") {
			continue
		}
		t.Lines = append(t.Lines, TriggerLine{
			N: i + 1, Text: ln,
			// "no fim" é o último terço do conteúdo: é onde o append cai, e é
			// onde ninguém rola até.
			Tail: i >= ultimaComConteudo-(ultimaComConteudo/3) && ultimaComConteudo > 6,
		})
	}
	return t, true
}

// linhasDe devolve o conjunto de linhas de um arquivo de esqueleto, para o
// diff. Normalizado, porque espaçamento não é diferença.
func linhasDe(e *env.Env, path string) map[string]bool {
	out := map[string]bool{}
	b, err := e.ReadFile(path)
	if err != nil {
		return out
	}
	for _, ln := range strings.Split(string(b), "\n") {
		if s := normaliza(ln); s != "" {
			out[s] = true
		}
	}
	return out
}

// ehBinario usa a mesma heurística do `grep`: byte NUL no começo do arquivo.
// Barata e suficiente — texto de configuração não tem NUL.
func ehBinario(b []byte) bool {
	n := len(b)
	if n > 512 {
		n = 512
	}
	for i := 0; i < n; i++ {
		if b[i] == 0 {
			return true
		}
	}
	return false
}

func normaliza(s string) string { return strings.Join(strings.Fields(s), " ") }
