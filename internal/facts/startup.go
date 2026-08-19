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

	// Uma linha |"comando" no aliases faz o MTA executar aquilo a cada e-mail.
	{"/etc/aliases", "mail", "a cada e-mail recebido pelo alias"},
	{"/etc/supervisord.conf", "supervisor", "quando o supervisord sobe"},
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

	// Os diretórios do cron guardam SCRIPTS, e o agendamento sozinho não diz o
	// que eles executam. O XorDDoS depende exatamente dessa indireção: o cron
	// aponta para /etc/cron.hourly/gcc.sh, e é o CONTEÚDO do gcc.sh que aponta
	// para o payload. Sem ler o conteúdo, o alvo real fica invisível.
	{"/etc/cron.hourly", "cron_script", "de hora em hora"},
	{"/etc/cron.daily", "cron_script", "uma vez por dia"},
	{"/etc/cron.weekly", "cron_script", "uma vez por semana"},
	{"/etc/cron.monthly", "cron_script", "uma vez por mês"},
	{"/etc/periodic/15min", "cron_script", "a cada quinze minutos"},
	{"/etc/periodic/hourly", "cron_script", "de hora em hora"},
	{"/etc/periodic/daily", "cron_script", "uma vez por dia"},
	{"/etc/pam.d", "pam", "a cada autenticação"},
	{"/usr/lib/systemd/system-generators", "generator", "em todo boot e reload, ANTES das units"},
	{"/etc/systemd/system-generators", "generator", "em todo boot e reload, ANTES das units"},

	// Supervisores de processo (runbook §7.10): eles ressuscitam o que você
	// matar, e a config deles não está em /etc/systemd.
	{"/etc/supervisor/conf.d", "supervisor", "quando o supervisord sobe, e a cada restart que ele faz"},
	{"/etc/supervisord.d", "supervisor", "quando o supervisord sobe, e a cada restart que ele faz"},
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

	// Legado que continua funcionando onde há MTA local: uma linha
	// |"/caminho/comando" faz o MTA executar aquilo a CADA e-mail recebido.
	{".forward", "a cada e-mail recebido por aquele usuário"},
	{".procmailrc", "a cada e-mail entregue por procmail"},

	// pm2 guarda o que ressuscita no dump (runbook §7.10).
	{".pm2/dump.pm2", "a cada boot, se o pm2 estiver com startup configurado"},
}

// phpDirs: auto_prepend_file faz o PHP executar um arquivo ANTES de cada
// requisição, em qualquer rota. O docroot fica limpo, o grep de webshell da §16
// não acha nada, e o backdoor roda em 100% dos acessos.
var phpDirs = []string{"/etc/php", "/etc/php.d", "/etc/php5", "/etc/php7", "/etc/php8"}

func collectTriggers(f *Facts, e *env.Env) {
	// Os gatilhos de SISTEMA declaravam ausência em silêncio: lerTrigger devolve
	// ok=false tanto para "não existe" quanto para "não pude olhar", e só o laço
	// dos homes tinha o denyPersist. Com /etc/profile ilegível, trigger_exec,
	// shell_startup, bash_env e shell_env ficavam todos mudos sobre um arquivo
	// que roda em toda sessão.
	// registrar guarda o gatilho e DECLARA quando ele veio ilegível.
	//
	// O caminho do EACCES não era o que parecia: lstat de um arquivo modo 000
	// FUNCIONA — a permissão de stat vem do diretório, não do inode —, então
	// lerTrigger montava o Trigger, falhava no ReadFile e devolvia ok=true com
	// Ilegvel marcado. E `Ilegvel` era escrito e lido por NINGUÉM: os checks
	// iteram t.Lines, que estava vazio, e concluíam que o arquivo não executa
	// nada. Um /etc/profile sem permissão de leitura silenciava trigger_exec,
	// shell_startup, bash_env e shell_env de uma vez.
	registrar := func(t Trigger, quando string) {
		f.Triggers = append(f.Triggers, t)
		if t.Ilegvel {
			f.denyPersist("startup", t.File+" existe e não pôde ser LIDO: o que ele "+
				"executa "+quando+" NÃO foi avaliado")
		}
	}
	for _, g := range gatilhosDeSistema {
		if t, ok := lerTrigger(e, g.path, g.kind, g.when, ""); ok {
			registrar(t, g.when)
			continue
		}
		if _, negado := lookup(e, g.path); negado {
			f.denyPersist("startup", g.path+" não pôde ser examinado: o que ele "+
				"executa "+g.when+" NÃO foi avaliado")
		}
	}
	for _, g := range gatilhosDeDiretorio {
		nomes, err := e.ReadDirNamesErr(g.dir)
		if env.EhLacuna(err) {
			f.denyPersist("startup", g.dir+" não pôde ser listado ("+
				env.MotivoDoErro(err)+"): o que roda "+g.when+" NÃO foi avaliado")
			continue
		}
		for _, n := range nomes {
			p := g.dir + "/" + n
			if e.IsDir(p) {
				continue
			}
			if t, ok := lerTrigger(e, p, g.kind, g.when, ""); ok {
				registrar(t, g.when)
			}
		}
	}

	// PHP: a árvore varia demais entre distribuições para ser lista fixa.
	for _, base := range phpDirs {
		procurarPHP(f, e, base, 0)
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
			if t.Ilegvel {
				negados = append(negados, p)
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

// procurarPHP desce na árvore de config do PHP, que muda de forma a cada
// distribuição e a cada versão. Profundidade curta: o que interessa está em
// php.ini e nos conf.d.
func procurarPHP(f *Facts, e *env.Env, dir string, prof int) {
	if prof > 3 {
		return
	}
	for _, n := range e.ReadDirNames(dir) {
		p := dir + "/" + n
		if e.IsDir(p) {
			procurarPHP(f, e, p, prof+1)
			continue
		}
		if !strings.HasSuffix(n, ".ini") {
			continue
		}
		if t, ok := lerTrigger(e, p, "php",
			"antes de CADA requisição, em qualquer rota", ""); ok {
			if t.Ilegvel {
				f.denyPersist("startup", p+" existe e não pôde ser LIDO: o "+
					"auto_prepend_file, que roda antes de CADA requisição, NÃO foi avaliado")
			}
			f.Triggers = append(f.Triggers, t)
		}
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

// collectServicosLegados lê inetd.conf, xinetd.d e inittab — três formas de
// persistência que EXECUTAM um programa (no connect ou no boot) e que a maioria
// dos times nunca abre, porque "ninguém usa mais isso" (runbook §7.7, ATT&CK
// T1543).
//
// Cada uma vira um Trigger com o PROGRAMA extraído como linha, então flui pelo
// mesmo persist.trigger_exec dos outros gatilhos: a pergunta é a de sempre —
// o binário é suspeito, ou nenhum pacote o reivindica?
func collectServicosLegados(f *Facts, e *env.Env) {
	collectInetd(f, e)
	collectXinetd(f, e)
	collectInittab(f, e)
}

// registrarServicoLegado monta o Trigger de um programa extraído de config
// legada, declarando ilegível como lacuna.
func registrarServicoLegado(f *Facts, e *env.Env, arquivo, kind, when string, linhas []TriggerLine) {
	fi, err := e.Lstat(arquivo)
	if err != nil {
		return
	}
	t := Trigger{
		File: arquivo, Kind: kind, When: when,
		Modo:   fi.Mode().String(),
		ModUTC: fi.ModTime().UTC().Format("2006-01-02T15:04:05Z"),
		Lines:  linhas,
	}
	f.Triggers = append(f.Triggers, t)
}

// collectInetd lê /etc/inetd.conf. Cada linha é
//
//	service socket_type proto flags user server args...
//
// e o campo 6 (server, índice 5) é o programa que roda quando alguém conecta na
// porta do serviço. Um backdoor aqui é `9999 stream tcp nowait root /bin/bash -i`.
func collectInetd(f *Facts, e *env.Env) {
	b, err := e.ReadFile("/etc/inetd.conf")
	if err != nil {
		if env.EhLacuna(err) {
			f.denyPersist("startup", "/etc/inetd.conf existe e não pôde ser lido: "+
				"o servidor que roda no connect NÃO foi avaliado")
		}
		return
	}
	var linhas []TriggerLine
	for i, raw := range strings.Split(string(b), "\n") {
		ln := strings.TrimSpace(raw)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		campos := strings.Fields(ln)
		if len(campos) < 6 {
			continue
		}
		// service(0) socket_type(1) proto(2) flags(3) user(4) server(5) args...
		// O programa é o campo 6 (índice 5); `internal` é serviço embutido no
		// inetd, sem programa externo. O `user` pode vir como `user.group`, mas
		// isso não desloca o server — continua no 5.
		prog := campos[5]
		if prog == "internal" {
			continue
		}
		linhas = append(linhas, TriggerLine{N: i + 1, Text: prog})
	}
	if len(linhas) > 0 {
		registrarServicoLegado(f, e, "/etc/inetd.conf", "inetd",
			"quando alguém conecta na porta do serviço", linhas)
	}
}

// collectXinetd lê /etc/xinetd.d/*. Cada arquivo é um bloco chave = valor; o
// `server =` é o programa, e `disable = yes` desliga o serviço (mas o arquivo
// continua lá, reativável).
func collectXinetd(f *Facts, e *env.Env) {
	nomes, err := e.ReadDirNamesErr("/etc/xinetd.d")
	if env.EhLacuna(err) {
		f.denyPersist("startup", "/etc/xinetd.d não pôde ser listado: os serviços "+
			"que rodam no connect NÃO foram avaliados")
		return
	}
	for _, n := range nomes {
		p := "/etc/xinetd.d/" + n
		if e.IsDir(p) {
			continue
		}
		b, err := e.ReadFile(p)
		if err != nil {
			if env.EhLacuna(err) {
				f.denyPersist("startup", p+" existe e não pôde ser lido: o servidor "+
					"xinetd dele NÃO foi avaliado")
			}
			continue
		}
		var server string
		var linha int
		desabilitado := false
		for i, raw := range strings.Split(string(b), "\n") {
			ln := strings.TrimSpace(raw)
			if k, v, ok := strings.Cut(ln, "="); ok {
				k, v = strings.TrimSpace(k), strings.TrimSpace(v)
				switch k {
				case "server":
					server, linha = v, i+1
				case "disable":
					desabilitado = strings.EqualFold(v, "yes")
				}
			}
		}
		if server == "" || desabilitado {
			continue
		}
		registrarServicoLegado(f, e, p, "xinetd",
			"quando alguém conecta na porta do serviço",
			[]TriggerLine{{N: linha, Text: server}})
	}
}

// collectInittab lê /etc/inittab (sysvinit). Cada linha é
//
//	id:runlevels:action:process
//
// e as ações que EXECUTAM são respawn, wait, once, boot, bootwait, sysinit.
// `x:2345:respawn:/tmp/.x` roda /tmp/.x no boot e o reergue se morrer — a
// persistência clássica de sistema legado, que era a motivação original desta
// ferramenta.
func collectInittab(f *Facts, e *env.Env) {
	b, err := e.ReadFile("/etc/inittab")
	if err != nil {
		if env.EhLacuna(err) {
			f.denyPersist("startup", "/etc/inittab existe e não pôde ser lido: o que "+
				"ele executa no boot NÃO foi avaliado")
		}
		return
	}
	acoesQueExecutam := map[string]bool{
		"respawn": true, "wait": true, "once": true,
		"boot": true, "bootwait": true, "sysinit": true,
	}
	var linhas []TriggerLine
	for i, raw := range strings.Split(string(b), "\n") {
		ln := strings.TrimSpace(raw)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		campos := strings.SplitN(ln, ":", 4)
		if len(campos) != 4 || !acoesQueExecutam[campos[2]] {
			continue
		}
		if prog := strings.TrimSpace(campos[3]); prog != "" {
			linhas = append(linhas, TriggerLine{N: i + 1, Text: prog})
		}
	}
	if len(linhas) > 0 {
		registrarServicoLegado(f, e, "/etc/inittab", "inittab",
			"no boot (e reergue, com respawn)", linhas)
	}
}
