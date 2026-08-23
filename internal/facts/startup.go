package facts

import (
	"sort"
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

	// AptHooks são os hooks ATIVOS de um apt.conf — o comando que
	// Pre-Install-Pkgs/Pre-Invoke/Post-Invoke executa —, extraídos com o lexer
	// do apt sobre os bytes crus. Existe porque Lines passou pelo parser
	// genérico, que descarta linha começada por # e assim perde um hook escondido
	// atrás de um bloco /* … */ mal fechado. Os checks de execução e de poder
	// leem isto para apt, nao Lines. Ver analisarAptHooks.
	AptHooks []TriggerLine `json:"apt_hooks,omitempty"`

	// EscapeN é a linha onde há SEQUÊNCIA DE ESCAPE de terminal, ou 0.
	//
	// Ela mora fora de Lines de propósito: o truque usa uma linha de
	// COMENTÁRIO, que Lines descarta por não executar nada.
	//
	//	echo "comando-do-invasor"      >  script.sh
	//	echo "# $(clear)"              >> script.sh
	//	echo "# Gerado por configure." >> script.sh
	//
	// Quem der `cat` no arquivo vê UMA linha — o `clear` embutido apaga o
	// resto da tela —, e a que sobra parece um cabeçalho gerado. O `less` e o
	// `vim` mostram tudo; o reflexo de quem investiga é `cat`.
	EscapeN int `json:"escape_line,omitempty"`
}

// LinhasExecutaveis devolve o que um gatilho EXECUTA, na representacao certa
// por tipo. Para apt.conf.d é AptHooks — o fato semantico do lexer do apt, imune
// ao descarte de linha-# do parser generico. Para o resto, Lines.
//
// Mora no FATO, e nao num check, porque é semantica do gatilho: todo consumidor
// que pergunta "o que este gatilho executa?" — persist.trigger_exec,
// integrity.timestomp e o DRIFT — precisa da mesma resposta, ou um hook escondido
// fica visivel para um e invisivel para outro.
func (t *Trigger) LinhasExecutaveis() []TriggerLine {
	if t.Kind == "pkg_hook" && ehArquivoApt(t.File) {
		return t.AptHooks
	}
	return t.Lines
}

// ehArquivoApt reconhece os arquivos de configuração do apt cujos hooks o lexer
// dedicado analisa — o principal /etc/apt/apt.conf e os fragmentos de
// apt.conf.d. Central para os consumidores não divergirem no recorte.
func ehArquivoApt(p string) bool {
	return strings.Contains(p, "/apt/apt.conf")
}

// TriggerLine é uma linha executável, com o que decide se ela é suspeita.
type TriggerLine struct {
	N    int    `json:"n"`
	Text string `json:"text" redact:"linha"`

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
	// O arquivo PRINCIPAL do apt, lido além dos fragmentos de apt.conf.d. Um
	// DPkg::Pre-Invoke aqui é executado igual, e ficava fora da coleta.
	{"/etc/apt/apt.conf", "pkg_hook", "a cada operação do gerenciador de pacotes"},
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
		if t, ok := lerTrigger(f, e, g.path, g.kind, g.when, ""); ok {
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
			if t, ok := lerTrigger(f, e, p, g.kind, g.when, ""); ok {
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
			t, ok := lerTrigger(f, e, p, "shell", g.when, u)
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
	nomes, err := e.ReadDirNamesErr(dir)
	if env.EhLacuna(err) {
		f.denyPersist("startup", dir+" não pôde ser listado ("+env.MotivoDoErro(err)+
			"): o auto_prepend_file do PHP, que roda antes de CADA requisição, "+
			"NÃO foi avaliado")
		return
	}
	for _, n := range nomes {
		p := dir + "/" + n
		if e.IsDir(p) {
			procurarPHP(f, e, p, prof+1)
			continue
		}
		if !strings.HasSuffix(n, ".ini") {
			continue
		}
		if t, ok := lerTrigger(f, e, p, "php",
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
func lerTrigger(f *Facts, e *env.Env, path, kind, when, user string) (Trigger, bool) {
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
	// apt.conf.d ganha extração SEMÂNTICA dos hooks, sobre os bytes crus e com o
	// lexer do apt — antes de o parser genérico de linhas descartar informação
	// que a gramática do apt ainda usaria. Ver analisarAptHooks.
	if kind == "pkg_hook" && ehArquivoApt(path) {
		t.AptHooks = resolverAptHooks(f, e, path, b, map[string]bool{path: true}, 0)
	}
	linhas := strings.Split(string(b), "\n")
	ultimaComConteudo := 0
	for i, ln := range linhas {
		if strings.TrimSpace(ln) != "" {
			ultimaComConteudo = i
		}
	}
	for i, raw := range linhas {
		// A sequência de escape é procurada na linha CRUA e ANTES do descarte
		// de comentário — é dentro do comentário que ela mora, e pular
		// comentário aqui apagaria a única forma que se usa. Mesma razão do
		// `<?php` atrás do `#` em configweb.go.
		if t.EscapeN == 0 && temEscapeDeTerminal(raw) {
			t.EscapeN = i + 1
		}
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

// temEscapeDeTerminal diz se a linha carrega uma sequência que faz o TERMINAL
// mostrar uma coisa e o arquivo conter outra.
//
// A primeira versão disparava com QUALQUER ESC (0x1b), e isso acusava a coisa
// mais comum que existe num arquivo de inicialização de shell: um prompt
// colorido. `PS1='\[<ESC>[01;32m\]\u@\h…'` está em todo .bashrc gerado por
// oh-my-zsh, powerlevel10k e afins, e sairia como CRÍTICO irreversível.
//
// O que esconde texto NÃO é a cor — é o movimento de cursor e o apagamento de
// tela. `<ESC>[2J` limpa, `<ESC>[H` volta ao canto, `<ESC>[1A` sobe uma linha, e
// o que estava escrito some da vista sem sair do arquivo. A cor (final `m`) não
// apaga nada, e o título de janela (OSC, `<ESC>]`) também não.
//
// Por isso a leitura é do BYTE FINAL da sequência CSI, que é o que diz o que
// ela faz:
//
//	J  apaga a tela        H  posiciona o cursor    A B  move o cursor
//	K  apaga a linha       f  posiciona o cursor    s u  salva/restaura
//	m  COR — não conta     ]  título — não conta
func temEscapeDeTerminal(linha string) bool {
	// CR no MEIO da linha volta ao começo, e o que vier depois SOBRESCREVE o
	// que já foi impresso. O `\r\n` do fim é o terminador de arquivo editado
	// no Windows, e acusá-lo seria acusar metade dos hosts.
	if strings.ContainsRune(strings.TrimSuffix(linha, "\r"), '\r') {
		return true
	}
	b := []byte(linha)
	for i := 0; i < len(b); i++ {
		if b[i] != 0x1b || i+1 >= len(b) || b[i+1] != '[' {
			continue
		}
		// CSI: parâmetros (0x30-0x3F), intermediários (0x20-0x2F), final
		// (0x40-0x7E). É o final que diz o que a sequência faz.
		j := i + 2
		for j < len(b) && b[j] >= 0x30 && b[j] <= 0x3f {
			j++
		}
		for j < len(b) && b[j] >= 0x20 && b[j] <= 0x2f {
			j++
		}
		if j >= len(b) {
			return false
		}
		if strings.IndexByte("JKHfABsu", b[j]) >= 0 {
			return true
		}
		i = j
	}
	return false
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
//
// O `cru` é o conteúdo do arquivo, e ele existe por causa do EscapeN: este
// caminho monta o Trigger à mão em vez de passar pelo lerTrigger, e sem o
// conteúdo o campo ficava zerado — que, pela nota do SchemaVersion 8, significa
// "foi lido e não tem escape nenhum".
//
// Justamente aqui isso doía mais: inetd.conf, xinetd.d e inittab são os
// arquivos que o comentário deste coletor descreve como "ninguém mais abre", e
// esconder texto de quem não abre o arquivo é redundante — esconder de quem
// ABRE é o ponto.
func registrarServicoLegado(f *Facts, e *env.Env, arquivo, kind, when string, linhas []TriggerLine, cru []byte) {
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
	for i, raw := range strings.Split(string(cru), "\n") {
		if temEscapeDeTerminal(raw) {
			t.EscapeN = i + 1
			break
		}
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
		// Guarda o server E os args: `root /bin/sh sh -c /tmp/.x` sem os args
		// vira só `/bin/sh`, e o /tmp/.x — o alvo real — some da decisão. O
		// alvoEfetivo do check desembrulha o `sh -c`, mas só se os args
		// chegarem até ele. `internal` é serviço embutido, sem programa externo.
		if campos[5] == "internal" {
			continue
		}
		linhas = append(linhas, TriggerLine{N: i + 1, Text: strings.Join(campos[5:], " ")})
	}
	if len(linhas) > 0 {
		registrarServicoLegado(f, e, "/etc/inetd.conf", "inetd",
			"quando alguém conecta na porta do serviço", linhas, b)
	}
}

// collectXinetd lê /etc/xinetd.d/*. Cada arquivo é um bloco chave = valor; o
// `server =` é o programa, e `disable = yes` desliga o serviço (mas o arquivo
// continua lá, reativável).
func collectXinetd(f *Facts, e *env.Env) {
	// A árvore de configuração do xinetd, seguindo `include`/`includedir` a
	// partir de /etc/xinetd.conf — como o próprio xinetd a monta. Ler
	// /etc/xinetd.d fixo tinha dois defeitos simétricos: um `includedir
	// /opt/.x` apontando para outro lugar era invisível (bypass), e
	// /etc/xinetd.d era varrido MESMO quando nada o incluía, transformando
	// config inerte em achado (FP).
	arquivos := arvoreXinetd(f, e)

	// defaults{} governa TODA a árvore, mesmo que more no xinetd.conf e o serviço
	// esteja num arquivo do includedir. Por isso a decisão de "está ligado?" só
	// pode ser tomada depois de ler tudo — dois passos, não um.
	desabilitadosGlobal := map[string]bool{}
	habilitadosGlobal := map[string]bool{}
	temEnabled := false
	type svc struct {
		arquivo, nome, cmd string
		linha              int
		// cru é o texto do arquivo de onde este serviço veio, para a busca de
		// sequência de escape (ver registrarServicoLegado).
		cru string
	}
	var servicos []svc
	for _, af := range arquivos {
		for _, bl := range parseXinetd(af.texto) {
			if bl.ehDefaults {
				for _, nm := range strings.Fields(bl.attrs["disabled"]) {
					desabilitadosGlobal[nm] = true
				}
				if v, ok := bl.attrs["enabled"]; ok {
					temEnabled = true
					for _, nm := range strings.Fields(v) {
						habilitadosGlobal[nm] = true
					}
				}
				continue
			}
			if strings.EqualFold(strings.TrimSpace(bl.attrs["disable"]), "yes") {
				continue
			}
			server := strings.TrimSpace(bl.attrs["server"])
			if server == "" {
				continue
			}
			cmd := server
			if sa := strings.TrimSpace(bl.attrs["server_args"]); sa != "" {
				// server + server_args: com NAMEINARGS o server é um wrapper
				// (tcpd) e o programa real está nos args. O alvoEfetivo do check
				// desembrulha, mas precisa dos args.
				cmd = server + " " + sa
			}
			servicos = append(servicos, svc{af.path, bl.nome, cmd, bl.serverLinha, af.texto})
		}
	}

	for _, sv := range servicos {
		if desabilitadosGlobal[sv.nome] {
			continue // defaults{ disabled = ... } desligou este
		}
		if temEnabled && !habilitadosGlobal[sv.nome] {
			continue // defaults{ enabled = ... } é lista branca: fora dela, off
		}
		registrarServicoLegado(f, e, sv.arquivo, "xinetd",
			"quando alguém conecta na porta do serviço",
			[]TriggerLine{{N: sv.linha, Text: sv.cmd}}, []byte(sv.cru))
	}
}

// blocoXinetd é um bloco `service NAME { ... }` ou `defaults { ... }` já lido.
type blocoXinetd struct {
	nome        string // vazio para defaults
	ehDefaults  bool
	attrs       map[string]string // última atribuição vence; server guarda a linha
	serverLinha int
}

// parseXinetd entende a gramática do xinetd o suficiente para a pergunta desta
// ferramenta: quais serviços estão declarados, com qual server, e ligados?
//
// A forma ingênua — varrer o arquivo pegando o último `server=` — funde blocos
// e mistura o server de um serviço com o disable de outro. Um arquivo com dois
// `service {}` (raro, mas válido) plantava um backdoor no segundo bloco e a
// leitura só via o primeiro. Aqui cada bloco é isolado por chaves.
func parseXinetd(texto string) []blocoXinetd {
	var blocos []blocoXinetd
	var cur *blocoXinetd
	esperandoAbre := false
	for i, raw := range strings.Split(texto, "\n") {
		ln := raw
		if j := strings.IndexByte(ln, '#'); j >= 0 {
			ln = ln[:j]
		}
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		if cur == nil {
			campos := strings.Fields(ln)
			switch campos[0] {
			case "service", "defaults":
				b := blocoXinetd{attrs: map[string]string{}, ehDefaults: campos[0] == "defaults"}
				if campos[0] == "service" && len(campos) >= 2 {
					b.nome = campos[1]
				}
				cur = &b
				if idx := strings.IndexByte(ln, '{'); idx >= 0 {
					// `{` na mesma linha; o que vier depois é atributo.
					esperandoAbre = false
					resto := strings.TrimSpace(ln[idx+1:])
					if resto != "" {
						aplicaAtributoXinetd(cur, resto, i+1)
					}
				} else {
					esperandoAbre = true
				}
			}
			continue
		}
		if esperandoAbre {
			if idx := strings.IndexByte(ln, '{'); idx >= 0 {
				esperandoAbre = false
				ln = strings.TrimSpace(ln[idx+1:])
				if ln == "" {
					continue
				}
			} else {
				// bloco malformado sem `{`; abandona-o para não engolir o resto.
				cur = nil
				continue
			}
		}
		if strings.HasPrefix(ln, "}") {
			blocos = append(blocos, *cur)
			cur = nil
			continue
		}
		aplicaAtributoXinetd(cur, ln, i+1)
	}
	if cur != nil {
		blocos = append(blocos, *cur)
	}
	return blocos
}

// aplicaAtributoXinetd registra uma linha `chave OP valor` (OP = `=`, `+=` ou
// `-=`) no bloco. Para esta ferramenta += e -= tratam-se como =: o interesse é
// SE um server foi nomeado, não a composição exata da lista.
func aplicaAtributoXinetd(b *blocoXinetd, ln string, linha int) {
	eq := strings.IndexByte(ln, '=')
	if eq < 0 {
		return
	}
	lhs := strings.TrimSpace(ln[:eq])
	op := "="
	switch {
	case strings.HasSuffix(lhs, "+"):
		op = "+="
		lhs = strings.TrimSpace(strings.TrimSuffix(lhs, "+"))
	case strings.HasSuffix(lhs, "-"):
		op = "-="
		lhs = strings.TrimSpace(strings.TrimSuffix(lhs, "-"))
	}
	chave := lhs
	valor := strings.TrimSpace(ln[eq+1:])
	if chave == "" {
		return
	}
	// `enabled`/`disabled` são atributos de CONJUNTO: += acrescenta, -= remove,
	// = redefine. Tratar tudo como = (o que o parser fazia) apagava
	// `enabled += ssh` sobre um `enabled = bd`, e o `bd` sumia da lista branca —
	// virava "desabilitado" e um serviço ativo passava despercebido.
	if chave == "enabled" || chave == "disabled" {
		b.attrs[chave] = aplicaConjuntoXinetd(b.attrs[chave], op, valor)
		return
	}
	b.attrs[chave] = valor // escalar: última atribuição vence
	if chave == "server" {
		b.serverLinha = linha
	}
}

// aplicaConjuntoXinetd aplica `=`/`+=`/`-=` a um atributo set-valued do xinetd,
// preservando a ordem de inserção.
func aplicaConjuntoXinetd(atual, op, valor string) string {
	var ordem []string
	set := map[string]bool{}
	push := func(x string) {
		if x != "" && !set[x] {
			set[x] = true
			ordem = append(ordem, x)
		}
	}
	if op != "=" {
		for _, x := range strings.Fields(atual) {
			push(x)
		}
	}
	if op == "-=" {
		rem := map[string]bool{}
		for _, x := range strings.Fields(valor) {
			rem[x] = true
		}
		var novo []string
		for _, x := range ordem {
			if !rem[x] {
				novo = append(novo, x)
			}
		}
		return strings.Join(novo, " ")
	}
	for _, x := range strings.Fields(valor) {
		push(x)
	}
	return strings.Join(ordem, " ")
}

const (
	maxXinetdArquivos = 256
	maxXinetdProf     = 16
)

// arquivoXinetd é um arquivo de configuração já lido, na ordem em que a árvore
// de include o alcançou — ordem determinística, ao contrário de um range sobre
// mapa.
type arquivoXinetd struct {
	path  string
	texto string
}

// arvoreXinetd percorre a configuração a partir de /etc/xinetd.conf, seguindo
// `include ARQUIVO` e `includedir DIR`. É o entrypoint do próprio xinetd: o que
// ele não alcança por include, ele não roda — e o que esta função não alcança,
// ela não reporta. visited-set contra ciclo; teto de arquivos e profundidade
// contra árvore hostil; corte declara lacuna.
func arvoreXinetd(f *Facts, e *env.Env) []arquivoXinetd {
	var out []arquivoXinetd
	visto := map[string]bool{}
	cortou := false
	cortouProf := false
	var seguir func(p string, prof int)
	seguir = func(p string, prof int) {
		if cortou || visto[p] {
			return
		}
		if prof > maxXinetdProf {
			// Teto de PROFUNDIDADE, separado do de quantidade: uma cadeia de
			// include muito funda (ou em ciclo que o visited-set não pega por
			// caminho variável) para aqui, e o que ficou além é lacuna, não
			// silêncio.
			cortouProf = true
			return
		}
		visto[p] = true
		if len(out) >= maxXinetdArquivos {
			cortou = true
			return
		}
		b, err := e.ReadFile(p)
		if err != nil {
			if env.EhLacuna(err) {
				f.denyPersist("startup", p+" (config do xinetd) não pôde ser lido ("+
					env.MotivoDoErro(err)+"): os serviços declarados ali NÃO foram avaliados")
			}
			return
		}
		out = append(out, arquivoXinetd{p, string(b)})
		for _, raw := range strings.Split(string(b), "\n") {
			ln := raw
			if i := strings.IndexByte(ln, '#'); i >= 0 {
				ln = ln[:i]
			}
			campos := strings.Fields(ln)
			if len(campos) < 2 {
				continue
			}
			switch campos[0] {
			case "include":
				seguir(campos[1], prof+1)
			case "includedir":
				nomes, derr := e.ReadDirNamesErr(campos[1])
				if env.EhLacuna(derr) {
					f.denyPersist("startup", campos[1]+" (includedir do xinetd) não pôde "+
						"ser listado ("+env.MotivoDoErro(derr)+"): os serviços dele NÃO "+
						"foram avaliados")
					continue
				}
				sort.Strings(nomes)
				for _, n := range nomes {
					// xinetd ignora nomes começados por '.', terminados em '~' ou
					// com '.' no meio (backup de editor, .rpmsave). "varrido =
					// rodaria" é o que evita transformar arquivo inerte em achado.
					if n == "" || n[0] == '.' || strings.HasSuffix(n, "~") || strings.ContainsRune(n, '.') {
						continue
					}
					q := campos[1] + "/" + n
					if e.IsDir(q) {
						continue
					}
					seguir(q, prof+1)
				}
			}
		}
	}
	seguir("/etc/xinetd.conf", 0)
	if cortou {
		f.denyPersist("startup", "a árvore de include do xinetd passou de "+
			strconv.Itoa(maxXinetdArquivos)+" arquivos e foi cortada: serviços além "+
			"disso NÃO foram avaliados")
	}
	if cortouProf {
		f.denyPersist("startup", "a árvore de include do xinetd passou de "+
			strconv.Itoa(maxXinetdProf)+" níveis de profundidade e foi cortada: "+
			"serviços incluídos além disso NÃO foram avaliados")
	}
	return out
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
			"no boot (e reergue, com respawn)", linhas, b)
	}
}
