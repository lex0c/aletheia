package checks

import "strings"

// Primitiva de escalada: o que um binário LEGÍTIMO devolve quando alguém o
// executa com privilégio emprestado — por uma regra de sudo/doas sem senha, ou
// pelo bit setuid.
//
// # O defeito que isto conserta
//
// O discriminador anterior era `ehShellOuInterp`, e ele conhecia dezesseis
// nomes: sh, bash, python, perl e a vizinhança imediata. Contra uma regra
// `NOPASSWD: /bin/bash` o relatório dizia CRÍTICO e estava certo. Contra
// `NOPASSWD: /usr/bin/find` ele dizia isto:
//
//	restrita a comando nomeado — é desenho de menor privilégio
//
// Que é FALSO. `sudo find . -exec /bin/sh \;` é root, sem senha, num passo,
// sem exploração. E o mesmo valia para tar, vim, awk, git, systemctl, apt-get
// e mais duzentos binários que qualquer distribuição instala de fábrica. O
// problema não era a severidade — era o relatório AFIRMAR o contrário do fato
// para quem estava lendo no meio de um incidente.
//
// # Por que uma tabela, numa ferramenta que não usa base de assinatura
//
// O README diz que a ferramenta trabalha com comportamento e correlação "em vez
// de depender de uma base de assinaturas", e isto aqui parece contradizer.
// Não contradiz, e a diferença importa:
//
//	assinatura de malware  descreve o ARTEFATO DO INVASOR, muda quando ele
//	                       recompila, e envelhece contra quem a escreveu
//
//	primitiva de binário   descreve o SOFTWARE LEGÍTIMO do host — que `tar`
//	                       tem `--to-command` é uma propriedade documentada,
//	                       estável há décadas, e verificável no manual
//
// A ferramenta já dependia de conhecimento dessa segunda espécie: os nomes de
// kthread, os caminhos de persistência do systemd, as capabilities que
// equivalem a root. Esta tabela é a mesma classe de fato.
//
// # O LIMITE, e ele é o principal
//
// A tabela não é a GTFOBins e nunca vai ser: são ~480 binários lá contra ~110
// aqui, escolhidos por aparecerem de fato em regra de sudo e por a primitiva
// ser conhecida sem ambiguidade. Um binário FORA dela não recebe absolvição —
// recebe a frase honesta ("o que esta regra concede depende do que aquele
// binário faz com privilégio"), que é a diferença entre não saber e afirmar
// que não há nada.
//
// O reconhecimento é por NOME, e é o mesmo limite que suid.go já declara: uma
// cópia de /bin/sh chamada `.dbus-helper` não casa com nada aqui. Quem detecta
// aquilo é a pergunta de propriedade, não esta lista.
type classePrimitiva int

const (
	primNenhuma classePrimitiva = iota

	// primShell — o binário É um interpretador. Executar já devolve o
	// privilégio; não há passo intermediário.
	primShell

	// primExec — executa comando arbitrário por opção documentada, escape de
	// modo interativo ou hook de configuração. `find -exec`, `tar
	// --to-command`, `vim :!`, `git core.pager`, `systemctl` abrindo o pager.
	primExec

	// primEscrita — escreve conteúdo arbitrário em caminho arbitrário. Com
	// privilégio de root isso é root por outro caminho: uma linha em
	// /etc/sudoers, uma chave em /root/.ssh, um arquivo em /etc/cron.d.
	primEscrita

	// primLeitura — lê arquivo arbitrário. NÃO é root imediato: entrega o
	// /etc/shadow, e o hash ainda precisa ser quebrado. Pesa menos, e por isso
	// é uma classe separada em vez de estar junto com escrita.
	primLeitura
)

func (c classePrimitiva) frase() string {
	switch c {
	case primShell:
		return "é um interpretador: executar já devolve o privilégio, sem passo intermediário"
	case primExec:
		return "executa comando arbitrário por opção documentada, escape de modo " +
			"interativo ou hook de configuração"
	case primEscrita:
		return "escreve conteúdo arbitrário em caminho arbitrário — com privilégio " +
			"de root isso é uma linha em /etc/sudoers ou uma chave em /root/.ssh"
	case primLeitura:
		return "lê arquivo arbitrário — entrega o /etc/shadow, e o hash ainda " +
			"precisa ser quebrado"
	}
	return ""
}

// primitivaDe é a tabela. Cada entrada é uma propriedade DOCUMENTADA do
// software, não uma observação sobre um invasor.
//
// A curadoria tem dois critérios, e os dois foram aplicados a cada nome:
// (1) o binário aparece de verdade em delegação de sudo — administrar
// serviço, publicar release, rodar backup, empacotar; (2) a primitiva é
// inequívoca, do tipo que está no `man` da ferramenta.
var primitivaDe = map[string]classePrimitiva{
	// ── Interpretadores ────────────────────────────────────────────────────
	// Os shells. `busybox` entra porque um applet dele É um shell, e em Alpine
	// ele é o shell.
	"sh": primShell, "bash": primShell, "zsh": primShell, "dash": primShell,
	"ksh": primShell, "ash": primShell, "csh": primShell, "tcsh": primShell,
	"fish": primShell, "busybox": primShell, "elvish": primShell,

	// Linguagens. Todas têm a forma de uma linha que executa comando do
	// sistema, e é a primeira coisa que qualquer um tenta.
	"python": primShell, "python2": primShell, "python3": primShell,
	"perl": primShell, "ruby": primShell, "php": primShell,
	"node": primShell, "nodejs": primShell, "lua": primShell,
	"tclsh": primShell, "expect": primShell, "irb": primShell,
	"guile": primShell, "julia": primShell, "Rscript": primShell,

	// ── Execução por opção, escape ou hook ─────────────────────────────────
	// awk tem `system()` e `print | "cmd"` na própria linguagem.
	"awk": primExec, "gawk": primExec, "mawk": primExec, "nawk": primExec,

	// find -exec. O caso que expôs o defeito.
	"find": primExec,

	// Editores e paginadores: `:!cmd` no vi, `!cmd` no less e no man, `^R^X`
	// no nano. O escape existe desde que essas ferramentas existem, e vale
	// MESMO com a regra fixando argumento — basta o editor abrir.
	"vi": primExec, "vim": primExec, "vimdiff": primExec, "view": primExec,
	"rvim": primExec, "ex": primExec, "nvim": primExec,
	"nano": primExec, "pico": primExec, "emacs": primExec, "ed": primExec,
	"less": primExec, "more": primExec, "most": primExec, "pg": primExec,
	"man": primExec, "w3m": primExec,

	// Arquivadores com hook de execução: `tar --to-command`,
	// `tar --checkpoint-action=exec`, `zip -TT`.
	"tar": primExec, "zip": primExec, "7z": primExec, "7za": primExec,

	// Transferência com comando remoto configurável: `rsync -e`,
	// `ssh -o ProxyCommand`, `scp -S`, `sftp !`, `ftp !`.
	"rsync": primExec, "ssh": primExec, "scp": primExec, "sftp": primExec,
	"ftp": primExec, "socat": primExec, "nc": primExec, "ncat": primExec,
	"netcat": primExec, "telnet": primExec, "lftp": primExec,

	// Envelopes: não fazem nada por conta própria, e é justamente isso —
	// `sudo env X` executa X, e a regra que nomeia o envelope concede o que
	// vier depois dele. É a forma mais direta de burlar uma regra "restrita".
	"env": primExec, "nohup": primExec, "timeout": primExec, "stdbuf": primExec,
	"setarch": primExec, "nice": primExec, "ionice": primExec, "taskset": primExec,
	"chrt": primExec, "choom": primExec, "flock": primExec, "watch": primExec,
	"script": primExec, "setsid": primExec, "unshare": primExec, "nsenter": primExec,
	"chroot": primExec, "capsh": primExec, "aa-exec": primExec, "runuser": primExec,
	"setpriv": primExec, "systemd-run": primExec, "xargs": primExec,
	"run-parts": primExec, "sudo": primExec, "doas": primExec, "pkexec": primExec,

	// Ferramentas de desenvolvimento que executam por desenho.
	"make": primExec, "cmake": primExec, "gcc": primExec, "cc": primExec,
	"gdb": primExec, "strace": primExec, "ltrace": primExec, "perf": primExec,
	"bpftrace": primExec, "stap": primExec, "ld.so": primExec,

	// git: `core.pager`, `core.editor`, `core.sshCommand`, hooks, e `git help`
	// que abre o man. Cinco caminhos, todos em configuração que o usuário
	// controla.
	"git": primExec, "hg": primExec, "svn": primExec,

	// Gerenciadores de pacote: executam script de mantenedor como root, e
	// aceitam hook em configuração (`APT::Update::Pre-Invoke`).
	"apt": primExec, "apt-get": primExec, "aptitude": primExec, "dpkg": primExec,
	"dnf": primExec, "yum": primExec, "rpm": primExec, "zypper": primExec,
	"pacman": primExec, "apk": primExec, "snap": primExec,

	// Gerenciadores de dependência de linguagem: script de instalação é
	// código do autor do pacote, rodando com o privilégio da regra.
	"pip": primExec, "pip3": primExec, "npm": primExec, "gem": primExec,
	"composer": primExec, "cargo": primExec, "go": primExec, "dotnet": primExec,
	"bundle": primExec,

	// Orquestração e agendamento: `crontab -e` abre o editor; `at` executa;
	// ansible executa por definição.
	"crontab": primExec, "at": primExec, "batch": primExec,
	"ansible": primExec, "ansible-playbook": primExec, "puppet": primExec,
	"salt-call": primExec,

	// systemd: `systemctl` sem pager configurado abre o `less`, e `systemctl
	// edit` abre o editor. O mesmo para journalctl.
	"systemctl": primExec, "journalctl": primExec, "machinectl": primExec,
	"loginctl": primExec, "busctl": primExec,

	// Runtime de contêiner: montar / no contêiner é o host.
	"docker": primExec, "podman": primExec, "ctr": primExec, "runc": primExec,
	"crictl": primExec, "lxc": primExec, "lxd": primExec, "nerdctl": primExec,

	// Clientes de banco com escape para o shell (`\!`, `.shell`, `!`).
	"mysql": primExec, "psql": primExec, "sqlite3": primExec, "mongo": primExec,

	// Multiplexadores: a sessão sobrevive, e dentro dela o privilégio também.
	"screen": primExec, "tmux": primExec,

	// Rede com script embutido.
	"nmap": primExec, "openssl": primExec, "openvpn": primExec, "fzf": primExec,

	// ── Escrita arbitrária ─────────────────────────────────────────────────
	// Escrever onde quiser, com privilégio de root, é root: uma linha em
	// /etc/sudoers, uma chave em /root/.ssh/authorized_keys, um arquivo em
	// /etc/cron.d. Nenhuma dessas ferramentas precisa de exploração.
	"dd": primEscrita, "tee": primEscrita, "cp": primEscrita, "mv": primEscrita,
	"install": primEscrita, "sed": primEscrita, "ln": primEscrita,
	"truncate": primEscrita, "debugfs": primEscrita, "dmsetup": primEscrita,
	"mount": primEscrita, "unzip": primEscrita, "gzip": primEscrita,
	"bzip2": primEscrita, "xz": primEscrita, "zstd": primEscrita,
	"cpio": primEscrita, "wget": primEscrita, "curl": primEscrita,

	// Mudar o metadado é escrever no que importa: `chmod u+s /bin/bash` é a
	// escalada inteira num comando, e `setcap` é a versão moderna dela.
	"chmod": primEscrita, "chown": primEscrita, "chgrp": primEscrita,
	"chattr": primEscrita, "setfacl": primEscrita, "setcap": primEscrita,

	// ── Leitura arbitrária ─────────────────────────────────────────────────
	// Entrega o /etc/shadow e as chaves privadas de /root. Não é root no ato,
	// e por isso pesa menos — mas `NOPASSWD: /bin/cat` sem argumento não é
	// menor privilégio coisa nenhuma.
	"cat": primLeitura, "head": primLeitura, "tail": primLeitura,
	"tac": primLeitura, "nl": primLeitura, "od": primLeitura, "xxd": primLeitura,
	"hexdump": primLeitura, "strings": primLeitura, "base64": primLeitura,
	"base32": primLeitura, "basenc": primLeitura, "cut": primLeitura,
	"sort": primLeitura, "uniq": primLeitura, "rev": primLeitura,
	"grep": primLeitura, "egrep": primLeitura, "fgrep": primLeitura,
	"diff": primLeitura, "cmp": primLeitura, "comm": primLeitura,
	"paste": primLeitura, "fold": primLeitura, "expand": primLeitura,
	"split": primLeitura, "csplit": primLeitura, "shuf": primLeitura,
	"column": primLeitura, "pr": primLeitura, "zcat": primLeitura,
}

// ehAliasDeComando reconhece um Cmnd_Alias do sudoers: ele é um NOME e não um
// caminho — maiúsculas, dígitos e sublinhado, sem barra nenhuma.
//
//	Cmnd_Alias PGCTL = /usr/bin/pg_ctl, /usr/bin/pg_ctlcluster
//	%dba ALL=(root) NOPASSWD: PGCTL
//
// A ferramenta NÃO resolve alias: o que PGCTL expande está em outra linha, e
// tratá-lo como binário produziria as duas respostas erradas — "não reconheço"
// soaria como absolvição, e casar por nome nunca casaria. Dizer que é alias, e
// mandar resolver com `sudo -l`, é a resposta honesta.
func ehAliasDeComando(tok string) bool {
	// `ALL` casa a forma de um alias e não é um: quem o lê é o regraAmpla, e o
	// ramo dele vem antes deste no switch. A guarda é redundante hoje e barata
	// — reordenar o switch amanhã não pode transformar "root irrestrito" em
	// "isto é um alias, resolva com sudo -l".
	if tok == "" || tok == "ALL" || strings.ContainsAny(tok, "/.") {
		return false
	}
	for _, r := range tok {
		if (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '_' {
			return false
		}
	}
	return true
}

// primitivaDoBinario responde pelo BASENAME, ignorando o ponto de um nome
// escondido — `/usr/local/bin/.tar` é `tar`.
func primitivaDoBinario(caminho string) classePrimitiva {
	b := strings.TrimPrefix(baseDe(caminho), ".")
	return primitivaDe[b]
}

// Comando é UM comando de uma especificação de sudoers ou doas, já separado do
// resto e já classificado.
type Comando struct {
	// Bin é o caminho como a regra o escreveu.
	Bin string
	// Classe é a primitiva conhecida, ou primNenhuma quando a tabela não
	// reconhece o nome — e aí a resposta é "não sei", não "não tem".
	Classe classePrimitiva

	// PresoPorArgumento diz que a regra fixou argumentos, e é o freio que
	// impede esta tabela de virar ruído.
	//
	// A semântica é do sudoers(5) e não é intuitiva:
	//
	//	/usr/bin/find            o usuário roda find com QUALQUER argumento
	//	/usr/bin/find ""         o usuário roda find SEM argumento nenhum
	//	/usr/bin/find /var/log   só com exatamente aquele argumento
	//
	// Ou seja: a regra que NÃO cita argumento é a mais ampla das três, e é
	// justamente a que parece mais restrita para quem lê depressa.
	PresoPorArgumento bool

	// Curinga marca a regra cujo ÚLTIMO token é um `*` sozinho — e só essa
	// forma, porque só ela devolve o que o argumento fixo tinha tirado:
	//
	//	/usr/bin/tar *                          REABRE: o usuário acrescenta
	//	                                        `--to-command=/bin/sh` e a regra
	//	                                        volta a valer o que valia sem
	//	                                        argumento nenhum
	//	/usr/bin/find /var/log -name '*.gz' -delete   NÃO reabre: o sudo casa a
	//	                                        linha inteira com fnmatch, e o
	//	                                        `-delete` literal DEPOIS do
	//	                                        curinga fecha o que ele abriu
	//
	// A primeira versão marcava qualquer `*` em qualquer posição, e teria
	// gritado CRÍTICO na segunda linha — que é uma regra de limpeza de log
	// perfeitamente comum. O sudoers(5) avisa sobre curinga em argumento
	// justamente na forma de cima.
	Curinga bool

	// CuringaNoMeio registra o curinga que NÃO reabre — o do meio da linha. Ele
	// não muda severidade e entra na nota: quem lê precisa saber que há um
	// curinga ali, porque a análise de fnmatch é sutil e o operador conhece a
	// regra melhor que a ferramenta.
	CuringaNoMeio bool
}

// Concede diz se este comando entrega execução ou escrita arbitrária a quem
// puder rodá-lo — ou seja, se chamar a regra de "menor privilégio" seria falso.
func (c Comando) Concede() bool {
	if c.Classe != primShell && c.Classe != primExec && c.Classe != primEscrita {
		return false
	}
	if !c.PresoPorArgumento || c.Curinga {
		return true
	}
	// Argumento fixado, sem curinga: o editor e o paginador ESCAPAM mesmo
	// assim — `sudo vim /etc/motd` continua sendo `:!sh`, e a regra parecia a
	// mais inocente do arquivo. Para o resto, o argumento é freio de verdade.
	//
	// O SHELL não entra nesta lista, e a razão é a semântica do sudo: a regra
	// `NOPASSWD: /bin/bash /opt/deploy/restart.sh` casa a linha de comando
	// INTEIRA, então quem a usa não consegue acrescentar `-c` nem trocar o
	// script. É o desenho de delegação mais comum que existe, e chamá-lo de
	// root irrestrito encheria de crítico toda frota que faz deploy assim.
	//
	// O que sobra dele é a nota (ver notaDePrisao): a rota volta se o script
	// apontado for gravável por quem tem a regra — e ESSA pergunta é do
	// priv.root_runs_writable, que já a responde com o inode na mão.
	return escapaMesmoPreso[strings.TrimPrefix(baseDe(c.Bin), ".")]
}

// escapaMesmoPreso são os binários cuja primitiva NÃO depende do argumento: ela
// mora no modo interativo, e abrir já basta. Fixar o arquivo que o vim edita
// não tira o `:!sh` dele.
var escapaMesmoPreso = map[string]bool{
	// Editores: `:!cmd`, `^R^X`, `M-!`. Abrir já basta, e qual arquivo abre
	// não muda nada.
	"vi": true, "vim": true, "vimdiff": true, "view": true, "rvim": true,
	"nvim": true, "ex": true, "nano": true, "pico": true, "emacs": true,
	"ed": true,
	// Paginadores: `!cmd`. O `man` conta porque ele ABRE um paginador.
	"less": true, "more": true, "most": true, "pg": true, "man": true,
	"w3m": true,
	// Sessão interativa de rede: `!cmd` dentro do prompt.
	"ftp": true, "sftp": true,
	// Depurador: o prompt tem `shell`, e ele aparece qualquer que seja o
	// binário depurado.
	"gdb": true,
	"fzf": true,

	// FICARAM DE FORA, e cada um por um motivo medido:
	//
	//	crontab   o escape é o `-e`, que é ARGUMENTO. `sudo crontab -l -u root`
	//	          não abre editor nenhum.
	//	mysql/psql/sqlite3   `-e`/`-c` os torna não interativos, e delegar UMA
	//	          consulta é desenho comum.
	//	screen/tmux   `screen -ls` não escapa; `tmux new-session` escapa. É o
	//	          argumento que decide, então o argumento fixado prende.
	//
	// Os quatro continuam disparando quando a regra NÃO fixa argumento, que é
	// quando a primitiva de fato está ao alcance.
}

// comandosDaSpec quebra a especificação de comando de uma regra nos comandos
// que ela concede, e classifica cada um.
//
// Ela existe porque a leitura anterior era `Fields(spec)[0]`: numa regra
// `NOPASSWD: /usr/bin/tar, /bin/bash` só o `tar` era olhado, e o `bash` — que
// é o caso CRÍTICO já implementado — sumia por estar depois de uma vírgula.
func comandosDaSpec(spec string) []Comando {
	var out []Comando
	for _, parte := range strings.Split(spec, ",") {
		campos := strings.Fields(parte)
		if len(campos) == 0 {
			continue
		}
		bin := campos[0]
		// ALL não é binário, e `!` nega em vez de conceder: os dois já são
		// lidos por regraAmpla e não têm primitiva.
		if bin == "ALL" || strings.HasPrefix(bin, "!") {
			continue
		}
		args := campos[1:]
		c := Comando{
			Bin:               bin,
			Classe:            primitivaDoBinario(bin),
			PresoPorArgumento: len(args) > 0,
		}
		for i, a := range args {
			if !strings.Contains(a, "*") {
				continue
			}
			// Só o ÚLTIMO token, e só quando ele é o curinga SOZINHO. Um `*`
			// colado num prefixo (`nginx*`) ainda obriga o começo; um `*` no
			// meio é fechado pelo literal que vem depois.
			if i == len(args)-1 && strings.Trim(a, `"'`) == "*" {
				c.Curinga = true
				continue
			}
			c.CuringaNoMeio = true
		}
		out = append(out, c)
	}
	return out
}

// As três predicadas recebem a lista JÁ DECODIFICADA, e não a spec: o
// chamador as invoca em sequência sobre a mesma regra, e cada uma refazia o
// `strings.Split` mais um `strings.Fields` por vírgula, alocando um
// `[]Comando` novo. Eram seis parses por linha de sudoers — quatro deles
// dentro do laço de classes do primitivaPresa, refazendo o mesmo trabalho a
// cada iteração.
//
// concedeExecucao devolve o primeiro comando da spec que entrega execução ou
// escrita arbitrária. É o substituto de `ehShellOuInterp`, que olhava dezesseis
// nomes e só o primeiro campo.
func concedeExecucao(cs []Comando) (Comando, bool) {
	// Shell primeiro, depois exec, depois escrita: quando a regra concede mais
	// de um, a evidência precisa citar o mais direto.
	for _, alvo := range []classePrimitiva{primShell, primExec, primEscrita} {
		for _, c := range cs {
			if c.Classe == alvo && c.Concede() {
				return c, true
			}
		}
	}
	return Comando{}, false
}

// concedeLeitura devolve o primeiro comando que entrega leitura arbitrária.
// Separado de concedeExecucao porque a conclusão é outra: lê o /etc/shadow, e
// isso é aviso, não root imediato.
func concedeLeitura(cs []Comando) (Comando, bool) {
	for _, c := range cs {
		if c.Classe == primLeitura && (!c.PresoPorArgumento || c.Curinga) {
			return c, true
		}
	}
	return Comando{}, false
}

// notaDeArgumento explica, na evidência, por que o argumento não segurou.
func (c Comando) notaDeArgumento() string {
	switch {
	case !c.PresoPorArgumento:
		return "e a regra NÃO fixa argumento: tanto no sudoers quanto no doas.conf " +
			"isso significa QUALQUER argumento — é a forma mais ampla das três, e a " +
			"que mais parece restrita para quem lê depressa"
	case c.Curinga:
		return "a regra fixa argumento, MAS há curinga (`*`): o curinga devolve o " +
			"que o argumento fixo tinha tirado, porque o usuário acrescenta o que " +
			"quiser onde ele está"
	default:
		return "a regra fixa argumento, e ainda assim a primitiva vale: ela mora no " +
			"modo interativo deste binário, e abrir já basta"
	}
}

// comandoDoDoas monta o Comando a partir de uma regra de doas já decodificada.
//
// O `args` do doas NÃO faz globbing — a comparação é literal, e por isso não há
// caso de curinga aqui. É a única diferença de leitura em relação ao sudoers,
// onde o `*` é expandido e reabre a regra.
func comandoDoDoas(cmd string, temArgs bool) Comando {
	// O parseDoas entrega o `cmd` como UM token, mas fixture de teste e regra
	// malformada aparecem com o comando inteiro no campo. Ler o primeiro campo
	// custa nada e evita que `python3 -c ...` deixe de casar com `python3`.
	campos := strings.Fields(cmd)
	if len(campos) == 0 {
		return Comando{}
	}
	return Comando{
		Bin:               campos[0],
		Classe:            primitivaDoBinario(campos[0]),
		PresoPorArgumento: temArgs || len(campos) > 1,
	}
}

// primitivaPresa devolve o comando cuja primitiva a tabela RECONHECE e que o
// argumento fixado segurou.
//
// Existe porque a primeira versão deste arquivo produziu, contra um sudoers de
// teste, exatamente o defeito que ele foi escrito para consertar:
//
//	NOPASSWD: /usr/bin/tar czf /backup/x.tgz /srv
//	  → "restrita a comando nomeado, que esta ferramenta NÃO reconhece
//	     como primitiva de escalada"
//
// A ferramenta reconhece o `tar` — reconhece tão bem que a linha de cima do
// mesmo relatório o chama de root irrestrito quando não há argumento. Dizer
// "não reconheço" ali é afirmar ignorância que não existe, e joga fora
// justamente a informação de que o operador precisa: o que segura esta regra é
// UMA string de argumento, e argumento é frágil.
func primitivaPresa(cs []Comando) (Comando, bool) {
	for _, alvo := range []classePrimitiva{primShell, primExec, primEscrita, primLeitura} {
		for _, c := range cs {
			if c.Classe == alvo && c.PresoPorArgumento && !c.Concede() {
				return c, true
			}
		}
	}
	return Comando{}, false
}

// notaDePrisao é a evidência do caso acima: o que a regra concede, e o que
// exatamente está segurando.
func (c Comando) notaDePrisao() []string {
	out := []string{
		"o binário `" + c.Bin + "` " + c.Classe.frase(),
		"MAS a regra fixa os argumentos, e é SÓ isso que a segura: o sudo compara " +
			"a linha de comando inteira, então a primitiva fica fora de alcance " +
			"enquanto ninguém acrescentar um curinga nem uma opção a esta linha",
		"o que vale conferir: se o argumento fixado contém caminho que o alvo " +
			"CONTROLA (um diretório gravável por ele), a primitiva volta por " +
			"dentro — o comando é o mesmo e o conteúdo é dele",
	}
	if c.CuringaNoMeio {
		out = append(out, "e HÁ curinga na linha, fora da última posição: o `*` do "+
			"sudoers é fnmatch sobre a linha inteira, e o literal que vem depois "+
			"dele fecha o que ele abriu. Esta ferramenta não simula o casamento — "+
			"leia a regra sabendo que o curinga está lá")
	}
	return out
}

// # A terceira porta do suid tem DUAS listas, e cada uma consertou um defeito
//
// A tabela acima responde "este binário devolve execução com privilégio
// emprestado?", e essa pergunta tem CONTEXTOS diferentes — é por isso que a
// GTFOBins separa `sudo` de `suid` em vez de ter uma coluna só. A primeira
// versão daqui colapsou os dois, e o resultado foi medido duas vezes:
//
//	no teste       `sudo`, `mount` e `pkexec` são setuid de fábrica em toda
//	               distribuição, e saíram como três CRITICAL
//	num host real  o `crontab` do Arch é setuid ROOT (o do Debian é setgid),
//	               e saiu como CRITICAL num desktop limpo
//
// As duas listas abaixo são o conserto, e a ordem entre elas importa:
//
//	viaSetuid         a primitiva funciona ATRAVÉS DO BIT. `sudo crontab -e`
//	                  abre um editor como root; `crontab` COM setuid não — ele
//	                  larga o privilégio antes de chamar o editor. Poder via
//	                  sudo não é poder via setuid, e tratá-los igual foi o erro.
//	setuidDeFabrica   dentro de viaSetuid, os que a distribuição ENTREGA com o
//	                  bit. `mount` e `pkexec` executam comando arbitrário E têm
//	                  o bit por desenho.
//
// A segunda é redundante com a primeira em quase todo nome, e é de propósito:
// um binário que amanhã entre em viaSetuid por engano ainda encontra a trava.

// viaSetuid é o subconjunto CONSERVADOR: os binários cujo bit setuid, sozinho,
// entrega a identidade do dono.
//
// Deliberadamente NÃO inclui `systemctl`, `apt-get`, `dnf`, `docker`, `npm`,
// `pip`, `git` de gerência, `crontab` nem `at`. Todos eles são primitiva de
// SUDO — o poder vem de quem os invoca —, e como setuid ou largam o privilégio
// ou dependem de configuração que o usuário real não controla como root.
// Deixá-los fora custa recall e compra o que uma ferramenta de triagem não pode
// perder: silêncio em host limpo.
var viaSetuid = map[string]bool{
	// Interpretador com o bit é o caso de manual.
	"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true,
	"ash": true, "csh": true, "tcsh": true, "fish": true, "busybox": true,
	"python": true, "python2": true, "python3": true, "perl": true,
	"ruby": true, "php": true, "node": true, "lua": true, "tclsh": true,
	"expect": true, "guile": true, "irb": true,
	"awk": true, "gawk": true, "mawk": true, "nawk": true,

	// Executam sem largar o privilégio efetivo.
	"find": true, "env": true, "xargs": true, "nohup": true, "timeout": true,
	"stdbuf": true, "setarch": true, "nice": true, "ionice": true,
	"taskset": true, "chrt": true, "flock": true, "watch": true, "script": true,
	"setsid": true, "unshare": true, "nsenter": true, "chroot": true,
	"capsh": true, "aa-exec": true, "make": true, "cmake": true, "gcc": true,
	"cc": true, "gdb": true, "strace": true, "ltrace": true, "perf": true,
	"bpftrace": true, "stap": true,

	// Editor e paginador: o escape mora no modo interativo.
	"vi": true, "vim": true, "nvim": true, "view": true, "rvim": true,
	"ex": true, "nano": true, "pico": true, "emacs": true, "ed": true,
	"less": true, "more": true, "most": true, "pg": true, "man": true,
	"w3m": true,

	// Arquivador e transferência com hook de execução.
	"tar": true, "cpio": true, "zip": true, "7z": true, "7za": true,
	"rsync": true, "socat": true, "nc": true, "ncat": true, "netcat": true,
	"nmap": true, "ftp": true, "sftp": true, "ssh": true, "scp": true,
	"telnet": true, "git": true,

	// Escrita arbitrária com o privilégio do dono.
	"dd": true, "tee": true, "cp": true, "mv": true, "install": true,
	"sed": true, "ln": true, "truncate": true, "debugfs": true,
	"dmsetup": true, "unzip": true, "gzip": true, "bzip2": true, "xz": true,
	"zstd": true, "wget": true, "curl": true,
	"chmod": true, "chown": true, "chgrp": true, "chattr": true,
	"setfacl": true, "setcap": true, "mount": true, "umount": true,

	// Escalada direta: entram para que setuidDeFabrica tenha o que absolver, e
	// para que um deles em lugar ERRADO (sem dono de pacote, ou em diretório
	// gravável) continue passando pelas outras duas portas.
	"sudo": true, "su": true, "doas": true, "pkexec": true,
}

// setuidDeFabrica é o conjunto que TEM o bit por desenho da distribuição — e é
// a trava final da terceira porta.
//
// Ela é consultada DEPOIS de viaSetuid, e existe porque as duas perguntas são
// diferentes: "o bit entrega privilégio?" e "a distribuição entrega o bit?".
// `mount` e `pkexec` respondem sim às duas.
//
// O teste que planta o conjunto inteiro está em primitiva_test.go, e ele é mais
// importante que o teste do achado: o defeito que mata uma ferramenta de
// triagem não é o que ela deixa de ver, é o que ela grita em todo lugar.
var setuidDeFabrica = map[string]bool{
	// Escalada e troca de identidade: é para isso que servem.
	"sudo": true, "sudoedit": true, "doas": true, "su": true, "newgrp": true,
	"pkexec": true, "polkit-agent-helper-1": true, "suexec": true,
	"newuidmap": true, "newgidmap": true,

	// Credencial: escrevem no /etc/shadow, que só root lê.
	"passwd": true, "chsh": true, "chfn": true, "gpasswd": true,
	"unix_chkpwd": true, "pam_timestamp_check": true, "chage": true,
	"expiry": true,

	// Montagem: o kernel exige privilégio, e o usuário monta o pendrive.
	"mount": true, "umount": true, "fusermount": true, "fusermount3": true,
	"ntfs-3g": true, "pmount": true, "pumount": true,
	"mount.nfs": true, "umount.nfs": true,

	// Socket cru: `ping` precisava de CAP_NET_RAW, e em distribuição antiga
	// isso era setuid. Na moderna é capability no xattr — que este mesmo check
	// lê por outro caminho.
	"ping": true, "ping6": true, "arping": true,
	"traceroute": true, "traceroute6": true, "mtr": true, "mtr-packet": true,

	// Agendamento e sessão. O `crontab` é o nome que veio de um HOST REAL: no
	// Arch ele é setuid ROOT e no Debian é setgid crontab, e uma lista escrita
	// olhando só para o Debian acusa todo desktop Arch do mundo.
	"crontab": true, "at": true, "batch": true,
	"screen": true, "wall": true, "write": true, "bsd-write": true,
	"sg": true, "utempter": true, "ssh-agent": true, "dotlockfile": true,
	"locate": true, "mlocate": true,

	// Infraestrutura de área de trabalho e de virtualização.
	"dbus-daemon-launch-helper": true, "ssh-keysign": true, "staprun": true,
	"snap-confine": true, "Xorg": true, "vmware-user-suid-wrapper": true,
}

// primitivaViaSetuid responde a pergunta da TERCEIRA PORTA: este bit, neste
// binário, entrega privilégio a quem o executar — e a distribuição não o
// entrega assim?
func primitivaViaSetuid(caminho string) bool {
	b := strings.TrimPrefix(baseDe(caminho), ".")
	return viaSetuid[b] && !setuidDeFabrica[b]
}
