package facts

import (
	"crypto/sha256"
	"encoding/base64"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/lex0c/aletheia/internal/env"
)

// SSH (runbook §7.5).
//
// Lido de arquivo, não de `sshd -T`: o binário do host é justamente o que pode
// estar adulterado, e a leitura de arquivo funciona sobre imagem montada.
//
// O preço dessa escolha está declarado: `sshd -T` resolve Match blocks e
// defaults compilados, e a leitura de arquivo não. O que se ganha é ver o que
// está ESCRITO — que é o que alguém plantou.

// SSHKey é uma linha de authorized_keys já separada.
//
//	[opções] <tipo> <chave base64> <comentário>
type SSHKey struct {
	File string `json:"file"`
	User string `json:"user,omitempty"`
	Line int    `json:"line"`

	// Options no início: raro em uso normal. `command="..."` executa algo a
	// CADA login — é backdoor com gatilho (runbook §7.5).
	Options string `json:"options,omitempty"`
	Type    string `json:"type,omitempty"`

	// Fingerprint é o SHA-256 no formato que o ssh-keygen imprime. É o IOC de
	// frota: a mesma chave em vários hosts é a mesma pessoa.
	Fingerprint string `json:"fingerprint,omitempty"`

	// Comment costuma ser user@host de quem GEROU a chave. Um comentário
	// estranho é o nome da máquina do atacante — IOC de graça.
	Comment string `json:"comment,omitempty"`

	ModUTC string `json:"mod_utc,omitempty"`
}

// SSHConfig são as diretivas do sshd que decidem QUEM entra e COMO.
type SSHConfig struct {
	Files []string `json:"files,omitempty"`

	// AuthorizedKeysFile fora do padrão esconde a chave do ~/.ssh que todo
	// mundo olha (runbook §7.5).
	AuthorizedKeysFile string `json:"authorized_keys_file,omitempty"`

	// AuthorizedKeysCommand faz o sshd PERGUNTAR a um programa quais chaves
	// valem. É persistência que não deixa chave em arquivo nenhum (§7.12).
	AuthorizedKeysCommand     string `json:"authorized_keys_command,omitempty"`
	AuthorizedKeysCommandUser string `json:"authorized_keys_command_user,omitempty"`

	PermitRootLogin        string   `json:"permit_root_login,omitempty"`
	PasswordAuthentication string   `json:"password_authentication,omitempty"`
	Ports                  []string `json:"ports,omitempty"`
}

func collectSSH(f *Facts, e *env.Env) {
	// OTIMISMO COM DESMENTIDO: as três fontes são dadas por completas, e cada
	// falha de leitura desmarca a SUA. É o padrão que o sudoers e o doas já
	// usam, e ele existe porque marcar em cada ponto de saída à mão é um a
	// esquecer.
	f.SSHServerCompleto = true
	f.SSHChavesCompleto = true
	f.SSHClienteCompleto = true
	collectSSHConfig(f, e)
	f.SSHServerColetado = true
	collectAuthorizedKeys(f, e)
	collectSSHClientConfig(f, e)
}

// SSHClientExec é uma diretiva do config do CLIENTE ssh que EXECUTA um comando —
// no fluxo de conexão, não de login. É a persistência de usuário que o inventário
// do sshd (chaves, ForceCommand) não alcança: quem controla `~/.ssh/config` roda
// código toda vez que a vítima dá `ssh`, sem tocar em nada com dono root.
//
//	ProxyCommand      roda o comando para ABRIR o transporte da conexão
//	LocalCommand      roda o comando LOCAL ao conectar (só com PermitLocalCommand)
//	Match exec        roda o comando para DECIDIR se o bloco Match se aplica —
//	                  e isso acontece a CADA invocação do ssh que casa o Host
type SSHClientExec struct {
	File      string `json:"file"`
	User      string `json:"user,omitempty"` // dono do config; "" = de sistema
	Line      int    `json:"line"`
	Directive string `json:"directive"` // ProxyCommand | LocalCommand | Match exec | KnownHostsCommand
	Command   string `json:"command" redact:"linha"`
	// Ativacao só vale para LocalCommand, que exige PermitLocalCommand yes para
	// rodar. "confirmada" = a permissão está no config; "não confirmada" = a
	// permissão não apareceu (o padrão é `no`), mas o binário ainda pode ser
	// chamado com `ssh -o PermitLocalCommand=yes`. Nunca se DESCARTA o
	// LocalCommand por isto — some-lo seria falso negativo; a incerteza vai para
	// a evidência.
	Ativacao string `json:"activation,omitempty"`

	// Escopo é o bloco `Host`/`Match` a que a diretiva pertence, normalizado —
	// `Host *` quando ela está fora de qualquer bloco.
	//
	// Sem ele, dois ProxyCommand em blocos diferentes do mesmo arquivo são
	// indistinguíveis, e trocar os destinos entre si (prod↔dev) mantinha o
	// CONJUNTO de comandos e invertia o comportamento por destino sem produzir
	// mudança nenhuma para quem compara dois retratos.
	Escopo string `json:"scope,omitempty"`

	ModUTC string `json:"mod_utc,omitempty"`
}

// cortaDiretiva separa `keyword valor`. O OpenSSH aceita o separador como
// ESPAÇO, TAB ou `=`, com ou sem branco em volta do `=` — e `Proxy​Command=/x` é
// evasão trivial se só se corta por espaço.
func cortaDiretiva(ln string) (string, string) {
	i := strings.IndexAny(ln, " \t=")
	if i < 0 {
		return ln, ""
	}
	k := ln[:i]
	v := strings.TrimLeft(ln[i:], " \t")
	if strings.HasPrefix(v, "=") {
		v = strings.TrimLeft(v[1:], " \t")
	}
	return k, strings.TrimSpace(v)
}

// diretivaExecCliente reconhece a diretiva de execução numa linha de config de
// cliente e devolve (rótulo, comando). ProxyCommand, LocalCommand e
// KnownHostsCommand executam um programa; o `none` do ProxyCommand e o
// PermitLocalCommand não. Match é tratado à parte (o comando fica depois de
// `exec`).
func diretivaExecCliente(k, v string) (string, string, bool) {
	switch strings.ToLower(k) {
	case "proxycommand":
		if v == "" || strings.EqualFold(v, "none") {
			return "", "", false
		}
		return "ProxyCommand", v, true
	case "localcommand":
		if v == "" {
			return "", "", false
		}
		return "LocalCommand", v, true
	case "knownhostscommand":
		// O ssh roda este comando para OBTER host keys, possivelmente várias
		// vezes por conexão. Mesma superfície de execução que o ProxyCommand, e
		// executa sem depender de outra diretiva.
		if v == "" || strings.EqualFold(v, "none") {
			return "", "", false
		}
		return "KnownHostsCommand", v, true
	}
	return "", "", false
}

// matchExec extrai o comando de uma linha `Match ... exec "cmd" ...`. O critério
// `exec` roda um comando para decidir se o bloco vale, então ele executa em toda
// invocação do ssh que chega até ali — é a forma mais silenciosa das três. O
// NEGADO `!exec "cmd"` também roda o comando (para saber se negar), então conta
// igual.
func matchExec(v string) (string, bool) {
	campos := strings.Fields(v)
	for i, c := range campos {
		if !strings.EqualFold(c, "exec") && !strings.EqualFold(c, "!exec") {
			continue
		}
		resto := strings.TrimSpace(strings.Join(campos[i+1:], " "))
		if resto == "" {
			return "", false
		}
		// exec "cmd com espaço" ou exec cmd — o ssh aceita as duas formas.
		if resto[0] == '"' {
			if fim := strings.IndexByte(resto[1:], '"'); fim >= 0 {
				return resto[1 : 1+fim], true
			}
			return resto[1:], true
		}
		return campos[i+1], true
	}
	return "", false
}

// dirCliente é uma diretiva crua de config de cliente, com a fonte (arquivo e
// linha) preservada — o achado precisa apontar para o arquivo INCLUÍDO certo, não
// para o que fez o Include.
type dirCliente struct {
	File, Kw, Val, Mod string
	Line               int
}

// collectSSHClientConfig lê o config do CLIENTE, SEGUINDO Include, e emite só o
// que EXECUTA. O de sistema (/etc/ssh/ssh_config e o que ele incluir) e o de
// cada usuário (~/.ssh/config e o que ele incluir).
//
// O ssh_config.d NÃO é varrido incondicionalmente: só entra se o config
// principal o INCLUIR — senão o ssh não o lê, e acusá-lo transformaria config
// inerte em achado. É a via Include que o traz.
//
// LocalCommand só roda com PermitLocalCommand yes. As duas são parâmetros
// INDEPENDENTES (o valor efetivo é o PRIMEIRO obtido, em qualquer ordem e em
// qualquer arquivo do escopo), então a permissão é resolvida por ESCOPO —
// escopo do usuário mais o de sistema —, não sequencialmente. E um LocalCommand
// sem a permissão confirmada NÃO é descartado: some-lo seria falso negativo.
func collectSSHClientConfig(f *Facts, e *env.Env) {
	var sysDirs []dirCliente
	coletaDirsCliente(f, e, "/etc/ssh/ssh_config", "/etc/ssh", "", map[string]bool{}, &sysDirs, 0)
	sysPermit := temPermitLocalYes(sysDirs)
	f.SSHClientExec = append(f.SSHClientExec, execDeDirs(sysDirs, "", sysPermit)...)

	for _, home := range homeDirs(f, e, "ssh") {
		u := home[strings.LastIndexByte(home, '/')+1:]
		var dirs []dirCliente
		coletaDirsCliente(f, e, home+"/.ssh/config", home+"/.ssh", home, map[string]bool{}, &dirs, 0)
		// A permissão do usuário OU a de sistema habilita o LocalCommand dele.
		f.SSHClientExec = append(f.SSHClientExec,
			execDeDirs(dirs, u, temPermitLocalYes(dirs) || sysPermit)...)
	}
}

// coletaDirsCliente varre um arquivo seguindo Include e acumula as diretivas
// cruas. baseDir resolve Include relativo (~/.ssh para usuário, /etc/ssh para
// sistema, como o ssh faz); home expande o `~`. Config ilegível (não ausente)
// vira LACUNA declarada — a diferença entre "não há config" e "não pude ler".
func coletaDirsCliente(f *Facts, e *env.Env, arquivo, baseDir, home string, vistos map[string]bool, out *[]dirCliente, prof int) {
	if prof > maxArquivosSSH {
		// Teto atingido: o resto da cadeia NÃO foi lido, e sair calado aqui
		// transformava "parei de olhar" em "não há mais nada". Um ProxyCommand
		// no arquivo 66 da cadeia simplesmente não existiria.
		f.SSHClienteCompleto = false
		f.denyPersist("ssh", "a cadeia de Include do cliente SSH passou de "+
			strconv.Itoa(maxArquivosSSH)+" arquivos em "+arquivo+" e foi cortada "+
			"no teto: a config de cliente além dele NÃO foi lida")
		return
	}
	if vistos[arquivo] {
		// Já lido: Include circular ou diamante. Não é lacuna — o conteúdo
		// entrou na varredura na primeira visita.
		return
	}
	vistos[arquivo] = true
	b, err := e.ReadFile(arquivo)
	if err != nil {
		if env.EhLacuna(err) {
			f.SSHClienteCompleto = false
			f.denyPersist("ssh", arquivo+" não pôde ser lido ("+env.MotivoDoErro(err)+
				"): config de cliente NÃO entrou na varredura")
		}
		return
	}
	mod := modUTC(e, arquivo)
	for i, raw := range strings.Split(string(b), "\n") {
		ln := strings.TrimSpace(raw)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		k, v := cortaDiretiva(ln)
		if strings.EqualFold(k, "include") {
			for _, campo := range strings.Fields(v) {
				for _, inc := range expandirIncludeCliente(f, e, baseDir, home, campo) {
					coletaDirsCliente(f, e, inc, baseDir, home, vistos, out, prof+1)
				}
			}
			continue
		}
		*out = append(*out, dirCliente{File: arquivo, Line: i + 1, Kw: k, Val: v, Mod: mod})
	}
}

// expandirIncludeCliente resolve o alvo de um Include de cliente. `~/` vira o
// home; relativo é sob baseDir; o glob é expandido COMPONENTE A COMPONENTE (sem
// filepath.Glob, que fugiria da raiz travada em modo image).
//
// O GLOB VALE EM QUALQUER COMPONENTE, e supor o contrário era um ponto cego.
// A versão anterior recusava padrão com curinga no diretório, com o comentário
// "fora do que o ssh aceita" — e isso é FALSO. Medido contra o OpenSSH 9.2:
//
//	Include ~/.ssh/profiles/*/ops.conf   ->  ssh -G aplica o ProxyCommand de lá
//
// Pior que o ponto cego era a forma dele: o `return nil` saía calado, sem
// lacuna, então um ProxyCommand plantado um nível abaixo simplesmente não
// existia para esta ferramenta.
func expandirIncludeCliente(f *Facts, e *env.Env, baseDir, home, padrao string) []string {
	p := padrao
	switch {
	case strings.HasPrefix(p, "~/") && home != "":
		p = home + p[1:]
	case !strings.HasPrefix(p, "/"):
		p = baseDir + "/" + p
	}
	// A flag é a do CLIENTE: esta função expande Include de ssh_config, não de
	// sshd_config. Derrubar a do servidor fazia as duas pontas errarem de uma
	// vez — o ssh.cliente_exec seguia acreditando que o conjunto era exaustivo
	// DEPOIS de truncá-lo, e a comparação do sshd era degradada sem nada ter
	// acontecido com ela.
	return expandirGlobSSH(e, p, func(motivo string) {
		f.SSHClienteCompleto = false
		f.denyPersist("ssh", "o Include `"+padrao+"` do cliente: "+motivo)
	})
}

// expandirGlobSSH é a expansão COMPONENTE A COMPONENTE, e é uma só para o
// cliente e para o servidor.
//
// Duas coisas justificam a função compartilhada, e as duas foram defeito:
//
//	O GLOB VALE EM QUALQUER COMPONENTE. O sshd_config(5) diz que cada pathname
//	de Include pode conter curinga de glob(7), sem restringi-lo ao último
//	componente — e o lado do SERVIDOR recusava padrão com curinga no diretório,
//	com um comentário afirmando o contrário. Um `Include
//	/etc/ssh/profiles/*/sshd.conf` virava `nil` calado.
//
//	LISTAGEM QUE FALHA NÃO É DIRETÓRIO VAZIO. Os dois lados usavam
//	ReadDirNames, que engole o erro por desenho — o comentário dele diz, com
//	todas as letras, para não usá-lo onde a diferença decide cobertura. Um
//	diretório de perfis sem permissão dava zero matches e o conjunto seguia
//	"completo".
//
// `degradar` é como a fonte de quem chama paga por isso: ela desmarca o fato de
// completude DELA e declara a lacuna. A função não sabe — nem precisa saber —
// se está expandindo config de cliente ou de servidor.
func expandirGlobSSH(e *env.Env, p string, degradar func(motivo string)) []string {
	if !strings.ContainsAny(p, "*?[") {
		return []string{p}
	}
	// Caminha os componentes mantendo o conjunto de diretórios que casaram até
	// aqui. Componente sem curinga só concatena; com curinga, lista e filtra.
	atuais := []string{""}
	comps := strings.Split(strings.TrimPrefix(p, "/"), "/")
	for i, comp := range comps {
		if comp == "" {
			continue
		}
		var prox []string
		for _, base := range atuais {
			if !strings.ContainsAny(comp, "*?[") {
				prox = append(prox, base+"/"+comp)
				continue
			}
			nomes, err := e.ReadDirNamesErr(base + "/")
			if env.EhLacuna(err) {
				degradar(base + "/ não pôde ser listado (" + env.MotivoDoErro(err) +
					"): os arquivos de configuração que o curinga alcançaria ali " +
					"NÃO foram lidos")
				continue
			}
			for _, n := range nomes {
				if ok, err := path.Match(comp, n); err == nil && ok {
					prox = append(prox, base+"/"+n)
				}
			}
		}
		// TETO GLOBAL, e ele é por QUANTIDADE — o teto anterior era só de
		// profundidade de Include, e um único `*` pode abrir milhares de
		// caminhos. Estourar vira lacuna declarada, nunca silêncio.
		if len(prox) > maxExpansaoInclude {
			degradar("expandiu para mais de " + strconv.Itoa(maxExpansaoInclude) +
				" caminhos no componente " + strconv.Itoa(i+1) + ": a expansão foi " +
				"cortada e os arquivos restantes NÃO foram lidos")
			prox = prox[:maxExpansaoInclude]
		}
		atuais = prox
		if len(atuais) == 0 {
			return nil
		}
	}
	sort.Strings(atuais) // o ssh e o sshd aplicam em ordem lexicográfica
	return atuais
}

// maxExpansaoInclude limita quantos caminhos um único Include pode abrir.
const maxExpansaoInclude = 512

func temPermitLocalYes(dirs []dirCliente) bool {
	for _, d := range dirs {
		if strings.EqualFold(d.Kw, "permitlocalcommand") && strings.EqualFold(d.Val, "yes") {
			return true
		}
	}
	return false
}

// execDeDirs filtra as diretivas que EXECUTAM e as converte em SSHClientExec. O
// LocalCommand carrega a ativação resolvida; ProxyCommand, KnownHostsCommand e
// Match exec executam sem depender de outra diretiva.
func execDeDirs(dirs []dirCliente, user string, permitLocal bool) []SSHClientExec {
	var out []SSHClientExec
	// O BLOCO A QUE A DIRETIVA PERTENCE. Um `ProxyCommand` sob `Host prod` e
	// outro sob `Host dev` são coisas DIFERENTES, e sem este contexto os dois
	// ficavam indistinguíveis para quem compara dois retratos: trocar os
	// destinos entre si mantinha o conjunto de comandos e invertia o
	// comportamento por destino, sem produzir mudança nenhuma.
	//
	// O escopo vale a partir da linha do bloco até o próximo — é assim que o
	// ssh_config funciona, e por isso ele é rastreado em ORDEM.
	escopo := "Host *"
	for _, d := range dirs {
		if strings.EqualFold(d.Kw, "host") {
			escopo = "Host " + strings.Join(strings.Fields(d.Val), " ")
			continue
		}
		if strings.EqualFold(d.Kw, "match") {
			escopo = "Match " + strings.Join(strings.Fields(d.Val), " ")
			if cmd, ok := matchExec(d.Val); ok {
				out = append(out, SSHClientExec{
					File: d.File, User: user, Line: d.Line, Escopo: escopo,
					Directive: "Match exec", Command: cmd, ModUTC: d.Mod,
				})
			}
			continue
		}
		rotulo, cmd, ok := diretivaExecCliente(d.Kw, d.Val)
		if !ok {
			continue
		}
		s := SSHClientExec{
			File: d.File, User: user, Line: d.Line, Escopo: escopo,
			Directive: rotulo, Command: cmd, ModUTC: d.Mod,
		}
		if rotulo == "LocalCommand" {
			s.Ativacao = "não confirmada"
			if permitLocal {
				s.Ativacao = "confirmada"
			}
		}
		out = append(out, s)
	}
	return out
}

// AnalisaConfigClienteParaTeste expõe o parser puro de UM blob (sem seguir
// Include), como o ParseAuthorizedKeyParaTeste. A ativação do LocalCommand é
// resolvida pelo próprio blob.
func AnalisaConfigClienteParaTeste(arquivo, user string, b []byte) []SSHClientExec {
	var dirs []dirCliente
	for i, raw := range strings.Split(string(b), "\n") {
		ln := strings.TrimSpace(raw)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		k, v := cortaDiretiva(ln)
		if strings.EqualFold(k, "include") {
			continue
		}
		dirs = append(dirs, dirCliente{File: arquivo, Line: i + 1, Kw: k, Val: v})
	}
	return execDeDirs(dirs, user, temPermitLocalYes(dirs))
}

// maxArquivosSSH limita a cadeia de Include. Um ciclo já é barrado por
// `vistos`; o teto é contra a expansão explosiva de globs encadeados.
const maxArquivosSSH = 64

// expandirIncludeSSH resolve o alvo de um Include do SERVIDOR. Caminho relativo
// é relativo a /etc/ssh, como o sshd faz.
//
// A expansão é a mesma do cliente — ver expandirGlobSSH, e ver ali os dois
// defeitos que motivaram unificá-las.
func expandirIncludeSSH(f *Facts, e *env.Env, padrao string) []string {
	if !strings.HasPrefix(padrao, "/") {
		padrao = "/etc/ssh/" + padrao
	}
	return expandirGlobSSH(e, padrao, func(motivo string) {
		f.SSHServerCompleto = false
		f.denyPersist("ssh", "o Include `"+padrao+"` do sshd: "+motivo)
	})
}

func collectSSHConfig(f *Facts, e *env.Env) {
	arquivos := []string{"/etc/ssh/sshd_config"}
	// Include é o padrão nas distribuições atuais, e ignorá-lo faria a
	// ferramenta ler o arquivo principal e perder a configuração REAL.
	for _, n := range f.listarNegando(e, "ssh", "/etc/ssh/sshd_config.d") {
		if strings.HasSuffix(n, ".conf") {
			arquivos = append(arquivos, "/etc/ssh/sshd_config.d/"+n)
		}
	}

	c := &f.SSH
	// Índice, não `range`: o laço APPENDA nos próprios `arquivos` ao seguir um
	// Include, e `range` congela o comprimento na entrada.
	vistos := map[string]bool{}
	for i := 0; i < len(arquivos) && i < maxArquivosSSH; i++ {
		p := arquivos[i]
		if vistos[p] {
			continue // Include circular: A inclui B que inclui A
		}
		vistos[p] = true
		// Ilegível é o oposto de ausente. O sshd_config é 0600 em host
		// endurecido, e um `continue` mudo aqui esvaziava c.Files — que é
		// exatamente o mesmo estado de "esta máquina não tem servidor SSH".
		// O relatório calava sobre PermitRootLogin de um host que aceita
		// login de root.
		b, ok := f.lerNegando(e, "ssh", p)
		if !ok {
			f.SSHServerCompleto = false
			continue
		}
		c.Files = append(c.Files, p)
		for _, raw := range strings.Split(string(b), "\n") {
			ln := strings.TrimSpace(raw)
			if ln == "" || strings.HasPrefix(ln, "#") {
				continue
			}
			// cortaDiretiva, e não Cut por espaço/TAB: o sshd aceita o
			// separador como `=` também, e cortar só por branco fazia
			// `PermitRootLogin=yes`, `AuthorizedKeysCommand=/tmp/.k` e
			// `Include=/etc/ssh/x.conf` caírem no continue — descartados sem
			// lacuna, com o relatório imprimindo o padrão do sshd como se fosse
			// o efetivo. O comentário de cortaDiretiva já chamava isso de
			// "evasão trivial"; o lado do SERVIDOR é que não a usava.
			if strings.IndexAny(ln, " \t=") < 0 {
				continue // linha sem separador: não é `keyword valor`
			}
			k, v := cortaDiretiva(ln)
			// Include REDIRECIONA a configuração para outro arquivo, e quem
			// escolhe o caminho é quem escreve o sshd_config. Ler só o
			// diretório fixo da distribuição cobria o caso de fábrica e deixava
			// o buraco: um `Include /etc/ssh/extra.conf` na primeira linha leva
			// junto PermitRootLogin e AuthorizedKeysFile, e como no sshd vence a
			// PRIMEIRA ocorrência, o relatório imprimia o valor do arquivo
			// principal como se fosse o efetivo. Pior, collectAuthorizedKeys
			// depende de c.AuthorizedKeysFile para saber onde procurar chave —
			// o arquivo de chaves real também não era lido, sem lacuna.
			if strings.EqualFold(k, "include") {
				for _, campo := range strings.Fields(v) {
					arquivos = append(arquivos, expandirIncludeSSH(f, e, campo)...)
				}
				continue
			}
			// A PRIMEIRA ocorrência vence no sshd. Sobrescrever com a última
			// reportaria uma configuração que não é a efetiva.
			switch strings.ToLower(k) {
			case "authorizedkeysfile":
				setSeVazio(&c.AuthorizedKeysFile, v)
			case "authorizedkeyscommand":
				setSeVazio(&c.AuthorizedKeysCommand, v)
			case "authorizedkeyscommanduser":
				setSeVazio(&c.AuthorizedKeysCommandUser, v)
			case "permitrootlogin":
				setSeVazio(&c.PermitRootLogin, v)
			case "passwordauthentication":
				setSeVazio(&c.PasswordAuthentication, v)
			case "port":
				c.Ports = append(c.Ports, v)
			}
		}
	}
	// O TETO DO LAÇO ACIMA, dito em voz alta.
	//
	// `arquivos` nasce com o sshd_config e o sshd_config.d, e CRESCE aqui
	// dentro a cada Include seguido — então a conferência fica depois do laço,
	// onde a lista final é conhecida. Parar no teto sem declarar nada era o
	// mesmo defeito do lado do cliente: um `AuthorizedKeysCommand` no arquivo
	// 65 saía como se não existisse, e a comparação do sshd continuava
	// afirmando que o conjunto estava inteiro.
	if len(arquivos) > maxArquivosSSH {
		f.SSHServerCompleto = false
		f.denyPersist("ssh", "a cadeia de Include do sshd passou de "+
			strconv.Itoa(maxArquivosSSH)+" arquivos e foi cortada no teto: as "+
			"diretivas declaradas além dele NÃO foram lidas")
	}
}

func setSeVazio(dst *string, v string) {
	if *dst == "" {
		*dst = v
	}
}

func collectAuthorizedKeys(f *Facts, e *env.Env) {
	type alvo struct{ user, path string }
	var alvos []alvo

	for _, home := range homeDirs(f, e, "ssh") {
		u := home[strings.LastIndexByte(home, '/')+1:]
		for _, n := range []string{"authorized_keys", "authorized_keys2"} {
			alvos = append(alvos, alvo{u, home + "/.ssh/" + n})
		}
	}
	// AuthorizedKeysFile fora do padrão: o caminho com %u por usuário.
	if p := f.SSH.AuthorizedKeysFile; p != "" && strings.HasPrefix(p, "/") {
		for _, home := range homeDirs(f, e, "ssh") {
			u := home[strings.LastIndexByte(home, '/')+1:]
			alvos = append(alvos, alvo{u, strings.NewReplacer(
				"%u", u, "%h", home, "%%", "%").Replace(p)})
		}
	}

	visto := map[string]bool{}
	var negados []string
	for _, a := range alvos {
		if visto[a.path] {
			continue
		}
		visto[a.path] = true

		b, err := e.ReadFile(a.path)
		if err != nil {
			// A NEGATIVA VEM DO ERRO DE LEITURA, e não de um Lstat à parte.
			//
			// O `lookup` responde por STAT, e stat de arquivo 0600 de outro
			// usuário SUCEDE quando os diretórios do caminho são atravessáveis
			// — que é o caso comum de /home/x/.ssh 0755. O read falhava com
			// EACCES, o lookup dizia "existe e não é negado", e o arquivo saía
			// da varredura em SILÊNCIO: SSHChavesCompleto continuava verdadeiro
			// sobre um authorized_keys que ninguém leu.
			if env.EhLacuna(err) {
				negados = append(negados, a.path)
			}
			continue
		}
		mod := modUTC(e, a.path)
		for i, raw := range strings.Split(string(b), "\n") {
			ln := strings.TrimSpace(raw)
			if ln == "" || strings.HasPrefix(ln, "#") {
				continue
			}
			k := parseAuthorizedKey(ln)
			k.File, k.User, k.Line, k.ModUTC = a.path, a.user, i+1, mod
			f.SSHKeys = append(f.SSHKeys, k)
		}
	}
	if len(negados) > 0 {
		f.SSHChavesCompleto = false
		f.denyPersist("ssh", strconv.Itoa(len(negados))+
			" arquivos authorized_keys não puderam ser lidos (permissão): "+
			resumoCaminhos(negados))
	}
}

// ParseAuthorizedKeyParaTeste expõe o parsing de uma linha. Mesma razão do
// cron: é função pura, e é onde o formato morde.
func ParseAuthorizedKeyParaTeste(ln string) SSHKey { return parseAuthorizedKey(ln) }

// parseAuthorizedKey separa opções, tipo, chave e comentário.
//
// A dificuldade é que as OPÇÕES vêm antes do tipo, são separadas por vírgula e
// podem conter espaço dentro de aspas — `command="/bin/x -a b",no-pty`. Cortar
// por espaço perderia metade da opção, que é justamente onde mora o gatilho.
func parseAuthorizedKey(ln string) SSHKey {
	var k SSHKey
	rest := ln

	// Se o primeiro campo não parece um tipo de chave, é bloco de opções.
	if primeiro, _, _ := strings.Cut(ln, " "); !pareceTipoDeChave(primeiro) {
		fim := fimDasOpcoes(ln)
		if fim <= 0 {
			return k
		}
		k.Options = strings.TrimSpace(ln[:fim])
		rest = strings.TrimSpace(ln[fim:])
	}

	tipo, r, ok := strings.Cut(rest, " ")
	if !ok {
		return k
	}
	k.Type = tipo
	blob, coment, _ := strings.Cut(strings.TrimSpace(r), " ")
	k.Comment = strings.TrimSpace(coment)
	k.Fingerprint = FingerprintSSH(blob)
	return k
}

// fimDasOpcoes acha onde o bloco de opções termina, respeitando aspas.
func fimDasOpcoes(ln string) int {
	emAspas := false
	for i := 0; i < len(ln); i++ {
		switch ln[i] {
		case '"':
			emAspas = !emAspas
		case ' ', '\t':
			if !emAspas {
				return i
			}
		}
	}
	return -1
}

func pareceTipoDeChave(s string) bool {
	return strings.HasPrefix(s, "ssh-") || strings.HasPrefix(s, "ecdsa-") ||
		strings.HasPrefix(s, "sk-")
}

// fingerprintSSH devolve o SHA-256 no formato que o ssh-keygen imprime.
// É o IOC de frota: a mesma chave em vários hosts é a mesma pessoa, e isso vale
// mais que hash de binário (runbook §23).
// FingerprintSSH é exportada porque o casamento por indicador (--ioc) precisa
// derivar a impressão digital da chave que o operador colou, e derivá-la em
// dois lugares faria as duas divergirem no dia em que o formato mudasse.
func FingerprintSSH(blob string) string {
	raw, err := base64.StdEncoding.DecodeString(blob)
	if err != nil || len(raw) == 0 {
		return ""
	}
	sum := sha256.Sum256(raw)
	return "SHA256:" + strings.TrimRight(base64.StdEncoding.EncodeToString(sum[:]), "=")
}
