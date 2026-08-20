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
	collectSSHConfig(f, e)
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
	Directive string `json:"directive"` // ProxyCommand | LocalCommand | Match exec
	Command   string `json:"command"`
	ModUTC    string `json:"mod_utc,omitempty"`
}

// diretivaExecCliente reconhece a diretiva de execução numa linha de config de
// cliente e devolve (rótulo, comando). O ProxyCommand com `none` e o
// PermitLocalCommand não executam nada por si — o primeiro é o "desligado"
// explícito, o segundo é só a permissão. Match é tratado à parte porque o
// comando fica entre aspas depois de `exec`.
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
	}
	return "", "", false
}

// matchExec extrai o comando de uma linha `Match ... exec "cmd" ...`. O critério
// `exec` roda um comando para decidir se o bloco vale, então ele executa em toda
// invocação do ssh que chega até ali — é a forma mais silenciosa das três.
func matchExec(v string) (string, bool) {
	campos := strings.Fields(v)
	for i, c := range campos {
		if !strings.EqualFold(c, "exec") {
			continue
		}
		resto := strings.TrimSpace(strings.Join(campos[i+1:], " "))
		if resto == "" {
			return "", false
		}
		// exec "cmd com espaço" ou exec cmd — o sshd aceita as duas formas.
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

// collectSSHClientConfig lê o config do CLIENTE: o de sistema (/etc/ssh/ssh_config
// e ssh_config.d) e o de cada usuário (~/.ssh/config). Só o que EXECUTA entra —
// o resto do config de cliente não é sinal de comprometimento.
//
// LocalCommand só roda com `PermitLocalCommand yes`, e por isso a permissão é
// rastreada por arquivo: sem ela, um LocalCommand é inerte e vira ruído se
// acusado. ProxyCommand e Match exec executam sem depender de outra diretiva.
func collectSSHClientConfig(f *Facts, e *env.Env) {
	sistema := []string{"/etc/ssh/ssh_config"}
	for _, n := range f.listarNegando(e, "ssh", "/etc/ssh/ssh_config.d") {
		if strings.HasSuffix(n, ".conf") {
			sistema = append(sistema, "/etc/ssh/ssh_config.d/"+n)
		}
	}
	for _, p := range sistema {
		if b, ok := f.lerNegando(e, "ssh", p); ok {
			parseClientConfig(f, e, p, "", b)
		}
	}

	for _, home := range homeDirs(e) {
		u := home[strings.LastIndexByte(home, '/')+1:]
		p := home + "/.ssh/config"
		b, err := e.ReadFile(p)
		if err != nil {
			continue
		}
		parseClientConfig(f, e, p, u, b)
	}
}

// parseClientConfig varre um arquivo de config de cliente e stampa o mtime. A
// varredura em si é pura (analisaConfigCliente), para ser testável sem env — a
// mesma razão do ParseAuthorizedKeyParaTeste.
func parseClientConfig(f *Facts, e *env.Env, arquivo, user string, b []byte) {
	f.SSHClientExec = append(f.SSHClientExec,
		analisaConfigCliente(arquivo, user, modUTC(e, arquivo), b)...)
}

// AnalisaConfigClienteParaTeste expõe o parser puro do config de cliente.
func AnalisaConfigClienteParaTeste(arquivo, user string, b []byte) []SSHClientExec {
	return analisaConfigCliente(arquivo, user, "", b)
}

// analisaConfigCliente é o parser PURO. `PermitLocalCommand yes` habilita o
// LocalCommand DAQUELE arquivo em diante — o sshd o lê por arquivo, e um
// LocalCommand sem a permissão não executa.
func analisaConfigCliente(arquivo, user, mod string, b []byte) []SSHClientExec {
	var out []SSHClientExec
	permiteLocal := false
	for i, raw := range strings.Split(string(b), "\n") {
		ln := strings.TrimSpace(raw)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		k, v, ok := strings.Cut(ln, " ")
		if !ok {
			if k, v, ok = strings.Cut(ln, "\t"); !ok {
				k, v = ln, ""
			}
		}
		v = strings.TrimSpace(v)

		if strings.EqualFold(k, "permitlocalcommand") {
			permiteLocal = strings.EqualFold(v, "yes")
			continue
		}
		if strings.EqualFold(k, "match") {
			if cmd, ok := matchExec(v); ok {
				out = append(out, SSHClientExec{
					File: arquivo, User: user, Line: i + 1,
					Directive: "Match exec", Command: cmd, ModUTC: mod,
				})
			}
			continue
		}
		rotulo, cmd, ok := diretivaExecCliente(k, v)
		if !ok {
			continue
		}
		// LocalCommand inerte sem a permissão: não é execução, não é achado.
		if rotulo == "LocalCommand" && !permiteLocal {
			continue
		}
		out = append(out, SSHClientExec{
			File: arquivo, User: user, Line: i + 1,
			Directive: rotulo, Command: cmd, ModUTC: mod,
		})
	}
	return out
}

// maxArquivosSSH limita a cadeia de Include. Um ciclo já é barrado por
// `vistos`; o teto é contra a expansão explosiva de globs encadeados.
const maxArquivosSSH = 64

// expandirIncludeSSH resolve o alvo de um Include. Caminho relativo é relativo
// a /etc/ssh, como o sshd faz, e o glob é expandido pelo diretório — sem
// filepath.Glob, que resolveria fora da raiz travada em modo image.
func expandirIncludeSSH(e *env.Env, padrao string) []string {
	if !strings.HasPrefix(padrao, "/") {
		padrao = "/etc/ssh/" + padrao
	}
	if !strings.ContainsAny(padrao, "*?[") {
		return []string{padrao}
	}
	dir, base := path.Split(padrao)
	dir = strings.TrimSuffix(dir, "/")
	if strings.ContainsAny(dir, "*?[") {
		return nil // glob no DIRETÓRIO: fora do que o sshd aceita
	}
	var out []string
	for _, n := range e.ReadDirNames(dir) {
		if ok, err := path.Match(base, n); err == nil && ok {
			out = append(out, dir+"/"+n)
		}
	}
	sort.Strings(out) // o sshd aplica em ordem lexicográfica
	return out
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
			continue
		}
		c.Files = append(c.Files, p)
		for _, raw := range strings.Split(string(b), "\n") {
			ln := strings.TrimSpace(raw)
			if ln == "" || strings.HasPrefix(ln, "#") {
				continue
			}
			k, v, ok := strings.Cut(ln, " ")
			if !ok {
				if k, v, ok = strings.Cut(ln, "\t"); !ok {
					continue
				}
			}
			v = strings.TrimSpace(v)
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
					arquivos = append(arquivos, expandirIncludeSSH(e, campo)...)
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
}

func setSeVazio(dst *string, v string) {
	if *dst == "" {
		*dst = v
	}
}

func collectAuthorizedKeys(f *Facts, e *env.Env) {
	type alvo struct{ user, path string }
	var alvos []alvo

	for _, home := range homeDirs(e) {
		u := home[strings.LastIndexByte(home, '/')+1:]
		for _, n := range []string{"authorized_keys", "authorized_keys2"} {
			alvos = append(alvos, alvo{u, home + "/.ssh/" + n})
		}
	}
	// AuthorizedKeysFile fora do padrão: o caminho com %u por usuário.
	if p := f.SSH.AuthorizedKeysFile; p != "" && strings.HasPrefix(p, "/") {
		for _, home := range homeDirs(e) {
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
			if _, negado := lookup(e, a.path); negado {
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
