package facts

import (
	"crypto/sha256"
	"encoding/base64"
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
}

func collectSSHConfig(f *Facts, e *env.Env) {
	arquivos := []string{"/etc/ssh/sshd_config"}
	// Include é o padrão nas distribuições atuais, e ignorá-lo faria a
	// ferramenta ler o arquivo principal e perder a configuração REAL.
	for _, n := range e.ReadDirNames("/etc/ssh/sshd_config.d") {
		if strings.HasSuffix(n, ".conf") {
			arquivos = append(arquivos, "/etc/ssh/sshd_config.d/"+n)
		}
	}

	c := &f.SSH
	for _, p := range arquivos {
		b, err := e.ReadFile(p)
		if err != nil {
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
