package facts

import (
	"encoding/base64"
	"strings"

	"github.com/lex0c/aletheia/internal/env"
)

// A OUTRA METADE DA HISTÓRIA DE SSH (runbook §7.5, §23).
//
// A ferramenta já lê `authorized_keys`, que responde quem ENTRA neste host. Ela
// não lia nada sobre o caminho inverso, e ele importa tanto quanto:
//
//	chave privada    para onde este host CONSEGUE ir
//	known_hosts      para onde este host JÁ foi
//
// Numa resposta a incidente as duas respondem a mesma pergunta por ângulos
// diferentes — o alcance. Um invasor que chegou aqui herda tudo que este host
// alcança, e dezenas de evidências desta ferramenta terminam em "procure a
// mesma coisa na frota (§23)" sem dizer QUAIS máquinas procurar.
//
// A chave privada tem um agravante próprio, e o velociraptor o nomeia bem: sem
// senha, o invasor a usa direto. Não precisa quebrar nada — é credencial de
// movimento lateral largada aberta.

// ChavePrivada é uma chave SSH privada encontrada em disco.
type ChavePrivada struct {
	Path string `json:"path"`
	Tipo string `json:"type,omitempty"`

	// Cifrada diz se a chave exige senha para ser usada. Sem ela, quem lê o
	// arquivo já pode usar a chave.
	Cifrada bool `json:"encrypted"`

	// DeHost marca a chave do próprio sshd. Elas são SEMPRE sem senha por
	// desenho — o daemon sobe sozinho no boot e não tem quem digite nada.
	DeHost bool `json:"host_key,omitempty"`

	ModUTC string `json:"mod_utc,omitempty"`
}

// DestinoConhecido é uma entrada de known_hosts: para onde este host já foi.
type DestinoConhecido struct {
	Arquivo string `json:"file"`
	Host    string `json:"host,omitempty"`

	// Hasheado marca a entrada que o OpenSSH gravou com o nome embaralhado
	// (HashKnownHosts). O destino não é recuperável, mas a CONTAGEM continua
	// dizendo o tamanho do alcance.
	Hasheado bool `json:"hashed,omitempty"`
}

func collectCredenciais(f *Facts, e *env.Env) {
	dirs := []string{"/etc/ssh"}
	for _, h := range homeDirs(e) {
		dirs = append(dirs, h+"/.ssh")
	}

	for _, d := range dirs {
		for _, n := range e.ReadDirNames(d) {
			p := d + "/" + n
			switch {
			case n == "known_hosts" || strings.HasPrefix(n, "known_hosts"):
				lerKnownHosts(f, e, p)
			case strings.HasSuffix(n, ".pub"), n == "authorized_keys", n == "config":
				// Chave pública, lista de autorizadas e config não são segredo:
				// as duas primeiras já têm check próprio.
			default:
				lerChavePrivada(f, e, p, d == "/etc/ssh")
			}
		}
	}
}

// cabecalhosDeChave são as formas em que uma chave privada se anuncia. A última
// já diz por si que está cifrada.
var cabecalhosDeChave = map[string]string{
	"-----BEGIN OPENSSH PRIVATE KEY-----":   "openssh",
	"-----BEGIN RSA PRIVATE KEY-----":       "rsa",
	"-----BEGIN DSA PRIVATE KEY-----":       "dsa",
	"-----BEGIN EC PRIVATE KEY-----":        "ec",
	"-----BEGIN PRIVATE KEY-----":           "pkcs8",
	"-----BEGIN ENCRYPTED PRIVATE KEY-----": "pkcs8-cifrada",
}

func lerChavePrivada(f *Facts, e *env.Env, p string, deEtcSSH bool) {
	fi, err := e.Lstat(p)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > 64*1024 {
		return
	}
	b, err := e.ReadFile(p)
	if err != nil {
		return
	}
	texto := string(b)

	var tipo string
	for cab, t := range cabecalhosDeChave {
		if strings.Contains(texto, cab) {
			tipo = t
			break
		}
	}
	if tipo == "" {
		return
	}

	c := ChavePrivada{
		Path: p, Tipo: tipo,
		Cifrada: chaveCifrada(texto, tipo),
		// Chave de HOST é sempre sem senha por desenho: o sshd sobe no boot e
		// não há quem digite. Marcá-las evita acusar toda instalação de SSH que
		// existe.
		DeHost: deEtcSSH && strings.Contains(p, "ssh_host_"),
	}
	if !fi.ModTime().IsZero() {
		c.ModUTC = fi.ModTime().UTC().Format("2006-01-02T15:04:05Z")
	}
	f.ChavesPrivadas = append(f.ChavesPrivadas, c)
}

// chaveCifrada diz se a chave exige senha, e cada formato responde de um jeito.
//
//	PEM clássico   cabeçalho `Proc-Type: 4,ENCRYPTED`
//	PKCS#8         o próprio cabeçalho diz ENCRYPTED
//	OpenSSH novo   o corpo em base64 traz o nome da cifra, e `none` é sem senha
//
// O terceiro é o formato padrão desde 2018 e o único que exige decodificar: sem
// isso, toda chave moderna sairia como "sem senha" ou como "com senha",
// dependendo do palpite — e as duas respostas erradas são piores que nenhuma.
func chaveCifrada(texto, tipo string) bool {
	if tipo == "pkcs8-cifrada" {
		return true
	}
	if strings.Contains(texto, "Proc-Type: 4,ENCRYPTED") ||
		strings.Contains(texto, "DEK-Info:") {
		return true
	}
	if tipo != "openssh" {
		return false
	}

	corpo := entreLinhas(texto,
		"-----BEGIN OPENSSH PRIVATE KEY-----",
		"-----END OPENSSH PRIVATE KEY-----")
	bin, err := base64.StdEncoding.DecodeString(corpo)
	if err != nil {
		// Não decodificou: dizer "sem senha" seria inventar. A ausência de
		// resposta é tratada como cifrada, que é a leitura conservadora — o
		// erro nessa direção cala um achado; na outra, acusa uma chave que
		// pede senha.
		return true
	}

	// openssh-key-v1\0 seguido de uma string de tamanho prefixado: o nome da
	// cifra.
	const magia = "openssh-key-v1\x00"
	if len(bin) < len(magia)+4 || string(bin[:len(magia)]) != magia {
		return true
	}
	r := bin[len(magia):]
	n := int(uint32(r[0])<<24 | uint32(r[1])<<16 | uint32(r[2])<<8 | uint32(r[3]))
	if n <= 0 || len(r) < 4+n {
		return true
	}
	return string(r[4:4+n]) != "none"
}

// entreLinhas devolve o corpo base64 entre os dois marcadores, sem quebras.
func entreLinhas(texto, ini, fim string) string {
	i := strings.Index(texto, ini)
	if i < 0 {
		return ""
	}
	resto := texto[i+len(ini):]
	j := strings.Index(resto, fim)
	if j < 0 {
		return ""
	}
	var b strings.Builder
	for _, ln := range strings.Split(resto[:j], "\n") {
		b.WriteString(strings.TrimSpace(ln))
	}
	return b.String()
}

func lerKnownHosts(f *Facts, e *env.Env, p string) {
	b, err := e.ReadFile(p)
	if err != nil {
		return
	}
	for _, ln := range strings.Split(string(b), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		campos := strings.Fields(ln)
		if len(campos) < 2 {
			continue
		}
		d := DestinoConhecido{Arquivo: p, Host: campos[0]}
		// `|1|salt|hash` é a forma embaralhada. O destino não volta, mas a
		// contagem continua dizendo o tamanho do alcance.
		if strings.HasPrefix(campos[0], "|") {
			d.Hasheado = true
			d.Host = ""
		}
		f.Destinos = append(f.Destinos, d)
	}
}
