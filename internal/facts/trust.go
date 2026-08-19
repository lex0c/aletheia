package facts

import (
	"crypto/x509"
	"encoding/pem"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/lex0c/aletheia/internal/env"
)

// Confiança do host (runbook §7.12).
//
// Duas coisas que, JUNTAS, formam um MITM completo e silencioso: o nome resolve
// para o atacante, e o certificado dele é aceito. Nenhuma ferramenta reclama —
// não há erro de TLS, não há processo estranho, não há porta aberta.
//
// Por isso as duas moram no mesmo arquivo: separá-las esconderia que o valor
// está na combinação.

// CACert é uma âncora de confiança instalada no host.
type CACert struct {
	File    string `json:"file"`
	Subject string `json:"subject,omitempty"`
	Issuer  string `json:"issuer,omitempty"`

	// AutoAssinado marca a CA raiz: emissor igual ao titular. É a forma de uma
	// CA plantada, e também a de toda CA raiz legítima — o que separa é quem
	// ela diz ser.
	AutoAssinado bool   `json:"self_signed,omitempty"`
	NotBefore    string `json:"not_before,omitempty"`
	NotAfter     string `json:"not_after,omitempty"`
	ModUTC       string `json:"mod_utc,omitempty"`
	Erro         string `json:"err,omitempty"`
}

// HostEntry é uma linha de /etc/hosts já resolvida.
type HostEntry struct {
	IP    string   `json:"ip"`
	Names []string `json:"names"`
	Line  int      `json:"line"`

	// Scope classifica o destino: um nome público apontando para IP público é
	// a forma do redirecionamento.
	Scope Scope `json:"scope,omitempty"`
}

// Resolver é a configuração de resolução de nome.
type Resolver struct {
	Nameservers []string `json:"nameservers,omitempty"`
	File        string   `json:"file,omitempty"`
	ModUTC      string   `json:"mod_utc,omitempty"`
	HostsModUTC string   `json:"hosts_mod_utc,omitempty"`
}

// caDirs são os diretórios em que o administrador acrescenta âncora de
// confiança. Os certificados do SISTEMA ficam em outro lugar e vêm de pacote —
// olhar aqui é olhar o que ALGUÉM instalou.
var caDirs = []string{
	"/usr/local/share/ca-certificates",
	"/etc/pki/ca-trust/source/anchors",
	"/etc/ca-certificates/trust-source/anchors",
}

func collectTrust(f *Facts, e *env.Env) {
	for _, dir := range caDirs {
		// ReadDir e NÃO ReadDirNames: um diretório de âncoras que não LISTA
		// (permissão) não é "nenhuma CA extra" — é evidência perdida. Vira
		// lacuna declarada; não-existe (o host não usa esse layout) não é lacuna.
		ents, err := e.ReadDir(dir)
		if err != nil {
			if env.EhLacuna(err) {
				f.denyPersist("trust", "o diretório de âncoras de confiança "+dir+
					" não pôde ser LISTADO (permissão): uma CA plantada ali NÃO foi "+
					"vista — e uma CA raiz sozinha já dá MITM de todo o TLS")
			}
			continue
		}
		for _, ent := range ents {
			p := dir + "/" + ent.Name()
			if e.IsDir(p) {
				continue
			}
			f.CACerts = append(f.CACerts, lerCA(e, p))
		}
	}
	collectHosts(f, e)
	collectResolver(f, e)
}

// lerCA decodifica o certificado. O parsing é NATIVO: chamar openssl seria
// depender de binário do host, e o que se quer saber aqui é quem o host passou
// a confiar.
func lerCA(e *env.Env, p string) CACert {
	c := CACert{File: p, ModUTC: modUTC(e, p)}
	b, err := e.ReadFile(p)
	if err != nil {
		c.Erro = err.Error()
		return c
	}
	bloco, _ := pem.Decode(b)
	if bloco == nil {
		c.Erro = "não é PEM"
		return c
	}
	cert, err := x509.ParseCertificate(bloco.Bytes)
	if err != nil {
		c.Erro = err.Error()
		return c
	}
	c.Subject = cert.Subject.String()
	c.Issuer = cert.Issuer.String()
	c.AutoAssinado = c.Subject == c.Issuer
	c.NotBefore = cert.NotBefore.UTC().Format(time.RFC3339)
	c.NotAfter = cert.NotAfter.UTC().Format(time.RFC3339)
	return c
}

func collectHosts(f *Facts, e *env.Env) {
	f.Resolver.HostsModUTC = modUTC(e, "/etc/hosts")
	b, err := e.ReadFile("/etc/hosts")
	if err != nil {
		if env.EhLacuna(err) {
			f.denyPersist("trust", "/etc/hosts não pôde ser lido ("+env.MotivoDoErro(err)+
				"): um redirecionamento de domínio de atualização plantado ali NÃO "+
				"foi avaliado")
		}
		return
	}
	for i, raw := range strings.Split(string(b), "\n") {
		ln := strings.TrimSpace(raw)
		if i := strings.IndexByte(ln, '#'); i >= 0 {
			ln = strings.TrimSpace(ln[:i])
		}
		campos := strings.Fields(ln)
		if len(campos) < 2 {
			continue
		}
		f.Hosts = append(f.Hosts, HostEntry{
			IP: campos[0], Names: campos[1:], Line: i + 1,
			Scope: scopeOf(campos[0]),
		})
	}
}

func collectResolver(f *Facts, e *env.Env) {
	for _, p := range []string{"/etc/resolv.conf", "/etc/systemd/resolved.conf"} {
		b, err := e.ReadFile(p)
		if err != nil {
			if env.EhLacuna(err) {
				f.denyPersist("trust", p+" não pôde ser lido ("+env.MotivoDoErro(err)+
					"): o servidor DNS configurado NÃO foi avaliado")
			}
			continue
		}
		if f.Resolver.File == "" {
			f.Resolver.File, f.Resolver.ModUTC = p, modUTC(e, p)
		}
		for _, raw := range strings.Split(string(b), "\n") {
			ln := strings.TrimSpace(raw)
			if ln == "" || strings.HasPrefix(ln, "#") || strings.HasPrefix(ln, ";") {
				continue
			}
			k, v, ok := strings.Cut(ln, "=")
			if !ok {
				k, v, ok = strings.Cut(ln, " ")
			}
			if !ok || !strings.EqualFold(strings.TrimSpace(k), "nameserver") &&
				!strings.EqualFold(strings.TrimSpace(k), "dns") {
				continue
			}
			for _, ns := range strings.Fields(v) {
				if net.ParseIP(ns) != nil {
					f.Resolver.Nameservers = append(f.Resolver.Nameservers, ns)
				}
			}
		}
	}
}

// --- hooks de git (runbook §7.12) ---
//
// Servidor que atualiza por `git pull` executa hook em TODO deploy: é
// persistência que sobrevive ao redeploy e não mora em /etc.

const (
	// Teto da varredura por hooks. É a primeira busca em ÁRVORE do coletor, e
	// por isso tem orçamento: estourar vira cobertura parcial DECLARADA, nunca
	// corte silencioso.
	//
	// O número saiu de medição: 400 diretórios custam ~45ms de coleta, 2000
	// custam ~150ms. O orçamento do `wtf` é 2s, então 150ms compra cobertura
	// barata.
	//
	// O que decide mais que o teto é a ORDEM. As raízes de deploy vêm primeiro,
	// então um home de estação de trabalho com mil repositórios nunca deixa
	// /srv e /var/www de fora — que é onde a §7.12 diz que o hook importa.
	maxGitDirs  = 2000
	maxGitDepth = 6
)

var gitRoots = []string{"/srv", "/opt", "/var/www", "/data", "/usr/share/nginx"}

func collectGitHooks(f *Facts, e *env.Env) {
	raizes := append([]string{}, gitRoots...)
	raizes = append(raizes, homeDirs(e)...)

	vistos := 0
	truncado := false
	ilegivel := 0
	for _, raiz := range raizes {
		procurarHooks(f, e, raiz, 0, &vistos, &truncado, &ilegivel)
	}
	if truncado {
		f.denyPersist("githook", "a busca por hooks de git parou (limite de "+
			strconv.Itoa(maxGitDirs)+" diretórios ou orçamento de tempo do wtf): "+
			"o excedente NÃO foi avaliado")
	}
	if ilegivel > 0 {
		f.denyPersist("githook", strconv.Itoa(ilegivel)+" diretório(s) sob as "+
			"árvores de repositório não puderam ser LISTADOS (permissão): um repo "+
			"ou hook ali NÃO foi procurado")
	}
	declararIgnore(f, e, "githook")
}

func procurarHooks(f *Facts, e *env.Env, dir string, prof int, vistos *int, truncado *bool, ilegivel *int) {
	e.Detalhe(dir)
	if prof > maxGitDepth || *truncado {
		return
	}
	// Mesmo prazo da varredura de SUID: no wtf a busca para quando o orçamento
	// acaba, e o que faltou vira lacuna em vez de "nenhum hook".
	if e.WalkExpired() {
		*truncado = true
		return
	}
	if *vistos >= maxGitDirs {
		*truncado = true
		return
	}
	*vistos++

	// ReadDir e NÃO ReadDirNames: um diretório que não LISTA vira "nenhum
	// repo/hook aqui" em silêncio. Ilegível é lacuna declarada; não-existe não é.
	ents, err := e.ReadDir(dir)
	if err != nil {
		if env.EhLacuna(err) {
			*ilegivel++
		}
		return
	}
	for _, ent := range ents {
		n := ent.Name()
		p := dir + "/" + n
		// --ignore ANTES de qualquer stat (IsDir), como no scanner de código.
		if e.Ignorado(p) {
			continue
		}
		if !e.IsDir(p) {
			continue
		}
		if n == ".git" {
			f.Repos = append(f.Repos, dir)
			lerHooks(f, e, p+"/hooks")
			continue
		}
		// Não desce em árvore que só gera ruído e profundidade.
		if n == "node_modules" || n == "vendor" || n == ".cache" {
			continue
		}
		procurarHooks(f, e, p, prof+1, vistos, truncado, ilegivel)
	}
}

func lerHooks(f *Facts, e *env.Env, dir string) {
	for _, n := range e.ReadDirNames(dir) {
		// Os .sample vêm com o git e não executam.
		if strings.HasSuffix(n, ".sample") {
			continue
		}
		p := dir + "/" + n
		if t, ok := lerTrigger(e, p, "git_hook",
			"a cada operação de git — sobrevive ao redeploy e não mora em /etc", ""); ok {
			f.Triggers = append(f.Triggers, t)
		}
	}
}

// ConfiancaDeHost é uma entrada de confiança HOST-BASED — .rhosts, .shosts,
// /etc/hosts.equiv, /etc/shosts.equiv (runbook §7.12, ATT&CK T1021.004).
//
// É a forma mais antiga de acesso sem senha que existe no Unix, e continua
// viva: um host listado num destes arquivos entra COMO O DONO do arquivo, sem
// autenticar. Um `+` sozinho é o pior — confia em QUALQUER host e QUALQUER
// usuário. Em sistema moderno esses arquivos quase nunca são legítimos, e é
// essa raridade que dá valor ao sinal.
//
// Não é gatilho (não executa nada), é AUTENTICAÇÃO: por isso mora aqui, ao lado
// da CA plantada e do /etc/hosts, e não em Triggers.
type ConfiancaDeHost struct {
	// Path é o arquivo; Escopo diz se ele vale para um usuário (o dono) ou para
	// o host inteiro (hosts.equiv).
	Path   string `json:"path"`
	Escopo string `json:"scope"` // "usuario" | "sistema"
	Conta  string `json:"account,omitempty"`

	// Curinga marca a presença de um `+` — confiança IRRESTRITA. É o que
	// transforma o achado de "confie neste host" em "confie em qualquer um".
	Curinga bool `json:"wildcard,omitempty"`
	// Linhas são as entradas não-comentário: os hosts (ou host+usuário)
	// confiados. Curtas por natureza; guardadas inteiras.
	Linhas []string `json:"entries,omitempty"`

	// Gravavel diz que grupo ou outros podem ESCREVER no arquivo — qualquer um
	// acrescenta um host de confiança. O rlogind recusa .rhosts gravável por
	// grupo/outros, mas o fato de existir gravável já é anomalia.
	Gravavel bool   `json:"group_or_world_writable,omitempty"`
	Modo     string `json:"mode,omitempty"`
	ModUTC   string `json:"mod_utc,omitempty"`
}

// arquivosDeConfiancaDeSistema: caminho fixo, valem para o host inteiro.
var arquivosDeConfiancaDeSistema = []string{"/etc/hosts.equiv", "/etc/shosts.equiv"}

// arquivosDeConfiancaDeHome: relativos ao home de cada conta.
var arquivosDeConfiancaDeHome = []string{".rhosts", ".shosts"}

// collectConfiancaDeHost lê os arquivos de confiança host-based.
func collectConfiancaDeHost(f *Facts, e *env.Env) {
	for _, p := range arquivosDeConfiancaDeSistema {
		if c, ok := lerConfiancaDeHost(e, p, "sistema", ""); ok {
			f.ConfiancaDeHost = append(f.ConfiancaDeHost, c)
		} else if _, negado := lookup(e, p); negado {
			f.denyPersist("trust", p+" existe e não pôde ser lido: uma confiança "+
				"host-based (login sem senha) plantada ali NÃO foi avaliada")
		}
	}
	for _, home := range homeDirs(e) {
		conta := home[strings.LastIndexByte(home, '/')+1:]
		for _, rel := range arquivosDeConfiancaDeHome {
			p := home + "/" + rel
			if c, ok := lerConfiancaDeHost(e, p, "usuario", conta); ok {
				f.ConfiancaDeHost = append(f.ConfiancaDeHost, c)
			} else if _, negado := lookup(e, p); negado {
				f.denyPersist("trust", p+" existe e não pôde ser lido: a confiança "+
					"host-based da conta "+conta+" NÃO foi avaliada")
			}
		}
	}
}

func lerConfiancaDeHost(e *env.Env, p, escopo, conta string) (ConfiancaDeHost, bool) {
	fi, err := e.Lstat(p)
	if err != nil {
		return ConfiancaDeHost{}, false
	}
	c := ConfiancaDeHost{Path: p, Escopo: escopo, Conta: conta,
		Modo:   fi.Mode().Perm().String(),
		ModUTC: fi.ModTime().UTC().Format(time.RFC3339),
		// Gravável por grupo (0o020) ou por outros (0o002).
		Gravavel: fi.Mode().Perm()&0o022 != 0,
	}
	b, err := e.ReadFile(p)
	if err != nil {
		return c, true // existe; ilegível é tratado pelo chamador via lookup
	}
	for _, ln := range strings.Split(string(b), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		// Um `+` como PRIMEIRO token de qualquer linha é curinga de host; um `+`
		// no SEGUNDO token é curinga de usuário. Os dois são confiança
		// irrestrita — basta o token isolado.
		for _, tok := range strings.Fields(ln) {
			if tok == "+" {
				c.Curinga = true
				break
			}
		}
		c.Linhas = append(c.Linhas, ln)
	}
	return c, true
}
