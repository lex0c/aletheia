package facts

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
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
	AutoAssinado bool `json:"self_signed,omitempty"`

	// O DN NÃO IDENTIFICA UMA ÂNCORA DE CONFIANÇA: ele é texto que quem emite
	// escolhe, e dois certificados com o mesmo `CN=Company Root CA` podem
	// carregar CHAVES DIFERENTES. Para o host, isso é trocar a autoridade
	// inteira; para qualquer comparação que olhasse só Subject/Issuer, nada
	// mudou.
	//
	//	Fingerprint  é ESTE certificado, byte a byte. Muda numa renovação.
	//	SPKI         é a CHAVE que ele carrega. NÃO muda numa renovação, e é
	//	             por isso que ele responde "a autoridade continua a mesma?".
	Fingerprint string `json:"fingerprint,omitempty"`
	SPKI        string `json:"spki,omitempty"`

	NotBefore string `json:"not_before,omitempty"`
	NotAfter  string `json:"not_after,omitempty"`
	ModUTC    string `json:"mod_utc,omitempty"`
	Erro      string `json:"err,omitempty"`
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
	// Quatro fontes, quatro fatos — ver o comentário em facts.go. A chave
	// `trust` continua declarando a lacuna para o operador; o que ela não pode
	// fazer é servir de dependência para as quatro famílias ao mesmo tempo.
	f.CACertsCompleto = true
	f.HostsLido = true
	f.ResolverLido = true
	f.HostTrustCompleto = true

	for _, dir := range caDirs {
		// ReadDir e NÃO ReadDirNames: um diretório de âncoras que não LISTA
		// (permissão) não é "nenhuma CA extra" — é evidência perdida. Vira
		// lacuna declarada; não-existe (o host não usa esse layout) não é lacuna.
		ents, err := e.ReadDir(dir)
		if err != nil {
			if env.EhLacuna(err) {
				f.CACertsCompleto = false
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
			c, ilegivel := lerCA(e, p)
			if ilegivel {
				// ARQUIVO LISTADO E NÃO LIDO é lacuna, e não estado.
				//
				// A entrada entra na lista assim mesmo — sumir com ela faria a
				// âncora parecer REMOVIDA —, mas com Subject/Issuer vazios ela
				// não pode alimentar a comparação: `emissor` e `auto_assinado`
				// decidem, e o vazio deles viraria "a autoridade mudou".
				// Certificado LIDO e inválido é outra coisa: aquilo é estado
				// real do host, e continua sendo comparado.
				f.CACertsCompleto = false
				f.denyPersist("trust", "a âncora de confiança "+p+" foi listada e "+
					"NÃO pôde ser lida ("+c.Erro+"): o que ela autoriza NÃO foi "+
					"examinado")
			}
			f.CACerts = append(f.CACerts, c)
		}
	}
	collectHosts(f, e)
	collectResolver(f, e)
}

// lerCA decodifica o certificado e diz se ele ficou ILEGÍVEL. O parsing é
// NATIVO: chamar openssl seria depender de binário do host, e o que se quer
// saber aqui é quem o host passou a confiar.
//
// Ilegível é diferente de inválido, e a diferença é a regra central desta
// ferramenta.
//
//	não pôde ser lido   LACUNA: ninguém sabe o que aquele arquivo autoriza
//	lido e não é PEM    ESTADO: o host tem um arquivo estranho no diretório de
//	                    âncoras, e isso é fato comparável
//
// Enquanto as duas saíam iguais — um CACert com Erro e nada mais —, um
// certificado que virasse ilegível entre dois retratos aparecia como emissor
// que sumiu e auto_assinado que virou falso: um drift de CONFIANÇA inventado,
// no lugar exato onde um falso positivo custa mais caro.
func lerCA(e *env.Env, p string) (CACert, bool) {
	c := CACert{File: p, ModUTC: modUTC(e, p)}
	b, err := e.ReadFile(p)
	if err != nil {
		c.Erro = env.MotivoDoErro(err)
		return c, env.EhLacuna(err)
	}
	bloco, _ := pem.Decode(b)
	if bloco == nil {
		c.Erro = "não é PEM"
		return c, false
	}
	cert, err := x509.ParseCertificate(bloco.Bytes)
	if err != nil {
		c.Erro = err.Error()
		return c, false
	}
	c.Subject = cert.Subject.String()
	c.Issuer = cert.Issuer.String()
	c.AutoAssinado = c.Subject == c.Issuer
	c.NotBefore = cert.NotBefore.UTC().Format(time.RFC3339)
	c.NotAfter = cert.NotAfter.UTC().Format(time.RFC3339)
	// O DN NÃO IDENTIFICA UMA ÂNCORA DE CONFIANÇA — ele é texto que quem emite
	// escolhe. Dois certificados com `CN=Company Root CA` de um lado e do outro
	// podem ter CHAVES DIFERENTES, e para o host isso é trocar a autoridade
	// inteira. Sem estes dois campos, substituir o arquivo por um self-signed de
	// mesmo Subject/Issuer não mudava nada que qualquer comparação olhasse.
	//
	//	Fingerprint  é ESTE certificado, byte a byte. Muda numa renovação.
	//	SPKI         é a CHAVE que ele carrega. NÃO muda numa renovação, e é
	//	             por isso que ele responde "a autoridade é a mesma?" —
	//	             a pergunta que interessa.
	soma := sha256.Sum256(cert.Raw)
	c.Fingerprint = "SHA256:" + hex.EncodeToString(soma[:])
	if der, err := x509.MarshalPKIXPublicKey(cert.PublicKey); err == nil {
		k := sha256.Sum256(der)
		c.SPKI = "SHA256:" + hex.EncodeToString(k[:])
	}
	return c, false
}

func collectHosts(f *Facts, e *env.Env) {
	f.Resolver.HostsModUTC = modUTC(e, "/etc/hosts")
	b, err := e.ReadFile("/etc/hosts")
	if err != nil {
		if env.EhLacuna(err) {
			f.HostsLido = false
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
				f.ResolverLido = false
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
	nomes, err := e.ReadDirNamesErr(dir)
	if env.EhLacuna(err) {
		// Categoria "githook", não "trust": persist.trigger_exec herda
		// PersistDenied["githook"], e uma lacuna gravada em "trust" existiria no
		// agregado mas sumiria da cobertura do check que depende dela.
		f.denyPersist("githook", dir+" não pôde ser listado ("+env.MotivoDoErro(err)+
			"): os git hooks — que rodam a cada operação de git e sobrevivem ao "+
			"redeploy — NÃO foram avaliados")
		return
	}
	for _, n := range nomes {
		// Os .sample vêm com o git e não executam.
		if strings.HasSuffix(n, ".sample") {
			continue
		}
		p := dir + "/" + n
		if t, ok := lerTrigger(e, p, "git_hook",
			"a cada operação de git — sobrevive ao redeploy e não mora em /etc", ""); ok {
			if t.Ilegvel {
				f.denyPersist("githook", p+" existe e não pôde ser LIDO: um git hook "+
					"plantado ali — que roda a cada operação de git — NÃO foi avaliado")
			}
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
		c, existe, ilegivel := lerConfiancaDeHost(e, p, "sistema", "")
		if ilegivel {
			f.HostTrustCompleto = false
			f.denyPersist("trust", p+" existe e não pôde ser LIDO: uma confiança "+
				"host-based (login sem senha, inclusive `+` irrestrito) plantada ali "+
				"NÃO foi avaliada")
			continue
		}
		if existe {
			f.ConfiancaDeHost = append(f.ConfiancaDeHost, c)
		}
	}
	for _, home := range homeDirs(e) {
		conta := home[strings.LastIndexByte(home, '/')+1:]
		for _, rel := range arquivosDeConfiancaDeHome {
			p := home + "/" + rel
			c, existe, ilegivel := lerConfiancaDeHost(e, p, "usuario", conta)
			if ilegivel {
				f.HostTrustCompleto = false
				f.denyPersist("trust", p+" existe e não pôde ser LIDO: a confiança "+
					"host-based da conta "+conta+" (login sem senha) NÃO foi avaliada")
				continue
			}
			if existe {
				f.ConfiancaDeHost = append(f.ConfiancaDeHost, c)
			}
		}
	}
}

func lerConfiancaDeHost(e *env.Env, p, escopo, conta string) (r ConfiancaDeHost, existe, ilegivel bool) {
	fi, err := e.Lstat(p)
	if err != nil {
		return ConfiancaDeHost{}, false, false
	}
	c := ConfiancaDeHost{Path: p, Escopo: escopo, Conta: conta,
		Modo:   fi.Mode().Perm().String(),
		ModUTC: fi.ModTime().UTC().Format(time.RFC3339),
		// Gravável por grupo (0o020) ou por outros (0o002).
		Gravavel: fi.Mode().Perm()&0o022 != 0,
	}
	b, err := e.ReadFile(p)
	if err != nil {
		// EXISTE e não pôde ser LIDO. Devolver isto como regra válida de
		// conteúdo vazio era o bug: um arquivo com `+` (login sem senha de
		// qualquer lugar) caía de CRÍTICO para AVISO porque Curinga nunca foi
		// lido, e o chamador nem declarava lacuna. lstat funcionar não prova que
		// o conteúdo é legível — a permissão de stat vem do diretório.
		return c, true, env.EhLacuna(err)
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
	return c, true, false
}
