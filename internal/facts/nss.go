package facts

import (
	"strings"

	"github.com/lex0c/aletheia/internal/env"
)

// Módulos NSS (runbook §7.8, ATT&CK T1556).
//
// O /etc/nsswitch.conf diz ao glibc de ONDE vem cada resolução de nome —
// passwd, group, shadow, hosts. Cada fonte listada (`files`, `dns`, `systemd`,
// `sss`) é uma biblioteca `libnss_<fonte>.so.2` que o glibc carrega e EXECUTA
// dentro de qualquer processo que resolva um nome: `getpwnam`, `gethostbyname`,
// o login, o sshd, o cron.
//
// É um esconderijo de persistência que quase ninguém audita. Um atacante
// acrescenta uma fonte — `passwd: files impl` — e deixa cair
// `libnss_impl.so.2`: dali em diante, toda vez que ALGUÉM (inclusive um daemon
// root) resolve um usuário, o código dele roda. Não há processo estranho, não
// há porta, não há cron.
//
// A pergunta que separa o módulo legítimo do implante é a MESMA do resto da
// ferramenta: quem empacotou esta biblioteca? nss-systemd vem do systemd, sss
// do sssd, mdns do avahi — todos com dono. O `libnss_impl.so.2` do atacante,
// não. Por isso o caminho resolvido entra na pergunta de propriedade.

// NSSModule é uma fonte declarada no nsswitch.conf e a biblioteca que ela
// carrega, quando encontrada.
type NSSModule struct {
	Fonte    string   `json:"source"`
	Path     string   `json:"path,omitempty"` // libnss_<fonte>.so.2 resolvido
	Servicos []string `json:"services,omitempty"`
}

// nssLibDirs é o caminho de busca PADRÃO do glibc para módulos NSS — não o do
// ld.so.conf, e sim os diretórios de biblioteca do sistema, incluindo o layout
// multiarch do Debian.
var nssLibDirs = []string{
	"/lib", "/usr/lib", "/lib64", "/usr/lib64",
	"/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu",
	"/lib/aarch64-linux-gnu", "/usr/lib/aarch64-linux-gnu",
	"/lib/i386-linux-gnu", "/usr/lib/i386-linux-gnu",
}

func collectNSS(f *Facts, e *env.Env) {
	b, err := e.ReadFile("/etc/nsswitch.conf")
	if err != nil {
		if env.EhLacuna(err) {
			f.denyPersist("nss", "/etc/nsswitch.conf não pôde ser lido ("+
				env.MotivoDoErro(err)+"): um módulo NSS malicioso — carregado em TODA "+
				"resolução de nome, inclusive por daemon root — NÃO foi avaliado")
		}
		return
	}

	porFonte := map[string]*NSSModule{}
	var ordem []string
	for _, raw := range strings.Split(string(b), "\n") {
		ln := raw
		if i := strings.IndexByte(ln, '#'); i >= 0 {
			ln = ln[:i]
		}
		servico, resto, ok := strings.Cut(ln, ":")
		if !ok {
			continue
		}
		servico = strings.TrimSpace(servico)
		if servico == "" {
			continue
		}
		// Um bloco de AÇÃO — `[NOTFOUND=return]` — não é fonte, e pode conter
		// espaços (`[ SUCCESS = return ]`). Rastreia-se a profundidade do
		// colchete para não confundir o conteúdo dele com nome de módulo.
		dentroColchete := false
		for _, tok := range strings.Fields(resto) {
			if dentroColchete {
				if strings.HasSuffix(tok, "]") {
					dentroColchete = false
				}
				continue
			}
			if strings.HasPrefix(tok, "[") {
				if !strings.HasSuffix(tok, "]") {
					dentroColchete = true
				}
				continue
			}
			fonte := tok
			m, existe := porFonte[fonte]
			if !existe {
				m = &NSSModule{Fonte: fonte}
				porFonte[fonte] = m
				ordem = append(ordem, fonte)
			}
			m.Servicos = append(m.Servicos, servico)
		}
	}

	// A glibc resolve o soname pelo LOADER, então a busca precisa da MESMA visão
	// do loader — não uma segunda lista fixa. Sem isto, um `libnss_impl.so.2` num
	// diretório que só o ld.so.conf.d do atacante conhece (`/opt/.lib`) era
	// localizável pela glibc e invisível para a ferramenta. Os SearchDirs saem do
	// collectLoader, que roda antes deste coletor.
	dirs := append([]string{}, nssLibDirs...)
	for _, d := range f.Loader.SearchDirs {
		dirs = append(dirs, d.Dir)
	}
	for _, fonte := range ordem {
		m := porFonte[fonte]
		m.Path = localizarLibNSS(e, dirs, fonte)
		f.NSSModules = append(f.NSSModules, *m)
	}
}

// localizarLibNSS acha a `libnss_<fonte>.so.{2,1}` nos diretórios de biblioteca
// do sistema E nos diretórios de busca declarados no ld.so.conf. Devolve o
// primeiro caminho que existe, ou "" se nenhum — uma fonte sem biblioteca
// localizada não é acusável (pode ser embutida no glibc, ou estar noutro lugar).
func localizarLibNSS(e *env.Env, dirs []string, fonte string) string {
	visto := map[string]bool{}
	for _, dir := range dirs {
		if dir == "" || visto[dir] {
			continue
		}
		visto[dir] = true
		for _, ver := range []string{".so.2", ".so.1"} {
			p := dir + "/libnss_" + fonte + ver
			if _, err := e.Lstat(p); err == nil {
				return p
			}
		}
	}
	return ""
}
