package facts

import (
	"sort"
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

// NSSModule é uma fonte declarada no nsswitch.conf e as bibliotecas candidatas
// que ela poderia carregar.
// acoesPadraoNSS é o que a glibc faz quando NÃO há bloco de ação, e está
// documentado no nsswitch.conf(5):
//
//	[SUCCESS=return NOTFOUND=continue UNAVAIL=continue TRYAGAIN=continue]
var acoesPadraoNSS = map[string]string{
	"success": "return", "notfound": "continue",
	"unavail": "continue", "tryagain": "continue",
}

var statusNSS = []string{"success", "notfound", "tryagain", "unavail"}

// tabelaNSS resolve um bloco de ação para a TABELA EFETIVA e devolve só o que
// DIVERGE do padrão, em ordem estável.
//
// # Por que não basta normalizar a sintaxe
//
// A primeira versão só passava para minúsculas e tirava espaço. Aquilo resolvia
// `[ SUCCESS = return ]` contra `[success=return]`, e deixava passar duas
// classes de falso positivo:
//
//	passwd: files sss                    são a MESMA configuração —
//	passwd: files [SUCCESS=return] sss   SUCCESS=return é o PADRÃO
//
//	[SUCCESS=return NOTFOUND=continue]   e o inverso, mesma tabela em
//	[NOTFOUND=continue SUCCESS=return]   ordem diferente
//
// Um bloco é uma TABELA, não uma sequência: a ordem dos termos não significa
// nada, e um termo que repete o padrão não muda comportamento nenhum. Comparar
// o texto fazia reescrita de configuração virar drift, e o comentário do campo
// prometia "configuração EFETIVA" — que era o que ele ainda não era.
//
// Devolve "" quando a tabela resultante É a padrão. Termo que este código não
// entende NÃO é descartado: ele volta em forma crua, porque tratar o
// desconhecido como padrão seria afirmar equivalência que ninguém verificou.
func tabelaNSS(toks []string) string {
	bruto := strings.ToLower(strings.Join(toks, " "))
	bruto = strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(bruto), "["), "]")

	tab := map[string]string{}
	for k, v := range acoesPadraoNSS {
		tab[k] = v
	}
	var naoEntendidos []string
	// Os termos são `[!]STATUS=ACTION`, e o `=` pode vir cercado de espaço.
	for _, termo := range termosNSS(bruto) {
		st, ac, ok := strings.Cut(termo, "=")
		if !ok {
			naoEntendidos = append(naoEntendidos, termo)
			continue
		}
		negado := strings.HasPrefix(st, "!")
		st = strings.TrimPrefix(st, "!")
		if acoesPadraoNSS[st] == "" || !acaoValidaNSS(ac) {
			naoEntendidos = append(naoEntendidos, termo)
			continue
		}
		if !negado {
			tab[st] = ac
			continue
		}
		// `!STATUS` aplica a ação a TODOS os outros status.
		for _, outro := range statusNSS {
			if outro != st {
				tab[outro] = ac
			}
		}
	}

	var partes []string
	for _, st := range statusNSS {
		if tab[st] != acoesPadraoNSS[st] {
			partes = append(partes, st+"="+tab[st])
		}
	}
	partes = append(partes, naoEntendidos...)
	sort.Strings(partes)
	if len(partes) == 0 {
		return ""
	}
	return "[" + strings.Join(partes, " ") + "]"
}

// termosNSS quebra o miolo do bloco em termos, tolerando espaço em volta do `=`
// (`[ SUCCESS = return ]` é sintaxe válida).
func termosNSS(miolo string) []string {
	var out []string
	var atual strings.Builder
	esperandoValor := false
	for _, campo := range strings.Fields(miolo) {
		switch {
		case campo == "=":
			atual.WriteString("=")
			esperandoValor = true
		case strings.HasSuffix(campo, "="):
			atual.WriteString(campo)
			esperandoValor = true
		case esperandoValor:
			atual.WriteString(campo)
			out = append(out, atual.String())
			atual.Reset()
			esperandoValor = false
		default:
			if atual.Len() > 0 {
				out = append(out, atual.String())
				atual.Reset()
			}
			if strings.Contains(campo, "=") {
				out = append(out, campo)
				continue
			}
			atual.WriteString(campo)
		}
	}
	if atual.Len() > 0 {
		out = append(out, atual.String())
	}
	return out
}

func acaoValidaNSS(a string) bool {
	switch a {
	case "return", "continue", "merge":
		return true
	}
	return false
}

// NSSService é a configuração EFETIVA de um database do nsswitch: a cadeia de
// fontes NA ORDEM em que a glibc as consulta.
//
// A primeira fonte que responde encerra a consulta (salvo ação explícita), então
// a ordem é a autoridade. Ela não sobrevive ao NSSModule, que agrupa por fonte.
type NSSService struct {
	Nome string `json:"name"`
	// Cadeia preserva a ORDEM e inclui os blocos de ação, normalizados
	// (`[notfound=return]`). Eles não são fonte, e mesmo assim decidem: são
	// eles que dizem se a próxima fonte chega a ser consultada, e um
	// `[success=merge]` faz duas responderem juntas.
	Cadeia []string `json:"chain"`
}

type NSSModule struct {
	Fonte string `json:"source"`
	// Paths são TODAS as libnss_<fonte>.so.{2,1} encontradas nos diretórios de
	// biblioteca. Guardar todas — e não só a primeira — importa contra
	// shadowing: uma cópia legítima em /usr/lib e um implante em /opt/.hidden
	// coexistem, e qual o loader carrega depende do ld.so.cache. Devolver só a
	// primeira mascararia o implante atrás da legítima.
	Paths    []string `json:"paths,omitempty"`
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
	f.NSSLido = true

	b, err := e.ReadFile("/etc/nsswitch.conf")
	if err != nil {
		if env.EhLacuna(err) {
			f.NSSLido = false
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
		var cadeia []string
		var acao []string
		// A ação vem DEPOIS da fonte a que se aplica, então ela é anexada ao
		// último elemento da cadeia.
		anexaAcao := func(toks []string) {
			t := tabelaNSS(toks)
			if t == "" || len(cadeia) == 0 {
				return
			}
			cadeia[len(cadeia)-1] += t
		}
		for _, tok := range strings.Fields(resto) {
			if dentroColchete {
				acao = append(acao, tok)
				if strings.HasSuffix(tok, "]") {
					dentroColchete = false
					anexaAcao(acao)
					acao = nil
				}
				continue
			}
			if strings.HasPrefix(tok, "[") {
				if !strings.HasSuffix(tok, "]") {
					dentroColchete = true
					acao = []string{tok}
					continue
				}
				// O BLOCO DE AÇÃO ENTRA NA CADEIA, colado na fonte a que
				// se aplica, e não é fonte.
				//
				// Ele foi descartado na primeira versão, sob o argumento de que
				// "não é módulo". Verdade, e irrelevante: `[NOTFOUND=return]` e
				// `[NOTFOUND=continue]` decidem se a PRÓXIMA fonte chega a ser
				// consultada, e `[SUCCESS=merge]` faz duas fontes responderem
				// juntas. Duas configurações com as mesmas fontes, na mesma
				// ordem, e comportamento efetivo diferente saíam idênticas —
				// que é apagar a semântica antes de comparar, exatamente o que
				// esta representação existe para não fazer.
				anexaAcao([]string{tok})
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
			cadeia = append(cadeia, fonte)
		}
		// A CADEIA, na ORDEM. O agrupamento por fonte acima responde "quais
		// bibliotecas podem ser carregadas"; ele não responde precedência, e
		// precedência é o que decide QUEM É USUÁRIO neste host. `passwd: files
		// sss` e `passwd: sss files` têm as mesmas fontes e as mesmas libs, e a
		// autoridade invertida.
		if len(cadeia) > 0 {
			f.NSSServicos = append(f.NSSServicos, NSSService{Nome: servico, Cadeia: cadeia})
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
		m.Paths = localizarLibNSS(e, dirs, fonte)
		f.NSSModules = append(f.NSSModules, *m)
	}
}

// localizarLibNSS acha TODAS as `libnss_<fonte>.so.{2,1}` nos diretórios de
// biblioteca do sistema E nos diretórios de busca do ld.so.conf. Devolve todas
// as que existem — o loader escolhe uma pelo ld.so.cache, e devolver só a
// primeira mascararia um implante que coexiste com a cópia legítima.
func localizarLibNSS(e *env.Env, dirs []string, fonte string) []string {
	var out []string
	visto := map[string]bool{}
	for _, dir := range dirs {
		if dir == "" || visto[dir] {
			continue
		}
		visto[dir] = true
		for _, ver := range []string{".so.2", ".so.1"} {
			p := dir + "/libnss_" + fonte + ver
			if _, err := e.Lstat(p); err == nil && !visto[p] {
				visto[p] = true
				out = append(out, p)
			}
		}
	}
	return out
}
