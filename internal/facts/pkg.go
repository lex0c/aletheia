package facts

import (
	"bufio"
	"sort"
	"strconv"
	"strings"

	"github.com/lex0c/aletheia/internal/env"
)

// Propriedade de pacote (runbook §24).
//
// A pergunta é uma só: ALGUM pacote reivindica este arquivo? É o discriminador
// que faltava para separar `/usr/local/sbin/systemd-oomd-helper` de um serviço
// legítimo — o nome imita, o caminho é de sistema, o comando é limpo, e nenhum
// pacote o instalou.
//
// # Por que NATIVO, e não `dpkg -V`
//
// A SPEC previu marcar achado vindo de binário do host como `origin:tool` e
// rebaixá-lo. Mas dpkg e apk guardam a lista de arquivos em TEXTO, e ler texto
// é mais barato que gerenciar desconfiança: o resultado passa a valer como
// prova, e funciona sobre imagem montada — que é o caminho da §35.6 quando o
// userland do alvo não é confiável.
//
// O rpm não dá essa opção: a base é binária. Ali a resposta é NÃO SEI, dita em
// voz alta, e não um silêncio que parece limpeza.
//
// # Por que não varremos o filesystem
//
// Perguntar "quem é o dono de cada arquivo do host" exigiria caminhar tudo. A
// pergunta útil é mais estreita: quem é o dono do que está RODANDO e do que
// algum gatilho EXECUTA. Isso são dezenas de caminhos, não milhões.

// PkgDB é a base de pacotes encontrada.
type PkgDB struct {
	Kind string `json:"kind"` // dpkg | apk | rpm | none
	Path string `json:"path,omitempty"`

	// Consultavel diz se dá para responder "quem é o dono". Falso no rpm, e a
	// diferença entre "nenhum pacote reivindica" e "não pude perguntar" é a
	// razão de ser desta ferramenta.
	Consultavel bool   `json:"queryable"`
	Motivo      string `json:"reason,omitempty"`
}

// Ownership é a resposta para um caminho.
type Ownership struct {
	Path  string   `json:"path"`
	Owned bool     `json:"owned"`
	Onde  []string `json:"where,omitempty"` // por que perguntamos por ele
}

func collectPkg(f *Facts, e *env.Env) {
	f.Pkg = detectarPkgDB(e)

	candidatos := candidatosDePropriedade(f)
	if len(candidatos) == 0 {
		return
	}
	if !f.Pkg.Consultavel {
		f.denyPersist("pkg", "propriedade de pacote não pôde ser consultada ("+
			f.Pkg.Motivo+"): "+strconv.Itoa(len(candidatos))+
			" binários em execução ou agendados NÃO foram verificados")
		return
	}

	donos := map[string]bool{}
	switch f.Pkg.Kind {
	case "dpkg":
		donosDpkg(e, candidatos, donos)
	case "apk":
		donosApk(e, candidatos, donos)
	}

	caminhos := make([]string, 0, len(candidatos))
	for p := range candidatos {
		caminhos = append(caminhos, p)
	}
	sort.Strings(caminhos)
	for _, p := range caminhos {
		f.Ownership = append(f.Ownership, Ownership{
			Path: p, Owned: donos[p], Onde: candidatos[p],
		})
	}
}

func detectarPkgDB(e *env.Env) PkgDB {
	switch {
	case e.IsDir("/var/lib/dpkg/info"):
		return PkgDB{Kind: "dpkg", Path: "/var/lib/dpkg/info", Consultavel: true}
	case e.Exists("/lib/apk/db/installed"):
		return PkgDB{Kind: "apk", Path: "/lib/apk/db/installed", Consultavel: true}
	case e.Exists("/var/lib/rpm"), e.Exists("/usr/lib/sysimage/rpm"):
		return PkgDB{
			Kind: "rpm", Path: "/var/lib/rpm", Consultavel: false,
			Motivo: "a base do rpm é binária e não é lida nativamente; " +
				"`rpm -qf` responderia, mas viria do binário do host",
		}
	}
	return PkgDB{Kind: "none", Consultavel: false,
		Motivo: "nenhuma base de pacotes encontrada"}
}

// candidatosDePropriedade é a pergunta estreita: quem é dono do que está
// RODANDO e do que algum gatilho EXECUTA.
func candidatosDePropriedade(f *Facts) map[string][]string {
	out := map[string][]string{}
	add := func(p, onde string) {
		if !strings.HasPrefix(p, "/") || strings.ContainsAny(p, "*?[]()|;&$\"'`<>") {
			return
		}
		out[p] = append(out[p], onde)
	}

	for i := range f.Processes {
		p := &f.Processes[i]
		if p.Self || p.Vanished || p.Exe == "" || p.ExeDeleted || p.ExeMemfd {
			continue
		}
		add(p.Exe, "processo pid="+strconv.Itoa(p.PID))
	}
	for i := range f.Units {
		u := &f.Units[i]
		for _, ex := range u.Exec {
			add(primeiroToken(ex.Cmd), "unit "+u.Name)
		}
	}
	for i := range f.Cron {
		c := &f.Cron[i]
		add(primeiroToken(c.Cmd), "cron "+baseNome(c.File))
	}
	return out
}

// donosDpkg percorre as listas de arquivos, que são texto puro: um caminho
// absoluto por linha.
//
// A armadilha aqui é o usrmerge: o dpkg lista `/bin/cat`, e o processo roda
// `/usr/bin/cat`. Sem casar as duas formas, TODO binário de /usr/bin apareceria
// sem dono — um falso positivo catastrófico, em todo host Debian moderno.
func donosDpkg(e *env.Env, cand map[string][]string, donos map[string]bool) {
	procurados := map[string]string{} // forma no arquivo -> caminho perguntado
	for p := range cand {
		for _, v := range formasUsrMerge(p) {
			procurados[v] = p
		}
	}

	for _, n := range e.ReadDirNames("/var/lib/dpkg/info") {
		if !strings.HasSuffix(n, ".list") {
			continue
		}
		b, err := e.ReadFile("/var/lib/dpkg/info/" + n)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(strings.NewReader(string(b)))
		sc.Buffer(make([]byte, 0, 4096), 64*1024)
		for sc.Scan() {
			if alvo, ok := procurados[sc.Text()]; ok {
				donos[alvo] = true
			}
		}
	}
}

// donosApk lê /lib/apk/db/installed. O formato é de blocos: `F:` fixa o
// diretório corrente e `R:` é um arquivo dentro dele.
func donosApk(e *env.Env, cand map[string][]string, donos map[string]bool) {
	procurados := map[string]string{}
	for p := range cand {
		for _, v := range formasUsrMerge(p) {
			procurados[v] = p
		}
	}

	b, err := e.ReadFile("/lib/apk/db/installed")
	if err != nil {
		return
	}
	dir := ""
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	sc.Buffer(make([]byte, 0, 4096), 256*1024)
	for sc.Scan() {
		ln := sc.Text()
		if len(ln) < 2 || ln[1] != ':' {
			continue
		}
		switch ln[0] {
		case 'F':
			dir = "/" + ln[2:]
		case 'R':
			if alvo, ok := procurados[dir+"/"+ln[2:]]; ok {
				donos[alvo] = true
			}
		}
	}
}

// formasUsrMerge devolve as grafias equivalentes de um caminho sob usrmerge.
// /usr/bin/cat e /bin/cat são o MESMO arquivo em distribuição moderna, e as
// bases de pacote não concordam sobre qual escrever.
func formasUsrMerge(p string) []string {
	out := []string{p}
	for _, d := range []string{"/bin/", "/sbin/", "/lib/", "/lib64/"} {
		if strings.HasPrefix(p, d) {
			out = append(out, "/usr"+p)
			return out
		}
		if strings.HasPrefix(p, "/usr"+d) {
			out = append(out, strings.TrimPrefix(p, "/usr"))
			return out
		}
	}
	return out
}

func primeiroToken(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, " \t"); i > 0 {
		s = s[:i]
	}
	return strings.TrimLeft(s, "-@+!:")
}

func baseNome(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}
