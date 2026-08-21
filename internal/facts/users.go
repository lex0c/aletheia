package facts

import (
	"os"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/lex0c/aletheia/internal/env"
)

// Usuários e privilégio (runbook §7.9).
//
// A regra que atravessa este arquivo: é o UID que define o poder, não o nome. O
// kernel só compara números — qualquer conta com uid 0 É root, chame-se
// `backup`, `systemd-net` ou `ftp`. Procurar por "root" acharia uma conta e
// perderia a outra.

// Account é uma conta do passwd, com o que decide se ela dá acesso.
type Account struct {
	Name  string `json:"name"`
	UID   int    `json:"uid"`
	GID   int    `json:"gid"`
	Home  string `json:"home,omitempty"`
	Shell string `json:"shell,omitempty"`

	// SemSenha vem do shadow: campo vazio significa login SEM autenticação.
	// Só é preenchido quando o shadow foi legível — e não conseguir ler é
	// diferente de não haver.
	SemSenha  bool `json:"no_password,omitempty"`
	Bloqueada bool `json:"locked,omitempty"`

	// SemShadow marca a conta que existe no passwd e NÃO tem entrada no
	// shadow. O `useradd` escreve nos dois sempre; a divergência é assinatura
	// de edição à mão. Só vale quando o shadow foi legível.
	SemShadow bool `json:"no_shadow_entry,omitempty"`
}

// Grupo é a associação que dá privilégio indireto.
type Grupo struct {
	Name    string   `json:"name"`
	GID     int      `json:"gid"`
	Members []string `json:"members,omitempty"`
}

// SudoRule é uma linha de sudoers que concede algo.
type SudoRule struct {
	File string `json:"file"`
	Line int    `json:"line"`
	Text string `json:"text"`
}

// DoasRule é uma regra de /etc/doas.conf (o sudo do OpenBSD, comum em Alpine e
// Arch). `permit nopass` é escalada SEM senha — o mesmo backdoor que o
// NOPASSWD do sudoers, num arquivo que ninguém audita porque "aqui é sudo".
type DoasRule struct {
	File string `json:"file"`
	Line int    `json:"line"`
	Text string `json:"text"`

	// Permit distingue `permit` de `deny`: só o permit concede.
	Permit bool `json:"permit"`
	// NoPass é a opção `nopass` — sem senha. É o que transforma a regra em
	// backdoor de escalada.
	NoPass bool `json:"nopass,omitempty"`
	// Identidade é o usuário (`nome`) ou grupo (`:grupo`) que a regra libera.
	Identidade string `json:"identity,omitempty"`
	// Alvo é o `as <conta>` — vazio significa root, o padrão do doas.
	Alvo string `json:"target,omitempty"`
	// Comando é o `cmd <programa>` — vazio significa QUALQUER comando.
	Comando string `json:"cmd,omitempty"`

	// TemArgs e Args guardam o `args ...`, e existem porque as TRÊS formas do
	// doas.conf concedem coisas diferentes — a mesma assimetria do sudoers:
	//
	//	cmd /usr/bin/tar               QUALQUER argumento (a mais AMPLA)
	//	cmd /usr/bin/tar args          NENHUM argumento
	//	cmd /usr/bin/tar args czf /x   só exatamente aqueles
	//
	// Sem esta distinção o classificador de primitiva (checks/primitiva.go)
	// leria a terceira forma como a primeira e acusaria de root irrestrito uma
	// regra de backup que fixa o comando inteiro.
	TemArgs bool     `json:"has_args,omitempty"`
	Args    []string `json:"args,omitempty"`
}

// ArquivoMeta guarda a data dos arquivos que decidem acesso. O ctime deles na
// janela do incidente é o que datA a alteração (runbook §9).
type ArquivoMeta struct {
	Path   string `json:"path"`
	ModUTC string `json:"mod_utc,omitempty"`
}

func collectUsers(f *Facts, e *env.Env) {
	// sudo e doas são persistência de ESCALADA, independente da lista de contas:
	// uma regra NOPASSWD vale mesmo sem conseguir ler /etc/passwd. Ficavam
	// depois do `return` do passwd ilegível/ausente — um host sem passwd legível
	// (ou uma imagem só com /etc/doas.conf) tinha as duas superfícies caladas.
	collectSudoers(f, e)
	collectDoas(f, e)

	shadow := lerShadow(f, e)

	b, err := e.ReadFile("/etc/passwd")
	if err != nil {
		f.denyPersist("users", "/etc/passwd ilegível: nenhuma conta foi avaliada")
		return
	}
	for _, ln := range strings.Split(string(b), "\n") {
		fs := strings.Split(ln, ":")
		// A linha COMENTADA não é conta. Comentar a linha do passwd é a forma
		// clássica de desabilitar um acesso, e sem este guarda ela virava
		// Account{Name: "#deploy"} — um nome que nunca está no shadow, logo
		// SemShadow=true, logo priv.account_no_shadow CRITICAL sobre uma conta
		// que não existe (e SevCritical quando o UID comentado é 0). O
		// NomesDeUsuario, no fim deste arquivo, sempre teve o guarda.
		if len(fs) < 7 || strings.HasPrefix(ln, "#") {
			continue
		}
		uid, err := strconv.Atoi(fs[2])
		if err != nil {
			continue
		}
		gid, _ := strconv.Atoi(fs[3])
		a := Account{Name: fs[0], UID: uid, GID: gid, Home: fs[5], Shell: fs[6]}
		if s, ok := shadow[a.Name]; ok {
			a.SemSenha = s == ""
			a.Bloqueada = strings.HasPrefix(s, "!") || strings.HasPrefix(s, "*")
		} else if len(shadow) > 0 {
			// A conta está no passwd e NÃO no shadow. O `useradd` escreve nos
			// dois, sempre — a divergência é assinatura de edição à mão.
			//
			// A guarda `len(shadow) > 0` importa: sem root o shadow é ilegível e
			// o mapa vem vazio, o que marcaria TODA conta do host. A lacuna já é
			// declarada pelo leitor do shadow.
			a.SemShadow = true
		}
		f.Accounts = append(f.Accounts, a)
	}

	if b, err := e.ReadFile("/etc/group"); env.EhLacuna(err) {
		f.denyPersist("users", "/etc/group não pôde ser lido: a resolução de GID→nome "+
			"degrada, e um GID sem conta no group não pode ser afirmado")
	} else if err == nil {
		for _, ln := range strings.Split(string(b), "\n") {
			fs := strings.Split(ln, ":")
			if len(fs) < 4 || strings.HasPrefix(ln, "#") {
				continue
			}
			gid, _ := strconv.Atoi(fs[2])
			var membros []string
			if fs[3] != "" {
				membros = strings.Split(fs[3], ",")
			}
			f.Grupos = append(f.Grupos, Grupo{Name: fs[0], GID: gid, Members: membros})
		}
	}

	for _, p := range []string{"/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/group"} {
		if m := modUTC(e, p); m != "" {
			f.MetaAcesso = append(f.MetaAcesso, ArquivoMeta{Path: p, ModUTC: m})
		}
	}
}

// lerShadow devolve o campo de senha por conta. Falhar aqui NÃO é "ninguém sem
// senha": é desconhecimento, e vira lacuna declarada.
func lerShadow(f *Facts, e *env.Env) map[string]string {
	out := map[string]string{}
	b, err := e.ReadFile("/etc/shadow")
	if err != nil {
		f.denyPersist("users", "/etc/shadow ilegível (precisa de root): "+
			"conta sem senha não pôde ser avaliada")
		return out
	}
	for _, ln := range strings.Split(string(b), "\n") {
		fs := strings.Split(ln, ":")
		if len(fs) < 2 || strings.HasPrefix(ln, "#") {
			continue
		}
		out[fs[0]] = fs[1]
	}
	return out
}

const (
	maxSudoersArquivos = 256
	maxSudoersProf     = 16
)

func collectSudoers(f *Facts, e *env.Env) {
	// Árvore de configuração a partir de /etc/sudoers, seguindo os includes que
	// o próprio sudo segue. Ler /etc/sudoers.d fixo tinha dois defeitos: um
	// `@includedir /opt/.x` era invisível (bypass), e /etc/sudoers.d era varrido
	// mesmo sem `@includedir` correspondente, podendo virar achado sobre regra
	// que o sudo nunca lê (FP). ReadDirNames engolindo o diretório ilegível era
	// o terceiro — agora vira lacuna.
	arvoreSudoers(f, e, "/etc/sudoers", 0, map[string]bool{}, new(int))
}

// arvoreSudoers percorre /etc/sudoers seguindo `@include`/`@includedir` e as
// formas legadas `#include`/`#includedir`. O `#include` NÃO é comentário — é a
// sintaxe antiga de include —, e por isso a checagem de include precede a de
// comentário. visited-set contra ciclo; teto de arquivos e profundidade contra
// árvore hostil; corte e diretório ilegível declaram lacuna.
func arvoreSudoers(f *Facts, e *env.Env, p string, prof int, visto map[string]bool, contador *int) {
	if visto[p] {
		return
	}
	if prof > maxSudoersProf {
		// Teto de PROFUNDIDADE, distinto do de quantidade: um `@include` em ciclo
		// (ou cadeia muito funda) para aqui, e o que ficou além NÃO foi avaliado.
		// Cortar em silêncio transformaria "parei" em "não há".
		f.denyPersist("users", "a árvore de include do sudoers passou de "+
			strconv.Itoa(maxSudoersProf)+" níveis de profundidade em "+p+
			" e foi cortada: regras incluídas além disso NÃO foram avaliadas")
		return
	}
	visto[p] = true
	if *contador >= maxSudoersArquivos {
		f.denyPersist("users", "a árvore de include do sudoers passou de "+
			strconv.Itoa(maxSudoersArquivos)+" arquivos e foi cortada: regras além "+
			"disso NÃO foram avaliadas")
		return
	}
	*contador++
	b, err := e.ReadFile(p)
	if err != nil {
		// /etc/sudoers é 0440 de root: sem privilégio ele é ILEGÍVEL, e engolir
		// isso faria a ferramenta dizer "nenhuma regra de sudo perigosa" quando
		// o que houve foi não ter conseguido olhar.
		if !os.IsNotExist(err) {
			f.denyPersist("users", p+" ilegível: as regras de sudo declaradas ali NÃO foram avaliadas")
		}
		return
	}
	dir := path.Dir(p)
	// LINHAS LÓGICAS, não físicas. sudoers junta a linha que termina em `\` com a
	// seguinte, SEM separador: `... NOPASS\<nl>WD: ALL` é `NOPASSWD` para o sudo,
	// e nenhuma das duas linhas físicas contém a substring que o check procura.
	// A junção é DIRETA (o espaço antes do `\`, quando há, fica preservado).
	for _, ll := range linhasLogicas(string(b)) {
		ln := strings.TrimSpace(ll.Texto)
		if ln == "" {
			continue
		}
		if alvo, ehDir, ok := diretivaIncludeSudoers(ln); ok {
			alvo = expandirCaminhoSudoers(alvo, f.Host.Hostname)
			resolvido := resolverIncludeSudoers(dir, alvo)
			if ehDir {
				nomes, derr := e.ReadDirNamesErr(resolvido)
				if env.EhLacuna(derr) {
					f.denyPersist("users", resolvido+" (includedir de sudoers) não pôde "+
						"ser listado ("+env.MotivoDoErro(derr)+"): as regras dele NÃO foram avaliadas")
					continue
				}
				sort.Strings(nomes)
				for _, n := range nomes {
					// sudo ignora nomes terminados em '~' ou com '.' no meio.
					if n == "" || strings.HasSuffix(n, "~") || strings.ContainsRune(n, '.') {
						continue
					}
					q := resolvido + "/" + n
					if e.IsDir(q) {
						continue
					}
					arvoreSudoers(f, e, q, prof+1, visto, contador)
				}
			} else {
				arvoreSudoers(f, e, resolvido, prof+1, visto, contador)
			}
			continue
		}
		if strings.HasPrefix(ln, "#") {
			continue // comentário de verdade (já descontados os #include)
		}
		// `Defaults` fica: `Defaults:usuario !authenticate` desliga a pergunta de
		// senha para aquele usuário, e é forma de backdoor tanto quanto um NOPASSWD.
		f.Sudoers = append(f.Sudoers, SudoRule{File: p, Line: ll.Num, Text: ln})
	}
}

// linhaLogica é uma linha lógica e o número da primeira linha física que a
// compõe.
type linhaLogica struct {
	Num   int
	Texto string
}

// linhasLogicas junta as continuações `\`. A junção é DIRETA — o `\` e a quebra
// somem, e o que estava antes do `\` (inclusive um espaço) fica. É o que o sudo
// e o shell fazem, e é o que faz `NOPASS\<nl>WD` virar `NOPASSWD`.
func linhasLogicas(conteudo string) []linhaLogica {
	fisicas := strings.Split(conteudo, "\n")
	var out []linhaLogica
	for i := 0; i < len(fisicas); {
		inicio := i
		ln := strings.TrimRight(fisicas[i], "\r")
		for strings.HasSuffix(ln, "\\") {
			ln = strings.TrimSuffix(ln, "\\")
			i++
			if i >= len(fisicas) {
				break
			}
			ln += strings.TrimRight(fisicas[i], "\r")
		}
		i++
		out = append(out, linhaLogica{Num: inicio + 1, Texto: ln})
	}
	return out
}

// diretivaIncludeSudoers reconhece as quatro formas de include do sudoers. A
// checagem de `includedir` precede a de `include` porque uma é prefixo da outra.
func diretivaIncludeSudoers(ln string) (alvo string, ehDir bool, ok bool) {
	for _, pref := range []string{"@includedir", "#includedir"} {
		if r, corta := strings.CutPrefix(ln, pref); corta && (r == "" || r[0] == ' ' || r[0] == '\t') {
			return descascaCaminhoSudoers(r), true, true
		}
	}
	for _, pref := range []string{"@include", "#include"} {
		if r, corta := strings.CutPrefix(ln, pref); corta && (r == "" || r[0] == ' ' || r[0] == '\t') {
			return descascaCaminhoSudoers(r), false, true
		}
	}
	return "", false, false
}

// expandirCaminhoSudoers aplica o que o sudo aplica ao caminho de include:
// `%h` vira o hostname, `%%` vira `%`, e `\x` desescapa (o espaço escapado do
// `@include /etc/sudoers\ local` é o caso). Sem isto, um include por hostname
// ou com espaço escapado não era seguido.
func expandirCaminhoSudoers(s, hostname string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '%' && i+1 < len(s):
			i++
			switch s[i] {
			case 'h':
				b.WriteString(hostname)
			case '%':
				b.WriteByte('%')
			default:
				b.WriteByte('%')
				b.WriteByte(s[i])
			}
		case s[i] == '\\' && i+1 < len(s):
			i++
			b.WriteByte(s[i]) // desescapa: \x -> x
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

func descascaCaminhoSudoers(s string) string {
	return strings.Trim(strings.TrimSpace(s), `"`)
}

// resolverIncludeSudoers resolve o alvo do include: absoluto vale como está,
// relativo é relativo ao diretório do arquivo que inclui — como o sudo faz.
func resolverIncludeSudoers(dir, alvo string) string {
	if strings.HasPrefix(alvo, "/") {
		return alvo
	}
	return path.Join(dir, alvo)
}

// collectDoas lê /etc/doas.conf e /etc/doas.d/*.conf. Formato:
//
//	permit|deny [options] identity [as target] [cmd command [args...]]
//
// options inclui `nopass` (sem senha), `keepenv`, `persist`, `setenv {...}`.
// Uma linha de continuação termina em `\`; doas as junta antes de avaliar.
func collectDoas(f *Facts, e *env.Env) {
	arquivos := []string{"/etc/doas.conf"}
	nomes, errD := e.ReadDirNamesErr("/etc/doas.d")
	if env.EhLacuna(errD) {
		f.denyPersist("users", "/etc/doas.d não pôde ser listado: as regras de doas "+
			"(escalada sem senha) NÃO foram avaliadas")
	}
	for _, n := range nomes {
		if strings.HasSuffix(n, ".conf") {
			arquivos = append(arquivos, "/etc/doas.d/"+n)
		}
	}
	for _, p := range arquivos {
		b, err := e.ReadFile(p)
		if err != nil {
			if !os.IsNotExist(err) {
				f.denyPersist("users", p+" ilegível: as regras de doas (escalada sem "+
					"senha) NÃO foram avaliadas")
			}
			continue
		}
		var pend string
		for i, raw := range strings.Split(string(b), "\n") {
			ln := strings.TrimSpace(raw)
			if pend != "" {
				ln, pend = pend+" "+ln, ""
			}
			if strings.HasSuffix(ln, "\\") {
				pend = strings.TrimSpace(strings.TrimSuffix(ln, "\\"))
				continue
			}
			if ln == "" || strings.HasPrefix(ln, "#") {
				continue
			}
			if r, ok := parseDoas(p, i+1, ln); ok {
				f.Doas = append(f.Doas, r)
			}
		}
	}
}

// parseDoas decodifica uma regra. Reconhece permit/deny, a opção nopass, a
// identidade, o `as <alvo>` e o `cmd <programa>`.
func parseDoas(file string, linha int, texto string) (DoasRule, bool) {
	campos := strings.Fields(texto)
	if len(campos) == 0 {
		return DoasRule{}, false
	}
	r := DoasRule{File: file, Line: linha, Text: texto}
	switch campos[0] {
	case "permit":
		r.Permit = true
	case "deny":
		r.Permit = false
	default:
		return DoasRule{}, false // não é regra (pode ser diretiva futura)
	}
	i := 1
	// options: tudo que vier antes da identidade. `setenv { ... }` tem chaves.
	dentroSetenv := false
	for ; i < len(campos); i++ {
		c := campos[i]
		if dentroSetenv {
			if strings.HasSuffix(c, "}") {
				dentroSetenv = false
			}
			continue
		}
		switch {
		case c == "nopass":
			r.NoPass = true
		case c == "persist" || c == "keepenv" || c == "nolog":
			// opções que não mudam a identidade
		case c == "setenv" || strings.HasPrefix(c, "setenv"):
			dentroSetenv = !strings.Contains(c, "}")
		default:
			// primeiro token que não é opção: é a identidade
			goto identidade
		}
	}
identidade:
	if i < len(campos) {
		r.Identidade = campos[i]
		i++
	}
	// as <alvo> e cmd <programa>, em qualquer ordem depois da identidade
	for ; i < len(campos); i++ {
		switch campos[i] {
		case "as":
			if i+1 < len(campos) {
				r.Alvo = campos[i+1]
				i++
			}
		case "cmd":
			if i+1 < len(campos) {
				r.Comando = campos[i+1]
				i++
			}
		case "args":
			// `args` consome o RESTO da linha: é sempre o último elemento da
			// gramática do doas.conf. A presença da palavra já muda o
			// significado, mesmo sem nada depois dela — `args` sozinho é
			// "nenhum argumento", e não "qualquer um".
			r.TemArgs = true
			if i+1 < len(campos) {
				r.Args = append(r.Args, campos[i+1:]...)
			}
			i = len(campos)
		}
	}
	return r, true
}

// NomesDeUsuario lê APENAS o /etc/passwd, para traduzir uid em nome.
//
// Existe para a coleta barata: o `info` responde sobre processo em dezenas de
// milissegundos porque não varre filesystem, e sem isto ele imprimiria "uid
// 1000" onde o operador espera "node" — que é justamente o nome que ele digitou
// no comando que falhou.
//
// É só o passwd: shadow, grupos e sudoers são a coleta completa, e nenhum deles
// é preciso para dar nome a um número.
func NomesDeUsuario(e *env.Env) []Account {
	b, err := e.ReadFile("/etc/passwd")
	if err != nil {
		return nil
	}
	var out []Account
	for _, ln := range strings.Split(string(b), "\n") {
		fs := strings.Split(ln, ":")
		if len(fs) < 4 || strings.HasPrefix(ln, "#") {
			continue
		}
		uid, err1 := strconv.Atoi(fs[2])
		gid, err2 := strconv.Atoi(fs[3])
		if err1 != nil || err2 != nil {
			continue
		}
		out = append(out, Account{Name: fs[0], UID: uid, GID: gid})
	}
	return out
}
