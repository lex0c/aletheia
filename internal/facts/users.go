package facts

import (
	"os"
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
		if len(fs) < 7 {
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
			if len(fs) < 4 {
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
		if len(fs) < 2 {
			continue
		}
		out[fs[0]] = fs[1]
	}
	return out
}

func collectSudoers(f *Facts, e *env.Env) {
	arquivos := []string{"/etc/sudoers"}
	for _, n := range e.ReadDirNames("/etc/sudoers.d") {
		arquivos = append(arquivos, "/etc/sudoers.d/"+n)
	}
	for _, p := range arquivos {
		b, err := e.ReadFile(p)
		if err != nil {
			// /etc/sudoers é 0440 de root: sem privilégio ele é ILEGÍVEL, e
			// engolir isso faria a ferramenta dizer "nenhuma regra de sudo
			// perigosa" quando o que houve foi não ter conseguido olhar.
			if !os.IsNotExist(err) {
				f.denyPersist("users", p+" ilegível: as regras de sudo NÃO foram avaliadas")
			}
			continue
		}
		for i, raw := range strings.Split(string(b), "\n") {
			ln := strings.TrimSpace(raw)
			if ln == "" || strings.HasPrefix(ln, "#") {
				continue
			}
			// `Defaults` fica: `Defaults:usuario !authenticate` desliga a
			// pergunta de senha para aquele usuário, e é forma de backdoor tanto
			// quanto um NOPASSWD.
			f.Sudoers = append(f.Sudoers, SudoRule{File: p, Line: i + 1, Text: ln})
		}
	}
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
