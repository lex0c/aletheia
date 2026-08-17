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

// ArquivoMeta guarda a data dos arquivos que decidem acesso. O ctime deles na
// janela do incidente é o que datA a alteração (runbook §9).
type ArquivoMeta struct {
	Path   string `json:"path"`
	ModUTC string `json:"mod_utc,omitempty"`
}

func collectUsers(f *Facts, e *env.Env) {
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

	if b, err := e.ReadFile("/etc/group"); err == nil {
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

	collectSudoers(f, e)
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
