package facts

import (
	"os"
	"strings"

	"github.com/lex0c/aletheia/internal/env"
)

// Histórico de shell (runbook §13, §21).
//
// A ferramenta manda o operador olhar o histórico — "o histórico dessa sessão
// está no home da conta" — e nunca olhou. É o mesmo padrão do wtmp, e aqui o
// que interessa não é o CONTEÚDO.
//
// Ler comando por comando é trabalho humano e cheio de falso positivo. O que
// uma ferramenta pode dizer com precisão é outra coisa, e é mais forte:
//
//	o histórico foi DESLIGADO, e desligar é um ato deliberado
//
// Ninguém aponta `.bash_history` para /dev/null por acidente. Ninguém escreve
// `unset HISTFILE` no `.bashrc` sem querer. São as formas mais baratas de
// anti-forense que existem, custam uma linha, e nenhum dos outros checks desta
// ferramenta olhava para elas.
//
// Anti-forense é uma categoria própria: o achado não é o implante, é a AUSÊNCIA
// deliberada de rastro. Quem desligou o histórico estava contando que alguém
// fosse procurar.

// HistoricoShell descreve o arquivo de histórico de uma conta.
type HistoricoShell struct {
	Path string `json:"path"`
	User string `json:"user,omitempty"`

	// Desviado marca o histórico apontado para outro lugar — /dev/null na
	// prática. É a forma mais direta de nunca gravar nada.
	Desviado string `json:"redirected_to,omitempty"`

	// Vazio marca arquivo que existe e não tem nada. Sozinho não diz muito:
	// conta nova é assim. Vale quando a conta TEM entradas registradas.
	Vazio bool `json:"empty,omitempty"`

	Tamanho int64  `json:"size"`
	ModUTC  string `json:"mod_utc,omitempty"`
}

// arquivosDeHistorico são os nomes usados pelos shells comuns.
var arquivosDeHistorico = []string{
	".bash_history", ".zsh_history", ".sh_history", ".history",
	".ash_history", ".python_history", ".mysql_history", ".psql_history",
}

func collectHistorico(f *Facts, e *env.Env) {
	b, err := e.ReadFile("/etc/passwd")
	if err != nil {
		return
	}
	for _, ln := range strings.Split(string(b), "\n") {
		campos := strings.Split(ln, ":")
		if len(campos) < 6 || campos[5] == "" || campos[5] == "/" {
			continue
		}
		user, home := campos[0], campos[5]
		if !e.IsDir(home) {
			continue
		}
		for _, n := range arquivosDeHistorico {
			p := home + "/" + n
			fi, err := e.Lstat(p)
			if err != nil {
				continue
			}
			h := HistoricoShell{Path: p, User: user, Tamanho: fi.Size()}

			// Lstat e não Stat: um link para /dev/null tem que aparecer COMO
			// link. Seguindo o link, o que se vê é um dispositivo de tamanho
			// zero — e a informação de que alguém o desviou some.
			if fi.Mode()&os.ModeSymlink != 0 {
				if alvo, err := e.Readlink(p); err == nil {
					h.Desviado = alvo
				}
			} else {
				h.Vazio = fi.Size() == 0
				if !fi.ModTime().IsZero() {
					h.ModUTC = fi.ModTime().UTC().Format("2006-01-02T15:04:05Z")
				}
			}
			f.Historicos = append(f.Historicos, h)
		}
	}
}

// DesligaHistorico reconhece, numa linha de arquivo de inicialização de shell,
// a intenção de não gravar histórico.
//
// As formas são poucas e todas explícitas — não há como escrever nenhuma delas
// sem querer:
//
//	HISTFILE=/dev/null   grava no vazio
//	unset HISTFILE       o shell não sabe onde gravar
//	HISTSIZE=0           não guarda nada em memória
//	set +o history       desliga o registro em si
func DesligaHistorico(linha string) (string, bool) {
	l := strings.ToLower(strings.TrimSpace(linha))
	l = strings.TrimPrefix(l, "export ")

	switch {
	case strings.HasPrefix(l, "unset histfile"),
		strings.HasPrefix(l, "unset histsize"):
		return "o shell fica sem onde gravar", true
	case strings.HasPrefix(l, "set +o history"),
		strings.Contains(l, "set +o history"):
		return "o registro de histórico é desligado", true
	}

	nome, valor, ok := strings.Cut(l, "=")
	if !ok {
		return "", false
	}
	nome = strings.TrimSpace(nome)
	valor = strings.Trim(strings.TrimSpace(valor), `"'`)
	switch nome {
	case "histfile":
		if valor == "" || valor == "/dev/null" {
			return "o histórico é gravado no vazio", true
		}
	case "histsize", "histfilesize", "savehist":
		if valor == "0" {
			return "o histórico não guarda nenhuma linha", true
		}
	}
	return "", false
}
