package facts

import (
	"sort"
	"strings"

	"github.com/lex0c/aletheia/internal/env"
)

// Montagens (runbook §8, §7.11).
//
// A tabela de montagem não é um achado por si — é o que dá SIGNIFICADO a
// achados de outros checks:
//
//	nosuid   o bit setuid de um arquivo naquele filesystem é INERTE. O achado
//	         continua verdadeiro, e a urgência dele não é a mesma
//	noexec   nada executa dali, e um binário largado num /tmp com noexec é
//	         material, não ameaça em execução
//
// É a mesma distinção que o check de rc.local já fazia: um arquivo sem bit de
// execução é inerte hoje — mas um chmod o ativa, e o ctime data isso. Aqui vale
// igual, com o `mount -o remount,suid` no lugar do chmod.
//
// E há um sinal próprio, que só a tabela mostra: uma montagem POR CIMA de
// diretório de sistema. Montar algo sobre /etc ou /usr/bin esconde o conteúdo
// real sem tocar em nenhum arquivo — e some no reboot sem deixar rastro.

// Montagem é uma linha de /proc/self/mountinfo.
type Montagem struct {
	Ponto  string `json:"mountpoint"`
	Tipo   string `json:"fstype"`
	Origem string `json:"source,omitempty"`

	// Raiz é a parte do filesystem de origem que foi montada. Diferente de "/"
	// significa BIND: um pedaço de outra árvore aparecendo aqui.
	Raiz string `json:"root,omitempty"`

	NoSuid bool `json:"nosuid,omitempty"`
	NoExec bool `json:"noexec,omitempty"`
	NoDev  bool `json:"nodev,omitempty"`
	RO     bool `json:"ro,omitempty"`

	Opcoes string `json:"options,omitempty"`

	// Dev é o dispositivo, resolvido uma vez na coleta. Existe para a varredura
	// de arquivos saber onde a árvore troca de filesystem sem perguntar ao
	// kernel a cada diretório.
	Dev uint64 `json:"-"`
}

func collectMounts(f *Facts, e *env.Env) {
	b, err := e.ReadFile("/proc/self/mountinfo")
	if err != nil {
		// Em modo image não há mountinfo, e isso não é lacuna: a tabela é do
		// host VIVO, e um rootfs desligado não tem uma. O que ela informaria —
		// se o bit setuid é inerte — passa a ser desconhecido, e o check que
		// usa isso diz que não pôde saber.
		f.denyPersist("mounts", "/proc/self/mountinfo ilegível: não dá para saber "+
			"se o filesystem de um achado está montado com nosuid ou noexec")
		return
	}

	for _, ln := range strings.Split(string(b), "\n") {
		// O formato tem campos OPCIONAIS no meio, terminados por " - ". Sem
		// respeitar isso, o tipo de filesystem sai errado em toda montagem
		// compartilhada — que é a maioria num host com systemd.
		antes, depois, ok := strings.Cut(ln, " - ")
		if !ok {
			continue
		}
		a := strings.Fields(antes)
		d := strings.Fields(depois)
		if len(a) < 6 || len(d) < 1 {
			continue
		}

		m := Montagem{
			Raiz:   desescapaMount(a[3]),
			Ponto:  desescapaMount(a[4]),
			Opcoes: a[5],
			Tipo:   d[0],
		}
		if len(d) > 1 {
			m.Origem = desescapaMount(d[1])
		}
		for _, o := range strings.Split(a[5], ",") {
			switch o {
			case "nosuid":
				m.NoSuid = true
			case "noexec":
				m.NoExec = true
			case "nodev":
				m.NoDev = true
			case "ro":
				m.RO = true
			}
		}
		if fi, err := e.Lstat(m.Ponto); err == nil {
			m.Dev, _ = dispositivoDeInfo(fi)
		}
		f.Mounts = append(f.Mounts, m)
	}

	// Do mais específico para o mais genérico: a resolução de qual montagem
	// governa um caminho pega a PRIMEIRA que casa, e sem esta ordem um
	// /tmp/x seria atribuído a "/" em vez de a /tmp.
	sort.SliceStable(f.Mounts, func(i, j int) bool {
		return len(f.Mounts[i].Ponto) > len(f.Mounts[j].Ponto)
	})
}

// MontagemDe devolve a montagem que governa um caminho, ou nil.
//
// É por PREFIXO de caminho e não por dispositivo: o que interessa é qual
// conjunto de opções vale para aquele arquivo, e é o ponto de montagem mais
// específico que decide.
func (f *Facts) MontagemDe(p string) *Montagem {
	for i := range f.Mounts {
		m := &f.Mounts[i]
		if m.Ponto == "/" || p == m.Ponto || strings.HasPrefix(p, m.Ponto+"/") {
			return m
		}
	}
	return nil
}

// desescapaMount resolve os escapes octais do mountinfo. O kernel escapa
// espaço, tab, barra invertida e nova linha — e um diretório com espaço no nome
// derrotaria a correspondência de prefixo em silêncio.
func desescapaMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	return desescapaMtree(s) // mesmo formato de escape octal
}
