package checks

import (
	"strconv"
	"strings"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

func init() { check.Register(suspiciousPath) }

// suspiciousPath — runbook §8.
//
// Não é "binário desconhecido": é binário RODANDO de um diretório onde
// instalação nenhuma coloca binário. O sinal não está no arquivo, está no lugar
// — e o lugar é escolhido pelo atacante porque é onde ele consegue escrever.
var suspiciousPath = check.Check{
	ID:       "proc.suspicious_path",
	Ref:      "8",
	Title:    "processo executando de diretório onde nada se instala",
	Group:    "proc",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive,
	Requires: env.CapProcfs,
	Optional: env.CapRoot,
	Wtf:      true,
	FalsePositives: []string{
		"instalador, build e teste rodam de /tmp por design — `go test` executa o " +
			"binário compilado a partir de /tmp/go-buildNNN, e cloud-init roda " +
			"script de /var/tmp. Em estação de desenvolvimento isto é rotina; em " +
			"servidor de produção, quase nunca",
		"atualizador de aplicativo de desktop guarda binário em ~/.config " +
			"(extensão de editor, cliente de chat). ~/.local NÃO entra aqui: é o " +
			"lugar padronizado pelo XDG para binário de usuário",
		"sem root, o exe de processo alheio é ilegível e o achado não pode ser formado",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		var unreadable int
		for i := range f.Processes {
			p := &f.Processes[i]
			if p.Self || p.Vanished {
				continue
			}
			if p.ExeDenied {
				unreadable++
				continue
			}
			// memfd e binário apagado têm check próprio (§3.16, §3.14): contar
			// duas vezes o mesmo processo confunde a triagem.
			if p.Exe == "" || p.ExeMemfd || p.ExeDeleted {
				continue
			}
			why, ok := suspectDir(p.Exe)
			if !ok {
				continue
			}

			ev := []string{
				"exe=" + p.Exe,
				why,
				"comm=" + p.Comm + " uid=" + strconv.Itoa(p.UID) + " ppid=" + strconv.Itoa(p.PPID),
			}
			if p.Cwd != "" {
				ev = append(ev, "cwd="+p.Cwd)
			}
			// O FILESYSTEM pode já ter impedido isto, e a diferença muda a
			// urgência sem mudar o fato.
			//
			// É o simétrico do `nosuid` no check de privilégio: lá o bit é
			// inerte, aqui o binário não executaria daquele caminho. Um processo
			// EM EXECUÇÃO num diretório noexec significa que ou ele foi iniciado
			// antes da montagem, ou alguém copiou para outro lugar para rodar —
			// e as duas coisas o operador precisa saber.
			if m := f.MontagemDe(p.Exe); m != nil && m.NoExec {
				ev = append(ev, "e "+m.Ponto+" está montado com `noexec`: dali não "+
					"se executa — este processo começou antes da montagem, ou foi "+
					"iniciado a partir de uma cópia em outro lugar")
			}
			if len(p.Argv) > 0 {
				ev = append(ev, "argv="+strings.Join(p.Argv, " "))
			}
			if p.StartUTC != "" {
				ev = append(ev, "início="+p.StartUTC)
			}

			fd := self.F(check.SevWarn, "pid="+strconv.Itoa(p.PID), "", ev...)
			fd.Quando, fd.QuandoFonte = p.StartUTC, "início do processo"
			fd.Irreversible = true
			fd.NextSteps = []string{
				"preserve o binário ANTES de qualquer coisa — em tmpfs " +
					"ele some no reboot, e em /tmp o systemd-tmpfiles o apaga sozinho",
				preservarPID(e, p.PID),
				"identifique a FAMÍLIA antes de mitigar: o nome da ferramenta define o " +
					"raio de alcance",
			}
			r.Findings = append(r.Findings, fd)
		}
		r.Partial = partialForUnreadable(unreadable)
		return r
	},
}

// suspectDir classifica o diretório do executável. A ordem importa: a exceção
// do XDG precisa ser avaliada antes da regra do diretório oculto no home.
func suspectDir(exe string) (string, bool) {
	switch {
	// tmpfs: o arquivo mora em RAM e some no reboot. Nada se instala aqui, e
	// o atacante ganha de brinde a destruição da evidência (runbook §3.16).
	case hasDir(exe, "/dev/shm/"), hasDir(exe, "/run/shm/"), hasDir(exe, "/run/user/"):
		return "em tmpfs: o binário existe só em RAM e some no reboot", true

	case hasDir(exe, "/tmp/"), hasDir(exe, "/var/tmp/"):
		return "em diretório gravável por qualquer usuário", true

	// /dev não é lugar de executável — exceto /dev/shm, já tratado acima.
	case hasDir(exe, "/dev/"):
		return "sob /dev, que é árvore de device e não de programa", true

	// ~/.local é o caminho que o XDG define para binário de usuário: pipx,
	// pip --user e cargo instalam ali. Não é sinal.
	case strings.Contains(exe, "/.local/"):
		return "", false

	case isHome(exe) && (strings.Contains(exe, "/.config/") || strings.Contains(exe, "/.cache/")):
		return "em diretório de configuração/cache do usuário, que guarda estado e não programa", true
	}
	return "", false
}

func hasDir(path, dir string) bool { return strings.HasPrefix(path, dir) }

func isHome(path string) bool {
	return strings.HasPrefix(path, "/home/") || strings.HasPrefix(path, "/root/")
}

// diretorioDeSistema diz se o caminho está numa árvore governada pelo
// gerenciador de pacotes — e portanto se o binário ali herda alguma reputação.
//
// UMA definição, usada por toda isenção que decide reputação por caminho.
// Havia duas e elas discordavam: a do runtime com JIT casava "/usr/" inteiro,
// a do AuthorizedKeysCommand listava subdiretórios. O comentário da segunda
// dizia "mesma regra do runtime com JIT" — e não era.
//
// A discordância tinha consequência medida: um binário chamado `node` em
// /usr/local/bin herdava a isenção de JIT porque "/usr/" casa "/usr/local/".
//
// /usr/local é EXCLUÍDO apesar de estar sob /usr. A FHS o reserva ao
// administrador LOCAL: é onde quem conseguiu root escreve, e todo o resto
// desta ferramenta o trata assim — "sem dono ali é a norma". Reputação de
// pacote não se herda de um diretório que existe para receber o que não vem de
// pacote.
//
// LIMITE: isto é reputação por CAMINHO, que é o discriminador fraco. O forte é
// a pergunta de propriedade — "que pacote entregou este arquivo?" —, e ela nem
// sempre tem resposta (base RPM não é consultável). Onde houver resposta, ela
// deveria mandar.
func diretorioDeSistema(p string) bool {
	if p == "" || strings.HasPrefix(p, "/usr/local/") {
		return false
	}
	for _, d := range []string{
		"/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/",
		"/opt/", "/snap/", "/nix/store/", "/var/lib/flatpak/", "/app/",
	} {
		if strings.HasPrefix(p, d) {
			return true
		}
	}
	return false
}
