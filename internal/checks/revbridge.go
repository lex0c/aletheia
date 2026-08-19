package checks

import (
	"strconv"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

func init() { check.Register(revshellBridge) }

// revshellBridge — runbook §17.
//
// # O que o correlate.revshell NÃO vê
//
// O check clássico exige a forma pura: fd 0, 1 e 2 do MESMO processo no MESMO
// socket. Ela é de altíssima precisão e não se mexe. Mas a evasão mais comum
// dela põe um intermediário no meio:
//
//	bash                     socat / python / perl / nc
//	 stdin  ← pipe:[Y] ←──────  lê da rede, escreve no pipe
//	 stdout → pipe:[X] →──────  lê do pipe, escreve na rede
//	                                    │
//	                                    └── socket ESTAB de SAÍDA, destino público
//
// O shell nunca toca o socket: ele lê comando de um PIPE e devolve saída por
// outro. O correlate.revshell não casa, e o canal com o operador passa.
//
// # A assinatura estrutural, e por que ela é precisa
//
// As DUAS pontas de um pipe anônimo carregam o mesmo inode, então dois
// processos com o mesmo PipeInode detêm referência ao MESMO objeto pipe. Esse é
// o fato, e ele não depende do PPID — que a morte do pai zeraria.
//
// O caminho NORMAL de chegar aí é herança de quem criou o pipe, e é por isso
// que o achado vale. Mas "compartilham o pipe" não é a mesma afirmação que
// "têm ancestral comum": um fd atravessa um socket unix por SCM_RIGHTS, e
// supervisor e ativação por socket fazem isso de propósito. O achado é AVISO
// justamente por essa distância — ele descreve o canal, e quem decide o
// parentesco é quem investiga.
//
// O que separa isto de um pipeline comum (`ps | grep`) é a combinação: de um
// lado um SHELL, com o STDIN vindo do pipe — ele recebe comando de fora —, e do
// outro a ponte com um socket de SAÍDA para destino PÚBLICO. `logger.sh | curl`
// não casa: ali o shell ESCREVE no pipe (stdout), não LÊ dele (stdin), e não
// recebe comando de ninguém.
//
// # WARN, não CRITICAL
//
// O correlate.revshell, que vê a forma pura, é que é CRITICAL. Esta é a variante
// mais fraca — precisa de mais peças para casar e tem mais história legítima
// (agente de acesso remoto) —, então entra como WARN, e a evidência de
// proveniência da ponte é o que o operador usa para decidir.
var revshellBridge = check.Check{
	ID:       "correlate.revshell_bridge",
	Ref:      "17",
	Title:    "reverse shell por ponte: shell lê de um pipe, o outro lado fala com a rede",
	Group:    "net",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive,
	Requires: env.CapProcfs,
	Optional: env.CapRoot | env.CapPkgDB,
	Wtf:      true,
	FalsePositives: []string{
		"AGENTE DE ACESSO REMOTO tem exatamente esta forma por design: SSM, " +
			"Teleport, um runner de CI e o próprio sshd podem dar a um shell um " +
			"stdin vindo de pipe, com o processo do outro lado falando com a " +
			"rede. O discriminador é a PROVENIÊNCIA da ponte — um socat/python " +
			"de /tmp ou sem dono de pacote é o sinal; um agente em /usr, com " +
			"dono, é provavelmente legítimo",
		"a DIREÇÃO do socket é inferida, não lida (mesma ressalva do " +
			"correlate.revshell): a dedução cai quando o serviço fecha o listener " +
			"depois de aceitar, e a faixa de porta efêmera desempata",
		"sem root, o dono do socket e os fds da ponte de processo alheio são " +
			"invisíveis, e o achado não pode ser formado",
		"LIMITE de forma: cobre a ponte por PIPE. A ponte por PTY (socat com " +
			"pty) é outra estrutura — /dev/pts/N não carrega inode compartilhado " +
			"como o pipe — e NÃO entra aqui; é a próxima fase",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		semDono := caminhosSemDono(f)
		for i := range f.Processes {
			s := &f.Processes[i]
			if s.Self || s.Vanished || !ehShell(s) {
				continue
			}
			// O STDIN do shell vindo de um pipe é o que importa: é por ele que
			// o comando entra. Um shell que só ESCREVE num pipe (stdout) é um
			// pipeline comum, e não recebe ordem de ninguém.
			stdin := pipeDoFD(s, 0)
			if stdin == 0 {
				continue
			}
			for _, bpid := range f.PidsComPipe(stdin) {
				if bpid == s.PID {
					continue
				}
				b := f.ProcessByPID(bpid)
				if b == nil || b.Self || b.Vanished {
					continue
				}
				canal := canalDeSaidaPublico(f, bpid)
				if canal == nil {
					continue
				}

				ev := []string{
					"shell pid=" + strconv.Itoa(s.PID) + " (" + nz(s.Exe, s.Comm) +
						") lê do pipe:[" + strconv.FormatUint(stdin, 10) + "]",
					"a ponte pid=" + strconv.Itoa(bpid) + " (" + nz(b.Exe, b.Comm) +
						") segura o mesmo pipe e fala com " + canal.Peer() + " (saída, público)",
				}
				// Bidirecional: a saída do shell também volta pela ponte. É a
				// forma completa do canal, e vale dizer.
				if saida := pipeDoFD(s, 1); saida != 0 && saida != stdin && seguraPipe(f, bpid, saida) {
					ev = append(ev, "e a SAÍDA do shell (stdout) volta pela ponte por "+
						"pipe:["+strconv.FormatUint(saida, 10)+"]: canal bidirecional")
				}
				ev = append(ev, provenienciaDaPonte(b, semDono)...)
				ev = append(ev, "comm shell="+s.Comm+" · comm ponte="+b.Comm+
					" · uid shell="+strconv.Itoa(s.UID)+" uid ponte="+strconv.Itoa(b.UID))

				fd := self.F(check.SevWarn, "pid="+strconv.Itoa(s.PID), "", ev...)
				fd.Quando, fd.QuandoFonte = s.StartUTC, "início do shell"
				fd.Irreversible = true
				fd.NextSteps = []string{
					"NÃO mate antes de preservar: o canal vive nos DOIS processos, e " +
						"matar um destrói o que o outro explica (runbook §6)",
					preservarPID(e, s.PID),
					preservarPID(e, bpid),
					"isolar na camada de REDE, não no host — e não bloqueie só o IP: " +
						"C2 por relay não tem IP fixo (runbook §18)",
				}
				r.Findings = append(r.Findings, fd)
			}
		}
		r.Partial = partialForOrphanSockets(f)
		return r
	},
}

// ehShell reconhece o shell pelo nome do binário e pelo comm. É o mesmo
// conjunto que a árvore de processos usa (tree.go).
func ehShell(p *facts.Process) bool {
	return shells[p.Comm] || (p.Exe != "" && shells[baseDe(p.Exe)])
}

// pipeDoFD devolve o inode do pipe naquele descritor, ou 0 se o fd não é pipe.
func pipeDoFD(p *facts.Process, n int) uint64 {
	for _, fd := range p.FDs {
		if fd.N == n && fd.Pipe {
			return fd.PipeInode
		}
	}
	return 0
}

func seguraPipe(f *facts.Facts, pid int, inode uint64) bool {
	for _, h := range f.PidsComPipe(inode) {
		if h == pid {
			return true
		}
	}
	return false
}

// canalDeSaidaPublico devolve um socket ESTABELECIDO de SAÍDA para destino
// público que o processo segura, ou nil. É o que faz a ponte ser uma ponte com
// o operador, e não com um serviço interno.
func canalDeSaidaPublico(f *facts.Facts, pid int) *facts.Socket {
	for _, sk := range f.SocketsOf(pid) {
		if sk.Dir == facts.DirOut && sk.State == "ESTAB" && sk.PeerScope == facts.ScopePublic {
			s := sk
			return &s
		}
	}
	return nil
}

// provenienciaDaPonte é a evidência que decide o falso positivo: de onde vem o
// binário da ponte. É a mesma escada do §24 — um socat de /tmp ou sem dono não
// tem leitura inocente; um agente de acesso remoto em /usr, com dono, tem.
func provenienciaDaPonte(b *facts.Process, semDono map[string]bool) []string {
	var ev []string
	switch {
	case b.ExeMemfd:
		ev = append(ev, "a ponte NUNCA esteve em disco (memfd): fileless")
	case b.ExeDeleted:
		ev = append(ev, "o binário da ponte foi APAGADO do disco")
	}
	if motivo, gravavel := suspectDir(b.Exe); gravavel {
		ev = append(ev, "a ponte roda "+motivo)
	} else if b.Exe != "" && semDono[b.Exe] {
		ev = append(ev, "nenhum pacote reivindica o binário da ponte ("+b.Exe+")")
	} else if b.Exe != "" {
		ev = append(ev, "a ponte ("+b.Exe+") tem dono de pacote: pode ser agente de "+
			"acesso remoto legítimo — confirme pelo nome antes de concluir")
	}
	return ev
}
