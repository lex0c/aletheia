package checks

import (
	"strconv"
	"strings"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

func init() {
	check.Register(revshell)
	check.Register(pivot)
}

// revshell — runbook §17.
//
// A assinatura ESTRUTURAL de um shell reverso, não a assinatura de uma família:
// stdin, stdout e stderr ligados ao MESMO socket. É a definição — o shell lê
// comando da rede e devolve a saída por ela. É por isso que este check envelhece
// bem: reconhece o formato de qualquer implante, não um malware específico.
var revshell = check.Check{
	ID:       "correlate.revshell",
	Ref:      "17",
	Title:    "reverse shell: fd 0, 1 e 2 no mesmo socket",
	Group:    "net",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive,
	Requires: env.CapProcfs,
	Optional: env.CapRoot,
	Wtf:      true,
	FalsePositives: []string{
		"ativação por socket do systemd (StandardInput=socket) e inetd têm EXATAMENTE " +
			"essa forma, por design — descartados aqui pela DIREÇÃO: neles o socket é " +
			"de ENTRADA, num reverse shell é de SAÍDA",
		"sem root o dono do socket é invisível, e o achado não pode ser formado",
		"a DIREÇÃO é inferida, e não lida: o kernel não registra quem iniciou a " +
			"conexão. A dedução principal é a tabela de escuta, e ela cai quando " +
			"o serviço FECHA o listener depois de aceitar — inetd faz isso. A " +
			"faixa de porta efêmera desempata esse caso; quando as DUAS portas " +
			"caem dentro da faixa (C2 escutando em porta alta) não há o que " +
			"deduzir, e a conexão é tratada como de saída",
		"LIMITE de fonte: são lidas as tabelas TCP e UDP. Implante que usa UDP " +
			"com sendto() sem connect() não expõe o destino em /proc/net/udp — a " +
			"porta local aparece, o peer não. Socket RAW e unix não são lidos",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		for i := range f.Processes {
			p := &f.Processes[i]
			if p.Self || p.Vanished {
				continue
			}
			inode, ok := stdioSameSocket(p)
			if !ok {
				continue
			}
			sock := f.SocketByInode(inode)
			if sock == nil {
				continue // socket sumiu entre a leitura dos fds e a da tabela
			}

			// A DIREÇÃO é o descarte. Ativação por socket entrega um socket de
			// ENTRADA em fd 0/1/2; um reverse shell sai para o operador.
			if sock.Dir != facts.DirOut {
				continue
			}

			sev := check.SevCritical
			if sock.PeerScope != facts.ScopePublic {
				// destino interno: pode ser pivô lateral, mas não é o canal
				// com o operador — não merece a mesma confiança
				sev = check.SevWarn
			}

			ev := []string{
				"fd 0,1,2 → socket:[" + strconv.FormatUint(inode, 10) + "]",
				"peer=" + sock.Peer() + " (" + string(sock.PeerScope) + ", saída iniciada por este processo)",
				"exe=" + nz(p.Exe, "?"),
				"comm=" + p.Comm + " uid=" + strconv.Itoa(p.UID) + " ppid=" + strconv.Itoa(p.PPID),
			}
			if hasPTY(p) {
				// TTY do outro lado: o operador está digitando, não só
				// automatizando (runbook §17).
				ev = append(ev, "PTY aberto: shell INTERATIVO, com terminal do outro lado")
			}
			if p.StartUTC != "" {
				ev = append(ev, "início="+p.StartUTC)
			}

			fd := self.F(sev, "pid="+strconv.Itoa(p.PID), "", ev...)
			fd.Quando, fd.QuandoFonte = p.StartUTC, "início do processo"
			fd.Irreversible = true
			fd.NextSteps = []string{
				"NÃO mate antes de preservar (runbook §6) — e NÃO bloqueie só o IP: " +
					"C2 por relay não tem IP fixo (runbook §18.1)",
				preservarPID(e, p.PID),
				"isolar na camada de REDE, não no host (runbook §18)",
			}
			r.Findings = append(r.Findings, fd)
		}
		r.Partial = partialForOrphanSockets(f)
		return r
	},
}

// pivot — runbook §12.2.
//
// A assinatura estrutural de relay: um processo falando com os dois lados ao
// mesmo tempo. E a DIREÇÃO é o que separa isso de proxy reverso legítimo —
// sem ela, o check dispara em todo nginx que serve tráfego público:
//
//	proxy   ENTRADA externa  +  saída interna
//	pivô    SAÍDA   externa  +  saída interna
var pivot = check.Check{
	ID:       "net.pivot",
	Ref:      "12.2",
	Title:    "pivô: saída externa e saída interna no mesmo processo",
	Group:    "net",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive,
	Requires: env.CapProcfs,
	Optional: env.CapRoot,
	Wtf:      true,
	FalsePositives: []string{
		"agente que reporta para fora E consulta serviço interno — monitoração, " +
			"coletor de log, backup para nuvem. São poucos e você os conhece pelo nome",
		"proxy reverso NÃO cai aqui: nele o tráfego externo é de ENTRADA",
		"LIMITE de fonte: TCP e UDP. Um pivô que fale por socket RAW ou por " +
			"protocolo fora dessas duas tabelas não aparece aqui",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result

		// Um pool de aplicação tem a MESMA forma que um pivô, multiplicada pelo
		// número de workers. Ver pool.go: o agrupamento é o que impede que um
		// servidor php-fpm produza um aviso por processo.
		grupo := novoPool()
		type dados struct {
			p                  *facts.Process
			ext, intn, inbound []facts.Socket
		}
		por := map[string]*dados{}

		for i := range f.Processes {
			p := &f.Processes[i]
			if p.Self || p.Vanished {
				continue
			}

			var ext, intn, inbound []facts.Socket
			for _, s := range f.SocketsOf(p.PID) {
				if s.State != "ESTAB" {
					continue
				}
				switch {
				case s.Dir == facts.DirIn && s.PeerScope == facts.ScopePublic:
					inbound = append(inbound, s)
				case s.Dir != facts.DirOut:
					continue
				case s.PeerScope == facts.ScopePublic:
					ext = append(ext, s)
				case s.PeerScope == facts.ScopePrivate:
					intn = append(intn, s)
				}
			}
			if len(ext) == 0 || len(intn) == 0 {
				continue
			}

			// A forma é o executável mais o conjunto dos DOIS lados. Dois
			// workers que falam com destinos diferentes continuam sendo duas
			// histórias, e continuam saindo separados.
			chave := grupo.junta(nz(p.Exe, "?"), append(peersDe(ext), peersDe(intn)...), p.PID)
			if _, visto := por[chave]; !visto {
				por[chave] = &dados{p: p, ext: ext, intn: intn, inbound: inbound}
			}
		}

		for _, chave := range grupo.Grupos() {
			d := por[chave]
			pids := grupo.PIDs(chave)

			ev := []string{
				"saída externa: " + joinPeers(d.ext, 3),
				"saída interna: " + joinPeers(d.intn, 4),
				"exe=" + nz(d.p.Exe, "?"),
				"comm=" + d.p.Comm + " uid=" + strconv.Itoa(d.p.UID),
			}
			if len(d.inbound) > 0 {
				// Recebe de fora E sai para fora: pode ser proxy que também
				// fala com o operador. Vale registrar, não descartar.
				ev = append(ev, "atenção: também recebe conexão externa ("+
					joinPeers(d.inbound, 2)+") — confira se é proxy legítimo")
			}

			sujeito := "pid=" + strconv.Itoa(d.p.PID)
			if len(pids) > 1 {
				sujeito = nz(d.p.Exe, d.p.Comm)
				ev = append(ev, notaDoPool(len(pids), nz(d.p.Exe, "?")), listaDePIDs(pids))
			}

			fd := self.F(check.SevWarn, sujeito, "", ev...)
			fd.Quando, fd.QuandoFonte = d.p.StartUTC, "início do processo"
			fd.NextSteps = []string{
				"este host é CAMINHO, não só alvo: os alvos internos passam a ser suspeitos (runbook §23)",
				"o alcance interno está na §12.4; a mitigação é egress default-deny (runbook §34.3)",
			}
			r.Findings = append(r.Findings, fd)
		}
		r.Partial = partialForOrphanSockets(f)
		return r
	},
}

// stdioSameSocket devolve o inode quando fd 0, 1 e 2 apontam para o MESMO
// socket. Os três precisam existir: dois iguais e um ausente não é a forma.
func stdioSameSocket(p *facts.Process) (uint64, bool) {
	var seen [3]uint64
	for _, fd := range p.FDs {
		if fd.N > 2 || !fd.Socket {
			continue
		}
		seen[fd.N] = fd.SocketInode
	}
	if seen[0] == 0 || seen[0] != seen[1] || seen[1] != seen[2] {
		return 0, false
	}
	return seen[0], true
}

func hasPTY(p *facts.Process) bool {
	for _, fd := range p.FDs {
		if fd.PTY {
			return true
		}
	}
	return false
}

func joinPeers(ss []facts.Socket, max int) string {
	var out []string
	for i, s := range ss {
		if i >= max {
			out = append(out, "… (+"+strconv.Itoa(len(ss)-max)+")")
			break
		}
		out = append(out, s.Peer())
	}
	return strings.Join(out, " · ")
}

// partialForOrphanSockets: socket sem dono identificado significa que o check
// não pôde avaliar aquele processo. Sem isto, uma execução sem root reportaria
// cobertura completa tendo enxergado só os próprios sockets.
func partialForOrphanSockets(f *facts.Facts) []string {
	n := 0
	for _, s := range f.Sockets {
		if s.PID == 0 && s.State == "ESTAB" {
			n++
		}
	}
	if n == 0 {
		return nil
	}
	return []string{strconv.Itoa(n) + " conexões sem dono identificado não foram avaliadas"}
}

func nz(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// peersDe extrai os endereços remotos, para compor a forma do grupo.
func peersDe(ss []facts.Socket) []string {
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		out = append(out, s.Peer())
	}
	return out
}
