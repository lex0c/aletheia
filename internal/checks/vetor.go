package checks

import (
	"sort"
	"strconv"
	"strings"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

func init() {
	check.Register(backendExposto)
	check.Register(vetorPorUsuario)
}

// backendExposto — runbook §15.
//
// # A segunda armadilha do proxy
//
// O runbook é explícito: não confie no proxy como proteção, porque "a porta
// interna pode estar exposta direto — o atacante pula o proxy". Um backend que
// deveria ouvir só o nginx em 127.0.0.1 e está em 0.0.0.0 é alcançável da rede
// inteira, e todo filtro que mora no proxy — WAF, autenticação, rate limit —
// deixa de existir para quem for direto.
//
// # Como isto se afirma sem adivinhar
//
// "Está em 0.0.0.0" sozinho não é achado: metade dos serviços de um host
// legítimo escuta assim, de propósito. O que transforma isso em sinal é a
// EVIDÊNCIA DE USO:
//
//	escuta fora do loopback           condição necessária, e insuficiente
//	e TODAS as conexões estabelecidas o serviço é usado só de dentro — então
//	nele vêm do loopback              ele NÃO precisava estar aberto para fora
//
// Um servidor web de verdade tem conexão de fora e não cai aqui. Um backend
// atrás de proxy só conversa com o proxy, que é local — e é exatamente esse o
// caso que o runbook manda procurar.
var backendExposto = check.Check{
	ID:       "net.backend_exposed",
	Ref:      "15",
	Title:    "serviço usado só pelo proxy local, mas exposto para a rede inteira",
	Group:    "net",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive,
	Requires: env.CapProcfs,
	Optional: env.CapRoot,
	Wtf:      false,
	FalsePositives: []string{
		"SERVIÇO RECÉM-INICIADO ainda não recebeu conexão de fora, e no instante " +
			"da varredura todas as que existem são locais. A janela é estreita, " +
			"mas é real — confirme com uma segunda varredura",
		"balanceador ou health check que vem de FORA e ainda não estava " +
			"conectado no instante da leitura tem o mesmo efeito",
		"há casos em que o bind aberto é deliberado: cluster que fala entre nós, " +
			"réplica de banco, agente que escuta a rede de gestão. Aqui o achado " +
			"é 'ninguém de fora estava usando', não 'ninguém deveria usar'",
		"sem root, o dono de socket alheio é invisível e o serviço não é " +
			"nomeado: o achado sai menor, não sai errado",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result

		// Por PORTA local, não por processo: um pool com SO_REUSEPORT tem N
		// processos na mesma porta, e a pergunta é sobre a porta.
		type escutaAberta struct {
			porta            int
			ip, proto        string
			pid              int
			comm             string
			locais, externas int
			paresLocais      []string
		}
		por := map[string]*escutaAberta{}
		var ordem []string

		for i := range f.Sockets {
			s := &f.Sockets[i]
			if s.State != "LISTEN" || ehLoopback(s.LocalIP) {
				continue
			}
			k := s.Proto + ":" + strconv.Itoa(s.LocalPort)
			if _, visto := por[k]; !visto {
				p := f.ProcessByPID(s.PID)
				comm := s.Comm
				if p != nil {
					comm = p.Comm
				}
				por[k] = &escutaAberta{porta: s.LocalPort, ip: s.LocalIP,
					proto: s.Proto, pid: s.PID, comm: comm}
				ordem = append(ordem, k)
			}
		}
		if len(por) == 0 {
			r.Partial = partialForOrphanSockets(f)
			return r
		}

		// As conexões ESTABELECIDAS na mesma porta local dizem quem de fato usa.
		for i := range f.Sockets {
			s := &f.Sockets[i]
			if s.State != "ESTAB" || s.Dir != facts.DirIn {
				continue
			}
			a, ok := por[s.Proto+":"+strconv.Itoa(s.LocalPort)]
			if !ok {
				continue
			}
			if ehLoopback(s.PeerIP) {
				a.locais++
				if len(a.paresLocais) < 3 {
					a.paresLocais = append(a.paresLocais, s.Peer())
				}
				continue
			}
			a.externas++
		}

		for _, k := range ordem {
			a := por[k]
			// Sem NENHUMA conexão não há evidência de uso, e sem evidência isto
			// seria só "escuta em 0.0.0.0" — que é metade dos serviços de
			// qualquer host, e não é achado.
			if a.locais == 0 || a.externas > 0 {
				continue
			}
			ev := []string{
				"escuta em " + a.ip + ":" + strconv.Itoa(a.porta) + " (" + a.proto +
					"), que não é loopback: alcançável de fora do host",
				"e as " + strconv.Itoa(a.locais) + " conexão(ões) estabelecida(s) " +
					"nesta porta vêm todas do LOOPBACK: " + strings.Join(a.paresLocais, ", "),
				"quem usa este serviço está DENTRO do host — o proxy local. Quem " +
					"vier de fora fala direto com ele, e não passa por filtro nenhum",
				"processo: " + a.comm + " (pid=" + strconv.Itoa(a.pid) + ")",
			}
			fd := self.F(check.SevWarn, a.ip+":"+strconv.Itoa(a.porta), "", ev...)
			fd.NextSteps = []string{
				"o bind correto para backend atrás de proxy é 127.0.0.1 (runbook §15)",
				"confirme de fora: o que responde nesta porta a partir de outro host?",
				"enquanto isso, a proteção que mora no proxy — WAF, autenticação, " +
					"limite de taxa — não vale para quem chega direto",
			}
			r.Findings = append(r.Findings, fd)
		}
		r.Partial = partialForOrphanSockets(f)
		return r
	},
}

func ehLoopback(ip string) bool {
	return strings.HasPrefix(ip, "127.") || ip == "::1" ||
		strings.HasPrefix(ip, "[::ffff:127.")
}

// vetorPorUsuario — runbook §14.
//
// # A heurística que estreita o vetor
//
// O runbook: "o backdoor rodou como um usuário específico. SÓ serviços que
// rodam como ESSE usuário podem ser o vetor — o resto provavelmente não é a
// entrada". O exemplo dele é direto: se o backdoor roda como `app-user` e o PHP
// roda como `www-data`, um RCE no PHP não explica o backdoor.
//
// É uma pergunta que a ferramenta pode responder sozinha, porque ela já tem as
// duas metades — o uid de cada processo e o dono de cada porta —, e é uma das
// poucas que ELIMINA hipóteses em vez de acrescentar.
//
// # Por que INFO
//
// Isto não acusa nada: nomeia por onde a entrada PODE ter acontecido, dado o
// que os outros checks acharam. Sem achado nenhum no host, não há pergunta — e
// o check fica calado.
var vetorPorUsuario = check.Check{
	ID:       "net.vector_same_user",
	Ref:      "14",
	Title:    "por onde a entrada pode ter acontecido: serviços do mesmo usuário",
	Group:    "net",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive,
	Requires: env.CapProcfs,
	Optional: env.CapRoot,
	FalsePositives: []string{
		"não é achado: é ELIMINAÇÃO de hipótese. Diz por onde a entrada pode " +
			"ter vindo, dado o usuário do que foi encontrado — e não que aquele " +
			"serviço tenha sido explorado",
		"a heurística cai quando houve escalada ANTES: quem já virou root escolhe " +
			"o usuário do que vai rodar, e aí o uid não diz mais de onde veio",
		"serviço que escuta como root é vetor para tudo, e não estreita nada",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result

		// Os uids dos processos que rodam de lugar suspeito ou sem dono de
		// pacote — o mesmo critério que os outros checks usam para acusar.
		alvos := map[int][]string{}
		for i := range f.Processes {
			p := &f.Processes[i]
			if p.Self || p.Vanished || p.Exe == "" {
				continue
			}
			if _, suspeito := suspectDir(p.Exe); !suspeito {
				continue
			}
			alvos[p.UID] = append(alvos[p.UID], p.Comm+" (pid="+strconv.Itoa(p.PID)+") "+p.Exe)
		}
		if len(alvos) == 0 {
			return r
		}

		// Os listeners de cada uid: são eles que aceitam dado de fora, e
		// portanto os únicos candidatos a porta de entrada.
		escutas := map[int][]string{}
		for i := range f.Sockets {
			s := &f.Sockets[i]
			if s.State != "LISTEN" || s.PID == 0 {
				continue
			}
			p := f.ProcessByPID(s.PID)
			if p == nil {
				continue
			}
			escutas[p.UID] = append(escutas[p.UID],
				p.Comm+" em "+s.Local()+" (pid="+strconv.Itoa(p.PID)+")")
		}

		for _, uid := range ordenados(alvos) {
			ev := []string{
				"o que foi encontrado roda como uid " + strconv.Itoa(uid) + ": " +
					strings.Join(corta(alvos[uid], 3), " · "),
			}
			if svc := escutas[uid]; len(svc) > 0 {
				ev = append(ev,
					"serviços que escutam COM O MESMO uid, e portanto são candidatos "+
						"a porta de entrada: "+strings.Join(corta(svc, 4), " · "),
					"os serviços de OUTRO usuário provavelmente não são o vetor: um "+
						"RCE neles daria o uid deles, não este (runbook §14)")
			} else {
				ev = append(ev,
					"NENHUM serviço escuta com este uid neste host: a entrada "+
						"provavelmente não foi por rede local — olhe credencial "+
						"válida, movimentação lateral e agendamento (runbook §12)")
			}
			r.Findings = append(r.Findings, self.F(check.SevInfo,
				"uid "+strconv.Itoa(uid), "", ev...))
		}
		return r
	},
}

func ordenados(m map[int][]string) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}
