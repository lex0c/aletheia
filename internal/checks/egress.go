package checks

import (
	"strconv"
	"strings"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

func init() {
	check.Register(escutaSemDono)
	check.Register(saidaSemDono)
}

// Rede cruzada com propriedade de pacote (runbook §4, §24).
//
// Os dois checks de rede que já existiam olham a FORMA da conexão: o revshell
// pela tabela de descritores, o pivô pela direção. Os dois daqui olham outra
// coisa — QUEM está do lado de cá.
//
// A pergunta é a mesma nos dois, e não tem nada a ver com o endereço de
// destino:
//
//	este processo que fala com a rede veio de um pacote?
//
// Reputação de IP envelhece em dias e exige uma fonte externa que a ferramenta
// não tem. "Nenhum pacote reivindica este binário" não envelhece, é local, e
// não depende de o invasor ter usado uma infraestrutura já conhecida — o que
// hoje custa quase nada de evitar.
//
// O discriminador não existia quando os checks de rede foram escritos. Passou a
// existir com o §24, e é ele que torna estes dois possíveis sem virar ruído:
// sem propriedade de pacote, "processo com conexão de saída" descreve metade de
// um servidor normal.

// escutaSemDono — runbook §4.2, §24.
//
// Uma porta aberta para fora por um binário que nenhum pacote entregou. É a
// forma do backdoor de escuta — o oposto do shell reverso, e o que sobra quando
// o firewall de saída é rígido mas o de entrada tem um furo.
var escutaSemDono = check.Check{
	ID:       "net.listener_unowned",
	Ref:      "4.2",
	Title:    "porta exposta para fora por binário que nenhum pacote entregou",
	Group:    "net",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive,
	Requires: env.CapProcfs | env.CapFilesystem,
	Optional: env.CapRoot,
	Wtf:      true,
	FalsePositives: []string{
		"aplicação instalada à mão é a norma em servidor real e cai exatamente " +
			"aqui: binário em /usr/local ou /opt, escutando numa porta alta, sem " +
			"dono de pacote porque ninguém empacotou. Por isso /usr/local e /opt " +
			"saem com severidade menor — o que muda o peso é o CAMINHO",
		"aplicação em contêiner quase nunca tem gerenciador de pacotes " +
			"reivindicando o binário da própria aplicação: num host de contêineres " +
			"este check fala muito e informa pouco",
		"sem root o dono do socket é invisível, e a escuta some junto — a " +
			"cobertura é que diz se a resposta vale",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		semDono := caminhosSemDono(f)
		if len(semDono) == 0 {
			r.Partial = append(r.Partial, f.PersistDenied["pkg"]...)
			return r
		}

		for i := range f.Sockets {
			s := &f.Sockets[i]
			if s.Dir != facts.DirListen || !facts.IsExposedLocal(s.LocalIP) || s.PID == 0 {
				continue
			}
			p := f.ProcessByPID(s.PID)
			if p == nil || p.Self || p.Exe == "" || !semDono[p.Exe] {
				continue
			}

			sev, nota := pesoDoCaminho(p.Exe)
			ev := []string{
				p.Comm + " (pid=" + strconv.Itoa(s.PID) + ") escuta em " +
					s.LocalIP + ":" + strconv.Itoa(s.LocalPort) + " (" + s.Proto + ")",
				"exe=" + p.Exe + " — nenhum pacote reivindica este binário (base: " +
					f.Pkg.Kind + ")",
				nota,
				"o endereço não é de loopback: a porta está aberta para fora",
			}
			if nome, ok := portasDeServico[s.LocalPort]; ok {
				// Ocupar a porta de um serviço conhecido com outro binário é a
				// substituição do serviço, e vale mais que a porta alta.
				sev = check.SevCritical
				ev = append(ev, "e a porta é a de "+nome+": um binário sem dono "+
					"ocupando a porta de um serviço conhecido é substituição, não "+
					"aplicação nova")
			}

			fd := self.F(sev, "pid="+strconv.Itoa(s.PID), "", ev...)
			fd.Irreversible = true
			fd.NextSteps = []string{
				"sudo cp " + p.Exe + " \"$IR/\"   # a amostra, antes de qualquer coisa (runbook §6)",
				"pergunte QUEM instalou: aplicação manual legítima tem essa mesma forma",
				"isole na camada de REDE antes de mexer no host (runbook §18)",
			}
			r.Findings = append(r.Findings, fd)
		}
		r.Partial = append(r.Partial, f.PersistDenied["pkg"]...)
		return r
	},
}

// saidaSemDono — runbook §4.3, §24.
//
// Conexão estabelecida para endereço público, saindo de um binário que nenhum
// pacote entregou. É a forma do canal de comando e controle.
//
// O que este check NÃO faz, e é deliberado: não olha o endereço de destino
// contra lista nenhuma. Reputação de IP envelhece em dias, exige fonte externa
// e falha justamente contra quem alugou infraestrutura ontem — que é a maioria.
// "Ninguém empacotou este binário" é local, não envelhece, e o invasor não
// contorna sem empacotar o implante.
var saidaSemDono = check.Check{
	ID:       "net.egress_unowned",
	Ref:      "4.3",
	Title:    "conexão para endereço público a partir de binário que nenhum pacote entregou",
	Group:    "net",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive,
	Requires: env.CapProcfs | env.CapFilesystem,
	Optional: env.CapRoot,
	Wtf:      true,
	FalsePositives: []string{
		"agente instalado à mão que fala com a nuvem por desenho — APM, coletor " +
			"de métricas, backup, cliente de VPN — tem EXATAMENTE esta forma, e " +
			"em servidor real existe mais de um",
		"aplicação própria chamando API externa é o caso mais comum de todos: " +
			"o binário não vem de pacote porque é da casa",
		"o que este check NÃO diz: nada sobre o destino. Um endereço público não " +
			"é suspeito — o achado é sobre a ORIGEM, e a pergunta que fica é " +
			"'quem instalou este binário?', não 'que IP é esse?'",
		"conexão de vida curta pode não estar na tabela no instante da leitura: " +
			"beacon com intervalo longo passa despercebido numa varredura única, " +
			"e é o motivo de o modo de observação existir",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		semDono := caminhosSemDono(f)
		if len(semDono) == 0 {
			r.Partial = append(r.Partial, f.PersistDenied["pkg"]...)
			return r
		}

		// Um processo pode ter muitas conexões para o mesmo destino; o achado é
		// sobre o PROCESSO, e repetir por socket inflaria a triagem.
		visto := map[int]bool{}
		for i := range f.Sockets {
			s := &f.Sockets[i]
			if s.Dir != facts.DirOut || s.PeerScope != facts.ScopePublic || s.PID == 0 {
				continue
			}
			if visto[s.PID] {
				continue
			}
			p := f.ProcessByPID(s.PID)
			if p == nil || p.Self || p.Exe == "" || !semDono[p.Exe] {
				continue
			}
			visto[s.PID] = true

			sev, nota := pesoDoCaminho(p.Exe)
			destinos := destinosPublicos(f, s.PID)
			ev := []string{
				p.Comm + " (pid=" + strconv.Itoa(s.PID) + ") mantém conexão para " +
					strings.Join(destinos, ", "),
				"exe=" + p.Exe + " — nenhum pacote reivindica este binário (base: " +
					f.Pkg.Kind + ")",
				nota,
				"o achado é sobre a ORIGEM, não sobre o destino: nenhuma lista de " +
					"reputação foi consultada, e nenhuma precisa ser",
			}
			if p.StartUTC != "" {
				ev = append(ev, "processo iniciado em "+p.StartUTC)
			}

			fd := self.F(sev, "pid="+strconv.Itoa(s.PID), "", ev...)
			fd.Irreversible = true
			fd.NextSteps = []string{
				"sudo cp " + p.Exe + " \"$IR/\"   # a amostra, antes de qualquer coisa (runbook §6)",
				"pergunte ao time se este binário deveria falar com a internet",
				"o destino vale como IOC de frota: procure a mesma conexão nos " +
					"outros hosts (runbook §23)",
			}
			r.Findings = append(r.Findings, fd)
		}
		r.Partial = append(r.Partial, f.PersistDenied["pkg"]...)
		return r
	},
}

// caminhosSemDono é o conjunto dos executáveis que nenhum pacote reivindica.
//
// Devolve vazio quando a base de pacotes não pôde ser consultada, e é por isso
// que os dois checks propagam a lacuna: sem a resposta, "nenhuma conexão de
// binário sem dono" significaria apenas que ninguém perguntou.
func caminhosSemDono(f *facts.Facts) map[string]bool {
	out := map[string]bool{}
	for i := range f.Ownership {
		if !f.Ownership[i].Owned {
			out[f.Ownership[i].Path] = true
		}
	}
	return out
}

// pesoDoCaminho traduz onde o binário mora na severidade, com o motivo junto.
// É a mesma escada do §24, e ela existe porque /usr/local sem dono é a norma e
// /usr/bin sem dono não é.
func pesoDoCaminho(exe string) (check.Severity, string) {
	if _, gravavel := suspectDir(exe); gravavel {
		return check.SevCritical, "e roda de diretório gravável por qualquer um: " +
			"nada se instala ali de propósito"
	}
	if dirDePacote(exe) {
		return check.SevCritical, "e está em diretório do GERENCIADOR DE PACOTES: " +
			"tudo ali deveria vir de um pacote, e este arquivo não vem de nenhum"
	}
	return check.SevWarn, "está em diretório de instalação manual (/usr/local, " +
		"/opt): sem dono ali é a norma, e o que dá sinal é a conexão"
}

// destinosPublicos lista para onde o processo fala. Um só destino é integração;
// vários, ou um que ninguém reconhece, é a pergunta que interessa.
func destinosPublicos(f *facts.Facts, pid int) []string {
	var out []string
	visto := map[string]bool{}
	for i := range f.Sockets {
		s := &f.Sockets[i]
		if s.PID != pid || s.Dir != facts.DirOut || s.PeerScope != facts.ScopePublic {
			continue
		}
		d := s.PeerIP + ":" + strconv.Itoa(s.PeerPort)
		if visto[d] {
			continue
		}
		visto[d] = true
		out = append(out, d)
		if len(out) >= 5 {
			break
		}
	}
	return out
}

// portasDeServico são portas cujo ocupante é conhecido de antemão. Um binário
// sem dono numa delas não é aplicação nova: é o serviço substituído.
var portasDeServico = map[int]string{
	22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
	143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
	5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB",
}
