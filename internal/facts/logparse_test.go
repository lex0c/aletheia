package facts

import (
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// ctxDeTeste fixa âncora e fuso para que a tabela abaixo não dependa do dia em
// que roda — o mesmo motivo pelo qual a produção não usa time.Now().
func ctxDeTeste() contextoDeTempo {
	return contextoDeTempo{
		Loc:    time.UTC,
		Ancora: time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC),
		Agora:  time.Date(2026, 8, 24, 18, 0, 0, 0, time.UTC),
	}
}

// A tabela do que este parser PROMETE entender.
//
// Cada linha aqui é uma variante que existe em campo. O que não estiver aqui e
// aparecer num host real vira contador de "candidata não reconhecida" — que é o
// sinal de que o formato daquele host não é este, e o coletor declara lacuna em
// vez de devolver zero eventos com cara de host limpo.
func TestParseDeLinhaPorProdutor(t *testing.T) {
	casos := []struct {
		nome  string
		linha string
		quer  EventoDeLog
	}{
		{
			nome: "sshd: chave pública traz o FINGERPRINT, que o utmp não tem",
			linha: "Aug 24 01:20:33 host sshd[1234]: Accepted publickey for deploy " +
				"from 185.10.2.4 port 55234 ssh2: RSA SHA256:47DEQpj8HBSa",
			quer: EventoDeLog{
				Kind: "auth.accepted", At: "2026-08-24T01:20:33Z", AtKnown: true, AtAnoInferido: true,
				User: "deploy", RemoteIP: "185.10.2.4", Metodo: "publickey",
				Fingerprint: "SHA256:47DEQpj8HBSa", Process: "sshd", PID: 1234,
			},
		},
		{
			nome:  "sshd: senha aceita, sem fingerprint",
			linha: "Aug 24 01:21:00 host sshd[9]: Accepted password for root from 10.0.0.1 port 5 ssh2",
			quer: EventoDeLog{
				Kind: "auth.accepted", At: "2026-08-24T01:21:00Z", AtKnown: true, AtAnoInferido: true,
				User: "root", RemoteIP: "10.0.0.1", Metodo: "password",
				Process: "sshd", PID: 9,
			},
		},
		{
			nome:  "sshd: usuário inválido é Kind PRÓPRIO, não uma falha qualquer",
			linha: "Aug 24 01:22:00 host sshd[9]: Failed password for invalid user admin from 1.2.3.4 port 5 ssh2",
			quer: EventoDeLog{
				Kind: "auth.invalid_user", At: "2026-08-24T01:22:00Z", AtKnown: true, AtAnoInferido: true,
				User: "admin", RemoteIP: "1.2.3.4", Metodo: "password",
				Process: "sshd", PID: 9,
			},
		},
		{
			nome: "sshd-session: o OpenSSH 9.8 partiu o binário em dois",
			linha: "Aug 24 01:23:00 host sshd-session[77]: Accepted publickey for ana " +
				"from 10.1.1.1 port 5 ssh2: ED25519 SHA256:AAAA",
			quer: EventoDeLog{
				Kind: "auth.accepted", At: "2026-08-24T01:23:00Z", AtKnown: true, AtAnoInferido: true,
				User: "ana", RemoteIP: "10.1.1.1", Metodo: "publickey",
				Fingerprint: "SHA256:AAAA", Process: "sshd-session", PID: 77,
			},
		},
		{
			nome:  "sudo: o COMMAND passa pelo resolvedor de alvos",
			linha: "Aug 24 02:00:00 host sudo[5]:   deploy : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/tmp/.upd",
			quer: EventoDeLog{
				Kind: "auth.sudo", At: "2026-08-24T02:00:00Z", AtKnown: true, AtAnoInferido: true,
				User: "deploy", Process: "sudo", PID: 5, Alvos: []string{"/tmp/.upd"},
			},
		},
		{
			nome:  "su: a troca de usuário, com o alvo entre parênteses",
			linha: "Aug 24 02:05:00 host su[6]: (to root) deploy on pts/0",
			quer: EventoDeLog{
				Kind: "auth.su", At: "2026-08-24T02:05:00Z", AtKnown: true, AtAnoInferido: true,
				User: "deploy", Process: "su", PID: 6, Alvos: []string{"root"},
			},
		},
		{
			nome:  "useradd: a conta criada, com o UID que o cruzamento precisa",
			linha: "Aug 24 03:00:00 host useradd[7]: new user: name=backdoor, UID=0, GID=0, home=/home/backdoor, shell=/bin/bash",
			quer: EventoDeLog{
				Kind: "account.created", At: "2026-08-24T03:00:00Z", AtKnown: true, AtAnoInferido: true,
				User: "backdoor", UID: 0, UIDKnown: true, Process: "useradd", PID: 7,
			},
		},
		{
			nome:  "CRON: o comando executado",
			linha: "Aug 24 04:00:01 host CRON[8]: (root) CMD (/usr/local/bin/coleta.sh)",
			quer: EventoDeLog{
				Kind: "cron.exec", At: "2026-08-24T04:00:01Z", AtKnown: true, AtAnoInferido: true,
				User: "root", Process: "CRON", PID: 8, Alvos: []string{"/usr/local/bin/coleta.sh"},
			},
		},
		{
			nome:  "kernel: perda de registro do auditd é buraco na trilha",
			linha: "Aug 24 05:00:00 host kernel: [12345.678901] audit: audit_lost=42 audit_rate_limit=0 audit_backlog_limit=64",
			quer: EventoDeLog{
				Kind: "audit.lost", At: "2026-08-24T05:00:00Z", AtKnown: true, AtAnoInferido: true,
				Process: "kernel",
			},
		},
		{
			nome:  "kernel: módulo fora da árvore",
			linha: "Aug 24 05:01:00 host kernel: [1.0] socknd: loading out-of-tree module taints kernel.",
			quer: EventoDeLog{
				Kind: "kernel.module_loaded", At: "2026-08-24T05:01:00Z", AtKnown: true, AtAnoInferido: true,
				Process: "kernel", Alvos: []string{"socknd"},
			},
		},
		{
			nome:  "busybox do Alpine insere facility.level entre host e tag",
			linha: "Aug 24 06:00:00 host authpriv.info sshd[3]: Accepted password for ana from 10.0.0.2 port 5 ssh2",
			quer: EventoDeLog{
				Kind: "auth.accepted", At: "2026-08-24T06:00:00Z", AtKnown: true, AtAnoInferido: true,
				User: "ana", RemoteIP: "10.0.0.2", Metodo: "password",
				Process: "sshd", PID: 3,
			},
		},
		{
			nome:  "rsyslog em ISO traz ano e offset: nada é inferido",
			linha: "2026-08-24T01:20:33.123456+02:00 host sshd[1]: Accepted password for ana from 10.0.0.3 port 5 ssh2",
			quer: EventoDeLog{
				Kind: "auth.accepted", At: "2026-08-23T23:20:33Z", AtKnown: true,
				User: "ana", RemoteIP: "10.0.0.3", Metodo: "password",
				Process: "sshd", PID: 1,
			},
		},
	}

	for _, c := range casos {
		t.Run(c.nome, func(t *testing.T) {
			ev, res, _ := parseLinhaSyslog(c.linha, ctxDeTeste())
			if res != linhaEvento {
				t.Fatalf("resultado = %v, quer linhaEvento", res)
			}
			ev.Trecho = "" // conferido à parte
			if !mesmoEvento(ev, c.quer) {
				t.Errorf("\n tem %+v\nquer %+v", ev, c.quer)
			}
		})
	}
}

func mesmoEvento(a, b EventoDeLog) bool { return reflect.DeepEqual(a, b) }

// AS RESPOSTAS SÃO DISTINTAS, e é disso que a medição de capacidade do parser
// depende. São seis, e cada par que se confunde apaga a medição por um lado:
//
//	compreendida × não reconhecida   confundi-las faz a razão medir o
//	                                 VOCABULÁRIO, e um host tranquilo — cheio de
//	                                 linhas sem interesse — sai acusado de ter
//	                                 formato desconhecido
//	não reconhecida × não medida     confundi-las põe o kernel no denominador,
//	                                 e o kernel escreve milhares de mensagens
//	                                 distintas: a lacuna apareceria em toda
//	                                 varredura saudável
//
// Nos dois casos a lacuna deixa de ser lida, que é o mesmo que não existir.
func TestAsRespostasDoParser(t *testing.T) {
	casos := []struct {
		nome  string
		linha string
		quer  ResultadoDeLinha
	}{
		{
			nome:  "envelope que não é syslog",
			linha: "isto não é uma linha de log",
			quer:  linhaNaoParseada,
		},
		{
			nome:  "JSON de aplicação: envelope nenhum",
			linha: `{"level":"error","msg":"failed to connect","ts":1755990137}`,
			quer:  linhaNaoParseada,
		},
		{
			nome:  "produtor fora da lista NÃO entra no denominador",
			linha: "Aug 24 01:00:00 host postgres[10]: connection authorized: user=app",
			quer:  linhaNaoCandidata,
		},
		{
			nome:  "candidata compreendida e deliberadamente descartada",
			linha: "Aug 24 01:00:00 host sshd[10]: Connection closed by 1.2.3.4 port 5 [preauth]",
			quer:  linhaReconhecidaSemEvento,
		},
		{
			nome: "systemd: vocabulário ABERTO, fora do denominador",
			// Ele gera evento (falha de unit) e não é medido: exigir que este
			// parser conheça toda mensagem do systemd produziria lacuna
			// permanente.
			linha: "Aug 24 01:00:00 host systemd[1]: Started Daily apt upgrade and clean activities.",
			quer:  linhaNaoMedida,
		},
		{
			nome: "kernel: idem, e por margem muito maior",
			linha: "Aug 24 01:00:00 host kernel: [1.0] e1000e 0000:00:1f.6 eth0: " +
				"NIC Link is Up 1000 Mbps Full Duplex",
			quer: linhaNaoMedida,
		},
		{
			nome: "sshd com variante DESCONHECIDA entra no denominador e não no numerador",
			// É a única resposta que faz a razão cair — e sem ela a catraca do
			// parser nunca dispararia, porque todo desconhecido virava
			// "compreendido".
			linha: "Aug 24 01:00:00 host sshd[10]: mensagem que este parser nunca viu",
			quer:  linhaNaoReconhecida,
		},
		{
			nome:  "sudo abrindo sessão não é o COMMAND",
			linha: "Aug 24 01:00:00 host sudo[10]: pam_unix(sudo:session): session opened for user root by deploy(uid=1000)",
			quer:  linhaReconhecidaSemEvento,
		},
		{
			nome:  "systemd: falha de unit É evento",
			linha: "Aug 24 01:00:00 host systemd[1]: backdoor.service: Failed with result 'exit-code'.",
			quer:  linhaEvento,
		},
	}
	for _, c := range casos {
		t.Run(c.nome, func(t *testing.T) {
			if _, res, _ := parseLinhaSyslog(c.linha, ctxDeTeste()); res != c.quer {
				t.Errorf("resultado = %v, quer %v", res, c.quer)
			}
		})
	}
}

// A linha SEM DATA UTILIZÁVEL continua virando evento.
//
// Recusá-la perderia o achado por causa do carimbo — e o carimbo é o que menos
// se pode exigir de um log. O que o consumidor precisa saber está em AtKnown.
func TestLinhaSemDataUtilizavelAindaEhEvento(t *testing.T) {
	// Sem âncora não há como inferir o ano.
	ctx := contextoDeTempo{Loc: time.UTC}
	ev, res, _ := parseLinhaSyslog(
		"Aug 24 01:20:33 host sudo[5]: deploy : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/tmp/.x",
		ctx)
	if res != linhaEvento {
		t.Fatalf("resultado = %v: a data não pode derrubar o evento", res)
	}
	if ev.AtKnown || ev.At != "" {
		t.Errorf("AtKnown=%v At=%q — sem data, e dizendo que não tem", ev.AtKnown, ev.At)
	}
}

// O FUSO SUPOSTO viaja no evento. Um horário com offset suposto não sustenta
// correlação de segundos, e quem o usa precisa saber disso pelo fato — não pela
// documentação.
func TestFusoSupostoMarcaOEvento(t *testing.T) {
	ctx := ctxDeTeste()
	ctx.Suposto = true
	ev, _, _ := parseLinhaSyslog("Aug 24 01:20:33 host sshd[1]: Accepted password for ana from 10.0.0.1 port 5 ssh2", ctx)
	if !ev.AtFusoInferido {
		t.Error("fuso suposto precisa marcar AtFusoInferido")
	}
	// E o ANO da forma tradicional é SEMPRE inferido: a linha não o carrega.
	if !ev.AtAnoInferido {
		t.Error("a forma tradicional não traz ano: ele sai da âncora, sempre")
	}
}

// O trecho é CRU e CORTADO, e o corte é declarado: um trecho cortado em
// silêncio manda o operador procurar no arquivo uma linha que não é a que ele
// está lendo.
func TestTrechoEhCortadoComMarca(t *testing.T) {
	longo := "Aug 24 01:20:33 host sudo[5]: deploy : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/x " +
		strings.Repeat("A", 500)
	ev, res, _ := parseLinhaSyslog(longo, ctxDeTeste())
	if res != linhaEvento {
		t.Fatal("não virou evento")
	}
	if len([]rune(ev.Trecho)) > maxTrechoLog+1 {
		t.Errorf("trecho com %d runas, teto é %d", len([]rune(ev.Trecho)), maxTrechoLog)
	}
	if !strings.HasSuffix(ev.Trecho, "…") {
		t.Error("o corte precisa ser visível no texto")
	}
}

// O resolvedor de alvos é o mesmo do ExecStart, e por isso `&&` não esconde o
// segundo programa — foi assim que um backdoor sumia de unit sem deixar lacuna.
func TestSudoComDoisProgramasNaLinha(t *testing.T) {
	ev, res, _ := parseLinhaSyslog(
		"Aug 24 02:00:00 host sudo[5]: deploy : TTY=pts/0 ; PWD=/ ; USER=root ; "+
			"COMMAND=/bin/sh -c '/usr/bin/true && /usr/lib/.backdoor'",
		ctxDeTeste())
	if res != linhaEvento {
		t.Fatal("não virou evento")
	}
	achou := false
	for _, a := range ev.Alvos {
		if a == "/usr/lib/.backdoor" {
			achou = true
		}
	}
	if !achou {
		t.Errorf("o segundo programa da linha sumiu: %v", ev.Alvos)
	}
}

// A FORMA ISO CARREGA O PRÓPRIO OFFSET, e marcá-la como inferida porque o
// /etc/localtime não abriu desqualifica um carimbo que não precisou de
// suposição nenhuma.
//
// Isso importa porque o contrato desta feature diz que horário inferido não
// sustenta correlação de segundos — e a segunda rodada é toda correlação.
func TestISONaoEhInferidaMesmoComFusoDesconhecido(t *testing.T) {
	ctx := ctxDeTeste()
	ctx.Suposto = true // /etc/localtime ilegível

	iso, _, _ := parseLinhaSyslog(
		"2026-08-24T01:20:33.123456+02:00 h sshd[1]: Accepted password for ana from 10.0.0.1 port 5 ssh2", ctx)
	if !iso.AtKnown {
		t.Fatal("a data ISO precisa ser conhecida")
	}
	if iso.AtFusoInferido || iso.AtAnoInferido {
		t.Error("a ISO traz ano E offset: nada foi inferido")
	}

	// E a forma tradicional, na MESMA execução, continua marcada.
	trad, _, _ := parseLinhaSyslog(
		"Aug 24 01:20:33 h sshd[1]: Accepted password for ana from 10.0.0.1 port 5 ssh2", ctx)
	if !trad.AtFusoInferido {
		t.Error("a forma tradicional depende do fuso do alvo, que aqui foi suposto")
	}
	if !trad.AtAnoInferido {
		t.Error("e o ano dela sai da âncora, sempre — é o que a janela recorta")
	}
}

// O TRECHO É EVIDÊNCIA, e cortar no byte exato parte a sequência UTF-8: um nome
// com acento, um caminho em chinês ou um emoji no User-Agent bastam para o
// operador passar a ler um caractere que a linha não tem.
//
// O teste anterior usava strings.Repeat("A", 500) — ASCII puro —, entãomedia
// contagem de runas sem exercer UTF-8 nenhum.
func TestTrechoNaoParteUTF8(t *testing.T) {
	// "é" tem 2 bytes: enchendo com ele, o teto de bytes cai no meio de um.
	msg := strings.Repeat("é", maxTrechoLog)
	ev, res, _ := parseLinhaSyslog(
		"Aug 24 01:20:33 h sudo[5]: deploy : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/x "+msg,
		ctxDeTeste())
	if res != linhaEvento {
		t.Fatal("não virou evento")
	}
	if !utf8.ValidString(ev.Trecho) {
		t.Errorf("o trecho não é UTF-8 válido: %q", ev.Trecho)
	}
	if len(ev.Trecho) > maxTrechoLog+len("…") {
		t.Errorf("o teto é de BYTES: %d bytes", len(ev.Trecho))
	}
	if !strings.HasSuffix(ev.Trecho, "…") {
		t.Error("o corte precisa continuar visível")
	}
}

// E o trecho é mesmo CRU: o espaçamento da mensagem é escolha de quem escreveu
// a linha, e reconstruí-la por Join de campos apagaria tabulação e espaço
// múltiplo.
func TestTrechoPreservaOEspacamentoOriginal(t *testing.T) {
	ev, res, _ := parseLinhaSyslog(
		"Aug 24 01:20:33 h sudo[5]:   deploy : TTY=pts/0 ;  PWD=/tmp\t; USER=root ; COMMAND=/tmp/.upd",
		ctxDeTeste())
	if res != linhaEvento {
		t.Fatal("não virou evento")
	}
	if !strings.Contains(ev.Trecho, ";  PWD=/tmp\t;") {
		t.Errorf("o espaçamento original se perdeu: %q", ev.Trecho)
	}
}
