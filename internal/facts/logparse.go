package facts

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

// Parsers de linha de syslog (runbook §10, §12).
//
// A postura é a mesma da varredura de código: isto é PENEIRA sobre texto que o
// alvo escreve, e texto que o alvo escreve é hostil por definição — qualquer
// usuário fala com /dev/log, e root reescreve o arquivo. Um evento aqui é uma
// ALEGAÇÃO do host sobre o próprio passado, nunca um fato provado.
//
// # A linha que ninguém entendeu não vira evento "desconhecido"
//
// Ela vira CONTADOR. A razão está no que se mede com ela: se este parser não
// conhece o formato deste host, a coleta devolve zero eventos COM SUCESSO — o
// falso "limpo" mais convincente que existe, porque nada falhou. O que denuncia
// isso é a razão entre candidatas e reconhecidas (ver FonteDeLog), e ela só
// funciona se as quatro respostas forem distintas.
//
// # Por que "reconhecida sem evento" existe
//
// `Connection closed by 1.2.3.4` é compreendida e deliberadamente descartada:
// ela aparece às centenas e nenhum check a consome. Contá-la como NÃO
// reconhecida faria a razão medir o VOCABULÁRIO em vez do parser, e um host
// tranquilo — cheio de linhas sem interesse — seria acusado de ter formato
// desconhecido.

// ResultadoDeLinha é o que aconteceu com uma linha. As quatro respostas são
// distintas porque cada uma alimenta um contador diferente de FonteDeLog.
type ResultadoDeLinha int

const (
	// linhaNaoParseada: o envelope não é syslog. Um arquivo inteiro assim não é
	// do formato esperado, e isso é lacuna — não ausência de evento.
	linhaNaoParseada ResultadoDeLinha = iota
	// linhaNaoCandidata: envelope bom, produtor que este parser não promete
	// entender (postgres, docker, a aplicação). Não entra no denominador.
	linhaNaoCandidata
	// linhaNaoMedida: o produtor gera evento, mas o vocabulário dele é ABERTO —
	// o kernel escreve milhares de mensagens diferentes, e o systemd quase
	// tantas. Elas não entram no denominador da capacidade do parser: com o
	// kernel dentro, a razão seria péssima em todo host saudável, e a lacuna
	// apareceria sempre até ninguém mais a ler.
	linhaNaoMedida
	// linhaReconhecidaSemEvento: candidata compreendida e deliberadamente fora do
	// vocabulário de Kind (`Connection closed by …`).
	linhaReconhecidaSemEvento
	// linhaNaoReconhecida: produtor MEDIDO e variante que este parser não
	// entende. É a única que entra no denominador sem entrar no numerador, e é
	// ela que faz a catraca do parser poder disparar. Sem este estado, todo
	// desconhecido virava "compreendido" e a medição não media nada.
	linhaNaoReconhecida
	// linhaEvento: virou EventoDeLog.
	linhaEvento
)

// maxTrechoLog é o teto do texto guardado por evento.
//
// O trecho existe para o operador reconhecer a linha no arquivo, não para
// carregar o log dentro do dump. 200 bytes pegam a mensagem inteira de quase
// toda linha de auth e cortam a cauda das que se estendem de propósito — um
// argumento de dez mil bytes é escolha de quem escreveu a linha.
const maxTrechoLog = 200

// produtoresCandidatos são as tags que este parser PROMETE entender. É o
// denominador da razão de reconhecimento: medir contra o total de linhas diria
// que um /var/log/messages saudável — com postgres, docker e a aplicação — tem
// parser quebrado, porque 99% das linhas dele nunca foram nossas.
//
// `sshd-session` está aqui porque o OpenSSH 9.8 partiu o sshd em dois binários,
// e é o filho quem escreve as linhas de autenticação. Sem ele, toda linha de
// auth de um host recente cairia como não candidata — e a razão de
// reconhecimento sairia perfeita sobre nada.
// produtoresMedidos é o DENOMINADOR da capacidade do parser: os produtores cujo
// vocabulário é fechado o bastante para que "não entendi" signifique alguma
// coisa. O kernel e o systemd ficam de fora — não porque não interessem, mas
// porque escrevem milhares de mensagens distintas, e exigir que este parser as
// conheça todas produziria lacuna permanente em host saudável.
var produtoresMedidos = map[string]bool{
	"sshd": true, "sshd-session": true, "dropbear": true,
	"sudo": true, "su": true, "doas": true,
	"useradd": true, "userdel": true, "usermod": true,
	"groupadd": true, "groupdel": true, "gpasswd": true,
	"chage": true, "passwd": true, "chpasswd": true,
	"CRON": true, "cron": true, "crond": true, "anacron": true,
	"auditd": true,
}

var produtoresCandidatos = map[string]bool{
	"sshd": true, "sshd-session": true, "dropbear": true,
	"sudo": true, "su": true, "doas": true,
	"useradd": true, "userdel": true, "usermod": true,
	"groupadd": true, "groupdel": true, "gpasswd": true,
	"chage": true, "passwd": true, "chpasswd": true,
	"CRON": true, "cron": true, "crond": true, "anacron": true,
	"kernel": true, "systemd": true, "auditd": true,
}

// linhaSyslog é o envelope, já separado da mensagem.
type linhaSyslog struct {
	Quando string // RFC3339 UTC; vazio = não foi possível datar
	Tag    string // sshd, sudo, kernel…
	PID    int
	// Msg é o resto da linha VERBATIM — espaçamento original incluído. Ela é
	// evidência, e reconstruí-la por Join de campos apagaria tabulação e espaço
	// múltiplo, que são escolha de quem escreveu a linha.
	Msg string
	// Inferido diz que o OFFSET desta data foi suposto, e não lido.
	//
	// Só a forma tradicional depende disso: a ISO carrega o próprio offset, e
	// marcar a data dela como inferida porque o /etc/localtime não abriu seria
	// desqualificar um carimbo que não precisou de suposição nenhuma.
	Inferido bool
}

// separaEnvelope lê a moldura comum a todas as famílias em texto.
//
// Três formas convivem em campo, e as três precisam passar:
//
//	Aug 24 01:20:33 host sshd[1234]: msg          rsyslog tradicional
//	2026-08-24T01:20:33.1+02:00 host sshd[1]: msg rsyslog ISO (RFC3339)
//	Aug 24 01:20:33 host auth.info sshd[1]: msg   busybox, que insere facility
//
// A terceira é o Alpine, e ela é a razão de a busca pela tag olhar DOIS tokens
// em vez de um: sem isso, todo log de Alpine sairia como envelope não
// reconhecido, e o arquivo inteiro seria declarado de formato desconhecido.
func separaEnvelope(linha string, ctx contextoDeTempo) (linhaSyslog, bool) {
	var out linhaSyslog
	campos := strings.Fields(linha)
	if len(campos) < 4 {
		return out, false
	}

	var resto []string
	consumidos := 0
	if t, ok := instanteISO(campos[0]); ok {
		out.Quando = utc(t)
		resto = campos[1:]
		consumidos = 1
	} else {
		mes, ok := mesDeSyslog[campos[0]]
		if !ok {
			return out, false
		}
		dia, err := strconv.Atoi(campos[1])
		if err != nil || dia < 1 || dia > 31 {
			return out, false
		}
		h, m, s, ok := horaDeSyslog(campos[2])
		if !ok {
			return out, false
		}
		// Data que não fecha NÃO derruba a linha: o envelope foi reconhecido, e o
		// evento vale sem carimbo — com AtKnown falso, que é o que o consumidor
		// precisa saber. Recusar aqui perderia o achado por causa da data.
		if t, ok := instanteDeSyslog(mes, dia, h, m, s, ctx); ok {
			out.Quando = utc(t)
		}
		// O ANO desta forma sempre sai do mtime do arquivo (ver
		// instanteDeSyslog); o OFFSET sai do /etc/localtime, e só ele pode
		// faltar. É o offset que decide correlação de segundos.
		out.Inferido = ctx.Suposto
		resto = campos[3:]
		consumidos = 3
	}
	if len(resto) < 2 {
		return out, false
	}

	// resto[0] é o host. A tag vem logo depois, ou depois de um `facility.level`.
	for i := 1; i <= 2 && i < len(resto); i++ {
		tok := resto[i]
		if !strings.HasSuffix(tok, ":") {
			// Só o `facility.level` do busybox pode ficar entre host e tag. Um
			// token qualquer significa que este envelope não é o que se pensava.
			if i == 1 && strings.Contains(tok, ".") && !strings.Contains(tok, "[") {
				continue
			}
			return out, false
		}
		tag := strings.TrimSuffix(tok, ":")
		if abre := strings.IndexByte(tag, '['); abre > 0 && strings.HasSuffix(tag, "]") {
			out.PID, _ = strconv.Atoi(tag[abre+1 : len(tag)-1])
			tag = tag[:abre]
		}
		if tag == "" {
			return out, false
		}
		out.Tag = tag
		out.Msg = depoisDeTokens(linha, consumidos+i+1)
		return out, true
	}
	return out, false
}

// depoisDeTokens devolve o resto da linha DEPOIS de n campos separados por
// branco, sem passar por Join: o espaçamento original é preservado.
func depoisDeTokens(linha string, n int) string {
	i, vistos := 0, 0
	for i < len(linha) && vistos < n {
		for i < len(linha) && ehBrancoDeLog(linha[i]) {
			i++
		}
		if i >= len(linha) {
			break
		}
		for i < len(linha) && !ehBrancoDeLog(linha[i]) {
			i++
		}
		vistos++
	}
	for i < len(linha) && ehBrancoDeLog(linha[i]) {
		i++
	}
	return linha[i:]
}

func ehBrancoDeLog(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\v' || c == '\f'
}

func horaDeSyslog(s string) (h, m, seg int, ok bool) {
	p := strings.Split(s, ":")
	if len(p) != 3 {
		return 0, 0, 0, false
	}
	var err error
	if h, err = strconv.Atoi(p[0]); err != nil || h > 23 {
		return 0, 0, 0, false
	}
	if m, err = strconv.Atoi(p[1]); err != nil || m > 59 {
		return 0, 0, 0, false
	}
	// 60 existe: é o segundo bissexto, e recusá-lo descartaria a linha.
	if seg, err = strconv.Atoi(p[2]); err != nil || seg > 60 {
		return 0, 0, 0, false
	}
	return h, m, seg, true
}

// parseLinhaSyslog é a função PURA: uma linha entra, um evento (ou um contador)
// sai. Sem I/O, sem estado — o File e a Line são do coletor, que é quem os
// conhece.
// O terceiro retorno é o CARIMBO DA LINHA, e ele existe para a cobertura.
//
// Cobertura mede OBSERVAÇÃO, não achado: uma linha `Connection closed by …` foi
// lida, parseada e datada — ela apenas não interessa como evento. Derivar o
// intervalo observado dos EVENTOS afirmaria que o arquivo só foi visto onde
// apareceu algo interessante, e é sobre esse intervalo que um check diz "N dias
// sem UMA linha de autenticação".
func parseLinhaSyslog(linha string, ctx contextoDeTempo) (EventoDeLog, ResultadoDeLinha, string) {
	env, ok := separaEnvelope(linha, ctx)
	if !ok {
		return EventoDeLog{}, linhaNaoParseada, ""
	}
	if !produtoresCandidatos[env.Tag] {
		return EventoDeLog{}, linhaNaoCandidata, env.Quando
	}
	medido := produtoresMedidos[env.Tag]

	ev := EventoDeLog{
		At:         env.Quando,
		AtKnown:    env.Quando != "",
		AtInferido: env.Inferido,
		Process:    env.Tag,
		PID:        env.PID,
		Trecho:     trechoDe(env.Msg),
	}

	var res ResultadoDeLinha
	switch env.Tag {
	case "sshd", "sshd-session", "dropbear":
		res = classificaSSH(&ev, env.Msg)
	case "sudo", "doas":
		res = classificaSudo(&ev, env.Msg)
	case "su":
		res = classificaSu(&ev, env.Msg)
	case "useradd", "userdel", "usermod", "groupadd", "groupdel", "gpasswd",
		"chage", "passwd", "chpasswd":
		res = classificaConta(&ev, env.Msg)
	case "CRON", "cron", "crond", "anacron":
		res = classificaCron(&ev, env.Msg)
	case "kernel":
		res = classificaKernel(&ev, env.Msg)
	case "systemd":
		res = classificaSystemd(&ev, env.Msg)
	case "auditd":
		res = classificaAuditd(&ev, env.Msg)
	default:
		res = linhaNaoMedida
	}
	// Produtor de vocabulário ABERTO nunca entra no denominador, nem quando este
	// parser não entendeu a linha: exigir que ele conheça toda mensagem do
	// kernel produziria lacuna em todo host saudável.
	if !medido && res == linhaNaoReconhecida {
		res = linhaNaoMedida
	}
	if res != linhaEvento {
		return EventoDeLog{}, res, env.Quando
	}
	return ev, linhaEvento, env.Quando
}

// trechoDe corta o texto guardado. O corte é DECLARADO com reticências: um
// trecho cortado em silêncio faz o operador procurar no arquivo uma linha que
// não é a que ele está lendo.
//
// O corte é em FRONTEIRA DE RUNA, e o teto continua sendo de BYTES — o
// orçamento é o tamanho do dump, não a contagem de caracteres. Cortar no byte
// exato parte a sequência UTF-8 no meio e produz `\uFFFD` na evidência: um
// nome de usuário com acento, um caminho em chinês ou um emoji no User-Agent
// bastam, e o operador passa a ler um caractere que a linha não tem.
func trechoDe(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= maxTrechoLog {
		return s
	}
	corte := maxTrechoLog
	for corte > 0 && !utf8.RuneStart(s[corte]) {
		corte--
	}
	return s[:corte] + "…"
}

// ---------------------------------------------------------------------------
// sshd

// classificaSSH extrai o que o utmp NÃO tem.
//
// O wtmp já registra quem entrou, de onde e quando, num formato binário mais
// difícil de forjar — e checks/login.go já o lê. O que só o log tem é o MÉTODO
// e o FINGERPRINT da chave: é o fingerprint que permite perguntar se a chave
// usada ainda está em algum authorized_keys, e essa pergunta não existe em
// nenhuma outra fonte deste host.
func classificaSSH(ev *EventoDeLog, msg string) ResultadoDeLinha {
	switch {
	case strings.HasPrefix(msg, "Accepted "):
		ev.Kind = "auth.accepted"
	case strings.HasPrefix(msg, "Failed "), strings.HasPrefix(msg, "error: PAM: Authentication failure"):
		ev.Kind = "auth.failed"
	case strings.HasPrefix(msg, "Invalid user "), strings.HasPrefix(msg, "input_userauth_request: invalid user"):
		ev.Kind = "auth.invalid_user"
		ev.User = campoDepois(msg, "Invalid user ", 0)
		ev.RemoteIP = campoDepois(msg, " from ", 0)
		return linhaEvento
	default:
		return compreendidaOuNao(msg, sshRotina)
	}

	campos := strings.Fields(msg)
	// `Accepted publickey for deploy from 1.2.3.4 port 5 ssh2: RSA SHA256:AAA`
	// `Failed password for invalid user admin from 1.2.3.4 port 5 ssh2`
	//
	// O método é o SEGUNDO token, e só quando o primeiro é um dos dois verbos:
	// um `error: PAM: Authentication failure` também cai aqui, e sem a guarda
	// saía com Metodo="PAM:" — um campo estruturado carregando lixo, que é pior
	// que campo vazio porque tem cara de dado.
	if len(campos) >= 2 && (campos[0] == "Accepted" || campos[0] == "Failed") {
		ev.Metodo = campos[1]
	}
	if i := indiceDe(campos, "for"); i >= 0 && i+1 < len(campos) {
		u := campos[i+1]
		if u == "invalid" && i+3 < len(campos) && campos[i+2] == "user" {
			ev.Kind = "auth.invalid_user"
			u = campos[i+3]
		}
		ev.User = u
	}
	if i := indiceDe(campos, "from"); i >= 0 && i+1 < len(campos) {
		ev.RemoteIP = campos[i+1]
	}
	// O fingerprint é o último token, e vem depois do tipo da chave:
	// `… ssh2: RSA SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU`
	for _, c := range campos {
		if strings.HasPrefix(c, "SHA256:") || strings.HasPrefix(c, "MD5:") {
			ev.Fingerprint = c
		}
	}
	return linhaEvento
}

// ---------------------------------------------------------------------------
// sudo e su

// classificaSudo lê a linha de comando executado.
//
//	deploy : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/tar czf …
//
// O COMMAND vai para o resolvedor de alvos que já existe (execalvo.go), pelo
// mesmo motivo que uma linha de ExecStart vai: uma linha de shell tem N
// programas, não um, e `cd /tmp && ./x` esconde o segundo de quem olhar só o
// primeiro token.
func classificaSudo(ev *EventoDeLog, msg string) ResultadoDeLinha {
	// A TENTATIVA QUE FALHOU também carrega COMMAND=, e tratá-la como execução
	// afirmaria que root rodou o que ninguém rodou.
	if strings.Contains(msg, "incorrect password attempt") ||
		strings.Contains(msg, "authentication failure") ||
		strings.Contains(msg, "user NOT in sudoers") ||
		strings.Contains(msg, "command not allowed") {
		return linhaReconhecidaSemEvento
	}
	i := strings.Index(msg, "COMMAND=")
	if i < 0 {
		return compreendidaOuNao(msg, sudoRotina)
	}
	ev.Kind = "auth.sudo"
	if u, _, ok := strings.Cut(msg, " : "); ok {
		ev.User = strings.TrimSpace(u)
	}
	cmd := strings.TrimSpace(msg[i+len("COMMAND="):])
	ev.Alvos, ev.AlvoIndeterminado = AlvosEfetivosDeExec(cmd)
	return linhaEvento
}

// classificaSu cobre a troca de usuário, inclusive a que FALHOU: `FAILED SU` é
// tentativa de escalada, e o utmp não a registra.
func classificaSu(ev *EventoDeLog, msg string) ResultadoDeLinha {
	if !strings.Contains(msg, "(to ") {
		return compreendidaOuNao(msg, sudoRotina)
	}
	ev.Kind = "auth.su"
	// `(to root) deploy on pts/0` — o alvo entre parênteses, quem chamou depois.
	if _, dep, ok := strings.Cut(msg, "(to "); ok {
		alvo, resto, _ := strings.Cut(dep, ")")
		ev.Alvos = []string{strings.TrimSpace(alvo)}
		if campos := strings.Fields(resto); len(campos) > 0 {
			ev.User = campos[0]
		}
	}
	return linhaEvento
}

// ---------------------------------------------------------------------------
// contas

// classificaConta cobre a criação e a alteração de conta e de grupo.
//
// É o evento que a segunda rodada cruza com o /etc/passwd de agora: `useradd`
// no log mais uma conta uid 0 existente hoje é a cadeia inteira, e nenhuma das
// duas metades diz isso sozinha.
func classificaConta(ev *EventoDeLog, msg string) ResultadoDeLinha {
	switch {
	case strings.HasPrefix(msg, "new user:"), strings.HasPrefix(msg, "new group:"),
		strings.HasPrefix(msg, "new account:"):
		ev.Kind = "account.created"
	case strings.HasPrefix(msg, "delete user"), strings.HasPrefix(msg, "removed user"),
		strings.HasPrefix(msg, "delete group"), strings.HasPrefix(msg, "removed group"),
		strings.HasPrefix(msg, "change user"), strings.HasPrefix(msg, "changed password"),
		strings.HasPrefix(msg, "password changed for"), strings.HasPrefix(msg, "add '"),
		strings.HasPrefix(msg, "user '"), strings.HasPrefix(msg, "add member"):
		ev.Kind = "account.modified"
	default:
		return compreendidaOuNao(msg, contaRotina)
	}

	// `new user: name=backdoor, UID=0, GID=0, home=…, shell=/bin/bash`
	for _, par := range strings.Split(msg, ",") {
		chave, valor, ok := strings.Cut(strings.TrimSpace(par), "=")
		if !ok {
			continue
		}
		switch {
		case strings.HasSuffix(chave, "name"):
			ev.User = valor
		case chave == "UID":
			if n, err := strconv.Atoi(valor); err == nil {
				ev.UID, ev.UIDKnown = n, true
			}
		}
	}
	if ev.User == "" {
		// `password changed for deploy`, `add 'deploy' to group 'sudo'`
		ev.User = strings.Trim(campoDepois(msg, "for ", 0), "'")
		if ev.User == "" {
			ev.User = strings.Trim(campoDepois(msg, "add ", 0), "'")
		}
	}
	return linhaEvento
}

// ---------------------------------------------------------------------------
// cron, kernel, systemd, auditd

// classificaCron guarda o que rodou, resolvido pelo mesmo resolvedor de alvos.
func classificaCron(ev *EventoDeLog, msg string) ResultadoDeLinha {
	i := strings.Index(msg, " CMD ")
	if i < 0 {
		return compreendidaOuNao(msg, cronRotina)
	}
	ev.Kind = "cron.exec"
	if u, _, ok := strings.Cut(strings.TrimPrefix(msg, "("), ")"); ok {
		ev.User = u
	}
	cmd := strings.TrimSpace(msg[i+len(" CMD "):])
	cmd = strings.TrimSuffix(strings.TrimPrefix(cmd, "("), ")")
	ev.Alvos, ev.AlvoIndeterminado = AlvosEfetivosDeExec(cmd)
	return linhaEvento
}

// classificaKernel cobre o que o kernel diz sobre si mesmo. As três formas que
// interessam existem também como REGISTRO do auditd, e lá são estruturadas —
// este caminho é o de host sem auditd, e é peneira sobre texto.
func classificaKernel(ev *EventoDeLog, msg string) ResultadoDeLinha {
	m := semCarimboDeUptime(msg)
	switch {
	case strings.Contains(m, "segfault at "), strings.Contains(m, "general protection fault"),
		strings.Contains(m, "trap invalid opcode"):
		ev.Kind = "kernel.segfault"
		if nome, _, ok := strings.Cut(m, "["); ok && nome != "" {
			ev.Process = strings.TrimSpace(nome)
		}
	case strings.HasPrefix(m, "Out of memory: Killed process"), strings.HasPrefix(m, "oom-kill:"),
		strings.Contains(m, "Out of memory: Kill process"):
		ev.Kind = "kernel.oom"
	case strings.Contains(m, "module verification failed"),
		strings.Contains(m, "loading out-of-tree module"),
		strings.Contains(m, "module license"):
		ev.Kind = "kernel.module_loaded"
		if nome, _, ok := strings.Cut(m, ":"); ok {
			ev.Alvos = []string{strings.TrimSpace(nome)}
		}
	case strings.HasPrefix(m, "audit:"), strings.HasPrefix(m, "audit_lost"):
		// `audit: audit_lost=42 audit_rate_limit=0 audit_backlog_limit=64` e
		// `audit: backlog limit exceeded` — as duas do kernel/audit.c.
		if !strings.Contains(m, "audit_lost=") && !strings.Contains(m, "backlog limit exceeded") {
			return linhaNaoMedida
		}
		ev.Kind = "audit.lost"
	default:
		// O kernel tem vocabulário ABERTO: não medido.
		return linhaNaoMedida
	}
	return linhaEvento
}

// semCarimboDeUptime tira o `[12345.678901]` que o kernel prefixa quando o
// printk_time está ligado. Sem tirar, todo prefixo de nome de processo e todo
// HasPrefix falham — e falham em SILÊNCIO, contando a linha como não
// reconhecida num host onde ela é perfeitamente legível.
func semCarimboDeUptime(msg string) string {
	m := strings.TrimSpace(msg)
	if !strings.HasPrefix(m, "[") {
		return m
	}
	fim := strings.IndexByte(m, ']')
	if fim < 0 {
		return m
	}
	miolo := strings.TrimSpace(m[1:fim])
	if _, err := strconv.ParseFloat(miolo, 64); err != nil {
		return m
	}
	return strings.TrimSpace(m[fim+1:])
}

// classificaSystemd só reporta FALHA.
//
// `Started …` sai às centenas em qualquer boot e nenhum check o consome — e
// contá-lo como não reconhecido faria a razão de reconhecimento medir o
// vocabulário. Ele é compreendido e descartado, que é o que o contador de
// "reconhecida sem evento" existe para representar.
func classificaSystemd(ev *EventoDeLog, msg string) ResultadoDeLinha {
	if !strings.Contains(msg, "Failed with result") && !strings.HasPrefix(msg, "Failed to start") {
		return linhaNaoMedida
	}
	ev.Kind = "service.failed"
	if u, _, ok := strings.Cut(msg, ":"); ok && strings.Contains(u, ".") {
		ev.Alvos = []string{strings.TrimSpace(u)}
	}
	return linhaEvento
}

// classificaAuditd cobre o que o DAEMON diz sobre si mesmo quando escreve no
// syslog. A parada do auditd tem a mesma consequência que o backlog estourado —
// a trilha ganha um buraco —, e é por isso que as duas viram o mesmo Kind.
func classificaAuditd(ev *EventoDeLog, msg string) ResultadoDeLinha {
	m := strings.ToLower(msg)
	switch {
	case strings.Contains(m, "audit_lost"), strings.Contains(m, "backlog limit exceeded"),
		strings.Contains(m, "audit daemon rotating"), strings.Contains(m, "the audit daemon is exiting"),
		strings.Contains(m, "audit daemon is exiting"):
		ev.Kind = "audit.lost"
		return linhaEvento
	}
	return compreendidaOuNao(m, auditdRotina)
}

// compreendidaOuNao separa a variante que este parser CONHECE e descarta da
// que ele simplesmente não entende.
//
// A distinção parece pedante e é a única coisa que faz a medição de capacidade
// significar alguma coisa. Enquanto todo desconhecido saía como "compreendido",
// um host cujo sshd escrevesse noutro idioma — outra versão, outro pacote, outra
// distribuição — devolvia zero eventos com razão de reconhecimento perfeita.
func compreendidaOuNao(msg string, rotina []string) ResultadoDeLinha {
	for _, p := range rotina {
		if strings.Contains(msg, p) {
			return linhaReconhecidaSemEvento
		}
	}
	return linhaNaoReconhecida
}

// As listas de rotina: variantes que aparecem às centenas, que este parser
// entende, e que nenhum check consome. Elas são o numerador legítimo.
var (
	sshRotina = []string{
		"Connection closed", "Connection reset", "Connection from", "Disconnected from",
		"Received disconnect", "Received signal", "Server listening", "Bad protocol version",
		"Unable to negotiate", "kex_exchange_identification", "banner exchange",
		"Timeout, client not responding", "Postponed ", "maximum authentication attempts",
		"Too many authentication failures", "input_userauth_request", "userauth_pubkey",
		"pam_unix(", "session opened", "session closed", "subsystem request",
		"reverse mapping", "refused connect", "not allowed because", "Starting session",
		"error: PAM: ", "Exiting on signal", "Read from socket failed", "no matching",
	}
	sudoRotina = []string{
		"pam_unix(", "session opened", "session closed", "incorrect password attempt",
		"authentication failure", "problem with defaults entries", "unable to resolve host",
		"user NOT in sudoers", "command not allowed", "Successful su", "FAILED su",
	}
	contaRotina = []string{
		"pam_unix(", "failed adding user", "group added to", "add 'root'",
		"lock user", "unlock user", "not found in", "shadow file",
	}
	cronRotina = []string{
		"pam_unix(", "session opened", "session closed", "STARTUP", "RELOAD",
		"Reloading", "LIST", "INFO", "No MTA installed", "(*system*",
	}
	auditdRotina = []string{
		"audit daemon", "started", "config change", "reload", "flush",
	}
)

// ---------------------------------------------------------------------------

func indiceDe(campos []string, alvo string) int {
	for i, c := range campos {
		if c == alvo {
			return i
		}
	}
	return -1
}

// campoDepois devolve o token de índice n depois do marcador, ou "".
func campoDepois(s, marcador string, n int) string {
	i := strings.Index(s, marcador)
	if i < 0 {
		return ""
	}
	campos := strings.Fields(s[i+len(marcador):])
	if n >= len(campos) {
		return ""
	}
	return campos[n]
}
