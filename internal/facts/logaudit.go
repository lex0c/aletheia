package facts

import (
	"strconv"
	"strings"
)

// O auditd (runbook §11).
//
// É a fonte de maior valor desta feature, e a única que preserva EXECUÇÃO. Um
// binário rodado às 03:00 e apagado às 03:05 não existe mais em lugar nenhum do
// retrato — nem arquivo, nem processo, nem socket. O EXECVE do auditd é o que
// sobrou dele.
//
// # Uma execução NÃO é uma linha
//
// Ela é um conjunto de registros que compartilham a identidade
// `msg=audit(epoch.ms:serial)`:
//
//	type=SYSCALL  msg=audit(1755990137.123:456): … uid=1001 comm="sh" exe="/bin/dash"
//	type=EXECVE   msg=audit(1755990137.123:456): argc=2 a0="./x" a1="-q"
//	type=CWD      msg=audit(1755990137.123:456): cwd="/tmp"
//	type=PATH     msg=audit(1755990137.123:456): item=0 name="/tmp/x" …
//
// Sem juntar, `a0="./x"` nunca vira `/tmp/x`, e a pergunta que dá valor à
// feature — este caminho tem dono de pacote? ainda existe? — não pode ser feita.
// Parsear linha a linha entregaria quatro fatos soltos e nenhuma execução.
//
// # O formato é verificado contra o kernel, não contra a memória de alguém
//
// Três detalhes decidem se o parser funciona, e os três estão no fonte:
//
//	envelope   `audit(%llu.%03lu:%u): ` — kernel/audit.c. O serial é unsigned
//	           int, REINICIA, e por isso a identidade é o PAR (epoch, serial)
//	hex        audit_string_contains_control() manda para hex qualquer byte
//	           `"`, < 0x21 ou > 0x7e — kernel/audit.c. 0x20 é ESPAÇO: todo
//	           caminho com espaço chega em hex, e isso não é caso exótico
//	partido    audit_log_execve_info() emite `a2_len=N` seguido de `a2[0]=`,
//	           `a2[1]=`… quando o argumento não cabe no buffer — kernel/auditsc.c

// RegistroAudit é UMA linha do audit.log, já decomposta.
type RegistroAudit struct {
	Tipo   string
	Epoch  float64
	Serial uint32
	Campos map[string]string
	Linha  int
}

// camposDeTextoAudit são os campos que passam por audit_log_untrustedstring no
// kernel — os únicos que podem chegar em HEX.
//
// A lista é fechada de propósito. Decodificar hex por FORMA ("parece hex, então
// é") corromperia campo numérico: `pid=1234` tem comprimento par e só dígitos
// hexadecimais, e viraria os bytes 0x12 0x34. O erro sairia silencioso, num
// campo que decide correlação.
var camposDeTextoAudit = map[string]bool{
	"name": true, "cwd": true, "cmd": true, "comm": true, "exe": true,
	"proctitle": true, "key": true, "acct": true, "old-disk": true, "new-disk": true,
}

// ehCampoDeArgumento reconhece `a0`, `a12` e os pedaços `a2[0]` de um argumento
// que não coube no buffer.
func ehCampoDeArgumento(chave string) bool {
	if len(chave) < 2 || chave[0] != 'a' {
		return false
	}
	corpo := chave[1:]
	if i := strings.IndexByte(corpo, '['); i >= 0 {
		if !strings.HasSuffix(corpo, "]") {
			return false
		}
		corpo = corpo[:i]
	}
	if corpo == "" {
		return false
	}
	for i := 0; i < len(corpo); i++ {
		if corpo[i] < '0' || corpo[i] > '9' {
			return false
		}
	}
	return true
}

// decodeHexAudit devolve o texto quando o valor é hex de verdade.
//
// Exigir comprimento PAR e todos os dígitos hexadecimais é o que o kernel
// garante (dois dígitos por byte). Valor que não casa volta como veio: um
// `comm="sh"` sem aspas por algum motivo continua sendo "sh", nunca vira lixo.
func decodeHexAudit(v string) (string, bool) {
	if v == "" || len(v)%2 != 0 {
		return v, false
	}
	b := make([]byte, len(v)/2)
	for i := 0; i < len(v); i += 2 {
		hi, ok1 := digitoHex(v[i])
		lo, ok2 := digitoHex(v[i+1])
		if !ok1 || !ok2 {
			return v, false
		}
		b[i/2] = hi<<4 | lo
	}
	return string(b), true
}

func digitoHex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// camposDeAudit decompõe `chave=valor` respeitando aspas.
//
// Duas formas de aspas, e as duas importam:
//
//	name="/tmp/um arquivo"   aspas duplas: o valor é literal, e tem espaço
//	msg='cwd="/root" cmd=6C73 …'   aspas simples: é um envelope ANINHADO, que os
//	                               registros de userspace (USER_CMD, USER_AUTH)
//	                               usam para carregar os próprios campos
//
// Sem desembrulhar o aninhado, todo `cmd=` de USER_CMD ficaria invisível — e é
// ele que diz o que o sudo executou.
func camposDeAudit(s string, out map[string]string) {
	i := 0
	for i < len(s) {
		for i < len(s) && s[i] == ' ' {
			i++
		}
		if i >= len(s) {
			return
		}
		j := i
		for j < len(s) && s[j] != '=' && s[j] != ' ' {
			j++
		}
		if j >= len(s) || s[j] != '=' {
			for j < len(s) && s[j] != ' ' {
				j++
			}
			i = j
			continue
		}
		chave := s[i:j]
		j++
		if j < len(s) && (s[j] == '"' || s[j] == '\'') {
			aspa := s[j]
			k := j + 1
			for k < len(s) && s[k] != aspa {
				k++
			}
			valor := s[j+1 : min(k, len(s))]
			if aspa == '\'' {
				// Envelope aninhado: os campos de dentro são os que interessam.
				camposDeAudit(valor, out)
			} else {
				out[chave] = valor
			}
			i = k + 1
			continue
		}
		k := j
		for k < len(s) && s[k] != ' ' {
			k++
		}
		valor := s[j:k]
		if camposDeTextoAudit[chave] || ehCampoDeArgumento(chave) {
			// SEM ASPAS num campo de texto significa hex — é o que o kernel faz
			// quando o valor tem espaço, aspas ou byte fora de ASCII imprimível.
			if dec, ok := decodeHexAudit(valor); ok {
				valor = dec
			}
		}
		out[chave] = valor
		i = k
	}
}

// parseRegistroAudit lê UMA linha. Puro: sem I/O e sem estado.
func parseRegistroAudit(linha string) (RegistroAudit, bool) {
	var r RegistroAudit
	if !strings.HasPrefix(linha, "type=") {
		return r, false
	}
	tipo, resto, ok := strings.Cut(linha[len("type="):], " ")
	if !ok || tipo == "" {
		return r, false
	}
	r.Tipo = tipo

	// `msg=audit(1755990137.123:456): …`
	i := strings.Index(resto, "msg=audit(")
	if i < 0 {
		return r, false
	}
	miolo, cauda, ok := strings.Cut(resto[i+len("msg=audit("):], ")")
	if !ok {
		return r, false
	}
	carimbo, serial, ok := strings.Cut(miolo, ":")
	if !ok {
		return r, false
	}
	ep, err := strconv.ParseFloat(carimbo, 64)
	if err != nil {
		return r, false
	}
	sn, err := strconv.ParseUint(serial, 10, 32)
	if err != nil {
		return r, false
	}
	r.Epoch, r.Serial = ep, uint32(sn)
	r.Campos = map[string]string{}
	camposDeAudit(strings.TrimPrefix(strings.TrimSpace(cauda), ":"), r.Campos)
	return r, true
}

// ---------------------------------------------------------------------------
// O montador

// chaveAudit é a IDENTIDADE de um evento. O serial sozinho não serve: ele é u32,
// reinicia, e se repete entre arquivos e entre boots — dois eventos distintos
// colidiriam num só, e o caminho de um sairia atribuído ao outro.
type chaveAudit struct {
	epoch  float64
	serial uint32
}

// maxGruposAuditAbertos limita quantos eventos incompletos ficam em memória.
//
// Os registros de um evento são adjacentes no arquivo, então o teto quase nunca
// morde. Ele existe para o caso que não é acidente: um audit.log plantado com um
// milhão de seriais ÓRFÃOS — um registro cada, nenhum completo — consumiria
// memória sem limite, e a varredura morreria com exit 2, que a frota lê como
// comprometimento. Ver guardaGoroutine para o mesmo raciocínio.
const maxGruposAuditAbertos = 5000

// montadorDeAudit acumula registros por identidade e devolve eventos.
type montadorDeAudit struct {
	grupos map[chaveAudit][]RegistroAudit
	ordem  []chaveAudit
	// FechadosPorTeto conta os eventos que foram montados ANTES de o arquivo
	// dizer que acabaram. Vira lacuna declarada: o evento saiu, e pode ter saído
	// sem o PATH que resolveria o caminho.
	FechadosPorTeto int
}

func novoMontadorDeAudit() *montadorDeAudit {
	return &montadorDeAudit{grupos: map[chaveAudit][]RegistroAudit{}}
}

// Alimenta acrescenta um registro e devolve o que fechou por causa dele.
func (m *montadorDeAudit) Alimenta(r RegistroAudit) []EventoDeLog {
	ch := chaveAudit{r.Epoch, r.Serial}
	if _, visto := m.grupos[ch]; !visto {
		m.ordem = append(m.ordem, ch)
	}
	m.grupos[ch] = append(m.grupos[ch], r)

	var out []EventoDeLog
	for len(m.ordem) > maxGruposAuditAbertos {
		velha := m.ordem[0]
		m.ordem = m.ordem[1:]
		rs := m.grupos[velha]
		delete(m.grupos, velha)
		m.FechadosPorTeto++
		if ev, ok := montarEventoAudit(rs); ok {
			out = append(out, ev)
		}
	}
	return out
}

// Fecha monta o que sobrou. Sem isto, o último evento do arquivo — que é o mais
// recente, e o que mais interessa numa triagem — ficaria de fora.
func (m *montadorDeAudit) Fecha() []EventoDeLog {
	var out []EventoDeLog
	for _, ch := range m.ordem {
		if ev, ok := montarEventoAudit(m.grupos[ch]); ok {
			out = append(out, ev)
		}
	}
	m.ordem, m.grupos = nil, map[chaveAudit][]RegistroAudit{}
	return out
}

// montarEventoAudit transforma um grupo de registros em UM evento. Puro.
func montarEventoAudit(rs []RegistroAudit) (EventoDeLog, bool) {
	if len(rs) == 0 {
		return EventoDeLog{}, false
	}
	var ev EventoDeLog
	ev.Serial = rs[0].Serial
	ev.Line = rs[0].Linha
	if t, ok := instanteDeEpoch(strconv.FormatFloat(rs[0].Epoch, 'f', 3, 64)); ok {
		ev.At, ev.AtKnown = utc(t), true
	}

	// Os campos de todos os registros do grupo, com o tipo de cada um à mão.
	tipos := map[string]map[string]string{}
	for i := range rs {
		if _, ja := tipos[rs[i].Tipo]; !ja {
			tipos[rs[i].Tipo] = rs[i].Campos
			continue
		}
		// PATH aparece várias vezes (item=0, item=1…). O primeiro é o programa;
		// os outros são bibliotecas e diretórios, e não são o alvo.
		if rs[i].Tipo == "PATH" && tipos["PATH"]["item"] != "0" && rs[i].Campos["item"] == "0" {
			tipos["PATH"] = rs[i].Campos
		}
	}

	sys := tipos["SYSCALL"]
	if c := sys["comm"]; c != "" {
		ev.Process = c
	}
	if p, err := strconv.Atoi(sys["pid"]); err == nil {
		ev.PID = p
	}
	if u, err := strconv.Atoi(sys["uid"]); err == nil {
		ev.UID, ev.UIDKnown = u, true
	}

	switch {
	case tipos["EXECVE"] != nil || sys["syscall"] == "59" || sys["syscall"] == "execve":
		ev.Kind = "audit.exec"
		montaExec(&ev, tipos)
	case tipos["USER_CMD"] != nil:
		ev.Kind = "auth.sudo"
		uc := tipos["USER_CMD"]
		ev.User = uc["acct"]
		if ev.User == "" {
			ev.User = uc["auid"]
		}
		if u, err := strconv.Atoi(uc["uid"]); err == nil {
			ev.UID, ev.UIDKnown = u, true
		}
		cmd := uc["cmd"]
		ev.Alvos, ev.AlvoIndeterminado = AlvosEfetivosDeExec(cmd)
		ev.Alvos = absolutizaAlvos(ev.Alvos, uc["cwd"])
		ev.Trecho = trechoDe(cmd)
		ev.Process = "sudo"
	case tipos["KERN_MODULE"] != nil:
		ev.Kind = "kernel.module_loaded"
		ev.Alvos = []string{tipos["KERN_MODULE"]["name"]}
		ev.Process = "kernel"
	case tipos["ANOM_ABEND"] != nil:
		ev.Kind = "kernel.segfault"
		aa := tipos["ANOM_ABEND"]
		if c := aa["comm"]; c != "" {
			ev.Process = c
		}
		if e := aa["exe"]; e != "" {
			ev.Alvos = []string{e}
		}
	case tipos["ADD_USER"] != nil, tipos["ADD_GROUP"] != nil:
		ev.Kind = "account.created"
		ev.User = campoDeAlgum(tipos, "acct", "ADD_USER", "ADD_GROUP")
	case tipos["USER_MGMT"] != nil, tipos["DEL_USER"] != nil, tipos["DEL_GROUP"] != nil,
		tipos["CHUSER_ID"] != nil, tipos["CHGRP_ID"] != nil:
		ev.Kind = "account.modified"
		ev.User = campoDeAlgum(tipos, "acct", "USER_MGMT", "DEL_USER", "DEL_GROUP",
			"CHUSER_ID", "CHGRP_ID")
	case tipos["DAEMON_ABORT"] != nil, tipos["DAEMON_END"] != nil:
		// A trilha ganha um buraco nos dois casos, e é essa a conclusão. A
		// DIFERENÇA entre eles — parada administrativa contra queda — é do
		// check, não do coletor: ela decide severidade, e severidade não é
		// fato.
		ev.Kind = "audit.lost"
		ev.Process = "auditd"
		if tipos["DAEMON_ABORT"] != nil {
			ev.Metodo = "abort"
		} else {
			ev.Metodo = "end"
		}
	default:
		if temPerda(rs) {
			ev.Kind = "audit.lost"
			ev.Process = "auditd"
			break
		}
		return EventoDeLog{}, false
	}

	if ev.Trecho == "" {
		ev.Trecho = trechoDe(resumoDoGrupo(rs))
	}
	return ev, true
}

// montaExec reconstrói a execução: o argv, o caminho absoluto, e os alvos.
func montaExec(ev *EventoDeLog, tipos map[string]map[string]string) {
	argv := argvDeExecve(tipos["EXECVE"])
	cwd := tipos["CWD"]["cwd"]

	// O CAMINHO PREFERIDO é o do PATH: ele já vem resolvido pelo kernel, e não
	// depende de reconstruir cwd + argv[0]. Só quando ele falta é que a
	// composição entra.
	alvo := tipos["PATH"]["name"]
	if !strings.HasPrefix(alvo, "/") {
		if len(argv) > 0 {
			alvo = argv[0]
		}
		if !strings.HasPrefix(alvo, "/") && cwd != "" {
			alvo = strings.TrimSuffix(cwd, "/") + "/" + strings.TrimPrefix(alvo, "./")
		}
	}
	if alvo != "" {
		ev.Alvos = append(ev.Alvos, alvo)
	}
	if e := tipos["SYSCALL"]["exe"]; e != "" && e != alvo {
		ev.Alvos = append(ev.Alvos, e)
	}

	// `sh -c '…'` é o caso em que o alvo do exec NÃO é o programa que interessa:
	// o binário executado é o shell, e o que se quer saber está no argumento. É
	// o mesmo raciocínio do ExecStart de unit, e usa o mesmo resolvedor.
	if i := indiceDe(argv, "-c"); i >= 0 && i+1 < len(argv) && ehShellDeExec(alvo) {
		// alvosDeLinhaDeShell, e não AlvosEfetivosDeExec: o argumento do `-c` JÁ
		// é a linha de shell. Passá-lo pelo desembrulhador de wrappers devolveria
		// só o primeiro programa — e `/usr/bin/true && /usr/lib/.backdoor` sairia
		// como `/usr/bin/true`, que é exatamente o defeito que a mudança para
		// Targets plural consertou no ExecStart.
		mais, indeterminado := alvosDeLinhaDeShell(argv[i+1])
		ev.Alvos = append(ev.Alvos, absolutizaAlvos(mais, cwd)...)
		ev.AlvoIndeterminado = ev.AlvoIndeterminado || indeterminado
	}
	if len(argv) > 0 {
		ev.Trecho = trechoDe(strings.Join(argv, " "))
	}
}

func ehShellDeExec(p string) bool {
	switch baseCaminhoExec(p) {
	case "sh", "bash", "dash", "ash", "zsh", "ksh", "busybox":
		return true
	}
	return false
}

// absolutizaAlvos resolve o alvo relativo contra o cwd do evento.
//
// É a razão inteira de o CWD ser lido: `./x` não responde pergunta nenhuma —
// não dá para perguntar quem é o dono do pacote de `./x`, nem se ele ainda
// existe. `/tmp/x` responde as duas.
func absolutizaAlvos(alvos []string, cwd string) []string {
	if cwd == "" {
		return alvos
	}
	out := make([]string, 0, len(alvos))
	for _, a := range alvos {
		if a == "" || strings.HasPrefix(a, "/") {
			out = append(out, a)
			continue
		}
		out = append(out, strings.TrimSuffix(cwd, "/")+"/"+strings.TrimPrefix(a, "./"))
	}
	return out
}

// argvDeExecve remonta os argumentos, inclusive os que vieram PARTIDOS.
//
// Um argumento que não cabe no buffer do kernel sai como `a2_len=N` seguido de
// `a2[0]=`, `a2[1]=`… (audit_log_execve_info). Ler só o `a2` daria string
// vazia para exatamente o argumento mais longo — que é o que carrega o payload
// numa linha de comando ofuscada.
func argvDeExecve(ex map[string]string) []string {
	if ex == nil {
		return nil
	}
	argc, _ := strconv.Atoi(ex["argc"])
	if argc <= 0 || argc > 4096 {
		argc = 0
		for k := range ex {
			if ehCampoDeArgumento(k) {
				argc++
			}
		}
	}
	out := make([]string, 0, argc)
	for i := 0; i < argc; i++ {
		nome := "a" + strconv.Itoa(i)
		if v, ok := ex[nome]; ok {
			out = append(out, v)
			continue
		}
		var b strings.Builder
		for j := 0; ; j++ {
			v, ok := ex[nome+"["+strconv.Itoa(j)+"]"]
			if !ok {
				break
			}
			b.WriteString(v)
		}
		out = append(out, b.String())
	}
	return out
}

func campoDeAlgum(tipos map[string]map[string]string, campo string, dos ...string) string {
	for _, t := range dos {
		if v := tipos[t][campo]; v != "" {
			return v
		}
	}
	return ""
}

// temPerda reconhece o registro que carrega contagem de evento PERDIDO.
func temPerda(rs []RegistroAudit) bool {
	for i := range rs {
		if v, ok := rs[i].Campos["lost"]; ok {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				return true
			}
		}
	}
	return false
}

// resumoDoGrupo é o trecho de evidência quando o evento não tem um texto
// natural: os tipos que o compuseram, para o operador achá-lo no arquivo.
func resumoDoGrupo(rs []RegistroAudit) string {
	tipos := make([]string, 0, len(rs))
	visto := map[string]bool{}
	for i := range rs {
		if !visto[rs[i].Tipo] {
			visto[rs[i].Tipo] = true
			tipos = append(tipos, rs[i].Tipo)
		}
	}
	return strings.Join(tipos, "+")
}

// tiposDeAuditConsumidos são os registros que este montador PROMETE transformar
// em alguma coisa. É o denominador da capacidade do parser para o audit.log.
//
// A lista é estreita de propósito, e a razão é a mesma que tira o kernel do
// denominador no syslog: o audit-userspace define mais de duzentos tipos, e
// quais aparecem depende inteiramente das regras carregadas. Um host com SELinux
// enche o arquivo de AVC; um com `-S all` enche de SYSCALL. Exigir que este
// parser conheça todos produziria lacuna permanente em qualquer host com
// auditoria séria — e lacuna que nunca fecha deixa de ser lida.
//
// Tipo fora desta lista conta como PARSEADO e não como candidato: ele foi
// compreendido no nível do envelope, e nunca prometemos mais que isso.
var tiposDeAuditConsumidos = map[string]bool{
	"SYSCALL": true, "EXECVE": true, "CWD": true, "PATH": true, "PROCTITLE": true,
	"USER_CMD": true, "KERN_MODULE": true, "ANOM_ABEND": true,
	"DAEMON_ABORT": true, "DAEMON_END": true,
	"ADD_USER": true, "ADD_GROUP": true, "USER_MGMT": true,
	"DEL_USER": true, "DEL_GROUP": true, "CHUSER_ID": true, "CHGRP_ID": true,
}
