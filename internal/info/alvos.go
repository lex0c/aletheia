package info

import (
	"sort"
	"strconv"
	"strings"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/facts"

	"github.com/lex0c/aletheia/internal/redact"
)

// Os quatro alvos que um respondedor investiga um por um, e que hoje custam
// dezenas de comandos encadeados: um processo, um endereço, uma porta, um
// arquivo.
//
// A regra que vale para os quatro: RESPONDER, não despejar. Cada dossiê junta o
// que está espalhado por `ps`, `ss`, `lsof`, `stat`, `getcap`, `lsattr`, `dpkg
// -S` e `find`, e diz o que a junção significa — inclusive quando significa
// "não achei nada sobre isto", que é uma resposta e precisa ser dada por
// escrito.

// Linha é um par rótulo/valor do dossiê, com uma nota opcional que diz o que
// aquele valor SIGNIFICA. A nota é o que separa isto de uma saída crua.
type Linha struct {
	Rotulo string `json:"label"`
	Valor  string `json:"value"`
	Nota   string `json:"meaning,omitempty"`
}

// Dossie é a resposta sobre um alvo.
type Dossie struct {
	Alvo string `json:"target"`
	// Achou é falso quando o alvo não existe nos fatos. Não é erro: é resposta.
	Achou bool `json:"found"`
	// Blocos são as seções, na ordem em que ajudam a decidir.
	Blocos []Bloco `json:"blocks,omitempty"`
	// Sinais são as coisas que pedem olhar humano — o que um scan chamaria de
	// achado, aqui dito sem veredito.
	Sinais []string `json:"signals,omitempty"`
	// Proximo são os comandos que fazem sentido em seguida, já preenchidos.
	Proximo []string `json:"next,omitempty"`
}

// Bloco é uma seção do dossiê.
type Bloco struct {
	Titulo string  `json:"title"`
	Linhas []Linha `json:"lines,omitempty"`
}

func (d *Dossie) bloco(titulo string, ls ...Linha) {
	var uteis []Linha
	for _, l := range ls {
		if l.Valor != "" {
			uteis = append(uteis, l)
		}
	}
	if len(uteis) > 0 {
		d.Blocos = append(d.Blocos, Bloco{Titulo: titulo, Linhas: uteis})
	}
}

// Processo monta o dossiê de um PID.
//
// A primeira pergunta do runbook (§3.3) é "ele É o que diz ser?", e ela se
// responde comparando três nomes que quase todo mundo confunde: `comm`, o
// `argv[0]` e o EXECUTÁVEL. Os dois primeiros o processo escolhe; o terceiro é o
// kernel que diz.
func Processo(f *facts.Facts, pid int) *Dossie {
	d := &Dossie{Alvo: "pid " + strconv.Itoa(pid)}
	p := f.ProcessByPID(pid)
	if p == nil {
		d.Sinais = append(d.Sinais, "nenhum processo com este pid nos fatos desta "+
			"coleta — ele pode ter terminado, ou nunca ter existido")
		return d
	}
	d.Achou = true

	argv0 := ""
	if len(p.Argv) > 0 {
		argv0 = p.Argv[0]
	}
	identidade := []Linha{
		{"executável", nz(p.Exe, "(ilegível)"), notaDoExe(p)},
		{"comm", p.Comm, ""},
		{"argv[0]", argv0, ""},
		{"linha", linhaCurta(p), ""},
	}
	if p.Exe != "" && argv0 != "" && !mesmaCoisa(p.Exe, argv0) {
		identidade = append(identidade, Linha{"⚠ divergência",
			"o nome que ele se dá não bate com o executável",
			"o `ps` mostra o argv, que o processo escolhe; o exe é o que o kernel diz"})
	}
	d.bloco("IDENTIDADE", identidade...)

	d.bloco("QUEM É E DESDE QUANDO",
		Linha{"usuário", nomeDoUID(f, p.UID) + " (uid " + strconv.Itoa(p.UID) + ")", diferencaDeEUID(p)},
		Linha{"início", p.StartUTC, ""},
		Linha{"estado", p.State, notaDoEstado(p.State)},
		Linha{"threads", numeroOuVazio(p.Threads), ""},
		Linha{"teto de processos", tetoTexto(p.NProcMax), "RLIMIT_NPROC conta processos E threads do uid"},
		Linha{"cgroup", p.Cgroup, "é o que diz QUAL serviço o gerou, mesmo depois de daemonizar"},
	)

	// Linhagem: o pai é o vetor de entrada, e a §16 do runbook começa por ele.
	var linhagem []Linha
	for pai, n := p.PPID, 0; pai > 0 && n < 6; n++ {
		pp := f.ProcessByPID(pai)
		if pp == nil {
			linhagem = append(linhagem, Linha{"pai " + strconv.Itoa(pai), "(já não existe)",
				"o pai morreu e este processo foi adotado pelo init: a linhagem original se perdeu"})
			break
		}
		linhagem = append(linhagem, Linha{"pai " + strconv.Itoa(pai),
			nz(pp.Exe, pp.Comm) + " · " + linhaCurta(pp), ""})
		pai = pp.PPID
	}
	d.bloco("LINHAGEM (o pai é o vetor de entrada)", linhagem...)

	// Rede: é aqui que "com quem ele fala" deixa de ser um `lsof` na mão.
	var rede []Linha
	for _, s := range f.SocketsOf(pid) {
		rotulo := string(s.Dir)
		if s.State == "LISTEN" {
			rotulo = "escuta"
		}
		rede = append(rede, Linha{rotulo, s.Local() + " ↔ " + nz(s.Peer(), "*"),
			string(s.PeerScope)})
	}
	d.bloco("REDE", rede...)

	var fds []Linha
	for _, fd := range p.FDs {
		switch {
		case fd.Deleted:
			fds = append(fds, Linha{"fd " + strconv.Itoa(fd.N), fd.Target,
				"APAGADO do disco e ainda aberto: enquanto este processo viver, esta é a única cópia"})
		case fd.PTY && fd.N <= 2:
			fds = append(fds, Linha{"fd " + strconv.Itoa(fd.N), fd.Target, "terminal"})
		}
	}
	d.bloco("DESCRITORES QUE DIZEM ALGO", fds...)

	filhos := 0
	for i := range f.Processes {
		if f.Processes[i].PPID == pid {
			filhos++
		}
	}
	if filhos > 0 {
		d.bloco("FILHOS", Linha{"processos filhos", strconv.Itoa(filhos), ""})
	}

	d.Sinais = append(d.Sinais, sinaisDoProcesso(p)...)
	d.Proximo = []string{
		"sudo aletheia preserve --out \"$IR\" --pid " + strconv.Itoa(pid) + " --mem",
		"aletheia info file " + check.Arg(nz(p.Exe, "<exe>")),
		"aletheia scan --only proc,net   # o veredito, com os falsos positivos junto",
	}
	return d
}

// IP responde "o que este endereço tem a ver com este host".
func IP(f *facts.Facts, addr string) *Dossie {
	d := &Dossie{Alvo: addr}
	var conexoes []Linha
	porProc := map[string]int{}
	var escopo string

	for i := range f.Sockets {
		s := &f.Sockets[i]
		if s.PeerIP != addr && s.LocalIP != addr {
			continue
		}
		d.Achou = true
		escopo = string(s.PeerScope)
		quem := "(dono não identificado)"
		if p := f.ProcessByPID(s.PID); p != nil {
			quem = nz(p.Exe, p.Comm) + " (pid=" + strconv.Itoa(s.PID) + ")"
		}
		porProc[quem]++
		if len(conexoes) < 12 {
			conexoes = append(conexoes, Linha{string(s.Dir) + " " + s.State,
				s.Local() + " ↔ " + s.Peer(), quem})
		}
	}
	d.bloco("CONEXÕES", conexoes...)
	if len(porProc) > 0 {
		var quem []Linha
		for _, c := range topN(porProc, 8) {
			quem = append(quem, Linha{strconv.Itoa(c.N) + "×", c.Rotulo, ""})
		}
		d.bloco("QUEM FALA COM ELE", quem...)
	}

	// O endereço também pode estar no disco, e aí ele diz outra coisa: alcance
	// (known_hosts), redirecionamento (/etc/hosts) ou resolução (resolv.conf).
	var disco []Linha
	for _, h := range f.Hosts {
		if h.IP == addr {
			disco = append(disco, Linha{"/etc/hosts", h.IP + " " + strings.Join(h.Names, " "),
				"um nome apontado para cá NÃO passa por DNS"})
			d.Achou = true
		}
	}
	for _, ns := range f.Resolver.Nameservers {
		if ns == addr {
			disco = append(disco, Linha{"resolv.conf", ns, "é o resolvedor deste host"})
			d.Achou = true
		}
	}
	for _, k := range f.Destinos {
		if strings.Contains(k.Host, addr) {
			disco = append(disco, Linha{"known_hosts", k.Arquivo,
				"este host JÁ se conectou lá: é alcance lateral"})
			d.Achou = true
		}
	}
	d.bloco("NO DISCO", disco...)

	if !d.Achou {
		d.Sinais = append(d.Sinais, "nenhum socket, nome ou chave menciona este "+
			"endereço nesta coleta. Conexão de vida curta não aparece num retrato "+
			"único — para isso existe o `watch`")
		return d
	}
	if escopo == string(facts.ScopePublic) {
		d.Sinais = append(d.Sinais, "endereço PÚBLICO: o que sai daqui sai do perímetro")
	}
	d.Proximo = []string{
		"aletheia scan --ioc <(echo ips: [" + check.Arg(addr) + "])   # o mesmo endereço no resto do que foi coletado",
		"e nos OUTROS hosts da frota: é assim que se acha a segunda máquina",
		"o volume que passou não está no host: veja `aletheia checks | grep exfil`",
	}
	return d
}

// Porta responde "quem abriu isto, e quem usa".
func Porta(f *facts.Facts, n int) *Dossie {
	d := &Dossie{Alvo: "porta " + strconv.Itoa(n)}
	var escutas, estab []Linha
	locais, externas := 0, 0

	for i := range f.Sockets {
		s := &f.Sockets[i]
		if s.LocalPort != n && s.PeerPort != n {
			continue
		}
		d.Achou = true
		quem := "(dono não identificado)"
		dono := ""
		if p := f.ProcessByPID(s.PID); p != nil {
			quem = nz(p.Exe, p.Comm) + " (pid=" + strconv.Itoa(s.PID) + ")"
			dono = donoDePacote(f, p.Exe)
		}
		switch {
		case s.State == "LISTEN" && s.LocalPort == n:
			escutas = append(escutas, Linha{s.Local(), quem, dono + exposicao(s.LocalIP)})
		case s.State == "ESTAB":
			if len(estab) < 12 {
				estab = append(estab, Linha{string(s.Dir), s.Local() + " ↔ " + s.Peer(), quem})
			}
			if s.LocalPort == n && s.Dir == facts.DirIn {
				if ehLoopback(s.PeerIP) {
					locais++
				} else {
					externas++
				}
			}
		}
	}
	d.bloco("QUEM ESCUTA", escutas...)
	d.bloco("CONEXÕES", estab...)

	if !d.Achou {
		d.Sinais = append(d.Sinais, "ninguém escuta nem conversa nesta porta neste "+
			"retrato — o que não é o mesmo que ela estar fechada no firewall")
		return d
	}
	if locais > 0 && externas == 0 && len(escutas) > 0 {
		d.Sinais = append(d.Sinais, "todas as "+strconv.Itoa(locais)+" conexões "+
			"estabelecidas vêm do LOOPBACK: na prática quem usa este serviço está "+
			"dentro do host. Se ele escuta fora do loopback, quem vier de fora fala "+
			"direto com ele e não passa pelo proxy")
	}
	d.Proximo = []string{
		"aletheia info process <pid>   # o dossiê de quem abriu",
		"e a pergunta: que outros serviços rodam com o MESMO usuário? " +
			"só eles podem ser o mesmo vetor",
	}
	return d
}

// Arquivo responde "de onde veio isto, e quem mexe nele".
func Arquivo(f *facts.Facts, caminho string) *Dossie {
	d := &Dossie{Alvo: caminho}

	var proc []Linha
	for i := range f.Processes {
		p := &f.Processes[i]
		if p.Exe == caminho {
			d.Achou = true
			proc = append(proc, Linha{"em execução",
				"pid=" + strconv.Itoa(p.PID) + " · " + linhaCurta(p),
				"uid " + strconv.Itoa(p.UID) + ", desde " + nz(p.StartUTC, "?")})
		}
	}
	d.bloco("EXECUTANDO AGORA", proc...)

	var proc2 []Linha
	for _, o := range f.Ownership {
		if o.Path != caminho {
			continue
		}
		d.Achou = true
		if o.Owned {
			proc2 = append(proc2, Linha{"pacote", o.Pacote, "quem entregou este arquivo"})
		} else {
			proc2 = append(proc2, Linha{"pacote", "NENHUM",
				"nenhum pacote reivindica este arquivo: a pergunta vira 'quem instalou?'"})
		}
	}
	for _, h := range f.HashDiff {
		if h.Path == caminho {
			d.Achou = true
			proc2 = append(proc2, Linha{"hash", "NÃO confere com o que o pacote " + h.Pacote + " declara",
				"o arquivo foi alterado depois de instalado"})
		}
	}
	for _, ok := range f.HashOK {
		if ok == caminho {
			proc2 = append(proc2, Linha{"hash", "confere com o pacote", ""})
		}
	}
	d.bloco("PROCEDÊNCIA", proc2...)

	var poder []Linha
	for _, s := range f.Suid {
		if s.Path != caminho {
			continue
		}
		d.Achou = true
		poder = append(poder, Linha{"dono", "uid " + strconv.Itoa(s.UID) + " gid " + strconv.Itoa(s.GID), ""})
		if s.Setuid {
			poder = append(poder, Linha{"setuid", "sim", "quem executar assume o dono"})
		}
		if s.CapPerm != 0 {
			poder = append(poder, Linha{"capabilities", "0x" + strconv.FormatUint(s.CapPerm, 16),
				"capability em xattr substitui o SUID e não aparece num `find -perm`"})
		}
	}
	for _, a := range f.Atributos {
		if a.Path == caminho {
			d.Achou = true
			atributos := []string{}
			if a.Imutavel {
				atributos = append(atributos, "imutável (i)")
			}
			if a.SoAnexa {
				atributos = append(atributos, "só anexa (a)")
			}
			poder = append(poder, Linha{"atributo de inode", strings.Join(atributos, ", "),
				"o imutável faz a remoção FALHAR até alguém rodar chattr -i"})
		}
	}
	d.bloco("PODER E TRAVAS", poder...)

	var executadoPorRoot []Linha
	for i := range f.AlvosDeRoot {
		a := &f.AlvosDeRoot[i]
		if a.Caminho != caminho {
			continue
		}
		d.Achou = true
		nota := a.QuemGrava()
		if nota == "" {
			nota = "só o root pode reescrevê-lo"
		}
		executadoPorRoot = append(executadoPorRoot, Linha{a.Origem, a.Onde, nota})
	}
	d.bloco("O ROOT EXECUTA ISTO", executadoPorRoot...)

	// O QUE ESTE ARQUIVO DEFINE — a pergunta INVERSA, e ela faltava.
	//
	// O bloco de baixo pergunta "quem manda executar este arquivo", casando o
	// caminho contra o COMANDO de cada agendamento. Ninguém perguntava se o
	// caminho É a fonte: um `/etc/cron.d/telemetry` respondia "este caminho não
	// aparece em nada que esta coleta examinou" — sobre o arquivo que o próprio
	// achado `persist.cron_suspect` cita como evidência.
	//
	// A lacuna apareceu num teste com cliente MCP real: o modelo achou o cron
	// backdoor, perguntou pelo arquivo, e recebeu found:false. É a próxima
	// pergunta óbvia depois de um achado de persistência, e o dossiê não
	// alcançava o artefato da própria conclusão.
	var define []Linha
	for i := range f.Cron {
		c := &f.Cron[i]
		if c.File != caminho {
			continue
		}
		d.Achou = true
		quando := c.Schedule
		if quando == "" && c.Reboot {
			quando = "no boot"
		}
		define = append(define, Linha{"agenda " + nz(quando, "?"),
			redact.Linha(c.Cmd), "como " + nz(c.User, "?")})
	}
	for i := range f.Units {
		u := &f.Units[i]
		if u.Path != caminho {
			continue
		}
		d.Achou = true
		for _, ex := range u.Exec {
			define = append(define, Linha{"unit " + u.Name,
				redact.Linha(ex.Cmd), ex.Key})
		}
		if len(u.Exec) == 0 {
			define = append(define, Linha{"unit " + u.Name, u.Kind, "sem Exec"})
		}
	}
	for i := range f.Triggers {
		t := &f.Triggers[i]
		if t.File != caminho {
			continue
		}
		d.Achou = true
		for _, ln := range t.Lines {
			define = append(define, Linha{
				t.Kind + ":" + strconv.Itoa(ln.N), redact.Linha(ln.Text),
				"executa " + nz(t.When, "no gatilho")})
		}
		if len(t.Lines) == 0 {
			define = append(define, Linha{t.Kind, t.File, "sem linha que execute"})
		}
	}
	d.bloco("O QUE ESTE ARQUIVO DEFINE", define...)

	var agendado []Linha
	for i := range f.Cron {
		if strings.Contains(f.Cron[i].Cmd, caminho) {
			d.Achou = true
			agendado = append(agendado, Linha{"cron", f.Cron[i].File, f.Cron[i].Schedule})
		}
	}
	for i := range f.Units {
		for _, ex := range f.Units[i].Exec {
			if strings.Contains(ex.Cmd, caminho) {
				d.Achou = true
				agendado = append(agendado, Linha{"unit", f.Units[i].Name, ex.Key})
			}
		}
	}
	d.bloco("QUEM MANDA EXECUTAR", agendado...)

	if !d.Achou {
		d.Sinais = append(d.Sinais, "este caminho não aparece em nada que esta "+
			"coleta examinou: nem em execução, nem em pacote, nem em agendamento. "+
			"Isso NÃO significa que ele não existe — significa que nada nesta "+
			"varredura o referencia")
	}
	d.Proximo = []string{
		"sudo aletheia preserve --out \"$IR\" --file " + check.Arg(caminho),
		"e as datas: o ctime não é falsificável com `touch`, o mtime é",
	}
	return d
}

func sinaisDoProcesso(p *facts.Process) []string {
	var out []string
	if p.ExeMemfd {
		out = append(out, "execução FILELESS: o binário nunca esteve em disco")
	}
	if p.ExeDeleted && !p.ExeMemfd {
		out = append(out, "o executável foi APAGADO do disco e o processo continua "+
			"rodando: matá-lo destrói a única cópia")
	}
	if p.TracerPID != 0 {
		out = append(out, "está sob ptrace do pid "+strconv.Itoa(p.TracerPID)+
			": alguém controla a memória dele")
	}
	if len(p.MapsRWX) > 0 {
		out = append(out, strconv.Itoa(len(p.MapsRWX))+" região(ões) de memória "+
			"gravável e executável")
	}
	if p.NProcMax > 0 && p.Threads >= p.NProcMax {
		out = append(out, "as threads DESTE processo já alcançam o teto do uid: "+
			"o próximo fork falha com EAGAIN")
	}
	return out
}

func notaDoExe(p *facts.Process) string {
	switch {
	case p.ExeMemfd:
		return "memória anônima: nunca houve arquivo"
	case p.ExeDeleted:
		return "APAGADO do disco, ainda aberto pelo processo"
	case p.ExeDenied:
		return "ilegível sem privilégio: rode como root"
	}
	return ""
}

func notaDoEstado(s string) string {
	switch s {
	case "Z":
		return "zumbi: terminou e o pai não o colheu"
	case "D":
		return "sono ININTERRUPTÍVEL: preso em I/O, e nem kill -9 o tira daí"
	case "T":
		return "parado (SIGSTOP ou ptrace)"
	}
	return ""
}

func diferencaDeEUID(p *facts.Process) string {
	if p.EUID != p.UID {
		return "euid " + strconv.Itoa(p.EUID) + " DIFERENTE do uid real: troca de privilégio"
	}
	return ""
}

func tetoTexto(n int) string {
	switch {
	case n < 0:
		return "sem limite"
	case n == 0:
		return ""
	}
	return strconv.Itoa(n)
}

func numeroOuVazio(n int) string {
	if n <= 0 {
		return ""
	}
	return strconv.Itoa(n)
}

// mesmaCoisa compara o que o processo DIZ ser com o que ele É.
//
// A comparação é entre `argv[0]` e o EXECUTÁVEL, e não com o `comm`: o disfarce
// clássico (o `exec -a` da §3.5) troca só o argv e deixa o comm verdadeiro. Usar
// o comm como desempate faria a ferramenta calar exatamente sobre o disfarce
// que ela existe para achar — e foi o que aconteceu na primeira versão, contra
// um processo que se dizia `[kworker/0:9]`.
//
// Os três casos legítimos que NÃO podem virar divergência:
//
//	-bash             shell de login: o traço é convenção, não disfarce
//	python3 → 3.11    o argv usa o nome curto e o exe é o versionado
//	nginx: master…    o processo reescreve o argv com o próprio nome na frente
func mesmaCoisa(exe, argv0 string) bool {
	b, a := ultimoNome(exe), strings.TrimPrefix(ultimoNome(argv0), "-")
	if a == "" || b == "" {
		return true // sem os dois lados não se afirma divergência nenhuma
	}
	return a == b || strings.HasPrefix(b, a) || strings.HasPrefix(a, b)
}

func ultimoNome(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

func donoDePacote(f *facts.Facts, exe string) string {
	for _, o := range f.Ownership {
		if o.Path == exe {
			if o.Owned {
				return "pacote " + o.Pacote + " · "
			}
			return "SEM dono de pacote · "
		}
	}
	return ""
}

func exposicao(ip string) string {
	if ehLoopback(ip) {
		return "só loopback"
	}
	return "EXPOSTO para fora do host"
}

func ehLoopback(ip string) bool {
	return strings.HasPrefix(ip, "127.") || ip == "::1" || strings.HasPrefix(ip, "[::ffff:127.")
}

// ordenar mantém a saída estável entre execuções: dois `info` do mesmo retrato
// precisam sair iguais, ou o diff entre eles não vale nada.
func ordenar(ls []Linha) {
	sort.SliceStable(ls, func(i, j int) bool { return ls[i].Rotulo < ls[j].Rotulo })
}
