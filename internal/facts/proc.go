package facts

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lex0c/aletheia/internal/env"
)

// Limites de coleta. Estourar vira cobertura parcial reportada — nunca
// truncamento silencioso.
const (
	maxMapLines = 4000
	maxFDs      = 512

	// Teto de leitores concorrentes de /proc. Baixo de propósito: a ferramenta
	// roda em host sob incidente, e saturar a CPU atrapalha quem responde.
	maxCollectWorkers = 8

	// Reconfirmação de cmdline: UMA espera para todos os candidatos, e teto no
	// número deles. Sem o teto, um usuário sem privilégio derruba o orçamento
	// do wtf criando processos com argv zerado.
	maxCmdlineRecheck   = 64
	cmdlineRecheckDelay = 20 * time.Millisecond
)

// Process é a identidade de um PID conforme o KERNEL a mantém, não conforme o
// processo se anuncia. Nome mente; exe não (runbook §3).
type Process struct {
	PID  int `json:"pid"`
	PPID int `json:"ppid"`
	UID  int `json:"uid"`
	GID  int `json:"gid"`

	// EUID/EGID são o privilégio que VALE agora. Diferente do real significa
	// troca de privilégio — setuid, ou o processo largou privilégio de propósito.
	EUID int `json:"euid"`
	EGID int `json:"egid"`

	Comm  string `json:"comm"`  // de /proc/<pid>/stat, entre parênteses
	State string `json:"state"` // R S D Z T ...

	Exe    string `json:"exe,omitempty"`
	ExeErr string `json:"exe_err,omitempty"` // texto para o relatório

	// ExeMissing e ExeDenied são a MESMA informação do ExeErr, tipada. Quem
	// decide precisa delas: comparar `ExeErr == "sem permissão"` faz o controle
	// de fluxo depender de uma string em português, e traduzir a mensagem
	// desligaria checks em silêncio, com a suíte inteira verde.
	//
	//	ExeMissing   o kernel não associa executável nenhum a este PID:
	//	             thread de kernel, ou zumbi
	//	ExeDenied    existe, e nós é que não pudemos ler
	ExeMissing bool `json:"exe_missing,omitempty"`
	ExeDenied  bool `json:"exe_denied,omitempty"`

	ExeDeleted bool   `json:"exe_deleted,omitempty"`
	ExeMemfd   bool   `json:"exe_memfd,omitempty"`
	Cwd        string `json:"cwd,omitempty"`
	CwdDeleted bool   `json:"cwd_deleted,omitempty"`

	// Argv vem de /proc/<pid>/cmdline: MESMA fonte que o ps lê, e o processo
	// pode reescrevê-la. Serve para ver o disfarce, não para confirmar
	// identidade — isso é o Exe (runbook §3.5).
	Argv         []string `json:"argv,omitempty"`
	CmdlineEmpty bool     `json:"cmdline_empty,omitempty"`

	// EnvKeys tem TODAS as chaves; Env só os valores da allowlist (SPEC 5.4).
	EnvKeys []string          `json:"env_keys,omitempty"`
	Env     map[string]string `json:"env,omitempty"`

	CapEff    uint64 `json:"cap_eff"`
	TracerPID int    `json:"tracer_pid,omitempty"`
	Threads   int    `json:"threads,omitempty"`

	StartUTC string        `json:"start_utc,omitempty"`
	Age      time.Duration `json:"-"`

	// MapsDenied e NSDenied são EXPORTADOS porque quem precisa deles é o
	// check: "nenhuma região rwx" e "nenhum namespace divergente" só valem
	// alguma coisa se a fonte tiver sido legível.
	MapsDenied bool `json:"maps_denied,omitempty"`
	NSDenied   bool `json:"ns_denied,omitempty"`

	Cgroup    string            `json:"cgroup,omitempty"`
	NS        map[string]string `json:"ns,omitempty"`
	FDs       []FD              `json:"fds,omitempty"`
	MapsRWX   []string          `json:"maps_rwx,omitempty"`  // regiões graváveis E executáveis
	MapsOdd   []string          `json:"maps_odd,omitempty"`  // path fora dos diretórios de biblioteca
	Truncated []string          `json:"truncated,omitempty"` // o que não coube no orçamento

	// Self marca a própria ferramenta e seus ancestrais: um scanner que se
	// reporta é um scanner que ninguém usa duas vezes.
	Self bool `json:"self,omitempty"`

	// Vanished marca processo que morreu durante a coleta. Nenhum check pode
	// concluir nada sobre ele: instruir a preservar um PID inexistente é pior
	// que não reportar.
	Vanished bool `json:"vanished,omitempty"`

	startTicks int64 // campo 22 de stat, em ticks desde o boot
	deniedFDs  bool  // /proc/<pid>/fd ilegível: vira cobertura parcial

	cmdlineCandidate bool // cmdline vazio na 1ª leitura; aguarda reconfirmação
}

// FD é um descritor aberto, já resolvido.
type FD struct {
	N           int    `json:"n"`
	Target      string `json:"target"`
	Socket      bool   `json:"socket,omitempty"`
	SocketInode uint64 `json:"socket_inode,omitempty"`
	PTY         bool   `json:"pty,omitempty"`
	Deleted     bool   `json:"deleted,omitempty"`
}

// envAllow são as variáveis cujo VALOR é gravado. Todas as demais têm só a
// chave registrada: environ carrega senha, token e chave (runbook §3.6), e o
// dump sai do host.
var envAllowExact = map[string]bool{
	"LD_PRELOAD":      true,
	"LD_LIBRARY_PATH": true,
	"SSH_CONNECTION":  true, // contém o IP de ORIGEM de quem abriu a sessão
	"SSH_CLIENT":      true,
	"SSH_TTY":         true,
	"INVOCATION_ID":   true, // presença = lançado pelo systemd
	"JOURNAL_STREAM":  true,
	"PATH":            true,
}

var envAllowPrefix = []string{"GS_", "GSOCKET_", "_GSOCKET_"}

func envAllowed(k string) bool {
	if envAllowExact[k] {
		return true
	}
	for _, p := range envAllowPrefix {
		if strings.HasPrefix(k, p) {
			return true
		}
	}
	return false
}

// libDirs são os prefixos onde biblioteca legitimamente mora. Fora deles, o
// mapeamento entra em MapsOdd (runbook §7.8).
var libDirs = []string{"/usr/lib", "/lib", "/usr/lib64", "/lib64", "/usr/local/lib", "/usr/libexec"}

func collectProcesses(f *Facts, e *env.Env) {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		f.partial("proc", "não foi possível listar /proc: "+err.Error())
		return
	}

	self := os.Getpid()

	pids := make([]int, 0, len(ents))
	for _, ent := range ents {
		if pid, err := strconv.Atoi(ent.Name()); err == nil {
			pids = append(pids, pid)
		}
	}
	// O que o readdir LISTOU, independente de termos conseguido ler. É um
	// conjunto diferente de f.Processes, e a diferença é permissão — usar a
	// lista de processos lidos como "o que está visível" faria a comparação
	// cruzada acusar de OCULTO todo processo alheio que não pudemos abrir.
	f.PidsListados = pids

	// A leitura de cada PID é INDEPENDENTE das outras: são arquivos diferentes,
	// sem estado compartilhado. Ler em paralelo é o único alívio real para um
	// servidor grande — o custo por processo é syscall, e o kernel formata o
	// texto de /proc/<pid>/maps na hora da leitura, coisa que otimização de
	// parsing não alcança.
	//
	// O teto é baixo de propósito. Este binário roda em host sob incidente,
	// possivelmente já sobrecarregado, e um scanner que satura a CPU atrapalha
	// exatamente quem está tentando responder.
	//
	// Env.Workers respeita afinidade E cota de cgroup: num contêiner com
	// --cpus=0.5 abrir oito leitores não acelera nada, só entrega mais trabalho
	// ao throttling. Em VM de 1 vCPU o resultado é serial, como antes.
	workers := e.Workers(maxCollectWorkers)

	type slot struct {
		p        *Process
		outcome  readOutcome
		panicked string
	}
	slots := make([]slot, len(pids))
	var next atomic.Int64
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := int(next.Add(1)) - 1
				if i >= len(pids) {
					return
				}
				slots[i].p, slots[i].outcome, slots[i].panicked = readProcessGuarded(pids[i])
			}
		}()
	}
	wg.Wait()

	// A agregação volta a ser serial: a ordem do relatório não pode depender de
	// qual worker terminou primeiro.
	var denied, deniedMaps, deniedNS, gone, hidden, listed int
	var panics []string
	for i := range slots {
		listed++
		if slots[i].panicked != "" {
			panics = append(panics, "pid "+strconv.Itoa(pids[i])+": "+slots[i].panicked)
			continue
		}
		p, outcome := slots[i].p, slots[i].outcome
		switch outcome {
		case readGone:
			// Terminou entre o ReadDir e a leitura. Não há o que avaliar, e não
			// há lacuna: o processo não existe mais para ninguém.
			gone++
			continue
		case readDenied:
			// Existe e não pudemos ler — sob hidepid=1, que é hardening CIS
			// comum, é a MAIORIA. Calar isso faz a ferramenta ver 4 de 310
			// processos e imprimir RESULT: OK.
			hidden++
			continue
		}
		// SÓ o próprio processo é isento. A versão anterior isentava toda a
		// cadeia de ancestrais — e como a caminhada terminava em 1, o PID 1
		// ficava isento em TODO host. Um /sbin/init substituído, ou um
		// container cujo PID 1 é o payload, nunca seria avaliado. Pior: o
		// ancestral mais comum de uma sessão de IR é o sshd, então um sshd
		// backdoored era exatamente o que se pulava.
		if p.PID == self {
			p.Self = true
		}
		if len(p.Truncated) > 0 {
			for _, t := range p.Truncated {
				f.partial("proc", "pid "+strconv.Itoa(p.PID)+": "+t)
			}
		}
		if p.deniedFDs {
			denied++
		}
		if p.MapsDenied {
			deniedMaps++
		}
		if p.NSDenied {
			deniedNS++
		}
		f.Processes = append(f.Processes, *p)
	}

	sort.Slice(f.Processes, func(i, j int) bool { return f.Processes[i].PID < f.Processes[j].PID })

	reconfirmCmdline(f)

	if denied > 0 {
		f.partial("proc", strconv.Itoa(denied)+" processos com fds ilegíveis (sem permissão): "+
			"reverse shell por fd 0/1/2 não pôde ser avaliado neles")
	}
	if deniedMaps > 0 {
		f.partial("proc", strconv.Itoa(deniedMaps)+" processos com /proc/<pid>/maps ilegível "+
			"(sem permissão): região rwx anônima — a assinatura de injeção — não pôde "+
			"ser avaliada neles")
	}
	if deniedNS > 0 {
		f.partial("proc", strconv.Itoa(deniedNS)+" processos com /proc/<pid>/ns/* ilegível "+
			"(sem permissão): namespace próprio não pôde ser avaliado neles")
	}
	if len(panics) > 0 {
		// Defeito da ferramenta é lacuna de cobertura, não achado sobre o host.
		f.partial("proc", strconv.Itoa(len(panics))+" PIDs derrubaram o coletor "+
			"(DEFEITO DA FERRAMENTA, não do host): "+strings.Join(panics, " · ")+
			" — esses processos NÃO foram avaliados por check nenhum")
	}
	if hidden > 0 {
		f.partial("proc", strconv.Itoa(hidden)+" de "+strconv.Itoa(listed)+
			" PIDs existem em /proc e não puderam ser LIDOS (hidepid ou permissão): "+
			"esses processos NÃO foram avaliados por check nenhum")
	}
	// gone NÃO entra em partial. Fica registrado para quem lê o JSONL: um
	// número alto é rotatividade fora do normal, e vale o olho humano — mas
	// não é "não consegui olhar".
	f.ProcessesGone = gone
	if noExe := countNoExe(f); noExe > 0 {
		f.partial("proc", strconv.Itoa(noExe)+" processos com /proc/<pid>/exe ilegível "+
			"(sem permissão): memfd, binário apagado e disfarce de kthread não puderam "+
			"ser avaliados neles — rode como root")
	}

	// StartUTC depende do boot time, que o coletor de host calculou.
	if !f.Host.bootTime.IsZero() {
		for i := range f.Processes {
			p := &f.Processes[i]
			if p.startTicks > 0 {
				t := f.Host.bootTime.Add(time.Duration(p.startTicks) * time.Second / time.Duration(f.Host.hz))
				p.StartUTC = t.UTC().Format(time.RFC3339)
				p.Age = e.Now.Sub(t)
			}
		}
	}
}

// countNoExe conta processos cujo exe falhou por PERMISSÃO. É diferente de
// thread de kernel, que legitimamente não tem exe — e a diferença decide se
// "não achei" pode ser impresso.
func countNoExe(f *Facts) int {
	n := 0
	for i := range f.Processes {
		if f.Processes[i].ExeDenied {
			n++
		}
	}
	return n
}

func procPath(pid int, sub string) string {
	return "/proc/" + strconv.Itoa(pid) + "/" + sub
}

// splitStatComm resolve a armadilha clássica: o campo comm de /proc/<pid>/stat
// pode conter espaço E parêntese. Parsear por Fields quebra silenciosamente —
// parseia-se a partir do ÚLTIMO ')'.
func splitStatComm(s string) (comm string, rest []string, ok bool) {
	i := strings.IndexByte(s, '(')
	j := strings.LastIndexByte(s, ')')
	if i < 0 || j < 0 || j < i {
		return "", nil, false
	}
	comm = s[i+1 : j]
	rest = strings.Fields(s[j+1:])
	return comm, rest, true
}

// readOutcome separa os dois desfechos que a versão anterior confundia. A
// diferença decide se a cobertura degrada:
//
//	readGone     o processo TERMINOU durante a coleta. Ninguém pode avaliá-lo
//	             — nem nós, nem um humano com ps. Não é lacuna de cobertura:
//	             é rotina, e acontece em toda varredura de servidor ocupado
//	readDenied   o processo EXISTE e nós é que não pudemos lê-lo — hidepid,
//	             permissão. Isso É lacuna, e é o que a ferramenta existe para
//	             não calar
//
// Tratar os dois como um só fazia um host de produção nunca reportar OK: basta
// um processo terminar nos 60ms da coleta.
type readOutcome int

const (
	readOK readOutcome = iota
	readGone
	readDenied
)

// readProcessGuarded isola a falha de UM pid.
//
// Não é zelo genérico: antes de a coleta ser paralela, um panic aqui subia até
// o recover() do main e virava exit 3 (ERROR). Em goroutine, o recover do main
// NÃO alcança — o processo morre com status 2, que o contrato desta ferramenta
// define como "CRITICAL: indicador de alta confiança". Um defeito NOSSO faria a
// automação de frota marcar o host como comprometido.
//
// É a mesma correção que o runGuarded fez para os checks, no lugar onde a
// paralelização a desfez.
func readProcessGuarded(pid int) (p *Process, out readOutcome, panicked string) {
	defer func() {
		if r := recover(); r != nil {
			p, out, panicked = nil, readDenied, fmt.Sprint(r)
		}
	}()
	p, out = readProcess(pid)
	return p, out, ""
}

func readProcess(pid int) (*Process, readOutcome) {
	p := &Process{PID: pid, NS: map[string]string{}}

	st, err := readTrimErr(procPath(pid, "stat"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, readGone
		}
		return nil, readDenied
	}
	comm, rest, ok := splitStatComm(st)
	if !ok {
		// stat existe e não parseia: não é ausência, é algo que não entendemos.
		return nil, readDenied
	}
	p.Comm = comm
	// rest[0] é o campo 3 (state); rest[n] é o campo n+3.
	if len(rest) > 0 {
		p.State = rest[0]
	}
	if len(rest) > 1 {
		p.PPID, _ = strconv.Atoi(rest[1])
	}
	if len(rest) > 17 {
		p.Threads, _ = strconv.Atoi(rest[17]) // campo 20
	}
	if len(rest) > 19 {
		p.startTicks, _ = strconv.ParseInt(rest[19], 10, 64) // campo 22
	}

	// Status lido pela METADE deixa UID e EUID em zero, e zero é root: o
	// processo passaria a ser pulado por proc.caps_unexpected como se fosse
	// root legítimo. Sem a identidade, não afirmamos nada sobre este PID.
	if err := readStatus(p); err != nil {
		if os.IsNotExist(err) {
			return nil, readGone
		}
		return nil, readDenied
	}
	readExe(p)
	readCwd(p)
	readCmdline(p)
	readEnviron(p)
	readCgroup(p)
	readNS(p)
	readFDs(p)
	readMaps(p)
	return p, readOK
}

// readStatus parseia por CHAVE. O conjunto de campos varia muito entre kernels;
// posição não é contrato.
// readStatus parseia por CHAVE, em fluxo, e PARA assim que tem o que precisa.
// O status vem com cerca de 60 linhas e as quatro que interessam estão nas
// primeiras vinte: ler o resto é trabalho jogado fora, multiplicado por
// processo.
func readStatus(p *Process) error {
	fh, err := os.Open(procPath(p.PID, "status"))
	if err != nil {
		return err
	}
	defer fh.Close()

	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 0, 4096), 64*1024)
	want := 4 // Uid, Gid, TracerPid, CapEff

	for sc.Scan() {
		if want == 0 {
			break
		}
		k, v, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch k {
		case "Uid":
			want--
			// real, efetivo, salvo, fs. O que MANDA é o efetivo: um binário
			// setuid tem uid real 1000 e efetivo 0 — ele É root, e ler só o
			// primeiro campo faz a ferramenta chamá-lo de processo comum
			// (runbook §3.7).
			if fs := strings.Fields(v); len(fs) > 1 {
				p.UID, _ = strconv.Atoi(fs[0])
				p.EUID, _ = strconv.Atoi(fs[1])
			} else if len(fs) == 1 {
				p.UID, _ = strconv.Atoi(fs[0])
				p.EUID = p.UID
			}
		case "Gid":
			want--
			if fs := strings.Fields(v); len(fs) > 1 {
				p.GID, _ = strconv.Atoi(fs[0])
				p.EGID, _ = strconv.Atoi(fs[1])
			} else if len(fs) == 1 {
				p.GID, _ = strconv.Atoi(fs[0])
				p.EGID = p.GID
			}
		case "TracerPid":
			want--
			p.TracerPID, _ = strconv.Atoi(v)
		case "CapEff":
			want--
			p.CapEff, _ = strconv.ParseUint(v, 16, 64)
		}
	}
	// sc.Scan() devolve false tanto no fim do arquivo quanto em ERRO. Sem
	// consultar sc.Err(), ler metade é indistinguível de ler tudo.
	return sc.Err()
}

func readExe(p *Process) {
	t, err := os.Readlink(procPath(p.PID, "exe"))
	if err != nil {
		p.ExeErr = classifyErr(err)
		p.ExeMissing = os.IsNotExist(err)
		p.ExeDenied = os.IsPermission(err)
		return
	}
	// Um binário executado via memfd_create nunca esteve em disco: o link
	// resolve para "/memfd:<nome> (deleted)" (runbook §3.16).
	if s, ok := strings.CutSuffix(t, " (deleted)"); ok {
		p.ExeDeleted = true
		t = s
	}
	if strings.HasPrefix(t, "/memfd:") {
		p.ExeMemfd = true
	}
	p.Exe = t
}

func readCwd(p *Process) {
	t, err := os.Readlink(procPath(p.PID, "cwd"))
	if err != nil {
		return
	}
	if s, ok := strings.CutSuffix(t, " (deleted)"); ok {
		p.CwdDeleted = true
		t = s
	}
	p.Cwd = t
}

func readCmdline(p *Process) {
	argv, err := readNULErr(procPath(p.PID, "cmdline"))
	p.Argv = argv
	if len(argv) > 0 || err != nil {
		return
	}
	// Thread de kernel tem cmdline vazio E não tem exe. Userspace com cmdline
	// vazio está se disfarçando de uma — mas processo em meio a exec também lê
	// vazio, e isso é corrida, não anomalia. Só marca CANDIDATO aqui; a
	// reconfirmação acontece numa SEGUNDA passada, fora do laço principal.
	//
	// O sleep costumava ficar aqui, serial: 50 processos com argv zerado —
	// que qualquer usuário sem privilégio consegue criar — custavam 1,2s e
	// estouravam o orçamento do wtf. Pior, a população que dispara isso é
	// exatamente a que o check caça, então a ferramenta ficava mais lenta
	// quanto mais comprometido o host.
	if p.Exe != "" {
		p.cmdlineCandidate = true
	}
}

// reconfirmCmdline é a segunda passada. Distingue os três desfechos da corrida,
// que a primeira leitura não separa:
//
//	argv apareceu   → era exec em curso, não é disfarce
//	erro na releitura → o processo MORREU: descartar, não virar achado
//	continua vazio  → disfarce confirmado
//
// O readNUL antigo devolvia nil tanto para ENOENT quanto para arquivo vazio,
// então um processo que morresse nos 20ms virava um CRITICAL com instrução de
// preservar um PID inexistente.
func reconfirmCmdline(f *Facts) {
	var cands []int
	for i := range f.Processes {
		if f.Processes[i].cmdlineCandidate {
			cands = append(cands, i)
		}
	}
	if len(cands) == 0 {
		return
	}
	if len(cands) > maxCmdlineRecheck {
		f.partial("proc", strconv.Itoa(len(cands))+" processos com cmdline vazio; "+
			"reconfirmados apenas "+strconv.Itoa(maxCmdlineRecheck)+
			" — o excedente NÃO foi avaliado para disfarce de kthread")
		cands = cands[:maxCmdlineRecheck]
	}

	time.Sleep(cmdlineRecheckDelay) // UM sleep para todos, não um por processo

	for _, i := range cands {
		p := &f.Processes[i]
		argv, err := readNULErr(procPath(p.PID, "cmdline"))
		switch {
		case err != nil:
			// morreu na janela: não afirma nada sobre ele
			p.Vanished = true
		case len(argv) > 0:
			p.Argv = argv // era exec em curso
		default:
			// Confirma que ainda é o MESMO processo: PID pode ter sido reusado.
			if st, ok := readTrim(procPath(p.PID, "stat")); ok {
				if _, rest, ok := splitStatComm(st); ok && len(rest) > 19 && rest[19] != strconv.FormatInt(p.startTicks, 10) {
					p.Vanished = true
					continue
				}
			}
			p.CmdlineEmpty = true
		}
	}
}

func readEnviron(p *Process) {
	kv := readNUL(procPath(p.PID, "environ"))
	if len(kv) == 0 {
		return
	}
	p.Env = map[string]string{}
	for _, e := range kv {
		k, v, ok := strings.Cut(e, "=")
		if !ok {
			continue
		}
		p.EnvKeys = append(p.EnvKeys, k)
		if envAllowed(k) {
			p.Env[k] = v
		}
	}
	sort.Strings(p.EnvKeys)
}

func readCgroup(p *Process) {
	b, err := os.ReadFile(procPath(p.PID, "cgroup"))
	if err != nil {
		return
	}
	// Duas gramáticas: v2 é "0::/path", v1 é "N:controller:/path".
	// O cgroup sobrevive ao daemonizar, então é o que restaura a origem quando
	// PPid vira 1 (runbook §3.11).
	//
	// No v1 há uma LINHA POR CONTROLADOR, e só a de name=systemd carrega a
	// unit. Pegar a primeira — que pode ser cpuset, net_cls, freezer — destrói
	// exatamente a proveniência que este campo existe para preservar.
	var fallback string
	for _, ln := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		parts := strings.SplitN(ln, ":", 3)
		if len(parts) != 3 {
			continue
		}
		switch {
		case parts[0] == "0" && parts[1] == "": // v2: hierarquia unificada
			p.Cgroup = parts[2]
			return
		case parts[1] == "name=systemd": // v1: a que tem a unit
			p.Cgroup = parts[2]
			return
		case fallback == "":
			fallback = parts[2]
		}
	}
	p.Cgroup = fallback
}

func readNS(p *Process) {
	for _, n := range []string{"mnt", "net", "pid", "user"} {
		t, err := os.Readlink(procPath(p.PID, "ns/"+n))
		switch {
		case err == nil:
			p.NS[n] = t
		case os.IsPermission(err):
			// Sem isto, um host sem root produziria mapa de namespace vazio e
			// o check leria "nenhum namespace divergente" — que é a mentira
			// que a ferramenta existe para não contar.
			p.NSDenied = true
		}
	}
}

func readFDs(p *Process) {
	ents, err := os.ReadDir(procPath(p.PID, "fd"))
	if err != nil {
		if os.IsPermission(err) {
			p.deniedFDs = true
		}
		return
	}

	// os.ReadDir ordena por NOME: "0","1","10","100","1000",… Aplicar o teto
	// sobre essa ordem descarta os fds de número BAIXO primeiro — num processo
	// com 1500 fds, o fd 2 cai no índice 612 e o 3 no 723, ambos além de 512.
	// São exatamente 0/1/2 que decidem reverse shell (runbook §3.8): o teto
	// apagaria em silêncio o único sinal que importa. Ordene numericamente
	// ANTES de cortar.
	nums := make([]int, 0, len(ents))
	for _, ent := range ents {
		if n, err := strconv.Atoi(ent.Name()); err == nil {
			nums = append(nums, n)
		}
	}
	sort.Ints(nums)
	if len(nums) > maxFDs {
		p.Truncated = append(p.Truncated,
			"processo tem "+strconv.Itoa(len(nums))+" fds; lidos os "+
				strconv.Itoa(maxFDs)+" de MENOR número (0,1,2 preservados)")
		nums = nums[:maxFDs]
	}

	for _, n := range nums {
		name := strconv.Itoa(n)
		t, err := os.Readlink(procPath(p.PID, "fd/"+name))
		if err != nil {
			continue
		}
		fd := FD{N: n, Target: t}
		if s, ok := strings.CutPrefix(t, "socket:["); ok {
			fd.Socket = true
			fd.SocketInode, _ = strconv.ParseUint(strings.TrimSuffix(s, "]"), 10, 64)
		}
		if t == "/dev/ptmx" || strings.HasPrefix(t, "/dev/pts/") {
			fd.PTY = true
		}
		if strings.HasSuffix(t, " (deleted)") {
			fd.Deleted = true
			fd.Target = strings.TrimSuffix(t, " (deleted)")
		}
		p.FDs = append(p.FDs, fd)
	}
}

// readMaps guarda só o que decide alguma coisa: região gravável E executável
// (código gerado ou injetado) e biblioteca carregada de fora dos diretórios
// padrão (runbook §3.10, §7.8).
// readMaps percorre /proc/<pid>/maps EM FLUXO, sem trazer o arquivo inteiro
// para a memória.
//
// A versão anterior fazia ReadFile + Split: duas cópias completas mais um slice
// com uma string por linha. Medindo contra o /proc real, ela sozinha respondia
// por 36% do tempo de coleta e 67% de toda a memória alocada — e isso SEM root,
// onde a maioria dos maps nem é legível. Uma JVM tem dezenas de milhares de
// linhas de maps; num servidor com várias, o custo é o do host inteiro.
//
// Em fluxo, o teto de linhas também deixa de ser cosmético: passando dele, o
// resto do arquivo simplesmente não é lido.
func readMaps(p *Process) {
	fh, err := os.Open(procPath(p.PID, "maps"))
	if err != nil {
		if os.IsPermission(err) {
			p.MapsDenied = true
		}
		return
	}
	defer fh.Close()

	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 0, 8192), 64*1024)

	oddSeen := map[string]bool{}
	n := 0
	for sc.Scan() {
		if n >= maxMapLines {
			p.Truncated = append(p.Truncated,
				"maps truncado em "+strconv.Itoa(maxMapLines)+" linhas")
			break
		}
		n++
		// sc.Bytes() não aloca; sc.Text() alocaria UMA string por linha, e são
		// milhares por processo. A conversão para string acontece só quando há
		// achado — que é o caso raro.
		perms, path, ok := splitMapLineBytes(sc.Bytes())
		if !ok {
			continue
		}
		if bytes.IndexByte(perms, 'w') >= 0 && bytes.IndexByte(perms, 'x') >= 0 {
			d := string(path)
			if d == "" {
				d = "(anônimo)"
			}
			p.MapsRWX = append(p.MapsRWX, string(perms)+" "+d)
		}
		if len(path) == 0 || path[0] != '/' || !looksLikeSO(path) {
			continue
		}
		ps := string(path)
		if isLibDir(ps) || oddSeen[ps] {
			continue
		}
		oddSeen[ps] = true
		p.MapsOdd = append(p.MapsOdd, ps)
	}
	// Mesmo motivo do readStatus: metade do maps lida sem rwx não é "não há
	// rwx". O que já foi encontrado continua valendo — achado é achado —, mas
	// o processo passa a contar como não avaliado.
	if sc.Err() != nil {
		p.MapsDenied = true
	}
}

// looksLikeSO reconhece biblioteca compartilhada sem alocar: ".so" no fim, ou
// ".so." no meio (libfoo.so.1.2).
func looksLikeSO(path []byte) bool {
	return bytes.HasSuffix(path, []byte(".so")) || bytes.Contains(path, []byte(".so."))
}

// splitMapLine separa "addr perms offset dev inode [path]". O kernel NÃO escapa
// espaço no path, então strings.Fields quebra em qualquer diretório com espaço
// no nome — e um rename derrotaria o MapsOdd em silêncio.
func splitMapLine(ln string) (perms, path string, ok bool) {
	pb, pa, ok := splitMapLineBytes([]byte(ln))
	return string(pb), string(pa), ok
}

// splitMapLineBytes é a versão sem alocação, usada no laço quente. Os cinco
// primeiros campos são fixos; o RESTO da linha é o caminho — que pode conter
// espaço, e por isso não pode sair de um Fields().
func splitMapLineBytes(ln []byte) (perms, path []byte, ok bool) {
	var f [5][]byte
	i := 0
	for n := 0; n < 5; n++ {
		for i < len(ln) && ln[i] == ' ' {
			i++
		}
		start := i
		for i < len(ln) && ln[i] != ' ' {
			i++
		}
		if start == i {
			return nil, nil, false
		}
		f[n] = ln[start:i]
	}
	for i < len(ln) && ln[i] == ' ' {
		i++
	}
	return f[1], ln[i:], true
}

func isLibDir(path string) bool {
	for _, d := range libDirs {
		if strings.HasPrefix(path, d+"/") {
			return true
		}
	}
	return false
}

func readNUL(p string) []string {
	v, _ := readNULErr(p)
	return v
}

// readNULErr separa "não consegui ler" de "está vazio" — a confusão entre os
// dois fabricava achado a partir de processo morto.
func readNULErr(p string) ([]string, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return nil, nil
	}
	parts := strings.Split(strings.TrimRight(string(b), "\x00"), "\x00")
	out := parts[:0]
	for _, s := range parts {
		if s != "" {
			out = append(out, s)
		}
	}
	return out, nil
}

func classifyErr(err error) string {
	switch {
	case os.IsPermission(err):
		return "sem permissão"
	case os.IsNotExist(err):
		return "não existe"
	default:
		return err.Error()
	}
}
