package facts

import (
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lex0c/aletheia/internal/env"
)

// Limites de coleta. Estourar vira cobertura parcial reportada — nunca
// truncamento silencioso.
const (
	maxMapLines = 4000
	maxFDs      = 512

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

	Comm  string `json:"comm"`  // de /proc/<pid>/stat, entre parênteses
	State string `json:"state"` // R S D Z T ...

	Exe        string `json:"exe,omitempty"`
	ExeErr     string `json:"exe_err,omitempty"`
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

	startTicks       int64 // campo 22 de stat, em ticks desde o boot
	deniedFDs        bool  // /proc/<pid>/fd ilegível: vira cobertura parcial
	cmdlineCandidate bool  // cmdline vazio na 1ª leitura; aguarda reconfirmação
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

	var denied, dropped, listed int
	for _, ent := range ents {
		pid, err := strconv.Atoi(ent.Name())
		if err != nil {
			continue
		}
		listed++
		p, ok := readProcess(pid)
		if !ok {
			// Pode ser processo que morreu entre o ReadDir e a leitura (normal)
			// OU /proc/<pid>/stat ilegível — sob hidepid=1/2, que é hardening
			// CIS comum, é a MAIORIA. Descartar em silêncio faz a ferramenta
			// ver 4 de 310 processos e imprimir RESULT: OK.
			dropped++
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
		f.Processes = append(f.Processes, *p)
	}

	sort.Slice(f.Processes, func(i, j int) bool { return f.Processes[i].PID < f.Processes[j].PID })

	reconfirmCmdline(f)

	if denied > 0 {
		f.partial("proc", strconv.Itoa(denied)+" processos com fds ilegíveis (sem permissão): "+
			"reverse shell por fd 0/1/2 não pôde ser avaliado neles")
	}
	if dropped > 0 {
		f.partial("proc", strconv.Itoa(dropped)+" de "+strconv.Itoa(listed)+
			" PIDs listados em /proc não puderam ser lidos (morreram na coleta, "+
			"ou hidepid restringe): esses processos NÃO foram avaliados por check nenhum")
	}
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
		if f.Processes[i].ExeErr == "sem permissão" {
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

func readProcess(pid int) (*Process, bool) {
	p := &Process{PID: pid, NS: map[string]string{}}

	st, ok := readTrim(procPath(pid, "stat"))
	if !ok {
		return nil, false
	}
	comm, rest, ok := splitStatComm(st)
	if !ok {
		return nil, false
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

	readStatus(p)
	readExe(p)
	readCwd(p)
	readCmdline(p)
	readEnviron(p)
	readCgroup(p)
	readNS(p)
	readFDs(p)
	readMaps(p)
	return p, true
}

// readStatus parseia por CHAVE. O conjunto de campos varia muito entre kernels;
// posição não é contrato.
func readStatus(p *Process) {
	b, err := os.ReadFile(procPath(p.PID, "status"))
	if err != nil {
		return
	}
	for _, ln := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(ln, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch k {
		case "Uid":
			if fs := strings.Fields(v); len(fs) > 0 {
				p.UID, _ = strconv.Atoi(fs[0])
			}
		case "Gid":
			if fs := strings.Fields(v); len(fs) > 0 {
				p.GID, _ = strconv.Atoi(fs[0])
			}
		case "TracerPid":
			p.TracerPID, _ = strconv.Atoi(v)
		case "CapEff":
			p.CapEff, _ = strconv.ParseUint(v, 16, 64)
		}
	}
}

func readExe(p *Process) {
	t, err := os.Readlink(procPath(p.PID, "exe"))
	if err != nil {
		p.ExeErr = classifyErr(err)
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
	for _, n := range []string{"mnt", "net", "pid"} {
		if t, err := os.Readlink(procPath(p.PID, "ns/"+n)); err == nil {
			p.NS[n] = t
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
func readMaps(p *Process) {
	b, err := os.ReadFile(procPath(p.PID, "maps"))
	if err != nil {
		return
	}
	lines := strings.Split(string(b), "\n")
	if len(lines) > maxMapLines {
		p.Truncated = append(p.Truncated, "maps truncado em "+strconv.Itoa(maxMapLines)+" linhas")
		lines = lines[:maxMapLines]
	}
	oddSeen := map[string]bool{}
	for _, ln := range lines {
		perms, path, ok := splitMapLine(ln)
		if !ok {
			continue
		}
		if strings.Contains(perms, "w") && strings.Contains(perms, "x") {
			d := path
			if d == "" {
				d = "(anônimo)"
			}
			p.MapsRWX = append(p.MapsRWX, perms+" "+d)
		}
		if path == "" || !strings.HasPrefix(path, "/") {
			continue
		}
		if isLibDir(path) || oddSeen[path] {
			continue
		}
		if strings.HasSuffix(path, ".so") || strings.Contains(path, ".so.") {
			oddSeen[path] = true
			p.MapsOdd = append(p.MapsOdd, path)
		}
	}
}

// splitMapLine separa "addr perms offset dev inode [path]". O kernel NÃO escapa
// espaço no path, então strings.Fields quebra em qualquer diretório com espaço
// no nome — e um rename derrotaria o MapsOdd em silêncio.
func splitMapLine(ln string) (perms, path string, ok bool) {
	var f [5]string
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
			return "", "", false
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
