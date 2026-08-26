package facts

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
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
	Argv         []string `json:"argv,omitempty" redact:"cmdline"`
	CmdlineEmpty bool     `json:"cmdline_empty,omitempty"`

	// EnvKeys tem as chaves OBSERVADAS; Env só os valores da allowlist
	// (SPEC 5.4) — ou todos, quando o operador dispensou a redação.
	EnvKeys []string `json:"env_keys,omitempty"`

	// EnvLido separa "o ambiente está vazio" de "não consegui ler o ambiente".
	//
	// readNULTrunc devolve erro em EACCES, EIO e ESRCH, e ele era descartado:
	// o processo saía com Env e EnvKeys nulos, indistinguível de um processo
	// que de fato não tem variável nenhuma — coisa que praticamente não existe.
	// É "não observei" virando "não havia nada", no fato que sustenta a tool
	// mais sensível do perfil completo.
	//
	// O campo é POSITIVO (lido, e não "falhou") de propósito: o zero value de um
	// Facts montado à mão em teste é `false`, e o lado seguro é o que não
	// afirma leitura.
	EnvLido bool `json:"env_read,omitempty"`
	// EnvCortado diz que o ambiente passou do teto e as variáveis seguintes NÃO
	// foram examinadas. Separado de Truncated porque a decisão de recusar uma
	// resposta completa não pode depender de procurar uma palavra numa lista de
	// frases em português.
	EnvCortado bool `json:"env_truncated,omitempty"`
	// EnvErro é a evidência de POR QUE a leitura falhou. Nunca controle de
	// fluxo: quem decide é EnvLido.
	EnvErro string `json:"env_error,omitempty"`

	// EnvBruto são as entradas do environ COMO O KERNEL AS EXPÔS: na ordem
	// original, com duplicatas, e com as entradas sem '=' preservadas.
	//
	// Env e EnvKeys são projeções, e cada uma perde algo. O mapa colapsa chave
	// repetida — e a repetição é observável: o ld.so honra a ÚLTIMA (medido,
	// com dois LD_PRELOAD e um alvo inexistente em cada posição), enquanto o
	// getenv da libc devolve a primeira. Consumidores diferentes do mesmo
	// ambiente discordam, e um retrato que só guarda o mapa apaga a pergunta.
	// A ordenação de EnvKeys destrói a ordem, que é o que decide aquilo.
	//
	// [][]byte, e não []string: environ é byte arbitrário, e o encoding/json
	// troca UTF-8 inválido por U+FFFD numa string. Em []byte ele vira base64, e
	// os bytes atravessam o artefato como estavam.
	//
	// Só é preenchido sob --allow-secrets: as entradas cruas carregam VALOR, e
	// gravá-las sem consentimento seria o vazamento que a allowlist evita.
	EnvBruto [][]byte          `json:"env_raw,omitempty"`
	Env      map[string]string `json:"env,omitempty"`

	CapEff    uint64 `json:"cap_eff"`
	TracerPID int    `json:"tracer_pid,omitempty"`
	Threads   int    `json:"threads,omitempty"`

	// NProcMax é o RLIMIT_NPROC efetivo deste processo — o teto de processos E
	// THREADS do uid REAL, que é o que produz EAGAIN quando estoura.
	//
	// Ele é por processo e não por usuário: um processo pode baixar o próprio
	// limite, e o do systemd não é o do login. Vale -1 para "sem teto" e 0 para
	// "não lido".
	NProcMax int `json:"nproc_max,omitempty"`

	StartUTC string        `json:"start_utc,omitempty"`
	Age      time.Duration `json:"-"`

	// MapsDenied e NSDenied são EXPORTADOS porque quem precisa deles é o
	// check: "nenhuma região rwx" e "nenhum namespace divergente" só valem
	// alguma coisa se a fonte tiver sido legível.
	MapsDenied bool `json:"maps_denied,omitempty"`
	NSDenied   bool `json:"ns_denied,omitempty"`

	Cgroup string `json:"cgroup,omitempty"`
	// Container é o runtime que criou este processo — docker, kubernetes,
	// podman —, derivado do cgroup. Vazio significa processo do HOST, e a
	// diferença muda qual pergunta faz sentido sobre o binário dele.
	Container   string            `json:"container,omitempty"`
	ContainerID string            `json:"container_id,omitempty"`
	NS          map[string]string `json:"ns,omitempty"`
	FDs         []FD              `json:"fds,omitempty"`
	MapsRWX     []string          `json:"maps_rwx,omitempty"` // regiões graváveis E executáveis
	MapsOdd     []string          `json:"maps_odd,omitempty"` // path fora dos diretórios de biblioteca

	// MapsLibs é TODA biblioteca carregada, inclusive as de diretório normal.
	// É a única fonte que torna uma biblioteca candidata à pergunta de
	// propriedade — ela não executa, então nada mais a traria.
	MapsLibs []string `json:"maps_libs,omitempty"`

	// MapsExecAnon são as regiões EXECUTÁVEIS sem arquivo por trás e SEM nome.
	//
	// É a metade que o MapsRWX não alcança, e ela é a mais limpa das duas. A
	// injeção que respeita W^X nunca deixa gravável e executável ligados ao
	// mesmo tempo:
	//
	//	mmap(RW) → write(payload) → mprotect(RX)
	//
	// No instante do retrato o que existe é r-xp anônimo, e o MapsRWX não o vê
	// por definição — ele exige o 'w'.
	//
	// SEM NOME faz parte do critério, e não é detalhe. Desde o 5.17 o kernel
	// guarda um rótulo por região (PR_SET_VMA_ANON_NAME) e o JIT moderno rotula
	// o código que gera: medido num desktop, o Firefox tem 85 regiões
	// [anon:js-executable-memory] e NENHUMA anônima sem nome. O que não tem
	// rótulo não foi declarado por ninguém.
	MapsExecAnon []string `json:"maps_exec_anon,omitempty"`
	// MapsExecAnonN é o TOTAL, porque a lista acima tem teto. Amostra e
	// contagem são coisas diferentes, e o check precisa das duas para não dizer
	// "16 regiões" onde há mil.
	MapsExecAnonN int `json:"maps_exec_anon_total,omitempty"`
	// MapsExecNomes são os rótulos das regiões executáveis anônimas que TÊM
	// nome. Não é achado: é o contexto que permite dizer "este processo rotula o
	// próprio JIT" — e portanto que uma região sem rótulo, no mesmo processo,
	// não é explicada por ele.
	MapsExecNomes []string `json:"maps_exec_named,omitempty"`
	// MapsApagados são os mapeamentos EXECUTÁVEIS sem arquivo vivo por trás. O
	// ExeDeleted responde pelo executável PRINCIPAL; uma biblioteca aberta com
	// dlopen e apagada em seguida não passa por ele, e o /proc/<pid>/exe do
	// processo continua apontando para um caminho perfeitamente legítimo.
	MapsApagados []MapaApagado `json:"maps_deleted_exec,omitempty"`

	Truncated []string `json:"truncated,omitempty"` // o que não coube no orçamento

	// Self marca a própria ferramenta e seus ancestrais: um scanner que se
	// reporta é um scanner que ninguém usa duas vezes.
	Self bool `json:"self,omitempty"`

	// Vanished marca processo que morreu durante a coleta. Nenhum check pode
	// concluir nada sobre ele: instruir a preservar um PID inexistente é pior
	// que não reportar.
	Vanished bool `json:"vanished,omitempty"`

	// CgroupDesconhecido marca o processo cujo /proc/<pid>/cgroup não pôde ser
	// lido ou interpretado. Existe porque Cgroup=="" tem DOIS significados —
	// "está no host" e "não consegui olhar" — e o primeiro é premissa de
	// acusação: proc.container_boundary chama de escape de contêiner o exe em
	// camada de imagem cujo cgroup é do host. Quem for afirmar sobre o host
	// precisa checar esta marca antes.
	CgroupDesconhecido bool `json:"cgroup_unknown,omitempty"`

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
	// Pipe e PipeInode são o outro fd que se herda: um pipe anônimo. As DUAS
	// pontas de um pipe carregam o MESMO inode, então dois processos com o
	// mesmo PipeInode detêm o mesmo objeto pipe — o caminho comum de chegar aí
	// é herança de quem o criou, mas um fd também atravessa socket unix por
	// SCM_RIGHTS, então isso é o CANAL e não a prova do parentesco (§17).
	Pipe      bool   `json:"pipe,omitempty"`
	PipeInode uint64 `json:"pipe_inode,omitempty"`
	PTY       bool   `json:"pty,omitempty"`
	Deleted   bool   `json:"deleted,omitempty"`
}

// MapaApagado é um mapeamento executável cujo arquivo não está no lugar.
type MapaApagado struct {
	Caminho string `json:"path"`
	Perms   string `json:"perms,omitempty"`
	// Ini e Fim são a FAIXA do mapeamento. Guardá-la é o que permite ao
	// preserve capturar o payload direto de /proc/<pid>/mem: o arquivo sumiu,
	// e este intervalo é o único lugar onde a cópia ainda existe.
	Ini uint64 `json:"start,omitempty"`
	Fim uint64 `json:"end,omitempty"`
	// Memfd marca o que NUNCA esteve em disco: o kernel escreve
	// "/memfd:<nome> (deleted)" para memória anônima nomeada. Tratá-lo como
	// arquivo apagado inventaria um arquivo que nunca existiu — e manda o
	// operador procurar em disco o que só existe naquela memória.
	Memfd bool `json:"memfd,omitempty"`
	// Recriado diz que existe um arquivo NESTE caminho AGORA. É o discriminador
	// entre as duas histórias que produzem a mesma linha no maps:
	//
	//	atualização de pacote   o arquivo foi SUBSTITUÍDO. O caminho volta a
	//	                        existir e dezenas de processos seguram o inode
	//	                        antigo — é o estado que o needrestart detecta,
	//	                        e é rotina em qualquer servidor sem reinício
	//	payload apagado         dlopen seguido de unlink. O caminho não existe
	//	                        mais para ninguém, e a única cópia do código
	//	                        está na memória do processo
	Recriado bool `json:"path_recreated,omitempty"`
	// Verificado diz se a pergunta acima chegou a ser feita. Sem ele, "não
	// recriado" e "não perguntei" teriam o mesmo JSON — e são conclusões
	// opostas.
	Verificado bool `json:"path_checked,omitempty"`
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

// maxProcessos é o teto de PIDs considerados numa coleta. Ver o comentário no
// laço que o aplica.
const maxProcessos = 50_000

func collectProcesses(f *Facts, e *env.Env) {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		f.partial("proc", "não foi possível listar /proc: "+err.Error())
		return
	}

	self := os.Getpid()

	pids := make([]int, 0, len(ents))
	cortouPids := false
	for _, ent := range ents {
		if pid, err := strconv.Atoi(ent.Name()); err == nil {
			// O TETO EXISTE E É DECLARADO.
			//
			// O número de entradas de /proc não é escolhido pela ferramenta, e
			// uma fork bomb ou um servidor patológico o levam a dezenas de
			// milhares. Cada pid custa várias leituras — status, maps, fd, ns —,
			// então o scanner passa a somar carga a um host que já está em
			// apuros. Cinquenta mil está acima de qualquer host real e abaixo
			// do que faz a coleta virar parte do problema.
			if len(pids) >= maxProcessos {
				cortouPids = true
				break
			}
			pids = append(pids, pid)
		}
	}
	if cortouPids {
		f.partial("proc", "mais de "+strconv.Itoa(maxProcessos)+" processos "+
			"listados em /proc: os demais NÃO foram lidos, e nada pode ser "+
			"afirmado sobre eles — um número desses num host que não é de "+
			"build é por si só algo a olhar")
	}
	// O que o readdir LISTOU, independente de termos conseguido ler. É um
	// conjunto diferente de f.Processes, e a diferença é permissão — usar a
	// lista de processos lidos como "o que está visível" faria a comparação
	// cruzada acusar de OCULTO todo processo alheio que não pudemos abrir.
	f.PidsListados = pids

	// O SUCESSO do readdir, promovido a CrossView: é a testemunha de base da
	// comparação de processos, e o dump não leva PidsListados (json:"-"). Sem
	// isso, crossview.get teria de inferir "a listagem foi lida" por outro sinal
	// — e inferir estado de leitura por cardinalidade é o defeito que o cross
	// inteiro existe para não cometer.
	f.Cross.ProcListLida = true
	f.Cross.ProcListN = len(pids)

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
	var expirou atomic.Bool
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
				// O PRAZO É CONFERIDO POR PROCESSO, e não só antes do laço.
				//
				// `wtf --budget 2s` calculava um WalkDeadline que a leitura de
				// /proc não olhava: num host com dezenas de milhares de
				// processos, a coleta passava do orçamento inteiro aqui dentro
				// sem nada poder interrompê-la. O slot fica com readIndefinido,
				// e a agregação conta isso como lacuna em vez de ausência.
				if e.WalkExpired() {
					expirou.Store(true)
					return
				}
				slots[i].p, slots[i].outcome, slots[i].panicked = readProcessGuarded(pids[i], e.Segredos)
			}
		}()
	}
	wg.Wait()

	if expirou.Load() {
		f.partial("proc", "a leitura de /proc parou pelo teto de TEMPO da "+
			"varredura: os processos que sobraram NÃO foram lidos, e o silêncio "+
			"sobre eles é da ferramenta, não do host")
	}

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
	resolverMapasApagados(f, e)

	if denied > 0 {
		f.partial("proc", strconv.Itoa(denied)+" processos com fds ilegíveis (sem permissão): "+
			"reverse shell por fd 0/1/2 não pôde ser avaliado neles")
	}
	if deniedMaps > 0 {
		f.partial("proc", strconv.Itoa(deniedMaps)+" processos com /proc/<pid>/maps ilegível "+
			"(sem permissão): região rwx anônima, região executável anônima e "+
			"biblioteca apagada ainda mapeada — as assinaturas de injeção — não "+
			"puderam ser avaliadas neles")
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
				// A DIVISÃO VEM ANTES da multiplicação, e a ordem não é
				// estética: `ticks * 1e9` estoura o int64 acima de ~9,22e9
				// ticks, que é uptime de 1068 dias a 100 Hz. Medido: com 1067
				// dias a conta acerta; com 1068 todo processo recente passa a
				// reportar uma data seis anos no passado — sem erro e sem
				// lacuna, só datas erradas com cara de precisas, alimentando
				// nove checks e a janela do --since.
				//
				// Servidor com três anos de uptime é exatamente o perfil do
				// i686 legado que esta ferramenta existe para examinar.
				seg := p.startTicks / int64(f.Host.hz)
				resto := p.startTicks % int64(f.Host.hz)
				t := f.Host.bootTime.
					Add(time.Duration(seg) * time.Second).
					Add(time.Duration(resto) * time.Second / time.Duration(f.Host.hz))
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
func readProcessGuarded(pid int, segredos bool) (p *Process, out readOutcome, panicked string) {
	defer func() {
		if r := recover(); r != nil {
			p, out, panicked = nil, readDenied, fmt.Sprint(r)
		}
	}()
	p, out = readProcess(pid, segredos)
	return p, out, ""
}

func readProcess(pid int, segredos bool) (*Process, readOutcome) {
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
	readLimites(p)
	readExe(p)
	readCwd(p)
	readCmdline(p)
	readEnviron(p, segredos)
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
	argv, cortado, err := readNULTrunc(procPath(p.PID, "cmdline"))
	p.Argv = argv
	if cortado {
		p.Truncated = append(p.Truncated, "a linha de comando passa de "+
			strconv.Itoa(maxNUL>>20)+" MB e foi CORTADA: os argumentos "+
			"seguintes não foram examinados")
	}
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
			//
			// A âncora falhava ABERTA: quando o readTrim ou o split não davam
			// certo, o código caía direto no CmdlineEmpty — afirmando sobre um
			// processo que ele não conseguiu identificar. Sem âncora não há o
			// que afirmar, e o certo é não afirmar.
			st, ok := readTrim(procPath(p.PID, "stat"))
			if !ok {
				p.Vanished = true
				continue
			}
			_, rest, ok := splitStatComm(st)
			if !ok || len(rest) <= 19 || rest[19] != strconv.FormatInt(p.startTicks, 10) {
				p.Vanished = true
				continue
			}
			// O ZUMBI tem cmdline vazio POR DEFINIÇÃO: o kernel já liberou o
			// mm_struct e só resta a entrada na tabela até o pai chamar wait().
			// O estado estava ali, em rest[0], recém-parseado e ignorado — e
			// contar zumbi como cmdline vazio produzia proc.kthread_disguise
			// CRITICAL irreversível sobre um processo que não é kthread nem
			// disfarce, só um filho que ninguém colheu.
			p.State = rest[0]
			if rest[0] == "Z" {
				continue
			}
			p.CmdlineEmpty = true
		}
	}
}

func readEnviron(p *Process, segredos bool) {
	kv, cortado, err := readNULTrunc(procPath(p.PID, "environ"))
	if err != nil {
		// LACUNA, e não ambiente vazio. O erro era descartado aqui, e o
		// processo saía com Env nulo — o que uma tool lê como "não há variável
		// nenhuma", que é a leitura mais tranquilizadora possível de uma
		// leitura que não aconteceu.
		p.EnvErro = motivoDeLeitura(err)
		return
	}
	p.EnvLido = true
	p.EnvCortado = cortado
	if cortado {
		p.Truncated = append(p.Truncated, "o ambiente passa de "+
			strconv.Itoa(maxNUL>>20)+" MB e foi CORTADO: as variáveis "+
			"seguintes não foram examinadas")
	}
	if len(kv) == 0 {
		return
	}
	p.Env = map[string]string{}
	for _, e := range kv {
		if segredos {
			// A representação FIEL, antes de qualquer projeção. Ver EnvBruto.
			p.EnvBruto = append(p.EnvBruto, []byte(e))
		}
		k, v, ok := strings.Cut(e, "=")
		if !ok {
			continue
		}
		p.EnvKeys = append(p.EnvKeys, k)
		// segredos é o --allow-secrets do servidor MCP, e ele só chega aqui
		// depois de o operador ter escrito a flag. Sem ele, o valor de tudo que
		// não está na allowlist NÃO é lido para dentro do Facts — a chave fica,
		// o valor não. Ver env.Env.Segredos.
		if segredos || envAllowed(k) {
			p.Env[k] = v
		}
	}
	sort.Strings(p.EnvKeys)
}

// motivoDeLeitura traduz o errno para o operador. É EVIDÊNCIA, e nunca controle
// de fluxo: quem decide se houve leitura é EnvLido.
func motivoDeLeitura(err error) string {
	switch {
	case os.IsNotExist(err):
		return "o processo terminou entre a listagem e a leitura"
	case os.IsPermission(err):
		return "sem permissão para ler o ambiente deste processo: ele é de outro " +
			"uid, e falta CAP_SYS_PTRACE ou root"
	}
	return "falha ao ler o ambiente: " + err.Error()
}

// readLimites lê o teto de processos do /proc/<pid>/limits.
//
// É o número que transforma "há muitos processos" em "por isso o `su` falha":
// o RLIMIT_NPROC conta processos E threads do uid real, e quando ele estoura o
// kernel recusa fork e execve com EAGAIN — inclusive o execve que o `su` faz
// DEPOIS de já ter trocado de identidade, que é o que produz a mensagem
// "failed to execute /bin/bash: Resource temporarily unavailable".
func readLimites(p *Process) {
	b, err := os.ReadFile(procPath(p.PID, "limits"))
	if err != nil {
		return
	}
	for _, ln := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(ln, "Max processes") {
			continue
		}
		campos := strings.Fields(strings.TrimPrefix(ln, "Max processes"))
		if len(campos) == 0 {
			return
		}
		if campos[0] == "unlimited" {
			p.NProcMax = -1
			return
		}
		if n, err := strconv.Atoi(campos[0]); err == nil {
			p.NProcMax = n
		}
		return
	}
}

func readCgroup(p *Process) {
	b, err := os.ReadFile(procPath(p.PID, "cgroup"))
	if err != nil {
		// Cgroup vazio por CEGUEIRA tem o mesmo formato de cgroup vazio por ser
		// do host — e "do host" é metade da premissa do CRITICAL de
		// proc.container_boundary ("exe em camada de imagem + cgroup do HOST").
		// Sem esta marca, um /proc/<pid>/cgroup que não abriu produzia a
		// acusação de escape de contêiner com o campo cgroup VAZIO na própria
		// evidência que a sustentava.
		p.CgroupDesconhecido = true
		return
	}
	if c := parseCgroup(string(b)); c != "" {
		p.Cgroup = c
		return
	}
	// Arquivo lido e sem nenhuma linha interpretável: também não autoriza a
	// afirmar "este processo está no host".
	p.CgroupDesconhecido = true
}

// parseCgroup separa as duas gramáticas. É função PURA sobre texto porque é
// nela que o formato morde, e testá-la pelo coletor exigiria um /proc de
// mentira para responder uma pergunta de string — o mesmo motivo de
// CronIntervalParaTeste e de ParseLinhaDeReflog existirem.
func parseCgroup(texto string) string {
	// Duas gramáticas: v2 é "0::/path", v1 é "N:controller:/path".
	// O cgroup sobrevive ao daemonizar, então é o que restaura a origem quando
	// PPid vira 1 (runbook §3.11).
	//
	// No v1 há uma LINHA POR CONTROLADOR, e só a de name=systemd carrega a
	// unit. Pegar a primeira — que pode ser cpuset, net_cls, freezer — destrói
	// exatamente a proveniência que este campo existe para preservar.
	var fallback string
	for _, ln := range strings.Split(strings.TrimSpace(texto), "\n") {
		parts := strings.SplitN(ln, ":", 3)
		if len(parts) != 3 {
			continue
		}
		switch {
		case parts[0] == "0" && parts[1] == "": // v2: hierarquia unificada
			return parts[2]
		case parts[1] == "name=systemd": // v1: a que tem a unit
			return parts[2]
		case fallback == "":
			fallback = parts[2]
		}
	}
	return fallback
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
		if s, ok := strings.CutPrefix(t, "pipe:["); ok {
			fd.Pipe = true
			fd.PipeInode, _ = strconv.ParseUint(strings.TrimSuffix(s, "]"), 10, 64)
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
// maxMapsLibs limita as bibliotecas guardadas por processo. Um processo mapeia
// dezenas; o teto existe para o caso patológico (runtime que carrega centenas
// de plugins), e a lista global é deduplicada depois.
const maxMapsLibs = 128

// Tetos das outras listas do maps. Mesma razão do maxMapsLibs — o caso
// patológico é o runtime com milhares de regiões de JIT —, com a diferença de
// que aqui a CONTAGEM total continua guardada à parte, e o corte é declarado.
const (
	maxMapsExecAnon = 16
	maxMapsNomes    = 8
	maxMapsApagados = 16
)

func readMaps(p *Process) {
	fh, err := os.Open(procPath(p.PID, "maps"))
	if err != nil {
		if os.IsPermission(err) {
			p.MapsDenied = true
		}
		return
	}
	defer fh.Close()
	lerMaps(p, fh)
}

// lerMaps percorre o maps EM FLUXO. Separado de readMaps pela mesma razão de
// parseCgroup: o que decide alguma coisa aqui é o parsing e os TETOS, e
// exercitá-los pelo /proc de verdade exigiria um processo com cento e trinta
// bibliotecas para responder uma pergunta de contagem.
func lerMaps(p *Process, r io.Reader) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 8192), 64*1024)

	oddSeen := map[string]bool{}
	apagadosVistos := map[string]bool{}
	nomesVistos := map[string]bool{}
	libsTruncadas, apagadosTruncados := false, false
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
		addr, perms, path, ok := splitMapLineBytes(sc.Bytes())
		if !ok {
			continue
		}
		// O kernel escapa o caminho com seq_path(m, path, "\n"): uma nova
		// linha no nome do arquivo sai como \012. Sem desescapar, uma .so
		// chamada "lib\nevil.so" virava um caminho IMPOSSÍVEL — o Lstat de
		// pkg.go devolvia ENOENT e o candidato era descartado em silêncio, sem
		// nunca fazer a pergunta "que pacote entregou esta biblioteca?".
		// A verificação é um scan por byte e a alocação só acontece quando há
		// barra invertida, que é o caso raro.
		if bytes.IndexByte(path, '\\') >= 0 {
			path = []byte(desescapaMtree(string(path)))
		}
		executavel := bytes.IndexByte(perms, 'x') >= 0
		gravavel := bytes.IndexByte(perms, 'w') >= 0
		if gravavel && executavel {
			d := string(path)
			if d == "" {
				d = "(anônimo)"
			}
			p.MapsRWX = append(p.MapsRWX, string(perms)+" "+d)
		}
		// As três formas de código executável que um retrato distingue e que o
		// MapsRWX não cobre. Só região EXECUTÁVEL chega aqui — a minoria das
		// linhas do maps —, então o custo não entra no laço quente de verdade.
		if executavel {
			switch {
			case len(path) == 0:
				// Sem arquivo e sem rótulo. A gravável já é do MapsRWX; a que
				// interessa aqui é a que passou pelo mprotect e deixou de ser.
				if gravavel {
					break
				}
				p.MapsExecAnonN++
				if len(p.MapsExecAnon) < maxMapsExecAnon {
					// O ENDEREÇO entra, e não só as permissões. Sem ele, N
					// regiões viram N cópias da string "r-xp": o operador não
					// sabe onde olhar com o gdb, e duas varreduras seguidas
					// ficam indistinguíveis para a baseline.
					p.MapsExecAnon = append(p.MapsExecAnon, string(addr)+" "+string(perms))
				}
			case bytes.HasPrefix(path, []byte("[anon:")):
				nome := string(path)
				if !nomesVistos[nome] && len(p.MapsExecNomes) < maxMapsNomes {
					nomesVistos[nome] = true
					p.MapsExecNomes = append(p.MapsExecNomes, nome)
				}
			case bytes.HasSuffix(path, []byte(" (deleted)")):
				c := string(bytes.TrimSuffix(path, []byte(" (deleted)")))
				if apagadosVistos[c] {
					break
				}
				apagadosVistos[c] = true
				if len(p.MapsApagados) >= maxMapsApagados {
					if !apagadosTruncados {
						apagadosTruncados = true
						p.Truncated = append(p.Truncated, "mais de "+
							strconv.Itoa(maxMapsApagados)+" mapeamentos executáveis "+
							"apagados: os demais NÃO entraram no retrato")
					}
					break
				}
				ini, fim := faixaDeMaps(addr)
				p.MapsApagados = append(p.MapsApagados, MapaApagado{
					Caminho: c, Perms: string(perms), Ini: ini, Fim: fim,
					Memfd: strings.HasPrefix(c, "/memfd:"),
				})
			}
		}
		if len(path) == 0 || path[0] != '/' || !looksLikeSO(path) {
			continue
		}
		ps := string(path)
		if oddSeen[ps] {
			continue
		}
		oddSeen[ps] = true

		// TODA biblioteca carregada, inclusive as dos diretórios normais.
		//
		// O MapsOdd abaixo guarda só as que vêm de lugar estranho, e isso é a
		// pergunta certa para "de onde veio". Mas o Ebury põe a dele NO LUGAR
		// da legítima — /lib/x86_64-linux-gnu/libkeyutils.so.1, caminho certo,
		// nome certo. Para perguntar "e o conteúdo confere?", a lista precisa
		// incluir justamente as que o MapsOdd descarta.
		//
		// É também a única fonte que existe para isso: biblioteca não executa,
		// então nada mais a torna candidata à pergunta de propriedade.
		if len(p.MapsLibs) < maxMapsLibs {
			p.MapsLibs = append(p.MapsLibs, ps)
		} else if !libsTruncadas {
			// O comentário acima diz que esta é a ÚNICA fonte que torna uma
			// biblioteca candidata à pergunta de propriedade — ela não executa,
			// então nada mais a traz. Descartar em silêncio apaga a pergunta
			// junto, e é exatamente a forma do Ebury: a libssh trocada NO LUGAR
			// dela, com o nome certo.
			libsTruncadas = true
			p.Truncated = append(p.Truncated, "mais de "+strconv.Itoa(maxMapsLibs)+
				" bibliotecas mapeadas: as demais NÃO entraram na pergunta de "+
				"propriedade, e biblioteca não tem outra fonte que a torne candidata")
		}
		if isLibDir(ps) {
			continue
		}
		p.MapsOdd = append(p.MapsOdd, ps)
	}
	// Mesmo motivo do readStatus: metade do maps lida sem rwx não é "não há
	// rwx". O que já foi encontrado continua valendo — achado é achado —, mas
	// o processo passa a contar como não avaliado.
	if sc.Err() != nil {
		p.MapsDenied = true
	}
}

// resolverMapasApagados pergunta, UMA vez por caminho, se o arquivo apagado
// voltou a existir — e é essa pergunta que separa as duas histórias que
// produzem exatamente a mesma linha no maps.
//
// Roda AQUI, e não dentro do lerMaps, por dois motivos que se somam: a leitura
// dos processos é paralela e um cache compartilhado precisaria de trava, e a
// mesma biblioteca substituída aparece em dezenas de processos — perguntar por
// processo faria dezenas de stat para responder uma coisa só.
//
// Falhar não é lacuna de cobertura: `stat` só responde "existe" ou "não
// existe", e as duas respostas são conclusões. O que não pode acontecer é a
// ausência da resposta virar "não recriado" — por isso o Verificado.
func resolverMapasApagados(f *Facts, e *env.Env) {
	// tri-state por caminho: o stat tem TRÊS respostas, não duas.
	//
	//	nil               existe: o arquivo voltou (atualização de pacote)
	//	fs.ErrNotExist    não existe: o arquivo sumiu de verdade
	//	EACCES/EIO/ELOOP  não consegui olhar — e tratar isto como "sumiu" fabrica
	//	                  a metade do caminho para um CRITICAL a partir de uma
	//	                  falha NOSSA
	type resposta struct{ recriado, verificado bool }
	cache := map[string]resposta{}
	for i := range f.Processes {
		p := &f.Processes[i]
		for j := range p.MapsApagados {
			m := &p.MapsApagados[j]
			if m.Memfd {
				continue // nunca houve arquivo: não há o que perguntar
			}
			r, ok := cache[m.Caminho]
			if !ok {
				_, err := e.Stat(m.Caminho)
				switch {
				case err == nil:
					r = resposta{recriado: true, verificado: true}
				case errors.Is(err, fs.ErrNotExist):
					r = resposta{recriado: false, verificado: true}
				default:
					r = resposta{verificado: false}
					f.partial("proc", m.Caminho+" (mapeamento apagado) não pôde ser "+
						"verificado ("+env.MotivoDoErro(err)+"): não se sabe se o arquivo "+
						"voltou a existir, e isso NÃO conta como sumiço")
				}
				cache[m.Caminho] = r
			}
			m.Recriado, m.Verificado = r.recriado, r.verificado
		}
	}
}

// faixaDeMaps decodifica "7f3c1a000000-7f3c1a021000" nos dois endereços. Vazio
// ou malformado devolve 0,0 — e o preserve trata faixa zero como "não sei
// onde", caindo para a leitura direta do maps.
func faixaDeMaps(addr []byte) (uint64, uint64) {
	i := bytes.IndexByte(addr, '-')
	if i <= 0 {
		return 0, 0
	}
	ini, err1 := strconv.ParseUint(string(addr[:i]), 16, 64)
	fim, err2 := strconv.ParseUint(string(addr[i+1:]), 16, 64)
	if err1 != nil || err2 != nil {
		return 0, 0
	}
	return ini, fim
}

// looksLikeSO reconhece biblioteca compartilhada sem alocar: ".so" no fim, ou
// ".so." no meio (libfoo.so.1.2).
func looksLikeSO(path []byte) bool {
	return bytes.HasSuffix(path, []byte(".so")) || bytes.Contains(path, []byte(".so."))
}

// splitMapLine separa "addr perms offset dev inode [path]". O kernel NÃO escapa
// espaço no path, então strings.Fields quebra em qualquer diretório com espaço
// no nome — e um rename derrotaria o MapsOdd em silêncio.
func splitMapLine(ln string) (addr, perms, path string, ok bool) {
	ab, pb, pa, ok := splitMapLineBytes([]byte(ln))
	return string(ab), string(pb), string(pa), ok
}

// splitMapLineBytes é a versão sem alocação, usada no laço quente. Os cinco
// primeiros campos são fixos; o RESTO da linha é o caminho — que pode conter
// espaço, e por isso não pode sair de um Fields().
func splitMapLineBytes(ln []byte) (addr, perms, path []byte, ok bool) {
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
			return nil, nil, nil, false
		}
		f[n] = ln[start:i]
	}
	for i < len(ln) && ln[i] == ' ' {
		i++
	}
	return f[0], f[1], ln[i:], true
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

// maxNUL é o teto de cmdline e environ.
//
// O kernel NÃO limita esses dois arquivos na leitura: get_mm_cmdline devolve
// `env_end - arg_start` e environ_read devolve `env_end - env_start`. O único
// teto é o do execve — bprm_stack_limits, em fs/exec.c, dá
// max(min(_STK_LIM/4*3, rlim_stack/4), ARG_MAX) —, que com `ulimit -s
// unlimited` e um argv grande chega a ~6 MB POR PROCESSO, para qualquer usuário
// sem privilégio. Duzentos processos assim eram 1,2 GB e um
// `fatal error: out of memory` com status 2, que o contrato desta ferramenta lê
// como CRITICAL.
//
// 1 MB é folgado para qualquer linha de comando real e barato de cortar.
const maxNUL = 1 << 20

func readNULErr(p string) ([]string, error) {
	v, _, err := readNULTrunc(p)
	return v, err
}

// readNULTrunc separa "não consegui ler" de "está vazio" — a confusão entre os
// dois fabricava achado a partir de processo morto — e devolve também se o
// conteúdo foi CORTADO, para que o chamador possa dizê-lo em vez de entregar
// uma linha de comando incompleta como se fosse inteira.
func readNULTrunc(p string) ([]string, bool, error) {
	fh, err := os.Open(p)
	if err != nil {
		return nil, false, err
	}
	defer fh.Close()
	// Um byte além do teto é o que distingue "coube" de "estourou". O tamanho
	// declarado não serve: /proc reporta 0 no stat (fs/proc/generic.c).
	b, err := io.ReadAll(io.LimitReader(fh, maxNUL+1))
	if err != nil {
		return nil, false, err
	}
	cortado := len(b) > maxNUL
	if cortado {
		b = b[:maxNUL]
	}
	if len(b) == 0 {
		return nil, false, nil
	}
	parts := strings.Split(strings.TrimRight(string(b), "\x00"), "\x00")
	out := make([]string, 0, len(parts))
	for _, s := range parts {
		if s != "" {
			// Clone: strings.Split devolve fatias do MESMO array, então guardar
			// uma única chave de environ prendia o buffer inteiro na memória
			// pelo tempo de vida do Facts.
			out = append(out, strings.Clone(s))
		}
	}
	return out, cortado, nil
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
