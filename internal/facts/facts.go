// Package facts coleta o estado do host UMA vez, para que os checks sejam
// funções puras sobre o resultado (SPEC 3, princípio 1).
//
// Consequência prática: todo check é testável sem root e sem host comprometido,
// bastando uma fixture. Consequência de projeto: correlação é possível, porque
// os fatos de rede, processo e systemd estão no mesmo lugar.
//
// Regra que atravessa o pacote: campo ausente nunca vira zero. Vira "desconhecido",
// e quem dependia dele reporta cobertura parcial.
package facts

import (
	"github.com/lex0c/aletheia/internal/env"
)

// SchemaVersion versiona o facts.json. Um binário novo lendo um dump antigo
// precisa saber o que mudou — e isso acontece no meio de incidente, com a VM
// já destruída.
const SchemaVersion = 1

// Facts é o retrato do host.
type Facts struct {
	SchemaVersion int    `json:"schema_version"`
	CollectedAt   string `json:"collected_at"` // RFC3339 UTC
	Source        string `json:"source"`       // live | image

	// Volatil marca a coleta PARCIAL do amostrador do `watch`: /proc e sockets,
	// sem nada de filesystem. Existe para que rodar checks sobre ela seja
	// impossível por acidente — um check que lê unit encontraria zero units e
	// diria "nada encontrado" onde o certo é "não olhei". O motor recusa em
	// voz alta (ver check.RunWith).
	Volatil bool `json:"volatile,omitempty"`

	Host      Host      `json:"host"`
	Processes []Process `json:"processes,omitempty"`
	Sockets   []Socket  `json:"sockets,omitempty"`
	// SocketsBrutos são os que leem PACOTE e não conexão: AF_PACKET e raw.
	// Ficam fora de Sockets de propósito — não têm par remoto, não têm estado
	// e nenhum check de conexão faz pergunta que caiba neles.
	SocketsBrutos []SocketBruto `json:"raw_sockets,omitempty"`
	Interfaces    []Interface   `json:"interfaces,omitempty"`

	// Persistência vem de ARQUIVO, então existe também em modo image — onde o
	// kernel é o do analista e ocultamento por rootkit não acontece (§35.6).
	Loader Loader `json:"loader"`
	// HooksInterp são as variáveis que fazem um interpretador carregar código
	// de terceiro — o LD_PRELOAD de quem não é ELF.
	HooksInterp    []HookInterp            `json:"interpreter_hooks,omitempty"`
	Units          []Unit                  `json:"units,omitempty"`
	ToolArtifacts  []ToolArtifact          `json:"tool_artifacts,omitempty"`
	Cron           []CronEntry             `json:"cron,omitempty"`
	SSH            SSHConfig               `json:"ssh"`
	SSHKeys        []SSHKey                `json:"ssh_keys,omitempty"`
	Triggers       []Trigger               `json:"triggers,omitempty"`
	CACerts        []CACert                `json:"ca_certs,omitempty"`
	Hosts          []HostEntry             `json:"hosts,omitempty"`
	Resolver       Resolver                `json:"resolver"`
	Pkg            PkgDB                   `json:"pkg"`
	Ownership      []Ownership             `json:"ownership,omitempty"`
	Accounts       []Account               `json:"accounts,omitempty"`
	Grupos         []Grupo                 `json:"groups,omitempty"`
	Sudoers        []SudoRule              `json:"sudoers,omitempty"`
	Suid           []SuidFile              `json:"suid,omitempty"`
	Modules        []ModuleConf            `json:"modules,omitempty"`
	ModuleFiles    []string                `json:"module_files,omitempty"`
	PkgEstranho    []ReivindicacaoEstranha `json:"pkg_odd_claims,omitempty"`
	HashDiff       []HashDivergente        `json:"hash_mismatch,omitempty"`
	Timestomps     []Timestomp             `json:"timestomps,omitempty"`
	HashOK         []string                `json:"hash_verified,omitempty"`
	Atributos      []AtributoInode         `json:"inode_attrs,omitempty"`
	Mounts         []Montagem              `json:"mounts,omitempty"`
	Logins         []Login                 `json:"logins,omitempty"`
	Ftrace         []HookFtrace            `json:"ftrace_hooks,omitempty"`
	BPF            BPF                     `json:"bpf"`
	Taint          Taint                   `json:"kernel_taint"`
	ChavesPrivadas []ChavePrivada          `json:"private_keys,omitempty"`
	Destinos       []DestinoConhecido      `json:"known_hosts,omitempty"`
	Historicos     []HistoricoShell        `json:"shell_history,omitempty"`
	Audit          Auditoria               `json:"audit"`
	Logs           []ArquivoDeLog          `json:"logs,omitempty"`
	MAC            MAC                     `json:"mac"`
	Segredos       []Segredo               `json:"secret_files,omitempty"`
	ExecOculto     []string                `json:"hidden_exec,omitempty"`
	MetaAcesso     []ArquivoMeta           `json:"access_meta,omitempty"`
	// HashesIOC só existe quando a execução trouxe hash na lista de
	// indicadores: é o hash dos arquivos que ESTA varredura examinou.
	HashesIOC []ArquivoHash `json:"ioc_hashes,omitempty"`
	Cross     CrossView     `json:"cross_view"`

	// PidsListados é o que o readdir de /proc devolveu — NÃO o que foi lido
	// com sucesso. A comparação cruzada depende dessa distinção.
	PidsListados []int `json:"-"`

	// PersistDenied é o que a coleta de persistência não pôde LER, por
	// categoria. Não é o mesmo que "não havia nada" — e sem root, /root e o
	// home dos outros usuários caem todos aqui.
	PersistDenied map[string][]string `json:"persist_denied,omitempty"`

	// ProcessesGone conta os PIDs que estavam em /proc e sumiram antes de serem
	// lidos. NÃO é lacuna de cobertura — o processo não existe mais para
	// ninguém. Fica registrado porque um número alto é rotatividade anormal.
	ProcessesGone int `json:"processes_gone,omitempty"`

	// Partial registra o que a própria coleta não conseguiu ler, por coletor.
	// Não é o mesmo que "não havia nada": é "não deu para olhar".
	Partial map[string][]string `json:"partial,omitempty"`

	idx *idx

	// idxMount indexa a tabela de montagem por ponto. Fica aqui e não no idx
	// geral porque é usado pela COLETA, antes de o índice existir.
	idxMount map[string]uint64
}

// idx são as buscas por chave. Sem elas, um check que pergunta "quais sockets
// são deste processo" para CADA processo custa P×S: num balanceador com 2 mil
// processos e 100 mil conexões isso mediu 1,5s só de laço — mais que o
// orçamento inteiro do `wtf`, antes mesmo da coleta.
//
// Fica fora do JSON de propósito: é derivado, e um dump carregado reconstrói.
type idx struct {
	socketsByPID  map[int][]Socket
	socketByInode map[uint64]int // inode → posição em f.Sockets
	procByPID     map[int]int    // pid → posição em f.Processes
}

// Index constrói as buscas. É idempotente e barato de chamar de novo; quem
// carrega um dump precisa chamá-lo, e o motor chama por garantia ANTES de
// qualquer check — o que também garante que a construção preguiçosa lá dentro
// nunca aconteça com checks concorrentes.
func (f *Facts) Index() {
	if f.idx != nil {
		return
	}
	x := &idx{
		socketsByPID:  make(map[int][]Socket, len(f.Processes)),
		socketByInode: make(map[uint64]int, len(f.Sockets)),
		procByPID:     make(map[int]int, len(f.Processes)),
	}
	for i := range f.Processes {
		x.procByPID[f.Processes[i].PID] = i
	}
	for i := range f.Sockets {
		x.socketByInode[f.Sockets[i].Inode] = i
	}
	// A relação socket→processo é de MUITOS para muitos: um fork herda o fd, e
	// pai e filho passam a deter o mesmo socket. Construir o índice a partir do
	// campo Socket.PID daria um dono só — o último a escrever no join — e um
	// pivô cujo filho ficou com uma das pernas não dispararia em ninguém.
	//
	// Construir do lado do PROCESSO resolve: cada dono enxerga o que realmente
	// tem aberto.
	for i := range f.Processes {
		p := &f.Processes[i]
		visto := map[uint64]bool{}
		for _, fd := range p.FDs {
			if !fd.Socket || visto[fd.SocketInode] {
				continue // dup2 do mesmo socket não conta duas vezes
			}
			si, ok := x.socketByInode[fd.SocketInode]
			if !ok {
				continue
			}
			visto[fd.SocketInode] = true
			x.socketsByPID[p.PID] = append(x.socketsByPID[p.PID], f.Sockets[si])
		}
	}
	f.idx = x
}

func (f *Facts) partial(collector, reason string) {
	if f.Partial == nil {
		f.Partial = map[string][]string{}
	}
	f.Partial[collector] = append(f.Partial[collector], reason)
}

// Collect roda os coletores disponíveis para o ambiente sondado.
func Collect(e *env.Env) *Facts {
	f := &Facts{
		SchemaVersion: SchemaVersion,
		CollectedAt:   e.Now.Format("2006-01-02T15:04:05Z"),
		Source:        e.Source.String(),
	}

	collectHost(f, e)
	// Antes de tudo que interpreta caminho: a tabela de montagem diz se o bit
	// setuid de um arquivo é inerte e se algo executa de um diretório.
	collectMounts(f, e)

	if e.Has(env.CapProcfs) {
		collectProcesses(f, e)
		// Depois dos processos: o dono de cada socket sai do join com os fds
		// que o coletor de processo já leu.
		collectSockets(f, e)
		// E os que leem PACOTE, que não aparecem em tabela de conexão nenhuma:
		// é por eles que um filtro de socket eBPF órfão continua vivo.
		collectSocketsBrutos(f, e)
		// Depois dos processos e ANTES de qualquer pergunta de propriedade: é
		// a classificação que decide se "que pacote entregou este binário?" faz
		// sentido para aquele processo.
		classificaContainers(f)
		// Depois dos processos: a comparação precisa da lista para saber o que
		// está VISÍVEL.
		collectCrossView(f, e)
		// Junto do cross-view: aqueles dizem que o kernel pode estar mentindo,
		// e este diz COMO.
		collectFtrace(f, e)
		// Marca do próprio kernel sobre o que já foi carregado nele. Não
		// depende de privilégio e não pode ser apagada sem reiniciar.
		collectTaint(f, e)
		// Depois dos processos: o dono de um programa eBPF é um descritor
		// aberto, e a lista de descritores já está lida.
		collectBPF(f, e)
	} else {
		f.partial("proc", e.Reason(env.CapProcfs))
	}

	if e.Has(env.CapFilesystem) {
		collectPersist(f, e)
		// Depois de tudo: o conjunto de candidatos a hash é o que os outros
		// coletores acharem interessante. Só roda com hash na lista.
		collectHashesIOC(f, e)
	} else {
		f.partial("persist", e.Reason(env.CapFilesystem))
	}

	f.Index()
	return f
}

// CollectVolatile é a coleta BARATA, para amostragem em intervalo curto.
//
// Medido: a coleta completa leva 1487ms e esta 164ms — nove vezes menos. A
// diferença é a varredura de filesystem, e é ela que impede um `watch` de
// amostrar de cinco em cinco segundos.
//
// O que ela entrega é o que muda em segundos: processo e socket. O que ela NÃO
// entrega é tudo o mais — unit, cron, propriedade de pacote, hash, atributo de
// inode. Por isso o resultado vem marcado com Volatil, e o motor de checks se
// recusa a rodar sobre ele: a economia não pode virar falso negativo.
func CollectVolatile(e *env.Env) *Facts {
	f := &Facts{
		SchemaVersion: SchemaVersion,
		CollectedAt:   e.Now.Format("2006-01-02T15:04:05Z"),
		Source:        e.Source.String(),
		Volatil:       true,
	}
	collectHost(f, e)
	if e.Has(env.CapProcfs) {
		collectProcesses(f, e)
		collectSockets(f, e)
	} else {
		f.partial("proc", e.Reason(env.CapProcfs))
	}
	f.Index()
	return f
}

// SocketsOf devolve os sockets pertencentes a um PID. O slice é do índice:
// leia, não modifique.
func (f *Facts) SocketsOf(pid int) []Socket {
	f.Index()
	return f.idx.socketsByPID[pid]
}

// SocketByInode devolve o socket daquele inode, ou nil. É como se sai do fd
// para a conexão (runbook §3.8).
func (f *Facts) SocketByInode(inode uint64) *Socket {
	f.Index()
	if i, ok := f.idx.socketByInode[inode]; ok {
		return &f.Sockets[i]
	}
	return nil
}

// ProcessByPID devolve o processo, ou nil.
func (f *Facts) ProcessByPID(pid int) *Process {
	f.Index()
	if i, ok := f.idx.procByPID[pid]; ok {
		return &f.Processes[i]
	}
	return nil
}
