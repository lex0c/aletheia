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
//
// A REGRA que dá sentido ao número: sobe sempre que um FATO SERIALIZADO novo, ou
// uma mudança de SEMÂNTICA de um fato existente, puder alterar a conclusão de
// quem analisar o dump depois. Sem isso, um dump anterior tem o campo VAZIO, e o
// check novo lê vazio como "olhei e não achei" quando a verdade é "esta versão
// nunca olhou" — a mentira central que a ferramenta existe para não cometer. O
// Carregar() do dump recusa (ErrEsquema) o que não casa, então subir aqui obriga
// a RE-COLETAR em vez de concluir ausência sobre o que não foi observado.
//
// A regra ANTERIOR dizia "sobe quando um coletor NOVO alimenta um check", e era
// estreita demais: deixou passar três commits seguidos. Depois do bump para 2
// entraram SysVShmSeg.CriadorEmRede (que decide o CRITICAL do perfil Ebury) e
// Unit.Manager/RootDirectory/RootImage — todos fatos serializados, todos
// alimentando decisão, nenhum coletor novo. Ficaram dois dumps declarando
// `schema_version: 2` com significados diferentes, que é exatamente o que o
// número existe para impedir.
//
//	2  coleta de /proc/sysvipc/shm (persist.sysv_shm_channel) e do config de
//	   cliente ssh (persist.ssh_client_exec). Um dump v1 não os tem, e os dois
//	   checks concluiriam "limpo" sobre fatos nunca coletados.
//	3  a sondagem de PID ganhou uma SEGUNDA testemunha (kill(2), cobrindo pid_max
//	   inteiro) e o alcance virou dois números: ProbeAte agora é o do sinal e
//	   ProbeProcfsAte é o do /proc. Num dump v2 o campo novo vem zerado e o campo
//	   antigo tem outro significado, então cross.hidden_pid imprimiria "sondagem
//	   foi até N por kill(2) e até 0 por /proc" — trocando o nome da testemunha e
//	   afirmando alcance zero onde houve alcance. Não é falso "limpo", é pior de
//	   um jeito: é evidência com a etiqueta errada, e é sobre ela que alguém
//	   decide se o host tem rootkit.
//	4  ExecLine.AlvoIndeterminado e Timestomp.Cluster, com a REGRA acima
//	   ampliada junto (ver abaixo). Num dump v3 os dois vêm zerados, e zerado
//	   ali MENTE nas duas direções: "alvo provado" para uma linha de `sh -c` que
//	   ninguém conseguiu resolver, e "não é lote" para o bloco de extração que
//	   fazia o check gritar doze CRITICAL num contêiner saudável.
const SchemaVersion = 4

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
	// LimitesRede são os tetos contra os quais a contagem de conexões vale
	// alguma coisa. Ver LimitesDeRede.
	LimitesRede LimitesDeRede `json:"net_limits,omitempty"`
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
	HooksInterp []HookInterp `json:"interpreter_hooks,omitempty"`
	Units       []Unit       `json:"units,omitempty"`
	// NSSModules são as fontes do /etc/nsswitch.conf e a lib que cada uma
	// carrega — um libnss_ sem dono é backdoor carregado em toda resolução.
	NSSModules    []NSSModule     `json:"nss_modules,omitempty"`
	ToolArtifacts []ToolArtifact  `json:"tool_artifacts,omitempty"`
	Cron          []CronEntry     `json:"cron,omitempty"`
	SSH           SSHConfig       `json:"ssh"`
	SSHKeys       []SSHKey        `json:"ssh_keys,omitempty"`
	SSHClientExec []SSHClientExec `json:"ssh_client_exec,omitempty"`
	SysVShm       []SysVShmSeg    `json:"sysvipc_shm,omitempty"`
	Triggers      []Trigger       `json:"triggers,omitempty"`
	// ConfiancaDeHost são as entradas .rhosts/hosts.equiv — login sem senha
	// host-based (ATT&CK T1021.004).
	ConfiancaDeHost []ConfiancaDeHost `json:"host_trust,omitempty"`
	CACerts         []CACert          `json:"ca_certs,omitempty"`
	Hosts           []HostEntry       `json:"hosts,omitempty"`
	Resolver        Resolver          `json:"resolver"`
	Pkg             PkgDB             `json:"pkg"`
	Ownership       []Ownership       `json:"ownership,omitempty"`
	Accounts        []Account         `json:"accounts,omitempty"`
	Grupos          []Grupo           `json:"groups,omitempty"`
	Sudoers         []SudoRule        `json:"sudoers,omitempty"`
	Doas            []DoasRule        `json:"doas,omitempty"`
	Suid            []SuidFile        `json:"suid,omitempty"`
	Donos           []DonoDeArquivo   `json:"file_owners,omitempty"`
	// SuidDirs e SuidArquivos medem o CUSTO da varredura de filesystem, para o
	// relatório de tempo dizer por que ela demorou.
	SuidDirs     int `json:"suid_dirs,omitempty"`
	SuidArquivos int `json:"suid_files,omitempty"`

	// CodigoSuspeito são arquivos de código com padrão de backdoor. Peneira, não
	// prova — o check pesa cada um com o mtime.
	CodigoSuspeito []CodigoSuspeito `json:"suspect_code,omitempty"`
	// Vigias é quem observa ARQUIVO por inotify ou fanotify. É a resposta para
	// "removi o backdoor e ele voltou": quem recria o arquivo apagado precisa
	// saber que ele sumiu, e é assim que sabe.
	Vigias  []Vigia      `json:"file_watchers,omitempty"`
	Modules []ModuleConf `json:"modules,omitempty"`
	// AlvosDeRoot são os caminhos que algo executa COMO ROOT, com o que o inode
	// diz sobre quem pode alterá-los (runbook §36.4).
	AlvosDeRoot []AlvoDeRoot `json:"root_targets,omitempty"`
	// Helpers são os programas que o KERNEL invoca sozinho: modprobe,
	// core_pattern, uevent_helper e binfmt_misc.
	Helpers []HelperDoKernel `json:"kernel_helpers,omitempty"`
	// Binfmt são os interpretadores registrados e VIVOS no kernel
	// (/proc/sys/fs/binfmt_misc); BinfmtConfig é a mesma coisa em ARQUIVO, que o
	// boot reaplica. Duas perguntas: o kernel roteia execução AGORA, e isso
	// volta depois do reboot.
	Binfmt       []BinfmtRegistro `json:"binfmt,omitempty"`
	BinfmtConfig []BinfmtConfig   `json:"binfmt_config,omitempty"`
	// Initramfs são os scripts e arquivos que ENTRAM na geração do initramfs —
	// a persistência que roda antes do userland, pega em disco sem descompactar
	// a imagem.
	Initramfs []ArtefatoInitramfs `json:"initramfs,omitempty"`
	// Boot são as linhas de comando de kernel: a que está RODANDO e as que a
	// configuração do bootloader entregaria no PRÓXIMO boot. As duas respondem
	// perguntas diferentes, e é na diferença entre elas que mora o achado.
	Boot []LinhaDeBoot `json:"boot_cmdline,omitempty"`
	// BootConfigLido diz que ALGUMA configuração de bootloader foi encontrada e
	// lida. Sem ele, "nada enfraquecido na configuração" e "não achei
	// bootloader nenhum" têm o mesmo JSON — e são conclusões opostas.
	BootConfigLido bool     `json:"boot_config_read,omitempty"`
	ModuleFiles    []string `json:"module_files,omitempty"`
	// ModuleFilesExternos são os .ko das árvores de compilação local — DKMS,
	// extra, weak-updates. Ficam FORA da pergunta de propriedade (nada ali vem
	// de pacote, por desenho) e DENTRO da pergunta "existe arquivo em disco
	// para este módulo carregado?". Sem a segunda lista, todo host com driver
	// DKMS reportava os módulos dele como sem arquivo em disco.
	ModuleFilesExternos []string `json:"module_files_external,omitempty"`
	// Repos são os repositórios git encontrados sob as árvores de aplicação. O
	// coletor de hooks já os visita; guardar o caminho é o que permite entregar
	// a verificação de integridade da §16 com o `-C` preenchido.
	Repos []string `json:"git_repos,omitempty"`
	// Carregados são os módulos que o kernel tem DENTRO dele agora, cada um
	// confrontado com o arquivo que deveria explicá-lo.
	Carregados []ModuloCarregado `json:"loaded_modules,omitempty"`
	// ArvoreDeModulos diz que /lib/modules foi encontrada e lida. Sem ela,
	// "módulo sem arquivo" não significa nada — significa que ninguém olhou.
	ArvoreDeModulos bool `json:"module_tree_read,omitempty"`
	// Protecao é o que o kernel deixa acontecer com ele mesmo: lockdown,
	// assinatura de módulo, IMA. Não é achado, é o contexto que pesa os achados.
	Protecao       ProtecaoKernel          `json:"kernel_protection"`
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

	// HistoricoDeLoginLido diz se /var/log/wtmp foi de fato examinado.
	//
	// Existe porque o achado de histórico zerado se apoia numa AUSÊNCIA, e
	// ausência só é evidência quando a fonte foi olhada. Sem este campo, um
	// wtmp em 0640 — que é o que o CIS Benchmark manda — produzia um CRITICAL
	// irreversível de anti-forense a partir de permissão negada.
	HistoricoDeLoginLido bool `json:"login_history_read,omitempty"`

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
	// pidsPorPipe liga um inode de pipe aos PIDs que o seguram. É o join que
	// acha os dois lados de uma ponte de reverse shell: shell de um lado, o
	// processo com o socket do outro (runbook §17).
	pidsPorPipe map[uint64][]int
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
		pidsPorPipe:   map[uint64][]int{},
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
		vistoPipe := map[uint64]bool{}
		for _, fd := range p.FDs {
			if fd.Pipe && fd.PipeInode != 0 && !vistoPipe[fd.PipeInode] {
				vistoPipe[fd.PipeInode] = true
				x.pidsPorPipe[fd.PipeInode] = append(x.pidsPorPipe[fd.PipeInode], p.PID)
			}
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

	e.Stage("host")
	collectHost(f, e)
	// Antes de tudo que interpreta caminho: a tabela de montagem diz se o bit
	// setuid de um arquivo é inerte e se algo executa de um diretório.
	e.Stage("montagens")
	collectMounts(f, e)

	if e.Has(env.CapProcfs) {
		e.Stage("processos")
		collectProcesses(f, e)
		// Depois dos processos: o dono de cada socket sai do join com os fds
		// que o coletor de processo já leu.
		// Os limites vêm ANTES dos sockets: além de serem os tetos que
		// transformam "há 400 conexões" em "e o próximo connect vai falhar",
		// a faixa de porta efêmera é INSUMO da inferência de direção.
		e.Stage("rede")
		collectLimitesDeRede(f, e)
		collectSockets(f, e)
		// DEPOIS dos sockets: o criador de um segmento SysV SHM é um cpid, e
		// saber se ele é DAEMON DE REDE (tem socket de escuta) exige os sockets já
		// lidos — é o discriminador que pega o Ebury 0600. O canal IPC que não
		// aparece em socket nem em fd.
		collectSysVShm(f, e)
		// E os que leem PACOTE, que não aparecem em tabela de conexão nenhuma:
		// é por eles que um filtro de socket eBPF órfão continua vivo.
		collectSocketsBrutos(f, e)
		// DEPOIS dos sockets: a segunda visão da mesma tabela, pelo netlink.
		// Ela precisa da primeira para ter com o que divergir.
		collectCrossSockets(f, e)
		// Depois dos processos e ANTES de qualquer pergunta de propriedade: é
		// a classificação que decide se "que pacote entregou este binário?" faz
		// sentido para aquele processo.
		classificaContainers(f)
		// Depois dos processos: a comparação precisa da lista para saber o que
		// está VISÍVEL.
		e.Stage("kernel e módulos")
		collectCrossView(f, e)
		// Junto do cross-view: aqueles dizem que o kernel pode estar mentindo,
		// e este diz COMO.
		collectFtrace(f, e)
		// Marca do próprio kernel sobre o que já foi carregado nele. Não
		// depende de privilégio e não pode ser apagada sem reiniciar.
		collectTaint(f, e)
		// O que o kernel deixa acontecer com ele mesmo. Vem antes dos módulos
		// carregados porque é o contexto que pesa o achado deles.
		collectProtecaoKernel(f, e)
		// Depois dos processos: o dono de um programa eBPF é um descritor
		// aberto, e a lista de descritores já está lida.
		collectBPF(f, e)
	} else {
		f.partial("proc", e.Reason(env.CapProcfs))
	}

	if e.Has(env.CapFilesystem) {
		// A parte cara: varre dezenas de milhares de diretórios. É o estágio em
		// que a coleta "parece travada" num disco lento, e por isso o que mais
		// justifica o batimento.
		e.Stage("varredura de filesystem")
		collectPersist(f, e)
		// Depois da persistência: a varredura de código reusa os web roots e
		// procura backdoor em PHP/JS/Python. Peneira declarada, com teto.
		e.Stage("varredura de código")
		collectCodigo(f, e)
		// DEPOIS da persistência: a pergunta "quem pode reescrever o que root
		// executa" precisa da lista do que root executa, e ela sai dali.
		collectAlvosDeRoot(f, e)
		// DEPOIS da persistência, que é quem varre /lib/modules: a pergunta
		// "que arquivo entregou este módulo?" precisa da lista de arquivos, e
		// respondê-la antes diria "nenhum" em todo host — a pior forma de falso
		// positivo, porque é uniforme e convincente.
		if e.Has(env.CapProcfs) {
			collectModulosCarregados(f, e)
		}
		// Depois de tudo: o conjunto de candidatos a hash é o que os outros
		// coletores acharem interessante. Só roda com hash na lista.
		collectHashesIOC(f, e)
	} else {
		f.partial("persist", e.Reason(env.CapFilesystem))
	}

	// POR ÚLTIMO: quem vigia arquivo precisa dos fds já lidos E do inventário
	// de caminhos que os outros coletores montaram — é contra ele que os
	// inodes observados ganham nome.
	if e.Has(env.CapProcfs) {
		e.Stage("vigias de arquivo")
		collectVigias(f, e)
	}

	e.Stage("finalizando")
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
		collectLimitesDeRede(f, e)
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

// PidsComPipe devolve os PIDs que seguram um inode de pipe. Dois deles com o
// mesmo inode compartilham o pipe — e, por herança, um ancestral comum.
func (f *Facts) PidsComPipe(inode uint64) []int {
	f.Index()
	return f.idx.pidsPorPipe[inode]
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
