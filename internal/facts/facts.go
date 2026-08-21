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
	"fmt"
	"sync"

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
//	5  Unit.Binds (BindPaths/BindReadOnlyPaths) e a âncora temporal do SysV
//	   (SysVShmSeg.CriadoEm/PIDReciclado/CriadorNaoConfirmado). Num dump v4 os
//	   dois vêm zerados, e zerado MENTE de novo nas duas direções: "esta unit
//	   não monta nada por cima de caminho de sistema", e "a autoria do segmento
//	   está provada" — que era justamente a afirmação que produzia CRITICAL a
//	   partir de PID reciclado.
//	6  Duas mudanças pós-schema-5, e as duas são exatamente o que a regra
//	   acima descreve — ela foi escrita e violada no mesmo dia, duas vezes:
//	   a semântica de SysVShmSeg.PIDReciclado ganhou tolerância temporal (dump
//	   v5 antigo pode trazer `true` que hoje seria `false`, apagando o Ebury), e
//	   o PersistDenied passou a carregar a lacuna de user manager, que dump v5
//	   anterior não tem. Entra também o Unit.BindReset: num dump v5 os binds
//	   foram gravados SEM o reset entre arquivos, então a base traz um bind que
//	   um drop-in já tinha desfeito — o falso positivo que o reset conserta.
//
//	   É por isso que existe o TestImpressaoDoEsquema: regra que depende de
//	   alguém lembrar continua sendo esquecida.
//	7  A rodada de conserto de confiabilidade. São DOIS campos novos e SEIS
//	   mudanças de semântica, e todas as oito mentem num dump v6 lido por este
//	   binário — a maioria na direção do falso "limpo".
//
//	   Campos novos:
//	     Process.CgroupDesconhecido  num dump v6 vem `false`, que afirma "o
//	       cgroup deste processo foi lido e é do host" sobre um /proc/<pid>/cgroup
//	       que ninguém conseguiu abrir. É metade da premissa do CRITICAL de
//	       proc.container_boundary — a outra metade é o exe estar em camada de
//	       imagem —, então zerado ali produz acusação de escape de contêiner a
//	       partir de cegueira.
//	     Finding.Chave não é fato, mas a CHAVE DA BASELINE mudou de forma junto
//	       (baseline.Schema 1 -> 2), e baseline antiga é recusada por lá.
//
//	   Semânticas mudadas, todas sobre campo que já existia:
//	     HistoricoDeLoginLido  v6 podia trazer `true` para um wtmp que o coletor
//	       declarou não ter interpretado. Hoje é `false`, e a diferença decide o
//	       CRITICAL irreversível de antiforense.wtmp_cleared.
//	     Logins  em Alpine x86_64 (musl) o registro tem 400 bytes e era lido com
//	       passo de 384: um dump v6 daquele host traz inventário de login LIDO DO
//	       BYTE ERRADO — usuário vindo do meio de outro campo, timestamp zero —
//	       com cara de dado bom.
//	     Accounts  v6 podia trazer Account{Name: "#deploy"} de uma linha
//	       COMENTADA do passwd, que nunca está no shadow: SemShadow=true e
//	       priv.account_no_shadow CRITICAL sobre conta que não existe.
//	     Ownership/Pkg.Consultavel  v6 montava Ownership com `donos` vazio quando
//	       a base de pacotes existia e não podia ser lida, carimbando Owned=false
//	       em TODO candidato. Hoje esse caso não monta Ownership e marca
//	       Consultavel=false. Um dump v6 assim dispara CRITICAL em série em
//	       integrity.no_package_owner, persist.unit_unowned, egress, binfmt,
//	       initramfs e helper.
//	     Units  o `.include` do systemd passou a ser expandido. Num dump v6 a
//	       unit que usa esse idioma — o override documentado no systemd 219, ou
//	       seja RHEL/CentOS 7 e SLES 12 — tem Exec VAZIO, e vazio ali é
//	       "esta unit não executa nada".
//	     SSH  as diretivas escritas com `=` (PermitRootLogin=yes,
//	       AuthorizedKeysCommand=/tmp/.k) eram descartadas: num dump v6 elas
//	       simplesmente não estão, e o relatório imprime o padrão do sshd como se
//	       fosse o efetivo.
//	     Modules  a continuação por `\` era truncada em `\`, e checks/modprobe
//	       aceitava `\` como nome de módulo e SUPRIMIA o achado. Um dump v6 traz
//	       o Cmd cortado no ponto que o torna invisível.
//	     Process.State/CmdlineEmpty  zumbi deixou de virar CmdlineEmpty. Num dump
//	       v6 ele vem marcado, e proc.kthread_disguise sai CRITICAL irreversível
//	       sobre um filho que ninguém colheu.
//	8  Duas superfícies novas, e as duas mentem num dump v7 lido por este
//	   binário — uma em cada direção, que é o par que mais custa caro.
//
//	   DoasRule.TemArgs/Args  o `args ...` do doas.conf nunca foi decodificado.
//	     Num dump v7 os dois campos vêm zerados, e zerado significa "esta regra
//	     aceita QUALQUER argumento" — que é a leitura mais AMPLA das três
//	     formas da gramática. Junto com a tabela de primitivas nova
//	     (checks/primitiva.go), uma regra de backup honesta
//	     (`cmd /usr/bin/tar args czf /backup/srv.tgz /srv`) sai como root
//	     irrestrito: CRITICAL sobre a automação que o time escreveu.
//	   ConfigWeb  a configuração POR DIRETÓRIO do servidor web (.htaccess,
//	     .user.ini) nunca foi coletada — o coletor de gatilhos só olhava
//	     /etc/php*, e a varredura de código seleciona por extensão, que esses
//	     arquivos não têm. Num dump v7 a lista vem vazia, e vazia ali é o falso
//	     "limpo" clássico: `app.web_config_exec` e a segunda metade de
//	     `persist.web_prepend` concluiriam que nenhum diretório servido mudou o
//	     que executa, sobre uma árvore que ninguém leu.
//	   Trigger.EscapeN  a sequência de escape de terminal dentro de arquivo que
//	     executa nunca foi procurada — e não dava para procurá-la em Lines,
//	     porque o truque mora numa linha de COMENTÁRIO, que Lines descarta. Num
//	     dump v7 o campo vem 0, e 0 significa "este arquivo foi lido e não tem
//	     escape nenhum" para `antiforense.hidden_text`.
const SchemaVersion = 9

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
	// SocketsIncompletos são os protocolos cuja tabela de /proc/net NÃO foi
	// lida inteira — ilegível ou cortada no teto de linhas.
	//
	// A lacuna já era declarada em texto sob a chave `net`, e isso não bastava:
	// aquela chave carrega desde "o módulo de diagnóstico de UDP não está
	// carregado" até "o dono do socket não pôde ser lido", e quem compara dois
	// retratos precisa saber especificamente se o CONJUNTO que ele está
	// comparando é exaustivo. Sem este campo, uma tabela truncada fazia uma
	// porta que continua lá aparecer como REMOVIDA — "não vi" virando "não
	// existe", que é a equivalência que esta ferramenta existe para recusar.
	SocketsIncompletos []string `json:"sockets_incomplete,omitempty"`
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
	NSSModules []NSSModule `json:"nss_modules,omitempty"`
	// NSSServicos é a configuração EFETIVA do nsswitch: um serviço, e a cadeia
	// de fontes NA ORDEM em que ele as consulta.
	//
	// NSSModules responde "quais bibliotecas podem ser carregadas", e é
	// inventário. Ele não responde precedência: agrupado por FONTE, ele perde
	// que `passwd: files sss` e `passwd: sss files` são configurações
	// diferentes — as mesmas fontes, as mesmas libs, e a autoridade sobre quem
	// é usuário invertida.
	NSSServicos   []NSSService    `json:"nss_services,omitempty"`
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
	// ShadowLido diz se /etc/shadow pôde ser lido. Sem ele, Account.SemSenha e
	// Account.Bloqueada vêm no zero-value `false` para TODA conta — e `false`
	// ali significa "não sei", não "tem senha". A lacuna é declarada sob
	// `users`, mas em granularidade de família: quem compara campo precisa
	// saber por CAMPO.
	ShadowLido bool            `json:"shadow_read,omitempty"`
	Grupos     []Grupo         `json:"groups,omitempty"`
	Sudoers    []SudoRule      `json:"sudoers,omitempty"`
	Doas       []DoasRule      `json:"doas,omitempty"`
	Suid       []SuidFile      `json:"suid,omitempty"`
	Donos      []DonoDeArquivo `json:"file_owners,omitempty"`
	// SuidDirs e SuidArquivos medem o CUSTO da varredura de filesystem, para o
	// relatório de tempo dizer por que ela demorou.
	SuidDirs     int `json:"suid_dirs,omitempty"`
	SuidArquivos int `json:"suid_files,omitempty"`

	// CodigoSuspeito são arquivos de código com padrão de backdoor. Peneira, não
	// prova — o check pesa cada um com o mtime.
	CodigoSuspeito []CodigoSuspeito `json:"suspect_code,omitempty"`
	// ConfigWeb é a configuração POR DIRETÓRIO do servidor web (.htaccess,
	// .user.ini) encontrada dentro das árvores servidas — e só as linhas dela
	// que têm consequência de EXECUÇÃO. Ver configweb.go.
	ConfigWeb []ConfigWeb `json:"web_config,omitempty"`
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

	// DriftDados é a comparação com um estado anterior, quando alguém pediu
	// uma. NÃO viaja no dump — ver o tipo Drift.
	DriftDados *Drift `json:"-"`

	idx *idx

	// idxMount indexa a tabela de montagem por ponto. Fica aqui e não no idx
	// geral porque é usado pela COLETA, antes de o índice existir.
	idxMount map[string]uint64
}

// muLacuna protege as escritas de lacuna vindas de GOROUTINE.
//
// É de PACOTE e não campo de Facts porque Facts é um tipo COPIADO — o dump o
// copia, e meia dúzia de tabelas de teste o carregam por valor. Um sync.Mutex
// lá dentro torna cada uma dessas cópias um erro que o `go vet` acusa, e com
// razão. Como o caminho guardado é raro (lacuna de goroutine, e panic de
// coletor), serializar por processo não custa nada.
var muLacuna sync.Mutex

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

// partialSeguro é o partial chamável de dentro de goroutine.
func (f *Facts) partialSeguro(collector, reason string) {
	muLacuna.Lock()
	defer muLacuna.Unlock()
	f.partial(collector, reason)
}

// guardaGoroutine isola o panic do corpo de UMA goroutine de varredura.
//
// O recover() do main NÃO alcança goroutine: ela morre levando o processo
// junto, e o status vira 2 — que o contrato desta ferramenta define como
// "CRITICAL: indicador de alta confiança". Um defeito NOSSO faz a automação de
// frota, que ordena host por exit code, marcar a máquina como comprometida.
//
// É a mesma correção que readProcessGuarded fez para o coletor de processos e
// que runGuarded fez para os checks; as varreduras de suid, de hash e de PID
// ficaram de fora, e elas percorrem justamente nomes de diretório e conteúdo de
// arquivo escolhidos por quem se quer esconder.
//
// Uso: `defer f.guardaGoroutine("suid")` DEPOIS do `defer wg.Done()`, para que
// o recover rode antes de o WaitGroup ser liberado.
//
// INVARIANTE que ele impõe ao resto da pool: nenhuma seção crítica pode ficar
// travada se o corpo dela entrar em pânico. Antes do recover, um panic ali
// derrubava o processo e o mutex ia junto; agora o processo sobrevive, e um
// mutex travado bloquearia os outros trabalhadores no Lock — o wg.Wait() nunca
// voltaria e a ferramenta PENDURARIA, sem saída e sem relatório, que é pior que
// cair. Por isso as seções críticas das pools guardadas usam `defer Unlock`.
func (f *Facts) guardaGoroutine(coletor string) {
	if r := recover(); r != nil {
		f.partialSeguro(coletor, "um trabalhador desta varredura caiu (panic: "+
			fmt.Sprint(r)+"): a parte da fila que estava com ele NÃO foi "+
			"examinada — o que ela diria não pode ser deduzido do silêncio")
	}
}

// rodarColetor isola a falha de UM coletor.
//
// Collect chama cerca de trinta coletores em sequência, e um panic em qualquer
// um deles subia até o recover do main: saída sem dump, exit 3, e TODOS os
// coletores anteriores descartados junto — de um host que pode não existir
// amanhã. Aqui a queda vira lacuna daquele coletor e a coleta segue.
// rodarColetor recebe a CHAVE de lacuna e o NOME do coletor separados.
//
// A chave decide qual check degrada, e por isso sai do vocabulário que os
// checks já consomem — a catraca de lacunas exige isso. O nome vai na mensagem
// porque uma chave sozinha não identifica o que caiu: `collectHost` e
// `collectProcesses` degradam o mesmo check, e "o coletor caiu" sem dizer qual
// manda o operador procurar no lugar errado.
func rodarColetor(f *Facts, chave, nome string, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			f.partialSeguro(chave, "o coletor "+nome+" caiu (panic: "+fmt.Sprint(r)+
				"): os fatos que ele produz NÃO foram coletados, e nenhuma "+
				"conclusão sobre eles pode sair desta execução")
		}
	}()
	fn()
}

// Collect roda os coletores disponíveis para o ambiente sondado.
func Collect(e *env.Env) *Facts {
	f := &Facts{
		SchemaVersion: SchemaVersion,
		CollectedAt:   e.Now.Format("2006-01-02T15:04:05Z"),
		Source:        e.Source.String(),
	}

	e.Stage("host")
	rodarColetor(f, "proc", "collectHost", func() { collectHost(f, e) })
	// Antes de tudo que interpreta caminho: a tabela de montagem diz se o bit
	// setuid de um arquivo é inerte e se algo executa de um diretório.
	e.Stage("montagens")
	rodarColetor(f, "mounts", "collectMounts", func() { collectMounts(f, e) })

	if e.Has(env.CapProcfs) {
		e.Stage("processos")
		rodarColetor(f, "proc", "collectProcesses", func() { collectProcesses(f, e) })
		// Depois dos processos: o dono de cada socket sai do join com os fds
		// que o coletor de processo já leu.
		// Os limites vêm ANTES dos sockets: além de serem os tetos que
		// transformam "há 400 conexões" em "e o próximo connect vai falhar",
		// a faixa de porta efêmera é INSUMO da inferência de direção.
		e.Stage("rede")
		rodarColetor(f, "net", "collectLimitesDeRede", func() { collectLimitesDeRede(f, e) })
		rodarColetor(f, "net", "collectSockets", func() { collectSockets(f, e) })
		// DEPOIS dos sockets: o criador de um segmento SysV SHM é um cpid, e
		// saber se ele é DAEMON DE REDE (tem socket de escuta) exige os sockets já
		// lidos — é o discriminador que pega o Ebury 0600. O canal IPC que não
		// aparece em socket nem em fd.
		rodarColetor(f, "sysvipc", "collectSysVShm", func() { collectSysVShm(f, e) })
		// E os que leem PACOTE, que não aparecem em tabela de conexão nenhuma:
		// é por eles que um filtro de socket eBPF órfão continua vivo.
		rodarColetor(f, "pacote", "collectSocketsBrutos", func() { collectSocketsBrutos(f, e) })
		// DEPOIS dos sockets: a segunda visão da mesma tabela, pelo netlink.
		// Ela precisa da primeira para ter com o que divergir.
		rodarColetor(f, "net", "collectCrossSockets", func() { collectCrossSockets(f, e) })
		// Depois dos processos e ANTES de qualquer pergunta de propriedade: é
		// a classificação que decide se "que pacote entregou este binário?" faz
		// sentido para aquele processo.
		classificaContainers(f)
		// Depois dos processos: a comparação precisa da lista para saber o que
		// está VISÍVEL.
		e.Stage("kernel e módulos")
		rodarColetor(f, "cross", "collectCrossView", func() { collectCrossView(f, e) })
		// Junto do cross-view: aqueles dizem que o kernel pode estar mentindo,
		// e este diz COMO.
		rodarColetor(f, "ftrace", "collectFtrace", func() { collectFtrace(f, e) })
		// Marca do próprio kernel sobre o que já foi carregado nele. Não
		// depende de privilégio e não pode ser apagada sem reiniciar.
		rodarColetor(f, "taint", "collectTaint", func() { collectTaint(f, e) })
		// O que o kernel deixa acontecer com ele mesmo. Vem antes dos módulos
		// carregados porque é o contexto que pesa o achado deles.
		rodarColetor(f, "taint", "collectProtecaoKernel", func() { collectProtecaoKernel(f, e) })
		// Depois dos processos: o dono de um programa eBPF é um descritor
		// aberto, e a lista de descritores já está lida.
		rodarColetor(f, "bpf", "collectBPF", func() { collectBPF(f, e) })
	} else {
		f.partial("proc", e.Reason(env.CapProcfs))
	}

	if e.Has(env.CapFilesystem) {
		// A parte cara: varre dezenas de milhares de diretórios. É o estágio em
		// que a coleta "parece travada" num disco lento, e por isso o que mais
		// justifica o batimento.
		e.Stage("varredura de filesystem")
		rodarColetor(f, "persist", "collectPersist", func() { collectPersist(f, e) })
		// Depois da persistência: a varredura de código reusa os web roots e
		// procura backdoor em PHP/JS/Python. Peneira declarada, com teto.
		e.Stage("varredura de código")
		rodarColetor(f, "codigo", "collectCodigo", func() { collectCodigo(f, e) })
		// DEPOIS da persistência: a pergunta "quem pode reescrever o que root
		// executa" precisa da lista do que root executa, e ela sai dali.
		rodarColetor(f, "gravavel", "collectAlvosDeRoot", func() { collectAlvosDeRoot(f, e) })
		// DEPOIS da persistência, que é quem varre /lib/modules: a pergunta
		// "que arquivo entregou este módulo?" precisa da lista de arquivos, e
		// respondê-la antes diria "nenhum" em todo host — a pior forma de falso
		// positivo, porque é uniforme e convincente.
		if e.Has(env.CapProcfs) {
			rodarColetor(f, "modulo", "collectModulosCarregados", func() { collectModulosCarregados(f, e) })
		}
		// Depois de tudo: o conjunto de candidatos a hash é o que os outros
		// coletores acharem interessante. Só roda com hash na lista.
		rodarColetor(f, "ioc", "collectHashesIOC", func() { collectHashesIOC(f, e) })
	} else {
		f.partial("persist", e.Reason(env.CapFilesystem))
	}

	// POR ÚLTIMO: quem vigia arquivo precisa dos fds já lidos E do inventário
	// de caminhos que os outros coletores montaram — é contra ele que os
	// inodes observados ganham nome.
	if e.Has(env.CapProcfs) {
		e.Stage("vigias de arquivo")
		rodarColetor(f, "vigia", "collectVigias", func() { collectVigias(f, e) })
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
