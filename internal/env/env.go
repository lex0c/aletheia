// Package env descobre o que este processo consegue ver, e a partir de onde.
//
// É o primeiro passo do fluxo (SPEC 5.1) e alimenta duas coisas: o motor, que
// decide se um check pode rodar, e o rodapé de cobertura, que diz o que NÃO foi
// verificado e por quê. Nada aqui adivinha: capacidade ausente vira motivo
// escrito, nunca silêncio.
package env

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/lex0c/aletheia/internal/ioc"
	"github.com/lex0c/aletheia/internal/kbpf"
	"github.com/lex0c/aletheia/internal/netlink"
)

// diagProtocolosSeguros diz, por protocolo, se a consulta de socket por netlink
// pode ser feita SEM disparar autoload de módulo.
//
// A consulta ao sock_diag faz o kernel chamar request_module para o handler da
// família/protocolo quando ele não está registrado — e request_module executa
// modprobe como root. Consultar é seguro só quando o handler JÁ está carregado
// (aparece em /proc/modules) ou é BUILTIN (aparece em modules.builtin): nos dois
// casos não há o que carregar.
//
// Com --allow-kernel-autoload o operador aceita o autoload, e todos os
// protocolos passam a ser consultáveis.
func diagProtocolosSeguros(e *Env) map[string]bool {
	if e.PermitirAutoload {
		return map[string]bool{"tcp": true, "tcp6": true, "udp": true, "udp6": true}
	}
	disp := modulosDisponiveis(e)
	inet := disp["inet_diag"]
	tcp := inet && disp["tcp_diag"]
	udp := inet && disp["udp_diag"]
	return map[string]bool{"tcp": tcp, "tcp6": tcp, "udp": udp, "udp6": udp}
}

// modulosDisponiveis é o conjunto de módulos que consultar NÃO autocarrega:
// os CARREGADOS (/proc/modules) e os BUILTIN (modules.builtin). Um módulo =m
// não carregado não está em nenhum dos dois — e é justamente ele que dispararia
// o request_module.
func modulosDisponiveis(e *Env) map[string]bool {
	out := map[string]bool{}
	if b, err := e.ReadFile("/proc/modules"); err == nil {
		for _, ln := range strings.Split(string(b), "\n") {
			if i := strings.IndexByte(ln, ' '); i > 0 {
				out[ln[:i]] = true
			}
		}
	}
	if rel := releaseDoKernel(e); rel != "" {
		if b, err := e.ReadFile("/lib/modules/" + rel + "/modules.builtin"); err == nil {
			for _, ln := range strings.Split(string(b), "\n") {
				base := ln[strings.LastIndexByte(ln, '/')+1:]
				base = strings.TrimSuffix(base, ".ko")
				if base != "" {
					out[base] = true
				}
			}
		}
	}
	return out
}

func releaseDoKernel(e *Env) string {
	b, err := e.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// primeiroProtoSeguro escolhe um protocolo consultável para a sonda de
// capacidade, na ordem em que eles importam.
func primeiroProtoSeguro(seg map[string]bool) (string, bool) {
	for _, p := range []string{"tcp", "tcp6", "udp", "udp6"} {
		if seg[p] {
			return p, true
		}
	}
	return "", false
}

func famDe(proto string) uint8 {
	if strings.HasSuffix(proto, "6") {
		return netlink.FamiliaIPv6
	}
	return netlink.FamiliaIPv4
}

func protoDe(proto string) uint8 {
	if strings.HasPrefix(proto, "udp") {
		return netlink.ProtoUDP
	}
	return netlink.ProtoTCP
}

// modprobeDeFabrica diz se o programa que o kernel executa para carregar módulo
// é o que a distribuição entrega. O usrmerge move um para o outro, e as quatro
// formas abaixo são o que as distribuições usam.
//
// ILEGÍVEL conta como não-seguro: o arquivo é legível por qualquer um em
// qualquer host normal, e não poder verificar a precondição de uma ação com
// efeito colateral é motivo para não tomar a ação.
func modprobeDeFabrica(e *Env) (string, bool) {
	b, err := e.ReadFile("/proc/sys/kernel/modprobe")
	if err != nil {
		return "ilegível (" + err.Error() + ")", false
	}
	v := strings.TrimSpace(string(b))
	switch v {
	case "/sbin/modprobe", "/usr/sbin/modprobe", "/bin/modprobe", "/usr/bin/modprobe":
		return v, true
	}
	if v == "" {
		// Vazio significa que o kernel não executa nada para carregar módulo:
		// não há gatilho, e a consulta é segura.
		return "", true
	}
	return v, false
}

// Cap é uma capacidade do ambiente. O check declara o que precisa (Requires) e
// o que gostaria (Optional); o motor confere aqui antes de rodar.
type Cap uint32

const (
	CapRoot Cap = 1 << iota
	CapProcfs
	CapDebugfs
	CapBPF
	CapSystemd
	CapPkgDB
	CapNetlink
	CapFilesystem
	// CapRtnetlink é o NETLINK_ROUTE, e é uma capacidade DIFERENTE do
	// CapNetlink apesar do nome parecido.
	//
	// As duas famílias não têm nada em comum além da palavra: o SOCK_DIAG
	// enumera socket e depende de inet_diag/tcp_diag/udp_diag — módulos que a
	// consulta pode AUTOCARREGAR, e é por isso que ele é tratado com pinça. O
	// NETLINK_ROUTE enumera interface, filtro de tc e programa de XDP, não
	// depende de módulo nenhum e não autocarrega nada.
	//
	// Enquanto eram a mesma capacidade, um host sem os módulos de diagnóstico
	// perdia tc e XDP JUNTO — e o relatório dizia que não os leu porque
	// "inet_diag não está carregado", que não tem relação com o que ele deixou
	// de ler. Uma lacuna com o motivo errado é pior que nenhuma: manda o
	// operador consertar o que não estava quebrado.
	//
	// Fica no FIM da lista de propósito: o bit é serializado por NOME no dump
	// (`caps: []string`), mas mover os anteriores tornaria qualquer leitura
	// posicional de dump antigo silenciosamente errada.
	CapRtnetlink
)

var capNames = []struct {
	c Cap
	n string
}{
	{CapRoot, "root"},
	{CapProcfs, "procfs"},
	{CapDebugfs, "debugfs"},
	{CapBPF, "bpf"},
	{CapSystemd, "systemd"},
	{CapPkgDB, "pkgdb"},
	{CapNetlink, "netlink"},
	{CapFilesystem, "filesystem"},
	{CapRtnetlink, "rtnetlink"},
}

// Names devolve os nomes das capacidades presentes no conjunto.
func (c Cap) Names() []string {
	var out []string
	for _, e := range capNames {
		if c&e.c != 0 {
			out = append(out, e.n)
		}
	}
	return out
}

func (c Cap) String() string { return strings.Join(c.Names(), ",") }

// Source é a origem dos dados: host vivo ou imagem montada.
type Source uint8

const (
	// SourceLive: /proc, netlink, systemd em runtime, processos vivos.
	SourceLive Source = 1 << iota
	// SourceImage: apenas filesystem, sob --root. Aqui o kernel é o do
	// analista, então ocultamento de arquivo por hook em getdents64 não
	// acontece (runbook §35.6).
	SourceImage
)

func (s Source) String() string {
	if s == SourceImage {
		return "image"
	}
	return "live"
}

// ClockState registra se a datação desta execução é confiável. Sem NTP
// sincronizado, todo achado datado é frágil (runbook §9) — e isso precisa estar
// no relatório, não ser descoberto depois.
type ClockState int

const (
	ClockUnknown ClockState = iota
	ClockSynced
	ClockUnsynced
)

func (c ClockState) String() string {
	switch c {
	case ClockSynced:
		return "sincronizado"
	case ClockUnsynced:
		return "NÃO sincronizado"
	default:
		return "desconhecido"
	}
}

// Env é o resultado do probe. Imutável depois de Probe.
type Env struct {
	Root      string // prefixo de caminho; "" = host vivo
	Source    Source
	Caps      Cap
	CapReason map[string]string // capacidade ausente -> motivo

	// WalkDeadline limita as varreduras de filesystem (SUID e git-hooks) no
	// tempo. Zero = sem limite, o padrão do scan. O wtf a define para a
	// varredura caber no orçamento: ela para no prazo e DECLARA o que não
	// examinou, em vez de estourar o "~2s" que o wtf promete. É a mesma lacuna
	// da truncagem por contagem, disparada pelo relógio.
	WalkDeadline time.Time

	// CodigoTudo liga a varredura de código sobre a FS montada INTEIRA (a
	// partir de /), no lugar da lista de web roots. Pseudo-FS e montagem de
	// rede são pulados e DECLARADOS. É o --all-fs do scan: cobertura máxima da
	// FS montada, ao custo de tempo, com os limites (contêiner, >2 MB) ditos.
	CodigoTudo bool

	// LogsTudo é o `--logs-all`: o teto de SELEÇÃO de arquivos sobe para o
	// limite rígido.
	//
	// Ele NÃO desliga teto nenhum de segurança. O host é adversário: um
	// `touch /var/log/x{000001..999999}` é barato, e um `.gz` de 40 KB pode
	// descomprimir para 40 GB. Bytes, linhas, eventos e descompressão continuam
	// valendo, e o que estourar vira lacuna declarada.
	LogsTudo bool

	// SemLogs é o `--no-logs`, e é o que o wtf liga SEMPRE.
	//
	// O wtf roda a coleta inteira dentro de ~2s, e LacunasDeColeta despeja todo
	// f.Partial na cobertura sem filtrar por seleção — um coletor de log que
	// estourasse o prazo daria ao wtf uma lacuna PERMANENTE, e uma lacuna que
	// nunca fecha é uma que as pessoas aprendem a ignorar.
	//
	// Desligado NÃO é lacuna: é escolha declarada, e ela viaja em
	// Facts.LogEstado para que um analyze sobre esse dump responda NÃO
	// VERIFICADO em vez de "não achei".
	SemLogs bool

	// ignorados são prefixos de caminho absoluto que NENHUMA varredura de
	// filesystem percorre — o --ignore. Excluir uma árvore gigante e
	// irrelevante (/data/xmls) do custo é escolha do operador, e como o --root,
	// atravessa todo coletor. A exclusão é DECLARADA: esquecer que se ignorou
	// algo e ler "limpo" é a cegueira silenciosa que a ferramenta combate.
	ignorados []string

	// stageMarks registra QUANDO cada estágio de coleta começou, para o CLI
	// poder dizer onde o tempo foi quando a coleta é lenta. Só a goroutine da
	// coleta chama Stage (ela é sequencial), então não precisa de lock.
	stageMarks []stageMark

	// Progress recebe o nome do estágio de coleta atual, para o CLI mostrar que
	// a varredura longa não travou. nil = silêncio, e é o padrão: nada em
	// `facts` ou nos testes precisa de um. Vive aqui porque `e` já atravessa
	// todo coletor.
	Progress ProgressSink

	// Segredos é o operador tendo dito --allow-secrets, e ele atravessa a coleta
	// inteira porque as DUAS metades dependem dele.
	//
	// A primeira é o que se COLETA: readEnviron guarda só os valores de uma
	// allowlist, e o resto sai como nome sem valor. A segunda é o que se
	// ESCREVE: dump.De redige argv, cron, unit e gatilho ao montar o artefato.
	//
	// Um dos dois sozinho é meia-medida perigosa. Coletar o environ inteiro e
	// então redigi-lo gastaria a leitura para jogar fora; pular a redação sobre
	// um Facts que já nasceu sem os valores entregaria um artefato marcado como
	// cru e sem o segredo que ele promete. Uma flag, as duas metades.
	//
	// O padrão é false, e nenhum caminho de CLI o liga a não ser o mcp com
	// --profile full --allow-secrets: `collect` nunca escreve dump cru em disco.
	Segredos bool

	// selado marca o ambiente RECONSTRUÍDO — o que dump.Env() devolve. Ele
	// descreve as condições de uma coleta que já terminou, então todo acesso a
	// filesystem por ele é recusado com ErrSelado. Ver raizIndisponivel.
	selado bool

	Now   time.Time // sempre UTC
	Clock ClockState

	ToolPath    string
	ToolSHA256  string
	ToolVersion string

	// NumCPU vem do runtime, que já respeita AFINIDADE (taskset, cpuset).
	NumCPU int

	// CPUQuota é a cota do cgroup em CPUs — 0,5 num `docker run --cpus=0.5`.
	// Zero significa sem limite, ou não determinado. É o que o runtime NÃO
	// enxerga, e é o que decide quantos leitores de /proc abrir.
	CPUQuota float64

	// IOC são os indicadores DESTE incidente, quando o operador os informou
	// (SPEC 6.4). Ficam aqui e não em Facts por uma razão de contrato: Facts é
	// o retrato do HOST, e a lista não é fato do host — é o que esta execução
	// está procurando, do mesmo jeito que --root é de onde ela olha.
	IOC *ioc.Lista

	// BPFSemMecanismo diz que este kernel não tem O QUE enumerar — a bpf(2) não
	// existe. É diferente de "não me deixaram olhar", e a diferença decide se a
	// ausência degrada a cobertura ou não.
	BPFSemMecanismo bool

	// NetlinkSemMecanismo é o mesmo para o sock_diag: o kernel não OFERECE a
	// interface (EPROTONOSUPPORT, ENOENT, EINVAL), e nenhuma permissão a faria
	// aparecer. O netlink.Erro já carregava esse bit, com a doc certa — e
	// nenhum chamador o lia. O efeito era um exit 1 PERMANENTE: CapNetlink
	// negada, cross.socket_view NotChecked, cobertura incompleta, e a mensagem
	// mandando usar --allow-kernel-autoload, que naquele host não pode ajudar
	// porque não há módulo a carregar. É a "lacuna constante que não é lacuna".
	NetlinkSemMecanismo bool

	// semMecanismo é o conjunto de capacidades cuja ausência é ESCOPO e não
	// lacuna. O motor não conta essas no denominador da cobertura: escopo se
	// declara uma vez, não como degradação em cada check.
	semMecanismo Cap

	// PermitirAutoload libera a consulta por netlink mesmo quando o handler de
	// diagnóstico ainda não está carregado — o que pode fazer o kernel
	// AUTOCARREGAR o módulo (request_module). É opt-in (--allow-kernel-autoload)
	// porque altera o estado do host, e o padrão desta ferramenta é NÃO alterar.
	PermitirAutoload bool
	// DiagSeguros diz, por protocolo, se consultá-lo por netlink NÃO dispara
	// autoload — porque o handler já está carregado ou é builtin. É o que o
	// coletor de socket usa para decidir quais famílias enumerar.
	DiagSeguros map[string]bool

	// root é a raiz travada em modo image. Ver fs.go: prefixar string não
	// impede symlink absoluto de escapar da imagem.
	root *os.Root
	// RootErr guarda a falha de abrir a raiz, se houver.
	RootErr error
}

// Close libera a raiz travada.
// Selar torna o ambiente incapaz de ler filesystem, para sempre. Não há como
// dessselar: quem precisa do host vivo constrói um Env com env.Novo, que é o
// caminho onde o operador já disse o que autoriza.
func (e *Env) Selar() { e.selado = true }

// Selado responde se este ambiente descreve uma coleta encerrada.
func (e *Env) Selado() bool { return e.selado }

func (e *Env) Close() {
	if e.root != nil {
		e.root.Close()
		e.root = nil
	}
}

// Path é APENAS para exibição: monta o caminho como ele aparece para o
// operador. Não use para abrir arquivo — o acesso real vai por ReadFile/Stat/
// ReadDir/Readlink (fs.go), que são travados na raiz. Prefixo de string não
// impede symlink absoluto de escapar da imagem.
func (e *Env) Path(p string) string {
	if e.Root == "" {
		return p
	}
	return filepath.Join(e.Root, filepath.Join("/", p))
}

// Has diz se todas as capacidades do conjunto estão presentes.
func (e *Env) Has(c Cap) bool { return e.Caps&c == c }

// Missing devolve as capacidades de c que faltam.
func (e *Env) Missing(c Cap) Cap { return c &^ e.Caps }

// SemMecanismo diz se TODAS as capacidades de c faltam porque o host não
// oferece o mecanismo — e não porque faltou permissão.
//
// A distinção é a mesma que o projeto já paga caro para manter em outros
// lugares: se a pergunta PODE ser feita neste host e não foi, é lacuna; se ela
// não existe aqui, é ESCOPO. Um kernel compilado sem inet_diag nunca vai
// responder ao sock_diag, e chamar isso de cobertura degradada faz TODA
// varredura naquele host sair INCOMPLETE com exit 1 — inclusive a de um host
// limpo.
//
// Exige que o conjunto INTEIRO seja sem-mecanismo: um check que precisa de
// netlink e de root, rodando sem root num kernel sem inet_diag, continua sendo
// lacuna — porque uma das duas ausências tem conserto.
func (e *Env) SemMecanismo(c Cap) bool {
	return c != 0 && c&^e.semMecanismo == 0
}

// MarcarSemMecanismo registra que a ausência daquela capacidade é escopo.
// Exportada porque a reconstrução do Env a partir de um dump precisa restaurar
// o bit: sem isso, analisar um dump coletado num kernel sem inet_diag voltaria a
// contar a capacidade ausente como lacuna, e o replay divergiria da coleta.
func (e *Env) MarcarSemMecanismo(c Cap) { e.semMecanismo |= c }

// Reason explica por que as capacidades do conjunto faltam. Devolve TODAS as
// razões: colapsar para a primeira faz o rodapé citar "sem root" e omitir
// "debugfs não montado", e o operador conclui que basta rodar com sudo.
func (e *Env) Reason(c Cap) string {
	var rs []string
	for _, n := range c.Names() {
		if r, ok := e.CapReason[n]; ok {
			rs = append(rs, r)
		}
	}
	if len(rs) == 0 {
		return "indisponível"
	}
	return strings.Join(rs, " · ")
}

// Options são as escolhas do operador que afetam o probe.
type Options struct {
	Root    string
	Version string
	IOC     *ioc.Lista
	// PermitirAutoload é o --allow-kernel-autoload: libera a consulta por
	// netlink quando ela poderia autocarregar o módulo de diagnóstico.
	PermitirAutoload bool
}

// Probe inspeciona o ambiente uma única vez.
func Probe(o Options) *Env {
	e := &Env{
		Root:        o.Root,
		Now:         time.Now().UTC(),
		CapReason:   map[string]string{},
		ToolVersion: o.Version,
		IOC:         o.IOC,
		NumCPU:      runtime.NumCPU(),
		CPUQuota:    probeCPUQuota(),
	}
	e.PermitirAutoload = o.PermitirAutoload

	if o.Root != "" {
		e.Source = SourceImage
		r, err := os.OpenRoot(o.Root)
		if err != nil {
			e.RootErr = err
		} else {
			e.root = r
		}
	} else {
		e.Source = SourceLive
	}

	e.probeSelf()
	e.probeCaps()
	e.probeClock()
	return e
}

// Workers devolve quantos leitores concorrentes abrir, respeitando teto,
// afinidade E cota de cgroup.
//
// Arredonda a cota para cima: com 0,5 CPU o certo é UM leitor, não zero — e um
// leitor sequencial é exatamente o comportamento anterior. Nunca devolve menos
// que 1.
func (e *Env) Workers(cap int) int {
	n := e.NumCPU
	if e.CPUQuota > 0 {
		q := int(e.CPUQuota)
		if float64(q) < e.CPUQuota {
			q++ // teto
		}
		if q < n {
			n = q
		}
	}
	if n > cap {
		n = cap
	}
	if n < 1 {
		n = 1
	}
	return n
}

// A identidade do binário EM EXECUÇÃO não muda durante o processo, e reler o
// caminho depois já responderia sobre outro arquivo. Medido: 8,2 ms por
// chamada, dominados pelo SHA-256 dos ~6 MB do próprio binário — e o `watch`
// chamava env.Probe a cada amostra, com intervalo mínimo de 1 s. Numa vigília
// de uma hora eram 3.600 re-hashes do mesmo arquivo, ~5% do custo de cada
// amostra, num host que o próprio código descreve como possivelmente já
// sobrecarregado. A resondagem de probeCaps por ciclo é deliberada — alimenta o
// aviso "COBERTURA MUDOU" — e continua acontecendo.
var (
	selfUma  sync.Once
	selfPath string
	selfSoma string
)

func (e *Env) probeSelf() {
	selfUma.Do(func() {
		p, err := os.Executable()
		if err != nil {
			return
		}
		if r, err := filepath.EvalSymlinks(p); err == nil {
			p = r
		}
		selfPath = p

		f, err := os.Open(p)
		if err != nil {
			return
		}
		defer f.Close()
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			return
		}
		selfSoma = hex.EncodeToString(h.Sum(nil))
	})
	e.ToolPath, e.ToolSHA256 = selfPath, selfSoma
}

func (e *Env) grant(c Cap, ok bool, reason string) {
	if ok {
		e.Caps |= c
		return
	}
	for _, n := range c.Names() {
		e.CapReason[n] = reason
	}
}

func (e *Env) probeCaps() {
	// root — pelo ALCANCE, e não pelo euid. Ver alcancaSuperficiePrivilegiada.
	alcanca, porQue := alcancaSuperficiePrivilegiada()
	e.grant(CapRoot, alcanca, porQue)

	// filesystem — em image depende da raiz travada ter aberto.
	if e.Source == SourceImage && e.root == nil {
		e.grant(CapFilesystem, false, "não foi possível abrir --root com raiz travada: "+errStr(e.RootErr))
	} else {
		e.grant(CapFilesystem, true, "")
	}

	// procfs — só existe no host vivo. Em imagem montada não há processo.
	if e.Source == SourceImage {
		e.grant(CapProcfs, false, "modo image: não há processo vivo numa imagem montada")
	} else {
		_, err := os.Stat("/proc/self/status")
		e.grant(CapProcfs, err == nil, "/proc não montado ou ilegível")
	}

	// debugfs — o caminho mudou entre kernels; sondar os dois. E a sondagem é
	// de MONTAGEM: /sys/kernel/tracing existe em todo kernel com o Kconfig
	// ligado, e o `IsDir` de antes concedia a capacidade sobre um diretório
	// vazio. O motivo acompanha o estado, porque "não está montado" manda
	// montar e "não consigo listar" manda rodar como root.
	dbg, indeterminado := false, false
	motivoDbg := "debugfs/tracefs não montado: ftrace e kprobes não foram verificados"
	for _, c := range []string{"/sys/kernel/tracing", "/sys/kernel/debug/tracing"} {
		switch e.EstadoDeMontagem(c) {
		case MontagemAtiva:
			dbg = true
		case MontagemIndeterminada:
			// O PRIMEIRO candidato indeterminado, não o último: /sys/kernel/tracing
			// é o caminho dos kernels atuais, e nomear o legado confundiria.
			if !indeterminado {
				indeterminado = true
				motivoDbg = c + " está montado e não pôde ser listado (exige " +
					"privilégio): ftrace e kprobes não foram verificados — rode como root"
			}
		}
		if dbg {
			break
		}
	}
	e.grant(CapDebugfs, dbg, motivoDbg)

	// systemd — presença por diretório, não por binário: precisa funcionar
	// sobre imagem montada.
	sysd := false
	for _, c := range []string{"/usr/lib/systemd/system", "/lib/systemd/system", "/etc/systemd/system"} {
		if e.IsDir(c) {
			sysd = true
			break
		}
	}
	e.grant(CapSystemd, sysd, "host sem systemd: checks de unit não se aplicam")

	// base de pacotes
	pkg := false
	// O pacman FALTAVA nesta lista, e o coletor tem backend para ele desde
	// sempre: em todo host Arch a coleta declarava "sem base de pacotes
	// legível" enquanto lia a base normalmente. A capacidade dizia uma coisa e
	// o coletor fazia outra — e quem lê o rodapé acredita na capacidade.
	for _, c := range []string{
		"/var/lib/dpkg/status", "/var/lib/rpm", "/usr/lib/sysimage/rpm",
		"/lib/apk/db", "/var/lib/pacman/local",
	} {
		if e.Exists(c) {
			pkg = true
			break
		}
	}
	e.grant(CapPkgDB, pkg, "sem base de pacotes legível: integridade não foi verificada")

	// eBPF — perguntado à própria bpf(2), não presumido.
	//
	// Esta capacidade passou por um período declarada como "não implementada", e
	// isso tinha um efeito que só apareceu quando alguém foi procurar: como
	// NENHUM check a exigia, o motivo nunca chegava ao rodapé. O ponto cego
	// estava escrito no código e invisível na saída — que é a única forma de
	// lacuna que esta ferramenta não pode ter.
	if e.Source == SourceImage {
		e.BPFSemMecanismo = true
		e.MarcarSemMecanismo(CapBPF)
		e.grant(CapBPF, false, "modo image: não há kernel vivo para enumerar programa eBPF")
	} else if err := kbpf.Sonda(); err != nil {
		var es *kbpf.ErroSonda
		if errors.As(err, &es) {
			e.BPFSemMecanismo = es.SemMecanismo
			if es.SemMecanismo {
				e.MarcarSemMecanismo(CapBPF)
			}
			e.grant(CapBPF, false, es.Motivo)
		} else {
			e.grant(CapBPF, false, "enumeração de eBPF indisponível: "+err.Error())
		}
	} else {
		e.grant(CapBPF, true, "")
	}

	// netlink — a segunda visão da tabela de conexões (runbook §35.5).
	//
	// A recusa do meio não é sobre permissão: é sobre o EFEITO da própria
	// pergunta. Consultar o sock_diag faz o kernel carregar sozinho o módulo de
	// diagnóstico quando ele não está carregado — e o kernel carrega módulo
	// EXECUTANDO /proc/sys/kernel/modprobe, como root. Num host onde esse
	// caminho foi trocado, a consulta desta ferramenta seria o gatilho do
	// implante que ela mesma denuncia (persist.kernel_helper).
	//
	// Diante disso ela não pergunta, e diz que não perguntou. Perder uma visão
	// cruzada é um preço menor que executar o implante do investigado.
	// O rtnetlink é decidido ANTES e por conta própria, porque a razão que
	// bloqueia o sock_diag não o alcança: abrir NETLINK_ROUTE não carrega módulo
	// e não executa nada.
	switch {
	case e.Source == SourceImage:
		e.grant(CapRtnetlink, false, "modo image: não há kernel vivo para consultar por netlink")
	default:
		if c, err := netlink.Abrir(syscall.NETLINK_ROUTE); err != nil {
			e.grant(CapRtnetlink, false, "rtnetlink indisponível ("+err.Error()+
				"): interface, filtro de tc e programa de XDP não puderam ser enumerados")
		} else {
			c.Fechar()
			e.grant(CapRtnetlink, true, "")
		}
	}

	switch {
	case e.Source == SourceImage:
		e.NetlinkSemMecanismo = true
		e.MarcarSemMecanismo(CapNetlink)
		e.grant(CapNetlink, false, "modo image: não há kernel vivo para consultar por netlink")
	default:
		e.DiagSeguros = diagProtocolosSeguros(e)
		protoSonda, temSeguro := primeiroProtoSeguro(e.DiagSeguros)
		switch {
		case !temSeguro:
			// O ponto central da não-intrusão: consultar o sock_diag pode fazer
			// o kernel AUTOCARREGAR tcp_diag/udp_diag (request_module), e isso
			// ALTERA o estado do host. Sem prova de que o handler já está
			// disponível, a ferramenta não pergunta — e diz que não perguntou.
			e.grant(CapNetlink, false, "consulta por netlink NÃO feita: os módulos de "+
				"diagnóstico (inet_diag + tcp_diag/udp_diag) não estão carregados nem são "+
				"builtin, e consultá-los faria o kernel AUTOCARREGAR módulo (request_module) "+
				"— alteração de estado do host, que esta ferramenta evita. Use "+
				"--allow-kernel-autoload para permitir; sem isso, a divergência /proc/net × "+
				"netlink NÃO foi verificada")
		case e.PermitirAutoload:
			// Com o autoload LIBERADO, o programa que o kernel executa para
			// carregar o módulo volta a importar: um /proc/sys/kernel/modprobe
			// sequestrado seria disparado por esta consulta.
			if alvo, seguroMp := modprobeDeFabrica(e); !seguroMp {
				e.grant(CapNetlink, false, "consulta por netlink liberada com "+
					"--allow-kernel-autoload, MAS /proc/sys/kernel/modprobe é "+alvo+
					", fora do padrão da distribuição: a ferramenta se recusa a ser o "+
					"gatilho de um helper sequestrado")
			} else {
				e.sondarNetlink(protoSonda)
			}
		default:
			// Handler já disponível: consultar NÃO autocarrega nada. A sonda usa
			// um protocolo comprovadamente seguro, nunca um que dispararia o load.
			e.sondarNetlink(protoSonda)
		}
	}
}

// sondarNetlink faz a sonda de capacidade e CLASSIFICA a falha.
//
// O netlink.Erro sempre carregou o bit SemMecanismo, com a doc certa ("não é
// lacuna de leitura"), e nenhum chamador o lia — o grep confirmava só
// atribuições. O contraste estava no vizinho: o kbpf.ErroSonda tem o mesmo bit
// e ele flui até facts/bpf.go, onde decide se a ausência degrada a cobertura.
//
// Sem essa leitura, um kernel compilado sem inet_diag — ou, muito mais comum,
// um host sem /lib/modules/$(uname -r)/modules.builtin, onde inet_diag é
// BUILTIN e portanto invisível a modulosDisponiveis — saía com CapNetlink
// negada, cross.socket_view NotChecked e INCOMPLETE com exit 1 em TODA
// execução, para sempre. E a frase mandava usar --allow-kernel-autoload, que
// ali não pode ajudar: não há módulo a carregar.
func (e *Env) sondarNetlink(protoSonda string) {
	err := netlink.Sonda(famDe(protoSonda), protoDe(protoSonda))
	if err == nil {
		e.grant(CapNetlink, true, "")
		return
	}
	var ne *netlink.Erro
	if errors.As(err, &ne) && ne.SemMecanismo {
		e.NetlinkSemMecanismo = true
		e.MarcarSemMecanismo(CapNetlink)
		e.grant(CapNetlink, false, "este kernel não OFERECE a enumeração de "+
			"socket por netlink ("+ne.Motivo+"): não é falta de permissão, e "+
			"nenhuma opção a faria aparecer — a divergência /proc/net × netlink "+
			"não se aplica a este host")
		return
	}
	e.grant(CapNetlink, false, "enumeração de socket por netlink indisponível: "+err.Error())
}

func (e *Env) probeClock() {
	if e.Source == SourceImage {
		e.Clock = ClockUnknown
		return
	}
	// systemd-timesyncd cria este arquivo quando o relógio sincroniza.
	if _, err := os.Stat("/run/systemd/timesync/synchronized"); err == nil {
		e.Clock = ClockSynced
		return
	}
	// Sem o marcador, não afirmamos nada: pode haver chrony ou ntpd, e
	// determinar isso exigiria falar com eles.
	e.Clock = ClockUnknown
}

func errStr(err error) string {
	if err == nil {
		return "motivo desconhecido"
	}
	return err.Error()
}

// ProgressSink recebe o rótulo do estágio corrente da coleta e, opcionalmente, o
// DETALHE do que está sendo feito agora (o caminho sendo lido). O CLI passa um
// escritor de terminal; um dump ou teste passa nil e tudo cala.
type ProgressSink interface {
	Stage(name string)
	Detalhe(s string)
}

// Ignorar registra os caminhos do --ignore, normalizados para caminho absoluto
// e limpo. Ignorar "/" seria esvaziar a varredura inteira e é recusado — quem
// quer isso não passa --ignore.
func (e *Env) Ignorar(paths []string) {
	for _, p := range paths {
		for _, item := range strings.Split(p, ",") {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			if !strings.HasPrefix(item, "/") {
				item = "/" + item
			}
			item = filepath.Clean(item)
			if item == "/" || e.jaIgnora(item) {
				continue
			}
			e.ignorados = append(e.ignorados, item)
		}
	}
}

func (e *Env) jaIgnora(p string) bool {
	for _, ig := range e.ignorados {
		if ig == p {
			return true
		}
	}
	return false
}

// Ignorado diz se um caminho absoluto está sob um prefixo do --ignore. O
// casamento respeita a fronteira de componente: --ignore /data/x não pega
// /data/xmls, só /data/x e o que estiver embaixo dele.
func (e *Env) Ignorado(p string) bool {
	if e == nil {
		return false
	}
	for _, ig := range e.ignorados {
		if p == ig || strings.HasPrefix(p, ig+"/") {
			return true
		}
	}
	return false
}

// Ignorados devolve os prefixos do --ignore, para o relatório DECLARAR o que
// foi excluído da varredura.
func (e *Env) Ignorados() []string { return e.ignorados }

// WalkExpired diz se a varredura de filesystem já passou do prazo. Falso quando
// não há prazo (WalkDeadline zero), que é o caso do scan.
func (e *Env) WalkExpired() bool {
	return e != nil && !e.WalkDeadline.IsZero() && time.Now().After(e.WalkDeadline)
}

// stageMark é o instante em que um estágio de coleta começou.
type stageMark struct {
	nome string
	em   time.Time
}

// StageDur é a duração medida de um estágio.
type StageDur struct {
	Nome string
	Dur  time.Duration
}

// Stage anuncia o estágio atual da coleta: marca o tempo (para o relatório de
// onde o tempo foi) e avisa o progresso, se houver.
func (e *Env) Stage(name string) {
	if e == nil {
		return
	}
	e.stageMarks = append(e.stageMarks, stageMark{name, time.Now()})
	if e.Progress != nil {
		e.Progress.Stage(name)
	}
}

// Detalhe informa ao progresso o que está sendo lido AGORA (um caminho). É
// chamado no laço quente das varreduras, então precisa ser barato: o reporter só
// guarda a string, e o tique decide quando desenhar. No-op sem terminal.
func (e *Env) Detalhe(s string) {
	if e != nil && e.Progress != nil {
		e.Progress.Detalhe(s)
	}
}

// Timings devolve quanto cada estágio levou, usando fim como o término do
// último. Ordenado do mais caro para o mais barato: o gargalo vem primeiro.
func (e *Env) Timings(fim time.Time) []StageDur {
	if e == nil || len(e.stageMarks) == 0 {
		return nil
	}
	out := make([]StageDur, 0, len(e.stageMarks))
	for i, m := range e.stageMarks {
		termino := fim
		if i+1 < len(e.stageMarks) {
			termino = e.stageMarks[i+1].em
		}
		out = append(out, StageDur{m.nome, termino.Sub(m.em)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Dur > out[j].Dur })
	return out
}
