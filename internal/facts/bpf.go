package facts

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/kbpf"
	"github.com/lex0c/aletheia/internal/netlink"
)

// Programas eBPF carregados (runbook §35, SPEC fase 8).
//
// # Por que este coletor é diferente dos outros
//
// Todo o resto desta ferramenta pergunta por ARQUIVO ou por PROCESSO. Um
// programa eBPF não é nenhum dos dois: depois de carregado ele vive dentro do
// kernel, sem caminho em disco, sem entrada em /proc/modules, sem aparecer em
// lista nenhuma que um operador conheça. O `find` não acha, o hash não compara,
// a base de pacotes não tem opinião — e ele intercepta syscall, lê pacote e
// altera retorno com a força de um módulo.
//
// É o implante fileless que o modelo de retrato ENXERGA, desde que alguém
// pergunte ao kernel. Este arquivo é a pergunta.
//
// # A pergunta que decide o falso positivo
//
// Um programa continua carregado enquanto ALGUÉM o segura. A pergunta não é
// "existe programa eBPF neste host?" — existe em todo host com systemd
// moderno, e num nó de Kubernetes existem dezenas. A pergunta é "quem segura
// este programa, e eu consigo ver?".
//
//	descritor aberto   /proc/<pid>/fd + fdinfo  → visível
//	perf_event legado  BPF_TASK_FD_QUERY        → visível
//	pin no bpffs       arquivo                  → visível
//	link               enumerável pela bpf(2)   → visível
//	tail call          entrada de prog_array    → visível
//	tc/xdp             netlink (rtnetlink)      → SIM
//	cgroup             BPF_PROG_QUERY (attached)  → SIM
//
// Os cinco primeiros são resolvidos aqui. O sexto é declarado pelo tipo
// (kbpf.FixacaoDe), e o check não acusa o que a ferramenta não sabe olhar.

// ProgramaBPF é um programa carregado, com tudo que se conseguiu descobrir
// sobre quem o segura.
type ProgramaBPF struct {
	ID      uint32 `json:"id"`
	Tipo    string `json:"type"`
	TipoNum uint32 `json:"type_num"`
	Nome    string `json:"name,omitempty"`
	// Tag é o hash do bytecode calculado pelo próprio kernel: o mesmo programa
	// carregado em dois hosts tem a mesma tag, e é por ela que se compara.
	Tag string `json:"tag,omitempty"`
	UID uint32 `json:"created_by_uid"`
	// CarregadoUTC é derivado do relógio de boot. Vazio quando o boot não é
	// conhecido — campo ausente vira desconhecido, nunca zero.
	CarregadoUTC string `json:"loaded_utc,omitempty"`
	Mapas        uint32 `json:"maps,omitempty"`
	Instrucoes   uint32 `json:"verified_insns,omitempty"`

	Donos    []DonoBPF `json:"holders,omitempty"`
	Pins     []string  `json:"pins,omitempty"`
	Anexos   []string  `json:"attachments,omitempty"`
	TailCall bool      `json:"tail_called,omitempty"`
}

// DonoBPF é um processo que segura o programa, e COMO ele o segura.
type DonoBPF struct {
	PID  int    `json:"pid"`
	Comm string `json:"comm,omitempty"`
	Como string `json:"how"`
}

// LinkBPF é um anexo vivo: programa × ponto do kernel.
type LinkBPF struct {
	ID     uint32 `json:"id"`
	Tipo   string `json:"type"`
	ProgID uint32 `json:"prog_id"`
	Alvo   string `json:"target,omitempty"`
}

// BPF é o retrato do subsistema.
type BPF struct {
	// Enumerado separa "não há programa carregado" de "não perguntei". Sem
	// esse bit, um host sem eBPF e um host onde a leitura falhou têm o mesmo
	// JSON — e são coisas opostas.
	Enumerado bool `json:"enumerated"`
	// Motivo é por que não se enumerou, quando não se enumerou.
	Motivo string `json:"reason,omitempty"`
	// Lacuna diz se esse "não" conta como cobertura degradada. Nem todo não
	// conta: ver collectBPF.
	Lacuna bool `json:"gap,omitempty"`

	Programas []ProgramaBPF `json:"programs,omitempty"`
	Links     []LinkBPF     `json:"links,omitempty"`
	Pins      int           `json:"pins,omitempty"`

	// Ocultos são ids CITADOS por descritor ou por pin que a enumeração não
	// devolveu — e que continuam existindo quando perguntados um a um.
	Ocultos []uint32 `json:"hidden_ids,omitempty"`

	// Cortado marca que algum teto foi atingido: a lista não é o total.
	Cortado bool `json:"truncated,omitempty"`
}

// SemDonoVisivel diz que nenhum dos detentores legíveis apareceu.
func (p ProgramaBPF) SemDonoVisivel() bool {
	return len(p.Donos) == 0 && len(p.Pins) == 0 && len(p.Anexos) == 0 && !p.TailCall
}

// maxPins limita a varredura do bpffs. Um host com cilium tem centenas de pins
// em subdiretórios; o teto existe para o caso patológico e é declarado quando
// bate.
const maxPins = 2048

func collectBPF(f *Facts, e *env.Env) {
	if !e.Has(env.CapBPF) {
		// Três "não" diferentes, e só um deles é lacuna de cobertura. A
		// distinção é a mesma que o coletor de ftrace já faz, e pelo mesmo
		// motivo — tratar todos igual deixaria TODA varredura em contêiner
		// permanentemente degradada, e com isso morreria a única forma que a
		// suíte tem de afirmar "contêiner limpo sai OK".
		//
		//	sem mecanismo   kernel sem bpf(2), ou imagem montada: não há o que
		//	                enumerar, e implante em eBPF é impossível ali
		//	em contêiner    o kernel é do HOST. Daqui não se enxerga o eBPF dele
		//	                pelo mesmo motivo que não se enxerga o ftrace dele, e
		//	                o risco que sobra é o que os checks de visão cruzada
		//	                já declaram
		//	o resto         falta privilégio, ou o kernel carrega programa e não
		//	                sabe listar (< 4.13). São lacunas de verdade
		f.BPF.Motivo = e.Reason(env.CapBPF)
		switch {
		case e.BPFSemMecanismo, f.Host.EmContainer:
		default:
			f.BPF.Lacuna = true
			f.partial("bpf", f.BPF.Motivo)
		}
		return
	}

	progs, cortou, err := kbpf.Programas()
	if err != nil {
		f.partial("bpf", "enumeração de programas eBPF falhou: "+err.Error())
		return
	}
	f.BPF.Enumerado = true
	f.BPF.Cortado = cortou

	porID := map[uint32]*ProgramaBPF{}
	for _, p := range progs {
		pr := ProgramaBPF{
			ID: p.ID, TipoNum: p.TipoNum, Tipo: p.Tipo, Nome: p.Nome,
			Tag: p.Tag, UID: p.UID, Mapas: p.NumMaps, Instrucoes: p.Insns,
			CarregadoUTC: quandoCarregou(f, p.CargaNS),
		}
		f.BPF.Programas = append(f.BPF.Programas, pr)
	}
	for i := range f.BPF.Programas {
		porID[f.BPF.Programas[i].ID] = &f.BPF.Programas[i]
	}

	citados := map[uint32]bool{}
	linksBPF(f, porID, citados)
	donosPorDescritor(f, porID, citados)
	pinsDoBpffs(f, porID, citados)
	// O QUINTO detentor: tc e XDP prendem o programa a uma INTERFACE, e quem
	// sabe disso é o rtnetlink — não a bpf(2). Sem ele, todo programa de rede
	// aparecia como "sem dono visível" e virava lacuna; num nó com cilium isso
	// é a maioria deles, e lacuna desse tamanho é indistinguível de não olhar.
	anexosDeRede(f, e, porID, citados)
	// O QUINTO detentor: programa preso a um CGROUP. Quem sabe é o próprio
	// kernel, por um FD do diretório do cgroup. Fecha o gap que o FixCgroup
	// declarava, e os IDs vistos aqui entram na lista de citados — um programa
	// que o kernel nega ter e um cgroup afirma segurar é a forma do bpf_hidden.
	anexosDeCgroup(f, porID, citados)
	tailCalls(f)

	f.BPF.Ocultos = confirmarOcultosBPF(citados, porID)

	sort.Slice(f.BPF.Programas, func(i, j int) bool {
		return f.BPF.Programas[i].ID < f.BPF.Programas[j].ID
	})
}

// anexosDeRede resolve os anexos que vivem numa INTERFACE: o XDP da placa e o
// filtro de tc.
//
// O que ele acrescenta não é só o nome do detentor. Um programa CITADO por um
// anexo e ausente da enumeração da bpf(2) é a mesma forma do PID oculto — uma
// interface do kernel entrega um objeto que a outra nega —, e por isso os ids
// vistos aqui entram na lista de citados.
func anexosDeRede(f *Facts, e *env.Env, porID map[uint32]*ProgramaBPF, citados map[uint32]bool) {
	if !e.Has(env.CapNetlink) {
		f.partial("bpf", "anexo de tc e de XDP NÃO foi lido ("+e.Reason(env.CapNetlink)+
			"): programa de rede sem dono visível continua sem atribuição")
		return
	}
	c, err := netlink.Abrir(syscall.NETLINK_ROUTE)
	if err != nil {
		f.partial("bpf", "rtnetlink indisponível ("+err.Error()+"): anexo de tc e "+
			"de XDP não foi lido")
		return
	}
	defer c.Fechar()

	ifaces, err := netlink.Interfaces(c)
	if err != nil {
		f.partial("bpf", "enumeração de interfaces por netlink falhou ("+err.Error()+
			"): anexo de tc e de XDP não foi lido")
		return
	}
	anotar := func(id uint32, onde string) {
		if id == 0 {
			return
		}
		citados[id] = true
		if p := porID[id]; p != nil {
			p.Anexos = append(p.Anexos, onde)
		}
	}
	var semFiltro int
	for _, i := range ifaces {
		anotar(i.XDPProgID, "xdp em "+i.Nome)
		filtros, err := netlink.FiltrosBPF(c, i)
		if err != nil {
			semFiltro++
			continue
		}
		for _, ft := range filtros {
			onde := "tc " + ft.Direcao + " em " + ft.Interface
			if ft.Nome != "" {
				onde += " (" + ft.Nome + ")"
			}
			anotar(ft.ProgID, onde)
		}
	}
	if semFiltro > 0 {
		f.partial("bpf", strconv.Itoa(semFiltro)+" interface(s) com filtro de tc "+
			"ilegível: programa preso nelas não pôde ser atribuído")
	}

	// A AÇÃO de tc (act_bpf): programa preso numa ação, não num filtro. É
	// enumerada por RTM_GETACTION, que pega inclusive a ação standalone que
	// nenhum filtro referencia ainda.
	acoes, err := netlink.AcoesBPF(c)
	if err != nil {
		f.partial("bpf", "ações de tc (act_bpf) não puderam ser lidas ("+err.Error()+
			"): programa preso numa AÇÃO não pôde ser atribuído")
		return
	}
	for _, ac := range acoes {
		onde := "act_bpf"
		if ac.Nome != "" {
			onde += " (" + ac.Nome + ")"
		}
		anotar(ac.ProgID, onde)
	}
}

// Tetos da varredura de cgroup. A árvore INTEIRA é percorrida — limitar por
// "topo + slices conhecidos" viraria regra de evasão documentada: bastaria
// anexar fora dos caminhos vigiados. Os slices conhecidos só decidem a ORDEM,
// para que o corte por orçamento caia nas folhas genéricas, não neles.
const (
	maxCgroups     = 16384
	maxCgroupDepth = 64
	prazoCgroup    = 5 * time.Second
)

// slicesPrioritarios são visitados PRIMEIRO em cada nível: é onde anexo de
// cgroup de fato mora (systemd põe device/skb no nível de slice; runtimes de
// contêiner, nos seus troncos). Prioridade de travessia, não fronteira.
var slicesPrioritarios = []string{
	"system.slice", "user.slice", "init.scope", "machine.slice",
	"kubepods", "docker", "libpod", "containerd", "crio", "buildkit",
}

func cgroupPrioritario(nome string) bool {
	for _, sl := range slicesPrioritarios {
		if strings.HasPrefix(nome, sl) {
			return true
		}
	}
	return false
}

// percorrerCgroups faz BFS da árvore, prioritários primeiro em cada nível. O
// teto de quantidade corta a cauda; o de profundidade é fusível contra árvore
// patológica. Devolve os caminhos, e se cada teto foi atingido — cada um é uma
// lacuna diferente.
func percorrerCgroups(raiz string, teto int) (paths []string, cortouTeto, cortouFundo bool) {
	type no struct {
		path  string
		depth int
	}
	fila := []no{{raiz, 0}}
	for len(fila) > 0 {
		if len(paths) >= teto {
			cortouTeto = true
			break
		}
		cur := fila[0]
		fila = fila[1:]
		paths = append(paths, cur.path)
		if cur.depth >= maxCgroupDepth {
			cortouFundo = true
			continue
		}
		ents, err := os.ReadDir(cur.path)
		if err != nil {
			continue
		}
		var filhos []string
		for _, ent := range ents {
			if ent.IsDir() {
				filhos = append(filhos, ent.Name())
			}
		}
		sort.SliceStable(filhos, func(i, j int) bool {
			pi, pj := cgroupPrioritario(filhos[i]), cgroupPrioritario(filhos[j])
			if pi != pj {
				return pi
			}
			return filhos[i] < filhos[j]
		})
		for _, nome := range filhos {
			fila = append(fila, no{cur.path + "/" + nome, cur.depth + 1})
		}
	}
	return
}

// anexosDeCgroup pergunta ao kernel, por FD de cada cgroup, quais programas
// estão ANEXADOS ali (não os efetivos: attached é o ponto real de anexação, e a
// herança se reconstrói porque a árvore inteira é percorrida).
func anexosDeCgroup(f *Facts, porID map[uint32]*ProgramaBPF, citados map[uint32]bool) {
	const base = "/sys/fs/cgroup"
	// cgroup.controllers só existe na raiz de uma hierarquia v2. Sem ele, ou é
	// v1 (outra interface, que esta ferramenta não lê) ou não está montado.
	if _, err := os.Stat(base + "/cgroup.controllers"); err != nil {
		f.partial("bpf", "cgroup v2 não encontrado em /sys/fs/cgroup: anexo BPF de "+
			"cgroup NÃO foi lido (cgroup v1 usa outra interface)")
		return
	}

	paths, cortouTeto, cortouFundo := percorrerCgroups(base, maxCgroups)
	prazo := time.Now().Add(prazoCgroup)
	var consultados, semTempo int
	for i, p := range paths {
		if time.Now().After(prazo) {
			semTempo = len(paths) - i
			break
		}
		fd, err := os.Open(p)
		if err != nil {
			continue // cgroup que sumiu ou sem permissão de abrir: segue
		}
		porTipo, _ := kbpf.AnexosDeCgroup(int(fd.Fd()), kbpf.TiposDeCgroup)
		fd.Close()
		consultados++
		rel := strings.TrimPrefix(p, base)
		if rel == "" {
			rel = "/"
		}
		for at, ids := range porTipo {
			for _, id := range ids {
				citados[id] = true
				if pr := porID[id]; pr != nil {
					pr.Anexos = append(pr.Anexos, "cgroup "+kbpf.NomeDeAnexo(at)+" em "+rel)
				}
			}
		}
	}
	if cortouTeto {
		f.partial("bpf", strconv.Itoa(consultados)+" cgroups consultados; o teto de "+
			strconv.Itoa(maxCgroups)+" foi atingido e os demais NÃO foram avaliados "+
			"para anexo BPF")
	}
	if cortouFundo {
		f.partial("bpf", "árvore de cgroup mais funda que "+strconv.Itoa(maxCgroupDepth)+
			" níveis: os cgroups abaixo NÃO foram descidos")
	}
	if semTempo > 0 {
		f.partial("bpf", strconv.Itoa(semTempo)+" cgroups NÃO foram consultados: o "+
			"prazo de "+strconv.Itoa(int(prazoCgroup/time.Second))+"s da varredura de "+
			"cgroup esgotou")
	}
}

// quandoCarregou traduz o relógio de boot para UTC.// quandoCarregou traduz o relógio de boot para UTC. Sem boot conhecido a
// resposta é vazia: uma data errada aqui apontaria a investigação para o dia
// errado.
func quandoCarregou(f *Facts, ns uint64) string {
	if f.Host.bootTime.IsZero() || ns == 0 {
		return ""
	}
	return f.Host.bootTime.Add(time.Duration(ns)).UTC().Format(time.RFC3339)
}

func linksBPF(f *Facts, porID map[uint32]*ProgramaBPF, citados map[uint32]bool) {
	links, cortou, err := kbpf.Links()
	if err != nil {
		// Kernel anterior ao 5.8 não tem link nenhum. Não é lacuna de leitura:
		// é ausência do mecanismo, e o programa de lá é segurado por descritor
		// ou por anexo legado. Declarar mesmo assim, porque muda o significado
		// de "sem anexo".
		f.partial("bpf", "este kernel não enumera link de eBPF (anterior ao 5.8): "+
			"o ponto de anexação de cada programa não foi lido")
		return
	}
	f.BPF.Cortado = f.BPF.Cortado || cortou
	for _, l := range links {
		f.BPF.Links = append(f.BPF.Links, LinkBPF{
			ID: l.ID, Tipo: l.Tipo, ProgID: l.ProgID, Alvo: l.Alvo,
		})
		citados[l.ProgID] = true
		if p := porID[l.ProgID]; p != nil {
			p.Anexos = append(p.Anexos, strings.TrimSpace(l.Tipo+" "+l.Alvo))
		}
	}
}

// donosPorDescritor liga programa a PROCESSO. É o dado que transforma
// "programa 47 carregado" em "o agente de observabilidade carregou e segura".
//
// Duas rotas, e a segunda existe por causa de um falso positivo previsível:
//
//	anon_inode:bpf-*        fdinfo cita prog_id/link_id direto
//	anon_inode:[perf_event] fdinfo NÃO cita nada, e o programa parece órfão.
//	                        BPF_TASK_FD_QUERY pergunta ao kernel, e é o
//	                        caminho de todo bpftrace com libbpf antiga
func donosPorDescritor(f *Facts, porID map[uint32]*ProgramaBPF, citados map[uint32]bool) {
	linkParaProg := map[uint32]uint32{}
	for _, l := range f.BPF.Links {
		linkParaProg[l.ID] = l.ProgID
	}

	for i := range f.Processes {
		p := &f.Processes[i]
		for _, fd := range p.FDs {
			switch {
			case strings.HasPrefix(fd.Target, "anon_inode:bpf-"):
				prog, link := idsDoFdinfo(p.PID, fd.N)
				if link != 0 {
					if pid, ok := linkParaProg[link]; ok {
						prog = pid
					}
				}
				if prog == 0 {
					continue
				}
				citados[prog] = true
				anexaDono(porID, prog, DonoBPF{
					PID: p.PID, Comm: p.Comm,
					Como: "descritor aberto (" + strings.TrimPrefix(fd.Target, "anon_inode:") + ")",
				})
			case fd.Target == "anon_inode:[perf_event]":
				prog, tipo, nome := kbpf.SondaDoDescritor(p.PID, fd.N)
				if prog == 0 {
					continue
				}
				citados[prog] = true
				como := "perf_event " + tipo
				if nome != "" {
					como += " em " + nome
				}
				anexaDono(porID, prog, DonoBPF{PID: p.PID, Comm: p.Comm, Como: como})
			}
		}
	}
}

func anexaDono(porID map[uint32]*ProgramaBPF, id uint32, d DonoBPF) {
	p := porID[id]
	if p == nil {
		return // citado e não enumerado: vira candidato a oculto
	}
	for _, j := range p.Donos {
		if j.PID == d.PID && j.Como == d.Como {
			return // o mesmo descritor duplicado por dup2 não é outro dono
		}
	}
	p.Donos = append(p.Donos, d)
}

// idsDoFdinfo lê o que o kernel escreve sobre um descritor de objeto bpf:
//
//	prog_type: 1
//	prog_id:   47
//
// e, para um link:
//
//	link_type: tracing
//	link_id:   3
//	prog_id:   47
func idsDoFdinfo(pid, fd int) (prog, link uint32) {
	b, err := os.ReadFile(procPath(pid, "fdinfo/"+strconv.Itoa(fd)))
	if err != nil {
		return 0, 0
	}
	return idsDoTextoFdinfo(string(b))
}

// idsDoTextoFdinfo é a decisão separada da leitura, pelo mesmo motivo de
// DiferencaDeModulos: o formato é do kernel e precisa de teste, e o teste não
// pode depender de haver um programa eBPF carregado na máquina que roda a suíte.
func idsDoTextoFdinfo(texto string) (prog, link uint32) {
	for _, ln := range strings.Split(texto, "\n") {
		chave, valor, ok := strings.Cut(ln, ":")
		if !ok {
			continue
		}
		n, err := strconv.ParseUint(strings.TrimSpace(valor), 10, 32)
		if err != nil {
			continue
		}
		switch strings.TrimSpace(chave) {
		case "prog_id":
			prog = uint32(n)
		case "link_id":
			link = uint32(n)
		}
	}
	return prog, link
}

// citadosNaoEnumerados é a metade PURA da visão cruzada: quem foi citado por
// alguém e não apareceu na lista. A outra metade — confirmar que ainda existe —
// depende do kernel e não cabe em teste unitário.
func citadosNaoEnumerados(citados map[uint32]bool, enumerados map[uint32]bool) []uint32 {
	var out []uint32
	for id := range citados {
		if id != 0 && !enumerados[id] {
			out = append(out, id)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// pinsDoBpffs percorre os pontos de montagem do tipo bpf. O pin é o mecanismo
// que faz um programa sobreviver à saída de quem o carregou de forma
// DECLARADA — tem caminho, tem dono, tem data.
func pinsDoBpffs(f *Facts, porID map[uint32]*ProgramaBPF, citados map[uint32]bool) {
	var raizes []string
	for _, m := range f.Mounts {
		if m.Tipo == "bpf" {
			raizes = append(raizes, m.Ponto)
		}
	}
	if len(raizes) == 0 {
		return // bpffs não montado: não há pin para achar, e isso é comum
	}

	vistos := 0
	for _, raiz := range raizes {
		err := filepath.WalkDir(raiz, func(caminho string, d os.DirEntry, err error) error {
			if err != nil {
				return nil // diretório ilegível: segue
			}
			if d.IsDir() {
				return nil
			}
			if vistos >= maxPins {
				f.BPF.Cortado = true
				return filepath.SkipAll
			}
			vistos++
			f.BPF.Pins++
			obj, err := kbpf.ObjetoDoPin(caminho)
			if err != nil || obj.Classe != "prog" {
				return nil
			}
			citados[obj.ID] = true
			if p := porID[obj.ID]; p != nil {
				p.Pins = append(p.Pins, caminho)
			}
			return nil
		})
		if err != nil {
			f.partial("bpf", "bpffs em "+raiz+" não pôde ser percorrido: "+err.Error())
		}
	}
}

// tailCalls marca quem é alcançado por prog_array. Sem esta leitura, todo
// programa encadeado por tail call — que é como cilium organiza o datapath —
// apareceria sem dono.
func tailCalls(f *Facts) {
	alcancados, cortou, err := kbpf.ProgsPorTailCall()
	if err != nil {
		f.partial("bpf", "os mapas do tipo prog_array não puderam ser lidos ("+
			err.Error()+"): programa alcançado por TAIL CALL pode aparecer sem dono")
		return
	}
	f.BPF.Cortado = f.BPF.Cortado || cortou
	for i := range f.BPF.Programas {
		if alcancados[f.BPF.Programas[i].ID] {
			f.BPF.Programas[i].TailCall = true
		}
	}
}

// confirmarOcultosBPF é a visão cruzada deste subsistema.
//
// Um id citado por descritor de processo, por pin ou por link e AUSENTE da
// enumeração significa uma de três coisas, e as duas primeiras são rotina:
//
//	nasceu depois     o programa foi carregado entre a enumeração e a leitura
//	morreu no meio    o carregador terminou
//	NÃO É LISTADO     existe quando perguntado pelo id e some quando se pede a
//	                  lista — que é a assinatura de ocultação, a mesma forma do
//	                  PID que responde a stat e não aparece no readdir
//
// As duas primeiras são descartadas do jeito mais barato possível: reenumerar
// (quem nasceu no meio aparece agora) e perguntar pelo id (quem morreu não
// responde). O que sobreviver às duas é a terceira.
func confirmarOcultosBPF(citados map[uint32]bool, porID map[uint32]*ProgramaBPF) []uint32 {
	enumerados := make(map[uint32]bool, len(porID))
	for id := range porID {
		enumerados[id] = true
	}
	suspeitos := citadosNaoEnumerados(citados, enumerados)
	if len(suspeitos) == 0 {
		return nil
	}

	segunda, _, err := kbpf.IDsDePrograma()
	if err != nil {
		// Sem a segunda enumeração não há confirmação, e acusar sem ela seria
		// pior que não acusar.
		return nil
	}
	agora := map[uint32]bool{}
	for _, id := range segunda {
		agora[id] = true
	}

	var out []uint32
	for _, id := range suspeitos {
		if agora[id] {
			continue // nasceu entre as duas leituras
		}
		if !kbpf.Existe(id) {
			continue // morreu: era efêmero, não oculto
		}
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
