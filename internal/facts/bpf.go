package facts

import (
	"errors"
	"io/fs"
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
	// UIDDesconhecido diz que o kernel NÃO preencheu created_by_uid — o campo
	// entrou no bpf_prog_info no 4.14, e num 4.13 a struct tem 40 bytes e para
	// antes dele. O leitor com bounds-check já devolvia 0 corretamente para
	// "não presente", e o zero era serializado e impresso como fato: a
	// evidência do achado dizia "carregado por uid 0", atribuindo a carga ao
	// ROOT num kernel que nunca disse quem carregou. Campo ausente virando zero
	// virando afirmação — a forma exata do erro que esta ferramenta existe para
	// não cometer.
	UIDDesconhecido bool `json:"created_by_uid_unknown,omitempty"`
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

	// OcultosConfirmados é uma ASSERÇÃO POSITIVA: a confirmação de duas passadas
	// (reenumerar + perguntar id a id, AMBAS completas) rodou até o fim. Sem ela,
	// Ocultos não pode virar acusação.
	//
	// Existe por causa do replay. O bug de truncamento — Ocultos preenchido a
	// partir de uma enumeração já cortada — foi corrigido em CÓDIGO, sem mudar o
	// esquema do dump. Um retrato tirado pelo binário bugado (mesmo schema 1)
	// atravessa o loader e traz Ocultos falso. Como Ocultos e Cortado estão
	// dessincronizados (Cortado pode ser ligado DEPOIS, por corte de link/pin,
	// sobre um Ocultos legítimo de enumeração completa), "ignora Ocultos se
	// Cortado" suprimiria achado real. A asserção positiva resolve os dois: o
	// dump antigo não a tem (vira false no unmarshal), então seu Ocultos é
	// desconfiado; o dump novo com corte tardio de link a mantém, e o achado
	// legítimo sobrevive. É o "não olhei ≠ não há" na dimensão do tempo.
	OcultosConfirmados bool `json:"hidden_confirmed,omitempty"`

	// Cortado marca que algum teto foi atingido: a lista não é o total.
	Cortado bool `json:"truncated,omitempty"`
	// ProgramasCortado é o corte ESPECÍFICO da enumeração de programas —
	// distinto do agregado Cortado (que também liga por corte de link/pin/tail
	// call). As duas rotas do bpf_hidden dependem só da lista de PROGRAMAS estar
	// completa; usar o agregado suprimia contradição de trampolim por um corte
	// de OUTRO subsistema.
	ProgramasCortado bool `json:"programs_truncated,omitempty"`
	// CoberturaAnexo diz se a busca pelo ponto de ANEXAÇÃO foi completa, por
	// mecanismo. É o que separa duas afirmações muito diferentes sobre um
	// programa sem dono visível:
	//
	//	"não achei onde ele está preso"          — pode ser cegueira minha
	//	"procurei em todo lugar e não há"        — é anomalia
	//
	// Sem isto, todo programa de cgroup e de rede era contado como NÃO
	// ATRIBUÍVEL por natureza, e o trabalho de ler tc, XDP, act_bpf e
	// BPF_PROG_QUERY só servia para nomear o detentor quando ele existia —
	// nunca para concluir a ausência dele.
	CoberturaAnexo CoberturaDeAnexo `json:"attach_coverage"`
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
	f.BPF.ProgramasCortado = cortou
	// A completude da lista de PROGRAMAS, capturada aqui — antes que links, pins
	// e tail calls façam OR em f.BPF.Cortado. A confirmação de programa oculto
	// depende SÓ de a enumeração de programas ter sido completa: um corte na
	// leitura de links ou pins não torna "citado e não listado" inconclusivo,
	// porque a lista de programas continua total. Usar o Cortado agregado
	// cancelava a confirmação por um corte de OUTRO subsistema — cobertura
	// degradada à toa (seguro, mas desnecessário).
	programasCompleta := !cortou

	porID := map[uint32]*ProgramaBPF{}
	for _, p := range progs {
		pr := ProgramaBPF{
			ID: p.ID, TipoNum: p.TipoNum, Tipo: p.Tipo, Nome: p.Nome,
			Tag: p.Tag, UID: p.UID, Mapas: p.NumMaps, Instrucoes: p.Insns,
			CarregadoUTC: quandoCarregou(f, p.CargaNS),
			// O kbpf já mede quanto o kernel preencheu; até aqui ninguém lia.
			UIDDesconhecido: p.SemDados,
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
	// A leitura por rtnetlink acima roda no netns da PRÓPRIA aletheia. O que
	// ficou de fora — filtro de tc/XDP legado preso numa interface DENTRO de
	// outro netns — é declarado, nunca lido por setns (mover o netns do processo
	// corromperia a visão de rede de tudo).
	lacunaDeNetns(f, e)
	// O QUINTO detentor: programa preso a um CGROUP. Quem sabe é o próprio
	// kernel, por um FD do diretório do cgroup. Fecha o gap que o FixCgroup
	// declarava, e os IDs vistos aqui entram na lista de citados — um programa
	// que o kernel nega ter e um cgroup afirma segurar é a forma do bpf_hidden.
	anexosDeCgroup(f, porID, citados)
	tailCalls(f)

	f.BPF.Ocultos = confirmarOcultosBPF(f, citados, porID, programasCompleta)

	sort.Slice(f.BPF.Programas, func(i, j int) bool {
		return f.BPF.Programas[i].ID < f.BPF.Programas[j].ID
	})
}

// CoberturaDeAnexo registra, por mecanismo, se a enumeração de anexos terminou
// SEM buraco. Só um `true` autoriza concluir que um programa daquele mecanismo
// está sem explicação; qualquer buraco devolve a resposta para "não pude olhar".
type CoberturaDeAnexo struct {
	// Netlink cobre tc (cls_bpf e act_bpf) e XDP. Fica falso quando falta a
	// capacidade, quando o rtnetlink não abre, quando a enumeração de
	// interfaces falha, ou quando alguma interface não pôde ser consultada.
	Netlink bool `json:"netlink"`
	// Cgroup cobre a árvore de cgroup v2 por BPF_PROG_QUERY. Fica falso quando
	// a hierarquia não é v2, e quando teto, profundidade, prazo, listagem ou
	// abertura deixaram qualquer cgroup para trás.
	Cgroup bool `json:"cgroup"`
	// NetnsGap continua sendo verdade mesmo com Netlink completo: a ferramenta
	// não entra em outro namespace de rede, e um filtro preso a uma interface
	// DENTRO de um netns de contêiner não é lido. É lacuna DECLARADA, não
	// resolvida — e por isso ela não derruba Netlink, ela acompanha.
	NetnsGap bool `json:"netns_gap"`
}

// anexosDeRede resolve os anexos que vivem numa INTERFACE: o XDP da placa e o
// filtro de tc.
//
// O que ele acrescenta não é só o nome do detentor. Um programa CITADO por um
// anexo e ausente da enumeração da bpf(2) é a mesma forma do PID oculto — uma
// interface do kernel entrega um objeto que a outra nega —, e por isso os ids
// vistos aqui entram na lista de citados.
func anexosDeRede(f *Facts, e *env.Env, porID map[uint32]*ProgramaBPF, citados map[uint32]bool) {
	// CapRtnetlink, e não CapNetlink: tc e XDP saem do NETLINK_ROUTE, que não
	// depende dos módulos de diagnóstico de socket. Enquanto isto olhava a
	// capacidade errada, todo host sem inet_diag carregado perdia tc e XDP e
	// recebia, como motivo, uma frase sobre autoload de sock_diag.
	if !e.Has(env.CapRtnetlink) {
		f.partial("bpf", "anexo de tc e de XDP NÃO foi lido ("+e.Reason(env.CapRtnetlink)+
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
	// Cobertura COMPLETA: capacidade presente, rtnetlink aberto, interfaces
	// enumeradas, nenhum filtro ilegível e as ações lidas. Só com todos esses
	// "sim" um programa de rede sem anexo pode ser AFIRMADO sem explicação —
	// qualquer um dos `return` acima deixa a cobertura falsa, que é o mesmo que
	// dizer "não pude olhar".
	if semFiltro == 0 {
		f.BPF.CoberturaAnexo.Netlink = true
	}
	for _, ac := range acoes {
		onde := "act_bpf"
		if ac.Nome != "" {
			onde += " (" + ac.Nome + ")"
		}
		anotar(ac.ProgID, onde)
	}
}

// lacunaDeNetns declara o que a atribuição por rtnetlink NÃO alcança.
//
// Interfaces(), FiltrosBPF() e AcoesBPF() rodam no netns da própria aletheia. Um
// filtro de tc/XDP ou uma ação act_bpf presa a uma interface DENTRO de outro
// netns — o de um contêiner — não aparece nessas consultas. Ler esses anexos
// exigiria entrar no netns (setns), que em Go moveria a thread e corromperia a
// visão de rede do processo inteiro: a escolha é declarar, não arriscar o host.
//
// Anexo por bpf_link é AGNÓSTICO a netns (o link tem id global) e já foi coberto
// por linksBPF — a lacuna é só dos anexos LEGADOS, os que só o rtnetlink do
// próprio netns enxerga.
//
// Só declara quando há OUTRO netns (contêiner) e as consultas de rede de fato
// rodaram (CapRtnetlink). Num host de um netns só — o comum — não há o que anunciar.
func lacunaDeNetns(f *Facts, e *env.Env) {
	if !e.Has(env.CapRtnetlink) || !e.Has(env.CapProcfs) {
		return
	}
	meu, ok := inodeDeNS("/proc/self/ns/net")
	if !ok {
		return
	}
	pids, err := e.ReadDirNamesErr("/proc")
	if err != nil {
		return // não listar /proc já é lacuna do coletor de proc; não duplica aqui
	}
	outros := map[uint64]bool{}
	for _, pid := range pids {
		if _, err := strconv.Atoi(pid); err != nil {
			continue
		}
		// ns/net ilegível (processo de outro usuário sem privilégio) é pulado: o
		// que importa é se ALGUM outro netns aparece, não enumerar todos.
		if ino, ok := inodeDeNS("/proc/" + pid + "/ns/net"); ok && ino != meu {
			outros[ino] = true
		}
	}
	if len(outros) == 0 {
		return // um netns só: não há nada fora do alcance do rtnetlink daqui
	}
	// A lacuna existe SÓ quando existe outro netns. Marcá-la incondicionalmente
	// fazia todo host — inclusive um sem contêiner nenhum — carregar uma
	// ressalva sobre namespace que não existe, e, pior, tornava impossível
	// distinguir "não há onde procurar" de "há e não procurei".
	f.BPF.CoberturaAnexo.NetnsGap = true
	f.partial("bpf", strconv.Itoa(len(outros))+" outro(s) network namespace(s) presente(s) "+
		"(contêiner): filtro de tc/XDP e ação act_bpf presos por rtnetlink DENTRO deles NÃO "+
		"foram lidos — entrar em cada netns moveria o namespace de rede do processo, e não é "+
		"feito. Anexo por bpf_link é coberto, qualquer que seja o netns.")
}

// inodeDeNS devolve o inode de um /proc/<pid>/ns/net — a identidade do netns.
func inodeDeNS(caminho string) (uint64, bool) {
	var st syscall.Stat_t
	if err := syscall.Stat(caminho, &st); err != nil {
		return 0, false
	}
	return st.Ino, true
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
// visitar é chamado AO TIRAR o cgroup da fila, antes de descer nos filhos. É o
// que torna a varredura streaming: com a consulta acontecendo depois de a
// árvore inteira ter sido enumerada, um host com dezenas de milhares de cgroups
// gastava o prazo DESCOBRINDO caminhos e consultava quase nenhum — e a
// priorização de system.slice/kubepods/docker, que existe para o orçamento cair
// no que importa, não servia para nada, porque a prioridade decidia só a ordem
// da descoberta. Intercalando, o prazo que acaba deixa para trás o que é fundo
// e irrelevante, não o que é prioritário.
func percorrerCgroups(raiz string, teto int, prazo time.Time, visitar func(path string)) (paths []string, cortouTeto, cortouFundo, cortouPrazo bool, ilegiveis []string) {
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
		// O PRAZO cobre a travessia, não só as consultas.
		//
		// Ele começava depois daqui, e a árvore inteira — readdir por nível,
		// sort dos filhos, montagem de paths[] — rodava sem orçamento nenhum.
		// Num host com dezenas de milhares de cgroups isso significa que o teto
		// de 5s valia para a parte barata e não para a cara.
		if time.Now().After(prazo) {
			cortouPrazo = true
			break
		}
		cur := fila[0]
		fila = fila[1:]
		paths = append(paths, cur.path)
		if visitar != nil {
			visitar(cur.path)
		}
		if cur.depth >= maxCgroupDepth {
			cortouFundo = true
			continue
		}
		ents, err := os.ReadDir(cur.path)
		if err != nil {
			// ENOENT é corrida normal: cgroup morre o tempo todo, e um
			// contêiner que sumiu entre o readdir do pai e este não é lacuna.
			// EACCES/EIO são: existe subárvore que NÃO foi percorrida, e os
			// programas anexados ali não entram no inventário. Engolir os dois
			// juntos é a mesma classe de "não consegui olhar" virando "não
			// havia" que o resto do coletor já não comete.
			if !errors.Is(err, fs.ErrNotExist) {
				ilegiveis = append(ilegiveis, cur.path+" ("+env.MotivoDoErro(err)+")")
			}
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

	prazo := time.Now().Add(prazoCgroup)
	var naoAbertos []string
	var consultados, falhasDeQuery, semProgQuery int
	consultar := func(p string) {
		// FD cru com O_DIRECTORY, no idioma de syscall do resto do kbpf: o
		// BPF_PROG_QUERY só quer o descritor do diretório do cgroup. Evita o
		// finalizer do *os.File e falha cedo se o caminho não for diretório.
		fd, err := syscall.Open(p, syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
		if err != nil {
			// Mesma distinção da travessia, e pela mesma razão. Depois de um
			// readdir bem-sucedido isto é quase sempre corrida — cgroup morre o
			// tempo todo —, mas "quase sempre" não é o critério: um EACCES aqui
			// significa cgroup NÃO consultado, e os programas anexados nele
			// ficam fora do inventário sem ninguém dizer.
			if !errors.Is(err, syscall.ENOENT) {
				naoAbertos = append(naoAbertos, p+" ("+env.MotivoDoErro(err)+")")
			}
			return
		}
		porTipo, errosPorTipo, semComando := kbpf.AnexosDeCgroup(fd, kbpf.TiposDeCgroup)
		syscall.Close(fd)
		consultados++
		// Comando ausente (kernel < 4.15) não é "nada anexado": é NADA
		// PERGUNTADO. Conta como falha de query para que a cobertura caia e o
		// cobreFixacao pare de autorizar a acusação de programa sem dono.
		if semComando {
			semProgQuery++
			falhasDeQuery++
		}
		rel := strings.TrimPrefix(p, base)
		if rel == "" {
			rel = "/"
		}
		// AnexosDeCgroup já filtra EINVAL/ENOTSUPP lá dentro como "este ponto
		// não existe neste kernel", então o que sobra neste mapa é lacuna de
		// verdade — EPERM num cgroup delegado, ENOSPC quando um tipo passa do
		// teto de programas. Descartá-lo fazia um cgroup/connect4 anexado sumir
		// do inventário com o cgroup contado como consultado: ausência afirmada
		// a partir de cegueira, que é a única classe de erro que esta
		// ferramenta não pode cometer.
		falhasDeQuery += len(errosPorTipo)
		for at, err := range errosPorTipo {
			f.partial("bpf", "cgroup "+rel+": a consulta de anexo "+
				kbpf.NomeDeAnexo(at)+" falhou ("+err.Error()+"): os programas "+
				"anexados ali NÃO foram enumerados")
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

	_, cortouTeto, cortouFundo, cortouPrazo, ilegiveis := percorrerCgroups(
		base, maxCgroups, prazo, consultar)
	if cortouPrazo {
		f.partial("bpf", "a varredura de cgroup parou no prazo de "+
			strconv.Itoa(int(prazoCgroup/time.Second))+"s depois de consultar "+
			strconv.Itoa(consultados)+": os cgroups restantes NÃO tiveram os anexos "+
			"BPF enumerados")
	}
	if n := len(ilegiveis); n > 0 {
		amostra := ilegiveis
		if len(amostra) > 3 {
			amostra = amostra[:3]
		}
		f.partial("bpf", strconv.Itoa(n)+" cgroup(s) não puderam ser listados, e a "+
			"subárvore deles NÃO foi percorrida: "+strings.Join(amostra, ", "))
	}
	if n := len(naoAbertos); n > 0 {
		amostra := naoAbertos
		if len(amostra) > 3 {
			amostra = amostra[:3]
		}
		f.partial("bpf", strconv.Itoa(n)+" cgroup(s) não puderam ser abertos para "+
			"consulta de anexo: os programas anexados neles NÃO foram enumerados — "+
			strings.Join(amostra, ", "))
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
	// O comando não existe: nada foi perguntado, e isso NÃO é "nada anexado".
	//
	// BPF_PROG_QUERY é do 4.15. Antes dele o bpf(2) devolve EINVAL para o
	// comando inteiro, com a mesma cara de "este attach type não existe" — e a
	// regra por tipo engolia os 28 calada, deixando a árvore "completa" sobre
	// zero consultas bem-sucedidas.
	if semProgQuery > 0 {
		f.partial("bpf", "este kernel não tem BPF_PROG_QUERY (o comando é do 4.15): "+
			"os anexos de cgroup de "+strconv.Itoa(semProgQuery)+" cgroup(s) NÃO "+
			"foram enumerados, e a ausência de anexo NÃO pode ser afirmada a partir daqui")
	}
	// Cobertura COMPLETA da árvore: nenhum teto, nenhum prazo, nenhum cgroup
	// ilegível ou não aberto. Cada um desses é um lugar onde um anexo pode
	// estar sem que ninguém tenha olhado, e basta um para a ausência deixar de
	// ser afirmável.
	// falhasDeQuery entra na conta, e é o caso mais fácil de esquecer: o cgroup
	// foi aberto e percorrido, mas um attach type específico devolveu EPERM ou
	// ENOSPC. O Partial já dizia isso; a cobertura não sabia, então um
	// cgroup/connect4 que não pôde ser consultado deixava a árvore "completa" e
	// autorizava afirmar que o programa não estava anexado em lugar nenhum.
	f.BPF.CoberturaAnexo.Cgroup = !cortouTeto && !cortouFundo && !cortouPrazo &&
		len(ilegiveis) == 0 && len(naoAbertos) == 0 && falhasDeQuery == 0
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
		// A frase NÃO afirma versão de kernel a partir de um errno.
		//
		// A versão anterior traduzia QUALQUER falha em "anterior ao 5.8", e num
		// kernel 6.x sob perfil restrito — seccomp ou LSM negando
		// BPF_LINK_GET_NEXT_ID, EPERM em cgroup delegado — o operador lia que o
		// kernel era velho e parava de investigar. É o mesmo erro que
		// kbpf.Sonda já aprendeu a não cometer, e o comentário de lá diz por
		// quê: o errno distingue "não existe" de "não me deixaram".
		//
		// EINVAL/ENOSYS são o mecanismo ausente (o comando não existe antes do
		// 5.8); o resto é lacuna de leitura, e vai com o errno cru.
		if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOSYS) {
			f.partial("bpf", "este kernel não tem BPF_LINK_GET_NEXT_ID, ou foi "+
				"compilado sem ele ("+err.Error()+"): o ponto de anexação de cada "+
				"programa NÃO foi lido, e o programa daqui é segurado por "+
				"descritor ou por anexo legado")
		} else {
			f.partial("bpf", "a enumeração de link de eBPF falhou ("+err.Error()+
				"): o ponto de anexação de cada programa NÃO foi lido — isto NÃO "+
				"diz que o kernel não os tem")
		}
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
		// A lacuna é ACUMULADA aqui dentro, e não deduzida do erro que o
		// WalkDir devolve: o callback só retornava nil ou SkipAll, e o WalkDir
		// converte SkipAll em nil — então o f.partial que ficava depois do
		// laço era código MORTO, inalcançável em qualquer execução. Com um pin
		// ilegível (SELinux, lockdown, bpffs sob namespace restrito) o programa
		// caía em SemDonoVisivel() e virava kernel.bpf_unowned CRITICAL, com a
		// evidência "não há pin no bpffs" afirmada a partir de cegueira.
		var ilegiveis, naoLidos []string
		_ = filepath.WalkDir(raiz, func(caminho string, d os.DirEntry, err error) error {
			if err != nil {
				ilegiveis = append(ilegiveis, caminho)
				return nil
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
			if err != nil {
				// "Não pude perguntar" separado de "não é programa": fundir os
				// dois num só `continue` era o que fazia o pin ilegível
				// desaparecer como se fosse um mapa.
				naoLidos = append(naoLidos, caminho)
				return nil
			}
			if obj.Classe != "prog" {
				return nil
			}
			citados[obj.ID] = true
			if p := porID[obj.ID]; p != nil {
				p.Pins = append(p.Pins, caminho)
			}
			return nil
		})
		if n := len(ilegiveis); n > 0 {
			f.partial("bpf", strconv.Itoa(n)+" caminho(s) do bpffs em "+raiz+
				" não puderam ser percorridos ("+amostraDeCaminhos(ilegiveis)+
				"): um programa com pin ali apareceria SEM dono")
		}
		if n := len(naoLidos); n > 0 {
			f.partial("bpf", strconv.Itoa(n)+" pin(s) do bpffs em "+raiz+
				" não puderam ser lidos ("+amostraDeCaminhos(naoLidos)+
				"): o programa que eles ancoram apareceria SEM dono")
		}
	}
}

// amostraDeCaminhos resume uma lista para caber numa linha de lacuna.
func amostraDeCaminhos(cs []string) string {
	if len(cs) > 3 {
		return strings.Join(cs[:3], ", ") + ", …"
	}
	return strings.Join(cs, ", ")
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
func confirmarOcultosBPF(f *Facts, citados map[uint32]bool, porID map[uint32]*ProgramaBPF, primeiraCompleta bool) []uint32 {
	enumerados := make(map[uint32]bool, len(porID))
	for id := range porID {
		enumerados[id] = true
	}
	suspeitos := citadosNaoEnumerados(citados, enumerados)
	if len(suspeitos) == 0 {
		return nil
	}

	// "citado e não enumerado" só significa OCULTO se a enumeração foi
	// COMPLETA. Com a lista truncada no teto de 4096, um programa legítimo
	// depois do corte é citado (por um fd, um pin, um anexo) e não aparece na
	// lista — pelo teto, não por manipulação. Acusar isso é um CRÍTICO
	// irreversível fabricado a partir do próprio limite da ferramenta.
	if !primeiraCompleta {
		f.partial("bpf", "a enumeração de programas eBPF foi truncada (teto), então "+
			"'citado e não listado' NÃO pode ser distinguido de 'além do teto': a "+
			"confirmação de programa OCULTO foi suprimida")
		return nil
	}

	segunda, segundaCortou, err := kbpf.IDsDePrograma()
	if err != nil || segundaCortou {
		// Sem uma segunda enumeração COMPLETA não há confirmação: um id que não
		// aparece na segunda lista truncada pode ter ficado depois do teto.
		// Acusar sem ela seria pior que não acusar.
		f.partial("bpf", "a reconfirmação de programa eBPF oculto não pôde ser "+
			"feita (segunda enumeração incompleta): a divergência não é conclusiva")
		return nil
	}
	// Aqui as DUAS passadas completaram (primeiraCompleta acima, e a segunda não
	// cortou logo agora): a confirmação é fidedigna, seja o resultado vazio ou
	// não. É esta asserção que o check exige antes de acusar, e que um dump
	// antigo não carrega.
	if f != nil {
		f.BPF.OcultosConfirmados = true
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
