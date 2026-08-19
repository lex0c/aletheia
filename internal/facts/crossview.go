package facts

import (
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/lex0c/aletheia/internal/env"
)

// Visões cruzadas (runbook §32, §35).
//
// A ideia é não confiar em UMA fonte. Um rootkit de userland reescreve
// `readdir()` e some com o processo da listagem de /proc — mas para esconder de
// verdade ele precisa mentir de forma CONSISTENTE em todas as interfaces, e
// isso é difícil. Onde duas fontes discordam, alguém está mentindo.
//
// Aqui tudo é NATIVO: nenhuma destas comparações chama binário do host. Isso
// importa porque o binário do host é justamente o que pode estar adulterado —
// comparar `ps` com `/proc` acrescentaria uma fonte e um risco ao mesmo tempo.
//
// O limite honesto, e ele é duro: se o KERNEL estiver comprometido, todas as
// fontes que dependem dele podem mentir juntas. Ausência de divergência não
// prova nada; presença de divergência prova muito.

const (
	// Teto da sondagem por PID. O pid_max moderno é 4194304, e sondar tudo
	// custaria segundos. Medido: 65 mil sondagens custam ~124ms.
	//
	// A faixa é escolhida pelo maior PID VISÍVEL, porque é ali que o kernel
	// está alocando: sondar de 1 a esse número mais uma margem cobre a região
	// em uso. O que ficar acima vira lacuna declarada.
	maxProbePids = 65536
	probeMargem  = 2048
)

// HiddenPid é um PID que responde a stat e NÃO aparece na listagem de /proc.
type HiddenPid struct {
	PID  int    `json:"pid"`
	Como string `json:"how"` // ppid | sondagem
	Comm string `json:"comm,omitempty"`
}

// ThreadDiff é a divergência entre o que o status declara e o que o diretório
// de threads mostra.
type ThreadDiff struct {
	PID    int `json:"pid"`
	Status int `json:"status_threads"`
	Task   int `json:"task_entries"`
}

// CrossView guarda o resultado das comparações.
type CrossView struct {
	Hidden  []HiddenPid  `json:"hidden_pids,omitempty"`
	Threads []ThreadDiff `json:"thread_diff,omitempty"`

	// ProbeAte é até onde a sondagem foi. Sem esse número, "nenhum PID oculto"
	// não tem significado.
	ProbeAte  int  `json:"probe_up_to,omitempty"`
	ProbeTeto bool `json:"probe_truncated,omitempty"`
	PidMax    int  `json:"pid_max,omitempty"`

	// Módulos vistos por cada interface do kernel.
	ModProc []string `json:"modules_proc,omitempty"`
	ModSys  []string `json:"modules_sys,omitempty"`
	ModDiff []string `json:"modules_only_in_one,omitempty"`

	// A SEGUNDA visão da tabela de conexões: NETLINK_INET_DIAG, que o kernel
	// serve por outro caminho de código que não o `tcp4_seq_show` do /proc.
	//
	// As contagens ficam aqui porque "nenhum socket oculto" sem elas não
	// significa nada: pode ser que as duas visões concordem, e pode ser que a
	// segunda não tenha sido consultada.
	SocketDiag     int  `json:"sockets_netlink,omitempty"`
	SocketProc     int  `json:"sockets_proc,omitempty"`
	SocketDiagLido bool `json:"socket_netlink_read,omitempty"`
	// SocketDiagMotivo é por que a segunda visão não existiu, quando não
	// existiu. É a frase que vai para o rodapé.
	SocketDiagMotivo  string `json:"socket_netlink_reason,omitempty"`
	SocketDiagCortado bool   `json:"socket_netlink_truncated,omitempty"`
	// SocketOcultos são os que o netlink entrega e /proc/net não — já
	// reconfirmados contra a corrida de socket recém-nascido.
	SocketOcultos []SocketOculto `json:"sockets_hidden,omitempty"`

	// A TERCEIRA interface: os módulos que o ftrace conhece por terem função
	// rastreável. Independente das outras duas — o registro do ftrace só é
	// limpo no descarregamento REAL, não quando um módulo se desencadeia da
	// lista. ModFtraceDiff é o que está anotado no ftrace e nega estar em
	// /proc/modules.
	ModFtrace     []string `json:"modules_ftrace,omitempty"`
	ModFtraceDiff []string `json:"modules_ftrace_hidden,omitempty"`
}

func collectCrossView(f *Facts, e *env.Env) {
	// "Visível" é o que a LISTAGEM devolveu, não o que conseguimos ler. Sem
	// essa distinção, todo processo alheio ilegível — a maioria, sem root —
	// seria acusado de oculto, e o check viraria 152 falsos positivos num
	// desktop comum. É a confusão entre "não achei" e "não consegui olhar",
	// desta vez dentro da própria ferramenta.
	visiveis := map[int]bool{}
	maior := 0
	for _, pid := range f.PidsListados {
		visiveis[pid] = true
		if pid > maior {
			maior = pid
		}
	}

	cruzarPPID(f, visiveis)
	cruzarThreads(f)
	sondarPids(f, visiveis, maior)
	cruzarModulos(f)
	cruzarModulosFtrace(f, e)
}

// cruzarPPID é a comparação mais barata que existe, e a mais precisa.
//
// Se um processo visível declara PPID=X e X não está na nossa lista, um stat
// resolve a ambiguidade sem corrida:
//
//	/proc/X existe      → a LISTAGEM mentiu: o pai está oculto
//	/proc/X não existe  → o pai simplesmente morreu, e o filho será reparentado
//
// Sem o stat, os dois casos seriam indistinguíveis — e o segundo é rotina.
func cruzarPPID(f *Facts, visiveis map[int]bool) {
	checado := map[int]bool{}
	for i := range f.Processes {
		ppid := f.Processes[i].PPID
		if ppid <= 1 || visiveis[ppid] || checado[ppid] {
			continue
		}
		checado[ppid] = true
		if _, err := os.Stat(procPath(ppid, "stat")); err != nil {
			continue // morreu: rotina
		}
		if tgid, ok := tgidDe(ppid); ok && tgid != ppid {
			continue // thread, não processo
		}
		h := HiddenPid{PID: ppid, Como: "ppid de processo visível"}
		if c, ok := readTrim(procPath(ppid, "comm")); ok {
			h.Comm = c
		}
		f.Cross.Hidden = append(f.Cross.Hidden, h)
	}
}

// cruzarThreads compara o que o status DECLARA com o que o diretório de threads
// MOSTRA. Esconder uma thread exige mentir nos dois, e são caminhos diferentes
// no kernel.
func cruzarThreads(f *Facts) {
	for i := range f.Processes {
		p := &f.Processes[i]
		if p.Threads <= 0 || p.Vanished {
			continue
		}
		ents, err := os.ReadDir(procPath(p.PID, "task"))
		if err != nil {
			continue // sem permissão ou morreu: não é divergência
		}
		// SÓ uma direção, e ela vem do mecanismo.
		//
		// Esconder uma thread significa sumir com a entrada do diretório: o
		// contador do status continua N, o diretório mostra N-1. A direção
		// oposta — diretório com MAIS do que o status declara — é a ordem de
		// leitura: o status foi lido antes, e uma thread nasceu no intervalo.
		if len(ents) >= p.Threads {
			continue
		}
		// E confirma antes de acusar. Uma thread que MORREU entre as duas
		// leituras produz exatamente esta forma, e runtime com pool de threads
		// (Go, JVM, Node) faz isso o tempo todo — o helper desta suíte gerou o
		// falso positivo que trouxe esta releitura.
		//
		// A diferença é que ocultação PERSISTE e corrida não: reler os dois na
		// ordem inversa custa duas leituras num caso raro e elimina a classe
		// inteira.
		ents2, err := os.ReadDir(procPath(p.PID, "task"))
		if err != nil {
			continue
		}
		st2, ok := threadsDe(p.PID)
		if !ok || len(ents2) >= st2 {
			continue
		}
		f.Cross.Threads = append(f.Cross.Threads, ThreadDiff{
			PID: p.PID, Status: st2, Task: len(ents2),
		})
	}
}

// sondarPids procura o que a listagem não mostra: PID que responde a stat sem
// aparecer no readdir. É a técnica do `unhide` (runbook §32), nativa.
func sondarPids(f *Facts, visiveis map[int]bool, maior int) {
	if s, ok := readTrim("/proc/sys/kernel/pid_max"); ok {
		f.Cross.PidMax, _ = strconv.Atoi(s)
	}

	ate := maior + probeMargem
	if ate > maxProbePids {
		ate = maxProbePids
		f.Cross.ProbeTeto = true
	}
	if f.Cross.PidMax > 0 && ate > f.Cross.PidMax {
		ate = f.Cross.PidMax
		f.Cross.ProbeTeto = false
	}
	f.Cross.ProbeAte = ate

	for pid := 1; pid <= ate; pid++ {
		if visiveis[pid] {
			continue
		}
		if _, err := os.Stat(procPath(pid, "stat")); err != nil {
			continue
		}
		// THREAD não é processo oculto.
		//
		// O procfs expõe /proc/<tid> para stat mas NÃO lista TIDs no readdir de
		// /proc — eles aparecem só em /proc/<pid>/task. Sem este filtro, toda
		// thread de todo processo vira "processo oculto": num desktop comum
		// foram 152 falsos positivos, e num contêiner de um processo só, 4.
		//
		// O que separa está no próprio status: líder de grupo tem Tgid == Pid.
		if tgid, ok := tgidDe(pid); ok && tgid != pid {
			continue
		}
		// Nasceu entre o readdir e a sondagem? O readdir foi ANTES, então um
		// processo novo aparece aqui sem ser oculto. O comm resolve pouco, mas
		// a contagem alta é o que dá sinal — e um processo novo é um, não vinte.
		h := HiddenPid{PID: pid, Como: "sondagem: responde a stat e não aparece na listagem"}
		if c, ok := readTrim(procPath(pid, "comm")); ok {
			h.Comm = c
		}
		f.Cross.Hidden = append(f.Cross.Hidden, h)
	}

	// CONFIRMA, e a confirmação precisa das DUAS metades ao mesmo tempo.
	//
	// "Oculto" significa uma coisa só: EXISTE e NÃO É LISTADO. Verificar as
	// duas em momentos diferentes deixa passar as duas corridas opostas —
	// nascer depois da listagem, e morrer depois da sondagem.
	//
	// Num guest recém-bootado as threads de kernel fazem exatamente isso: uma
	// `kworker/u2:0` nasce, responde à sondagem e morre. O kernel 3.18 acusava
	// uma a cada varredura, sempre com PID diferente — o sinal de corrida, e
	// não de ocultação.
	//
	// Relistar e reconferir a existência resolve as duas de uma vez, ao preço
	// de um readdir e de um stat por candidato.
	if len(f.Cross.Hidden) > 0 {
		f.Cross.Hidden = confirmarOcultos(f.Cross.Hidden)
	}

	// A lacuna é "há faixa não sondada", não "batemos no teto de 65536". Elas
	// não são a mesma coisa: num guest com pid_max de 4194304 e maior PID
	// visível 900, a sondagem para em 2948 sem chegar perto do teto — e nada
	// era dito sobre os outros 4,19 milhões, onde cabe um processo cujo PID foi
	// posicionado de propósito via ns_last_pid antes do fork. ProbeTeto continua
	// existindo para nomear POR QUE a faixa acabou.
	if f.Cross.PidMax > ate {
		motivo := "a sondagem para em maior_pid+" + strconv.Itoa(probeMargem)
		if f.Cross.ProbeTeto {
			motivo = "teto de " + strconv.Itoa(maxProbePids) + " sondagens"
		}
		f.partial("cross", "sondagem de PID foi até "+strconv.Itoa(ate)+
			" de um pid_max de "+strconv.Itoa(f.Cross.PidMax)+" ("+motivo+
			"): PID oculto acima disso NÃO foi procurado")
	}
	sort.Slice(f.Cross.Hidden, func(i, j int) bool {
		return f.Cross.Hidden[i].PID < f.Cross.Hidden[j].PID
	})
}

// cruzarModulos compara as duas interfaces que o kernel expõe para a MESMA
// informação. Um LKM que se remove da lista de /proc/modules costuma esquecer
// do sysfs, e vice-versa.
func cruzarModulos(f *Facts) {
	// LISTA VAZIA não é fonte ilegível.
	//
	// Um guest sem módulo carregado tem /proc/modules vazio, e isso é uma
	// resposta completa: não há nada para comparar. Tratar isso como lacuna
	// fazia toda VM mínima sair com cobertura degradada — a mesma confusão
	// entre "não há" e "não consegui ver", desta vez do lado do "não há".
	sProc, okProc := readTrim("/proc/modules")
	if okProc {
		for _, ln := range strings.Split(sProc, "\n") {
			if fs := strings.Fields(ln); len(fs) > 0 {
				f.Cross.ModProc = append(f.Cross.ModProc, fs[0])
			}
		}
	} else {
		f.partial("cross", "/proc/modules ilegível: a comparação de módulos não foi feita")
	}

	ents, errSys := os.ReadDir("/sys/module")
	if errSys == nil {
		for _, ent := range ents {
			f.Cross.ModSys = append(f.Cross.ModSys, ent.Name())
		}
	} else {
		f.partial("cross", "/sys/module ilegível: a comparação de módulos não foi feita")
	}
	if !okProc || errSys != nil || len(f.Cross.ModProc) == 0 {
		return
	}

	f.Cross.ModDiff = DiferencaDeModulos(f.Cross.ModProc, f.Cross.ModSys)
	// RECONFIRMA antes de deixar isto virar CRÍTICO — cross.module_view é
	// quebra-confiança, e invalida a cobertura inteira. As duas leituras são
	// sequenciais: um módulo legítimo carregado ou removido entre elas produz
	// divergência falsa. Relê e mantém só o que persiste nas DUAS leituras. É a
	// mesma paranoia já aplicada a hidden PID, thread e BPF.
	if len(f.Cross.ModDiff) > 0 {
		proc2, sys2, okProc, okSys := relerNomesDeModulos()
		if !okProc || !okSys {
			// Sem a segunda testemunha, a divergência é INCONCLUSIVA, não
			// confirmada: não vira CRÍTICO, e a lacuna é declarada.
			f.partial("cross", "a divergência de módulos entre /proc/modules e "+
				"/sys/module não pôde ser RECONFIRMADA (uma das interfaces ficou "+
				"ilegível na segunda leitura): não é conclusiva")
			f.Cross.ModDiff = nil
		} else {
			f.Cross.ModDiff = soPersistentes(f.Cross.ModDiff, DiferencaDeModulos(proc2, sys2))
		}
	}
}

// relerNomesDeModulos faz a segunda leitura das duas interfaces, para a
// reconfirmação. Devolve okProc/okSys PORQUE vazio e ilegível NÃO são a mesma
// coisa aqui — e a diferença é a que mais importa. Se a segunda leitura de
// /sys/module falhasse e voltasse vazia, DiferencaDeModulos(proc, vazio)
// marcaria TODO módulo como divergente, e a divergência inicial seria
// "confirmada" por uma testemunha que não pôde falar — um CRÍTICO falso que
// quebra a confiança do kernel inteiro. Quem chama descarta e declara lacuna
// quando qualquer leitura falha: sem a segunda testemunha não há prova.
func relerNomesDeModulos() (proc, sys []string, okProc, okSys bool) {
	if s, ok := readTrim("/proc/modules"); ok {
		okProc = true
		for _, ln := range strings.Split(s, "\n") {
			if fs := strings.Fields(ln); len(fs) > 0 {
				proc = append(proc, fs[0])
			}
		}
	}
	if ents, err := os.ReadDir("/sys/module"); err == nil {
		okSys = true
		for _, ent := range ents {
			sys = append(sys, ent.Name())
		}
	}
	return proc, sys, okProc, okSys
}

// soPersistentes devolve os itens de `primeira` que também estão em `segunda`.
// Como a formatação da divergência é determinística — mesmo módulo, mesma
// string —, intersectar os conjuntos de mensagens descarta a corrida sem
// precisar reparsear o nome.
func soPersistentes(primeira, segunda []string) []string {
	na2 := make(map[string]bool, len(segunda))
	for _, d := range segunda {
		na2[d] = true
	}
	var out []string
	for _, d := range primeira {
		if na2[d] {
			out = append(out, d)
		}
	}
	return out
}

// DiferencaDeModulos compara as duas listas e devolve as divergências.
//
// Está separada da leitura porque é a DECISÃO, e a leitura é do /proc de
// verdade — sem a separação, a regra que decide se um rootkit de kernel é
// acusado só podia ser exercitada bootando uma VM.
//
// Duas regras, e as duas nasceram de ruído medido:
//
//	NORMALIZAR   o sysfs usa "_" onde o /proc/modules às vezes usa "-".
//	             Comparar cru produziria dezenas de divergências falsas
//	UMA DIREÇÃO  presente no sysfs e ausente do /proc/modules é módulo
//	             EMBUTIDO no kernel, que é a maioria deles. O contrário —
//	             carregado e sem entrada no sysfs — é a forma do LKM que se
//	             esconde, e é a única que vira achado
func DiferencaDeModulos(emProc, emSys []string) []string {
	proc := map[string]bool{}
	for _, m := range emProc {
		proc[normalizaModulo(m)] = true
	}
	sys := map[string]bool{}
	for _, m := range emSys {
		sys[normalizaModulo(m)] = true
	}
	var out []string
	for m := range proc {
		if !sys[m] {
			out = append(out, m+" está em /proc/modules e NÃO em /sys/module")
		}
	}
	sort.Strings(out)
	return out
}

// tgidDe devolve o grupo de threads a que o PID pertence. Quando difere do
// próprio PID, aquilo é uma thread e não um processo.
func tgidDe(pid int) (int, bool) {
	b, err := os.ReadFile(procPath(pid, "status"))
	if err != nil {
		return 0, false
	}
	for _, ln := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(ln, "Tgid:"); ok {
			n, err := strconv.Atoi(strings.TrimSpace(v))
			return n, err == nil
		}
	}
	return 0, false
}

func normalizaModulo(s string) string { return strings.ReplaceAll(s, "-", "_") }

// threadsDe relê o contador de threads direto do status. Existe para a
// confirmação: o valor coletado no início da varredura já envelheceu.
func threadsDe(pid int) (int, bool) {
	b, err := os.ReadFile(procPath(pid, "status"))
	if err != nil {
		return 0, false
	}
	for _, ln := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(ln, "Threads:"); ok {
			n, err := strconv.Atoi(strings.TrimSpace(v))
			return n, err == nil
		}
	}
	return 0, false
}

// confirmarOcultos exige que as duas metades da definição valham JUNTAS: o
// processo continua existindo e continua fora da listagem.
//
// Descarta as duas corridas opostas — quem nasceu depois da primeira listagem
// (agora aparece nela) e quem morreu depois da sondagem (agora não existe).
func confirmarOcultos(cands []HiddenPid) []HiddenPid {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		// Sem a segunda listagem não há confirmação, e acusar sem ela seria
		// pior que não acusar: devolve vazio e o caso vira silêncio honesto.
		return nil
	}
	listado := map[int]bool{}
	for _, ent := range ents {
		if n, err := strconv.Atoi(ent.Name()); err == nil {
			listado[n] = true
		}
	}
	out := cands[:0]
	for _, h := range cands {
		if listado[h.PID] {
			continue // nasceu entre a listagem e a sondagem
		}
		if _, err := os.Stat(procPath(h.PID, "stat")); err != nil {
			continue // morreu depois da sondagem: era efêmero, não oculto
		}
		out = append(out, h)
	}
	return out
}
