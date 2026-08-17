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
		if len(ents) != p.Threads {
			f.Cross.Threads = append(f.Cross.Threads, ThreadDiff{
				PID: p.PID, Status: p.Threads, Task: len(ents),
			})
		}
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

	if f.Cross.ProbeTeto {
		f.partial("cross", "sondagem de PID foi até "+strconv.Itoa(ate)+
			" de um pid_max de "+strconv.Itoa(f.Cross.PidMax)+
			": PID oculto acima disso NÃO foi procurado")
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

	// O sysfs usa "_" onde o /proc/modules às vezes usa "-", e lista módulos
	// embutidos no kernel que nunca aparecem em /proc/modules. Comparar sem
	// normalizar produziria dezenas de divergências falsas.
	proc := map[string]bool{}
	for _, m := range f.Cross.ModProc {
		proc[normalizaModulo(m)] = true
	}
	sys := map[string]bool{}
	for _, m := range f.Cross.ModSys {
		sys[normalizaModulo(m)] = true
	}
	// Só a direção que importa: presente no sysfs e AUSENTE do /proc/modules é
	// ruído (módulo embutido). O contrário — carregado e sem entrada no sysfs —
	// é a forma do LKM que se esconde.
	for m := range proc {
		if !sys[m] {
			f.Cross.ModDiff = append(f.Cross.ModDiff,
				m+" está em /proc/modules e NÃO em /sys/module")
		}
	}
	sort.Strings(f.Cross.ModDiff)
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
