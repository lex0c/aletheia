package facts

import (
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

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
	// Teto da sondagem por PROCFS, e ele continua existindo por medição: um
	// stat() em /proc/<pid>/stat custa caro e NÃO escala com CPU. Medido neste
	// host: 65 mil custam ~124ms; a faixa inteira de 4,19 milhões custa 7,8s
	// em série e 2,8s com 12 goroutines — o procfs serializa por dentro, e
	// pagar 2,8s em toda varredura para cobrir uma faixa quase toda vazia é
	// caro pelo motivo errado.
	//
	// A faixa é escolhida pelo maior PID VISÍVEL, porque é ali que o kernel
	// está alocando: de 1 até esse número mais uma margem cobre a região em uso.
	maxProbePids = 65536
	probeMargem  = 2048

	// A varredura por SINAL cobre a faixa inteira, e é ela que fecha a lacuna.
	// Medido no mesmo host: kill(2) sobre os 4,19 milhões custa 2,4s em série
	// e 420ms com 8 goroutines — 6× mais barato que o procfs porque não toca
	// o dcache.
	sondaWorkers = 8
	sondaBloco   = 1 << 16

	// Teto ARQUITETURAL do pid_max: PID_MAX_LIMIT do kernel em 64 bits.
	//
	// O valor vem de /proc/sys/kernel/pid_max, ou seja, DO HOST SOB
	// INVESTIGAÇÃO — e o modelo de ameaça desta ferramenta diz, na primeira
	// linha deste arquivo, que o host pode mentir. Sem o teto, um valor perto de
	// MaxInt32 estourava a conta de blocos num build de 386 e o make() saía com
	// tamanho negativo: pânico no coletor, scan inteiro perdido. A sondagem
	// antiga não tinha esse risco porque nunca passava de 65536.
	//
	// Acima disto não é faixa: é valor impossível, e o que fica de fora sai
	// declarado como lacuna.
	pidMaxLimite = 4 << 20

	// Teto de tempo da varredura por sinal. É um PARA-QUEDAS, não um orçamento
	// de rotina — e a diferença custou uma rodada inteira da suíte para
	// aparecer.
	//
	// A primeira versão usava 2s, que é ~5× a medição ociosa e parecia folgado.
	// Não era: rodando 12 varreduras ao mesmo tempo num host de 12 CPUs — o que
	// a própria suíte de cenários faz —, cada uma passava de 5s e TODAS saíam
	// com a lacuna declarada. O defeito não é o tempo, é o que ele produz: uma
	// cobertura que muda com a CARGA do host. Duas execuções seguidas na mesma
	// máquina davam 106/106 e 104/106, e um número que oscila assim não pode ser
	// usado para decidir nada.
	//
	// 30s é 70× a faixa inteira ao custo medido (100ns por kill), o que deixa
	// espaço para contenção pesada e ainda corta antes de virar travamento em
	// hardware patológico. Estourar continua não sendo erro: é lacuna, e ela sai
	// declarada com o número exato de até onde deu.
	sondaOrcamento = 30 * time.Second

	// Acima disto, "PID oculto" deixa de ser a explicação mais simples. Ver o
	// teto de sanidade em sondarPids.
	sondaMaxOcultos = 32
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

	// O ESTADO DE LEITURA de cada testemunha, que os coletores já conhecem e
	// que se perdia ao chegar na interface MCP.
	//
	// A regra de todo o Aletheia é "vazio ≠ ilegível": o coletor de módulos
	// guarda okProc/errSys porque `/proc/modules` lido com zero módulos e
	// `/proc/modules` negado por EACCES são fatos opostos. Mas esses bits
	// ficavam locais ao coletor, e quem lê CrossView depois só via a cardinalidade
	// — e cardinalidade zero não distingue "não havia" de "não pude ver". Uma
	// camada de apresentação que infere "fonte lida" por `len()>0` desfaz a
	// distinção que o coletor teve o cuidado de preservar. Estes campos carregam
	// o fato até lá.
	//
	// ProcListLida é o sucesso do readdir de /proc — a testemunha de BASE contra
	// a qual cada sondagem é conferida. ProcListN é a contagem no momento da
	// coleta, que PidsListados (json:"-") não leva para o dump.
	ProcListLida bool `json:"proc_list_read,omitempty"`
	ProcListN    int  `json:"proc_list_count,omitempty"`

	// ProbeAte é até onde a sondagem foi. Sem esse número, "nenhum PID oculto"
	// não tem significado.
	//
	// São DUAS testemunhas com alcances diferentes, e por isso dois números:
	// ProbeAte é o da varredura por sinal, que cobre a faixa inteira;
	// ProbeProcfsAte é o da sondagem por /proc, que continua limitada. Um
	// número só esconderia qual das duas respondeu por qual faixa.
	ProbeAte       int  `json:"probe_up_to,omitempty"`
	ProbeProcfsAte int  `json:"probe_procfs_up_to,omitempty"`
	ProbeTeto      bool `json:"probe_truncated,omitempty"`
	PidMax         int  `json:"pid_max,omitempty"`

	// Módulos vistos por cada interface do kernel.
	ModProc []string `json:"modules_proc,omitempty"`
	ModSys  []string `json:"modules_sys,omitempty"`
	ModDiff []string `json:"modules_only_in_one,omitempty"`
	// ModProcLido/ModSysLido são os okProc/errSys do coletor: uma fonte lida com
	// zero módulos NÃO é a mesma coisa que uma fonte ilegível, e sem estes bits a
	// tool confundiria as duas por len()==0.
	ModProcLido bool `json:"modules_proc_read,omitempty"`
	ModSysLido  bool `json:"modules_sys_read,omitempty"`

	// A SEGUNDA visão da tabela de conexões: NETLINK_INET_DIAG, que o kernel
	// serve por outro caminho de código que não o `tcp4_seq_show` do /proc.
	//
	// As contagens ficam aqui porque "nenhum socket oculto" sem elas não
	// significa nada: pode ser que as duas visões concordem, e pode ser que a
	// segunda não tenha sido consultada.
	SocketDiag     int  `json:"sockets_netlink,omitempty"`
	SocketProc     int  `json:"sockets_proc,omitempty"`
	SocketDiagLido bool `json:"socket_netlink_read,omitempty"`
	// A comparação de sockets é POR PROTOCOLO, e o estado de CADA um viaja —
	// não uma contagem que some qual protocolo ficou de fora.
	//
	// A cardinalidade mentia por dois caminhos. "3 de 4 protocolos comparados"
	// não diz QUAL não foi, e um socket escondido do /proc/net/udp6 passa se udp6
	// foi o que faltou. Pior: o netlink PULA o protocolo cujo handler de
	// diagnóstico não está carregado, para não autocarregá-lo — então udp/udp6
	// podem nem entrar no denominador, e "2 de 2" viraria agree com metade da
	// superfície de socket sem ninguém ter olhado. O estado por protocolo é a
	// observabilidade por FONTE que o resto do Aletheia já faz.
	//
	//	compared         netlink consultou E /proc/net leu: as duas visões
	//	                 se confrontaram
	//	proc_unreadable  netlink consultou, /proc/net deu EACCES: não confrontado
	//	diag_skipped     netlink NÃO consultou (handler de diag ausente, pulado
	//	                 para não autocarregar): o protocolo existe e não foi visto
	SocketProtos map[string]string `json:"socket_protocols,omitempty"`
	// SocketDiagMotivo é por que a segunda visão não existiu, quando não
	// existiu. É a frase que vai para o rodapé.
	SocketDiagMotivo  string `json:"socket_netlink_reason,omitempty"`
	SocketDiagCortado bool   `json:"socket_netlink_truncated,omitempty"`
	// SocketOcultos são os que o netlink entrega e /proc/net não — já
	// reconfirmados contra a corrida de socket recém-nascido.
	SocketOcultos []SocketOculto `json:"sockets_hidden,omitempty"`
	// SocketInconclusivos conta os candidatos a oculto que a reconfirmação NAO
	// resolveu — uma das quatro leituras falhou, ou a 2a enumeracao netlink foi
	// truncada e o candidato pode estar alem do teto. E o estado que o coletor
	// ja declarava por Partial, promovido a CAMPO para a tool nao responder
	// "as tabelas concordam" onde houve discrepancia que ninguem fechou.
	SocketInconclusivos int `json:"sockets_inconclusive,omitempty"`

	// A TERCEIRA interface: os módulos que o ftrace conhece por terem função
	// rastreável. Independente das outras duas — o registro do ftrace só é
	// limpo no descarregamento REAL, não quando um módulo se desencadeia da
	// lista. ModFtraceDiff é o que está anotado no ftrace e nega estar em
	// /proc/modules.
	ModFtrace     []string `json:"modules_ftrace,omitempty"`
	ModFtraceDiff []string `json:"modules_ftrace_hidden,omitempty"`
	// ModFtraceLido é se available_filter_functions foi lido. Sem root, ou num
	// contêiner sem tracing próprio, ele não é — e "nenhum módulo escondido do
	// ftrace" sem ter lido o ftrace não é afirmação.
	ModFtraceLido bool `json:"modules_ftrace_read,omitempty"`
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
	tids := cruzarThreads(f)
	sondarPids(f, e, visiveis, tids, maior)
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
//
// Devolve as TIDs que viu pelo caminho. Não é subproduto acidental: a sondagem
// por sinal precisa delas, e são o readdir que ESTE laço já paga — repetir a
// leitura lá seria pagar duas vezes pela mesma informação.
func cruzarThreads(f *Facts) map[int]bool {
	tids := map[int]bool{}
	for i := range f.Processes {
		p := &f.Processes[i]
		if p.Threads <= 0 || p.Vanished {
			continue
		}
		ents, err := os.ReadDir(procPath(p.PID, "task"))
		if err != nil {
			continue // sem permissão ou morreu: não é divergência
		}
		for _, ent := range ents {
			if n, err := strconv.Atoi(ent.Name()); err == nil {
				tids[n] = true
			}
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
	return tids
}

// sondarPids procura o que a listagem não mostra: PID que EXISTE e não aparece
// no readdir. É a técnica do `unhide` (runbook §32), nativa.
//
// # Duas testemunhas, porque uma delas é hookável
//
// A sondagem original perguntava só ao procfs (stat em /proc/<pid>/stat), e
// pagava caro por PID — o que a obrigava a parar em 65 mil. Num host com
// pid_max de 4194304 isso deixava de fora 4,13 milhões de PIDs, e não como
// detalhe: neste host de desenvolvimento o maior PID VIVO era 952504, ou seja,
// a sondagem não alcançava sequer a faixa onde os processos estavam. A lacuna
// saía declarada — honesto —, mas saía em TODA execução, e uma lacuna constante
// não informa nada: só torna `cobertura completa` inalcançável.
//
// A saída é perguntar a faixa inteira por um caminho mais barato. `kill(pid, 0)`
// não envia sinal nenhum — faz só a verificação de erro — e não passa pelo
// dcache, o que o torna 6× mais barato que o stat e paralelizável de verdade.
//
// O procfs NÃO sai de cena, e o motivo é adversarial: rootkit que esconde
// processo costuma hookar `kill()` justamente para o PID escondido não responder
// a `kill -0`, e nesse caso quem responde é o /proc. Trocar uma testemunha pela
// outra teria fechado a lacuna abrindo um ponto cego. As duas rodam, e a união
// dos candidatos é o que segue para confirmação.
//
// Fica um ponto cego nomeado: rootkit que minta nas DUAS interfaces e ponha o
// PID acima da faixa do procfs não é encontrado aqui. Isso é limite do método,
// não lacuna de execução — está nos FalsePositives do check, e não na cobertura,
// pela mesma razão que o resto: sinal constante não é sinal.
func sondarPids(f *Facts, e *env.Env, visiveis, tids map[int]bool, maior int) {
	if s, ok := readTrim("/proc/sys/kernel/pid_max"); ok {
		f.Cross.PidMax, _ = strconv.Atoi(s)
	}

	// Sem pid_max legível não dá para afirmar alcance nenhum: varre o que o
	// teto antigo cobria e DIZ que o denominador é desconhecido.
	limite := f.Cross.PidMax
	switch {
	case limite <= 0:
		limite = maxProbePids
	case limite > pidMaxLimite:
		f.partial("cross", "/proc/sys/kernel/pid_max diz "+strconv.Itoa(limite)+
			", acima do máximo que o kernel aceita ("+strconv.Itoa(pidMaxLimite)+
			"): a sondagem foi só até esse máximo, e o valor declarado pelo host "+
			"não é confiável")
		limite = pidMaxLimite
	}

	// 1) Faixa INTEIRA, por sinal.
	//
	// O conjunto a ignorar é MAIOR que a listagem: `kill(pid, 0)` responde para
	// TID exatamente como para PID, e TID não aparece no readdir de /proc. Sem
	// as threads aqui, toda thread do host vira candidata e paga um
	// /proc/<tid>/status no filtro lá embaixo — medido neste desktop, 10s a mais
	// numa varredura de 1m44. As TIDs vêm do cruzarThreads, que já as leu.
	conhecidos := visiveis
	if len(tids) > 0 {
		conhecidos = make(map[int]bool, len(visiveis)+len(tids))
		for pid := range visiveis {
			conhecidos[pid] = true
		}
		for tid := range tids {
			conhecidos[tid] = true
		}
	}
	// A TESTEMUNHA POR SINAL SÓ VALE ONDE A LISTAGEM DE /proc É COMPLETA.
	//
	// `kill(2)` não passa pelo procfs, e é justamente isso que o torna útil —
	// mas também é isso que o torna perigoso sob hidepid=2: ali o /proc some
	// com os processos dos OUTROS usuários, enquanto o kill continua
	// respondendo EPERM para todos eles. O resultado é que todo processo do host
	// vira "existe e não está na listagem", que é a definição literal de PID
	// oculto. Medido no cenário 31-hidepid-sem-root: 56 avisos, todos falsos, e
	// o achado que importava perdido no meio.
	//
	// A FalsePositives deste check já prometia o contrário — "sob hidepid o
	// processo some das DUAS vias, e o que degrada é a cobertura, não a
	// comparação". Sob hidepid sem root, então, a promessa é cumprida do jeito
	// antigo: só a perna do procfs sonda, e a faixa que ficou de fora é lacuna.
	var cand map[int]string
	var ate int
	cabe := sondaCabeNoComando(e)
	usouSinal := cabe && sinalEhTestemunha(f, e)
	switch {
	case usouSinal:
		cand, ate = varrerPorSinal(limite, conhecidos, time.Now().Add(sondaOrcamento))
	case !cabe:
		cand = map[int]string{}
		f.partial("cross", "este comando tem teto de tempo e a varredura por sinal "+
			"não cabe nele: a sondagem ficou limitada à faixa em uso pelo /proc. "+
			"Rode `scan` sem teto para sondar pid_max inteiro")
	default:
		cand = map[int]string{}
		f.partial("cross", "/proc está montado com hidepid e esta execução não é "+
			"root: a listagem esconde processo de outro usuário e o kill(2) não, "+
			"então a varredura por sinal foi DESLIGADA para não acusar o host "+
			"inteiro. Rode como root para sondar pid_max inteiro")
	}
	f.Cross.ProbeAte = ate
	// ProbeTeto é "a varredura foi CORTADA no meio", e só faz sentido se ela
	// aconteceu. Sem esta condição, o caso do hidepid — em que ela nem começa —
	// entraria no relatório como orçamento esgotado, dando o motivo errado para
	// uma lacuna que já foi declarada com o certo logo acima.
	f.Cross.ProbeTeto = usouSinal && ate < limite

	// 2) Faixa PRÓXIMA, por procfs — a testemunha que sobrevive a um kill()
	// hookado. É o laço de antes, com o mesmo alcance de antes.
	procAte := maior + probeMargem
	if procAte > maxProbePids {
		procAte = maxProbePids
	}
	if procAte > limite {
		procAte = limite
	}
	// TETO DE SANIDADE, para as filtragens de /proc que eu não soube enumerar.
	//
	// O guarda acima cobre hidepid, que é o caso conhecido. Não cobre o
	// desconhecido — LSM, /proc mascarado por runtime de contêiner, sandbox —, e
	// nesses o erro sai caro do mesmo jeito. A forma, porém, é sempre a mesma e
	// é reconhecível: ocultação por rootkit esconde UM processo, ou alguns;
	// /proc filtrado esconde CENTENAS de uma vez.
	//
	// Passando do teto, o que sai é LACUNA e não achado — e ela diz o número,
	// para ninguém confundir com silêncio.
	if n := len(cand); n > sondaMaxOcultos {
		cand = map[int]string{}
		f.partial("cross", strconv.Itoa(n)+" PIDs respondem a kill(2) e não estão na "+
			"listagem de /proc. Essa é a forma de /proc FILTRADO, não de ocultação "+
			"pontual: a comparação foi descartada em vez de virar "+strconv.Itoa(n)+
			" achados. Rode como root, ou confira as opções de montagem de /proc")
	}

	f.Cross.ProbeProcfsAte = procAte
	for pid := 1; pid <= procAte; pid++ {
		if conhecidos[pid] {
			continue
		}
		if _, err := os.Stat(procPath(pid, "stat")); err == nil {
			cand[pid] = "stat em /proc"
		}
	}

	// O cruzarPPID já rodou, e o que ele achou NÃO pode ser achado de novo aqui.
	//
	// Antes isso quase nunca acontecia por acidente de alcance: o pai oculto só
	// colidia se estivesse abaixo de 65536. Com a faixa inteira coberta, TODO pai
	// oculto passa também pela sondagem, e o mesmo PID sairia duas vezes — com
	// severidades diferentes, porque a via do PPID é CRITICAL e a da sondagem
	// não. Duas linhas para um processo é o tipo de ruído que faz o operador
	// duvidar do resto do relatório.
	//
	// Quem fica é o PPID, e por mérito: aquela via não tem corrida — o filho
	// existe AGORA e declara o pai.
	jaAchados := make(map[int]bool, len(f.Cross.Hidden))
	for _, h := range f.Cross.Hidden {
		jaAchados[h.PID] = true
	}
	f.Cross.Hidden = append(f.Cross.Hidden, ocultosDeCandidatos(cand, jaAchados)...)

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

	// A lacuna é "há faixa não sondada POR NINGUÉM", e agora ela é rara em vez
	// de constante — que é a diferença entre um número que informa e um que só
	// enfeita a saída.
	//
	// Sobram dois casos, e os dois são reais:
	//
	//	pid_max ilegível   não há denominador. Varreu-se o teto antigo e não se
	//	                   pode AFIRMAR que era a faixa inteira
	//	orçamento estourou 1 CPU e pid_max de 4,19 milhões estouram os 2s. O
	//	                   número que sai é até onde deu, e ele é exato: os
	//	                   blocos são entregues em ordem e o corte é no último
	//	                   prefixo contíguo concluído
	switch {
	case !usouSinal:
		// A lacuna já saiu, com o motivo dela. Nada a acrescentar aqui.
	case f.Cross.PidMax <= 0:
		f.partial("cross", "pid_max não pôde ser lido: a sondagem foi até "+
			strconv.Itoa(ate)+", e não há como afirmar que essa era a faixa "+
			"inteira — PID oculto acima disso NÃO foi procurado")
	case f.Cross.ProbeTeto:
		f.partial("cross", "sondagem de PID foi até "+strconv.Itoa(ate)+
			" de um pid_max de "+strconv.Itoa(f.Cross.PidMax)+" (para-quedas de "+
			sondaOrcamento.String()+" acionado): PID oculto acima disso NÃO foi procurado")
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
	f.Cross.ModProcLido = okProc
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
	f.Cross.ModSysLido = errSys == nil
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
// ocultosDeCandidatos converte o que a sondagem encontrou nos achados que vão
// para o relatório, tirando pelo caminho as threads e o que outra via já achou.
//
// Está separada de sondarPids porque é a parte que dá para testar sem host
// comprometido: a sondagem em si depende do que o kernel responde, esta aqui é
// decisão pura sobre um conjunto de candidatos.
func ocultosDeCandidatos(cand map[int]string, jaAchados map[int]bool) []HiddenPid {
	var out []HiddenPid
	for _, pid := range ordenados(cand) {
		if jaAchados[pid] {
			continue
		}
		// THREAD não é processo oculto.
		//
		// O procfs expõe /proc/<tid> para stat mas NÃO lista TIDs no readdir de
		// /proc — eles aparecem só em /proc/<pid>/task. Sem este filtro, toda
		// thread de todo processo vira "processo oculto": num desktop comum
		// foram 152 falsos positivos, e num contêiner de um processo só, 4.
		//
		// O `kill(pid, 0)` responde para TID exatamente como o stat responde, o
		// que faz o filtro valer igual para as duas testemunhas.
		//
		// O que separa está no próprio status: líder de grupo tem Tgid == Pid.
		// Status ilegível não elimina: é justamente a forma de um PID escondido
		// do procfs, e ali o `ok` vem falso.
		if tgid, ok := tgidDe(pid); ok && tgid != pid {
			continue
		}
		// Nasceu entre o readdir e a sondagem? O readdir foi ANTES, então um
		// processo novo aparece aqui sem ser oculto. O comm resolve pouco, mas
		// a contagem alta é o que dá sinal — e um processo novo é um, não vinte.
		h := HiddenPid{PID: pid, Como: "sondagem: responde a " + cand[pid] +
			" e não aparece na listagem"}
		if c, ok := readTrim(procPath(pid, "comm")); ok {
			h.Comm = c
		}
		out = append(out, h)
	}
	return out
}

// prazoDaSonda decide quanto tempo a varredura por sinal pode tomar.
//
// Sozinha ela usa o para-quedas, que só existe para hardware patológico. Mas
// quando a EXECUÇÃO tem orçamento — é o caso do `wtf`, com seus 2s de teto rígido
// da SPEC 6.1 —, quem manda é o orçamento da execução, e por um motivo medido: a
// primeira versão ignorava isso e comia a fatia dos outros coletores. O cenário
// 44-wtf-revshell caiu de 88/89 para 82/89 — não porque a sondagem falhasse, mas
// porque ela gastava o tempo que a varredura de filesystem ia usar. Seis lacunas
// novas em coletores que não tinham nada a ver com PID.
//
// Estourar aqui é o comportamento CERTO do wtf, não um defeito: ali o contrato é
// "o que não couber vira NÃO VERIFICADO e sai no rodapé", e a sondagem cortada
// diz exatamente até que PID foi.
// COMANDO COM TETO DE TEMPO NÃO SONDA A FAIXA INTEIRA.
//
// Duas tentativas erradas antes desta, e as duas medidas no 44-wtf-revshell:
//
//	sem limite nenhum      a sondagem gastava o tempo que a varredura de código
//	                       e a de SUID iam usar. 88/89 -> 82/89, seis lacunas em
//	                       coletores sem relação nenhuma com PID
//	limitada ao WalkDeadline  pior: ela consumia o prazo INTEIRO antes de os
//	                       outros coletores começarem, e o wtf saía 0/89
//
// O erro nas duas é o mesmo — tratar um orçamento COMPARTILHADO como se fosse
// desta função. O `wtf` tem 2s para o host todo (SPEC 6.1); a sondagem sozinha
// custa ~0,4s ociosa e mais sob carga. Não cabe, e forçá-la a caber é tirar de
// quem também precisa.
//
// Então sob teto ela não roda, e a faixa que ficou de fora vira lacuna com o
// caminho escrito: quem quer a faixa inteira roda o `scan`, que é o comando
// que não tem pressa. Isso NÃO é regressão do wtf — ele já declarava esta mesma
// lacuna antes, quando a sondagem parava em 65536 para todo mundo.
func sondaCabeNoComando(e *env.Env) bool {
	return e == nil || e.WalkDeadline.IsZero()
}

// sinalEhTestemunha diz se o kill(2) pode ser usado como prova de ocultação
// NESTE host.
//
// Só não pode quando a listagem de /proc é incompleta para quem está olhando, e
// o caso real disso é hidepid=2 sem root: o procfs esconde o processo dos
// outros usuários e o kill continua respondendo por eles.
//
// hidepid=1 NÃO entra: ali as entradas continuam aparecendo no readdir (o que
// se perde é a leitura do conteúdo), a listagem segue completa, e desligar a
// varredura ali custaria a faixa inteira num host que é só endurecido — a
// configuração CIS mais comum que existe.
func sinalEhTestemunha(f *Facts, e *env.Env) bool {
	if e.Has(env.CapRoot) {
		return true
	}
	for i := range f.Mounts {
		if f.Mounts[i].Ponto != "/proc" {
			continue
		}
		for _, op := range strings.Split(f.Mounts[i].Opcoes, ",") {
			v, ok := strings.CutPrefix(op, "hidepid=")
			if !ok {
				continue
			}
			// O kernel aceita número e nome para a mesma coisa.
			return v != "2" && v != "invisible"
		}
	}
	return true
}

// varrerPorSinal pergunta ao kernel, por `kill(pid, 0)`, quais PIDs existem em
// [1, limite], e devolve os que existem sem estar na listagem.
//
// `kill` com sinal 0 não entrega sinal nenhum: o kernel faz a checagem de
// permissão e de existência e volta. EPERM prova existência tanto quanto o
// sucesso — é um processo de outro usuário —, e tratá-lo como ausência faria a
// varredura sem root enxergar só os processos do próprio usuário.
//
// # Por que em blocos, e em ordem
//
// O orçamento pode cortar a varredura no meio, e aí o número que sai precisa
// significar alguma coisa. Com faixas fixas por worker, o que sobra depois de um
// corte é um conjunto esburacado que nenhum número resume. Com blocos entregues
// em ordem por um contador atômico, o que se conclui é um PREFIXO — e o maior
// prefixo contíguo concluído é exatamente o "sondei até aqui" que a cobertura
// promete.
//
// O prazo entra por parâmetro em vez de sair de um relógio interno porque o
// caminho do CORTE é o que precisa de teste, e um teste que dependesse de o
// host ser lento o bastante para estourar 2s não provaria nada.
func varrerPorSinal(limite int, visiveis map[int]bool, prazo time.Time) (map[int]string, int) {
	cand := map[int]string{}
	if limite <= 0 {
		return cand, 0
	}
	// O teto vale AQUI TAMBÉM, e não só no chamador: é esta função que faz o
	// make(), e um invariante que depende de quem chama é um invariante que a
	// próxima chamada quebra.
	if limite > pidMaxLimite {
		limite = pidMaxLimite
	}
	blocos := (limite + sondaBloco - 1) / sondaBloco
	workers := min(sondaWorkers, max(1, runtime.NumCPU()))

	var proximo atomic.Int64
	feito := make([]atomic.Bool, blocos)

	var mu sync.Mutex
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Um panic aqui matava o PROCESSO: goroutine não é alcançada pelo
			// recover do main, e o status 2 que sai dali é justamente o que a
			// automação de frota lê como "CRITICAL, alta confiança" — um defeito
			// nosso marcando o host como comprometido.
			//
			// Recuperado, não há lacuna a declarar por fora: o bloco que estava
			// com este trabalhador não chega ao feito[b].Store(true), então o
			// prefixo contíguo `ate` para antes dele e a sondagem passa a
			// afirmar o alcance MENOR que de fato teve. É a resposta honesta, no
			// campo que já existe para dizê-la.
			defer func() { _ = recover() }()
			for {
				b := int(proximo.Add(1) - 1)
				if b >= blocos || time.Now().After(prazo) {
					return
				}
				lo, hi := b*sondaBloco+1, (b+1)*sondaBloco
				if hi > limite {
					hi = limite
				}
				var achados []int
				for pid := lo; pid <= hi; pid++ {
					if visiveis[pid] {
						continue
					}
					if err := syscall.Kill(pid, 0); err == nil || err == syscall.EPERM {
						achados = append(achados, pid)
					}
				}
				feito[b].Store(true)
				if len(achados) > 0 {
					// defer no Unlock — ver o invariante em
					// Facts.guardaGoroutine: com recover ativo, um panic com o
					// mutex travado pendura a pool inteira.
					func() {
						mu.Lock()
						defer mu.Unlock()
						for _, pid := range achados {
							cand[pid] = "kill(2)"
						}
					}()
				}
			}
		}()
	}
	wg.Wait()

	ate := 0
	for b := 0; b < blocos && feito[b].Load(); b++ {
		ate = min((b+1)*sondaBloco, limite)
	}
	return cand, ate
}

// existePid é a pergunta "este PID existe?" feita às duas interfaces, na ordem
// em que elas custam. Devolve por qual delas veio a resposta.
//
// É a mesma união usada na sondagem, e precisa ser: confirmar só por procfs
// descartaria justamente o candidato mais interessante — o que o kill(2)
// encontrou porque o /proc não o mostra.
func existePid(pid int) (string, bool) {
	if _, err := os.Stat(procPath(pid, "stat")); err == nil {
		return "stat em /proc", true
	}
	if err := syscall.Kill(pid, 0); err == nil || err == syscall.EPERM {
		return "kill(2)", true
	}
	return "", false
}

// ordenados devolve as chaves em ordem, para a saída não depender da iteração
// de mapa — dois scans do mesmo host precisam produzir o mesmo relatório.
func ordenados(m map[int]string) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}

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
		if _, ok := existePid(h.PID); !ok {
			continue // morreu depois da sondagem: era efêmero, não oculto
		}
		out = append(out, h)
	}
	return out
}
