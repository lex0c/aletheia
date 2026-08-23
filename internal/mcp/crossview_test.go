package mcp

import (
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/facts"
)

// A catraca central desta tool: SILÊNCIO DA SEGUNDA TESTEMUNHA NUNCA VIRA
// "CONCORDAM".
//
// É o defeito que a tool inteira existe para não cometer. "Nenhum socket
// oculto" com o netlink indisponível é a MESMA frase de "nenhum socket oculto"
// com as duas visões batendo, e as duas conclusões são opostas: a primeira não
// afirma nada, a segunda afirma bastante. Um estado binário — divergiu / não
// divergiu — apaga essa diferença, e quem lê a resposta não tem como recuperá-la.
//
// Cada caso abaixo é um jeito de a segunda testemunha faltar. Todos precisam
// chegar em not_compared, nenhum em agree.
func TestTestemunhaAusenteNaoViraConcordancia(t *testing.T) {
	casos := []struct {
		nome  string
		cross facts.CrossView
		eixo  func(*facts.CrossView) map[string]any
	}{
		{"netlink não respondeu",
			facts.CrossView{SocketProc: 12, SocketDiagLido: false}, eixoDeSockets},
		{"netlink respondeu CORTADO",
			facts.CrossView{SocketProc: 12, SocketDiag: 12, SocketProtos: protosCompared(),
				SocketDiagLido: true, SocketDiagCortado: true},
			eixoDeSockets},
		{"netlink leu, /proc/net não foi lido em protocolo nenhum",
			facts.CrossView{SocketDiagLido: true, SocketProtos: protosProcIlegivel()},
			eixoDeSockets},
		{"readdir de /proc não foi lido",
			facts.CrossView{ProbeAte: 4194304}, porCrossView(eixoDeProcessos)},
		{"listagem lida, mas nenhuma sondagem rodou",
			facts.CrossView{ProcListLida: true, ProcListN: 40},
			porCrossView(eixoDeProcessos)},
		{"nenhuma interface de módulo foi lida",
			facts.CrossView{}, eixoDeModulos},
		{"ftrace ilegível, com /proc/modules lido",
			facts.CrossView{ModProcLido: true, ModProc: []string{"a", "b"}},
			eixoDeFtrace},
	}
	for _, c := range casos {
		got := c.eixo(&c.cross)["state"]
		if got != "not_compared" {
			t.Errorf("%s: state=%v, queria not_compared.\n"+
				"Sem segunda testemunha não houve comparação, e responder %q "+
				"transforma 'ninguém olhou' em 'está limpo' — que é exatamente a "+
				"confusão que esta tool desfaz.", c.nome, got, got)
		}
	}
}

// READ É FATO COLETADO, NÃO CARDINALIDADE — os casos ASSIMÉTRICOS.
//
// Este é o buraco que a revisão apontou: os testes cobriam "as duas ausentes",
// mas não "uma lida, a outra ilegível". E é justamente aí que a inferência por
// len()>0 mentia: /proc/modules com EACCES e /sys/module lido com 300 entradas
// produzia ModProc=[], ModSys=[300], ModDiff=[] — e a tool respondia "agree"
// com uma testemunha marcada NÃO lida. A resposta dizia, na mesma linha, que uma
// visão não falou E que elas concordaram.
//
// A regra tem de ser mecânica: qualquer testemunha necessária que não respondeu
// leva a not_compared, mesmo que a outra tenha respondido e nada divirja.
func TestReadStateEhFatoNaoCardinalidade(t *testing.T) {
	casos := []struct {
		nome  string
		cross facts.CrossView
		eixo  func(*facts.CrossView) map[string]any
		quero string // read da testemunha-chave, para o caso "lida com zero"
	}{
		{"/proc/modules ilegível, /sys/module lido com 300",
			facts.CrossView{ModProcLido: false, ModSysLido: true,
				ModSys: make([]string, 300)}, eixoDeModulos, ""},
		{"/sys/module ilegível, /proc/modules lido",
			facts.CrossView{ModProcLido: true, ModSysLido: false,
				ModProc: []string{"nf_tables"}}, eixoDeModulos, ""},
		{"ftrace lido, /proc/modules ilegível",
			facts.CrossView{ModFtraceLido: true, ModProcLido: false,
				ModFtrace: []string{"nf_tables"}}, eixoDeFtrace, ""},
	}
	for _, c := range casos {
		e := c.eixo(&c.cross)
		if e["state"] != "not_compared" {
			t.Errorf("%s: state=%v, queria not_compared.\n"+
				"Uma testemunha necessária não foi lida, e a cardinalidade da OUTRA "+
				"não pode virar 'agree' — vazio ≠ ilegível.", c.nome, e["state"])
		}
	}
}

// A HONESTIDADE DA TESTEMUNHA: o campo read reflete a leitura, não a contagem.
//
// A queixa concreta da revisão não era só sobre o state — era sobre a resposta
// dizer "/proc/net read=true" enquanto aquela visão não falou. O state e o
// campo read do testemunho são coisas diferentes, e a segunda é a que o modelo
// lê ao lado do count. Um read=true fixo mente mesmo quando o state acerta.
func TestCampoReadDaTestemunhaEhHonesto(t *testing.T) {
	// sockets: netlink leu, /proc/net não foi lido em protocolo nenhum. A
	// testemunha /proc/net tem de dizer read=false.
	so := eixoDeSockets(&facts.CrossView{SocketDiagLido: true,
		SocketProtos: protosProcIlegivel()})
	procNet := so["witnesses"].([]map[string]any)[0]
	if procNet["read"] != false {
		t.Errorf("/proc/net não foi lido em protocolo nenhum e a testemunha diz "+
			"read=%v: a resposta afirma que uma visão falou quando ela não falou",
			procNet["read"])
	}

	// modules: /proc/modules ilegível, /sys/module lido. A testemunha
	// /proc/modules tem de dizer read=false, mesmo com /sys/module cheio.
	mo := eixoDeModulos(&facts.CrossView{ModProcLido: false, ModSysLido: true,
		ModSys: make([]string, 300)})
	procMod := mo["witnesses"].([]map[string]any)[0]
	if procMod["read"] != false {
		t.Errorf("/proc/modules ilegível e a testemunha diz read=%v — inferido da "+
			"cardinalidade da OUTRA testemunha", procMod["read"])
	}
}

// Fonte LIDA com zero objetos NÃO é fonte ilegível.
//
// O outro lado da mesma moeda: um kernel sem módulo carregado tem /proc/modules
// LIDO e VAZIO. Se a tool inferisse read por len()>0, ela chamaria esse host de
// "não comparado" e esconderia um agree legítimo. O bit de leitura é o que
// separa os dois.
func TestFonteLidaComZeroConcorda(t *testing.T) {
	// /proc/modules e /sys/module ambos LIDOS, ambos vazios: um kernel sem
	// módulo. É agree — as duas interfaces mostram o mesmo (nada), e as duas
	// foram observadas.
	c := facts.CrossView{ModProcLido: true, ModSysLido: true}
	if s := eixoDeModulos(&c)["state"]; s != "agree" {
		t.Errorf("as duas interfaces foram lidas e ambas vazias (kernel sem "+
			"módulo): state=%v, queria agree. read por len()>0 chamaria isto de "+
			"não comparado.", s)
	}

	// ftrace LIDO com zero tags: available_filter_functions foi lido e nenhum
	// módulo tinha função rastreável. /proc/modules lido também. É agree — as
	// duas visões foram observadas e nada divergiu. Inferir read por
	// len(ModFtrace)>0 chamaria este agree legítimo de "não comparado".
	cf := facts.CrossView{ModFtraceLido: true, ModProcLido: true,
		ModProc: []string{"a"}}
	if s := eixoDeFtrace(&cf)["state"]; s != "agree" {
		t.Errorf("ftrace lido com zero tags e /proc/modules lido: state=%v, "+
			"queria agree. len(ModFtrace)>0 esconderia esta leitura.", s)
	}
}

// O par /proc×/sys concordar NÃO pode arrastar o ftrace junto.
//
// Este é o caso REAL da máquina onde isto foi escrito: /proc/modules e
// /sys/module lidos e batendo, available_filter_functions ilegível porque exige
// root. Enquanto as duas comparações dividiam um estado só, a resposta era
// "modules: agree" — e carregava, de graça, a afirmação de que nada se
// escondeu do ftrace. Essa afirmação nunca foi feita, e é justamente a que pega
// o LKM que se desencadeia da lista.
func TestFtraceIlegivelNaoHerdaAConcordanciaDosOutros(t *testing.T) {
	c := facts.CrossView{
		ModProcLido: true, ModSysLido: true,
		ModProc: []string{"nf_tables", "overlay"},
		ModSys:  []string{"nf_tables", "overlay", "ext4"},
	}
	if s := eixoDeModulos(&c)["state"]; s != "agree" {
		t.Fatalf("o par /proc×/sys foi lido e bate; state=%v", s)
	}
	if s := eixoDeFtrace(&c)["state"]; s != "not_compared" {
		t.Errorf("ftrace não lido devolveu %v: a concordância de OUTRA "+
			"comparação virou afirmação sobre esta", s)
	}
}

// Contagens diferentes sob "agree" precisam de explicação NA RESPOSTA.
//
// /sys/module lista também o que foi compilado dentro do kernel: 248 contra 353
// no host de desenvolvimento. Publicar os dois números e dizer "concordam" sem
// mais nada é uma contradição na cara de quem lê — e o leitor sensato conclui
// que a ferramenta está errada, não que a comparação é unidirecional.
func TestDivergenciaLegitimaDeContagemEhExplicada(t *testing.T) {
	c := facts.CrossView{ModProcLido: true, ModSysLido: true,
		ModProc: []string{"a"}, ModSys: []string{"a", "b", "c"}}
	e := eixoDeModulos(&c)
	nota, _ := e["note"].(string)
	if !strings.Contains(nota, "DENTRO do kernel") {
		t.Errorf("as contagens divergem por construção e a resposta não diz "+
			"por quê. note=%q", nota)
	}
	if !strings.Contains(nota, "não foi verificado") {
		t.Errorf("a comparação corre num sentido só e a resposta não declara "+
			"o sentido que ficou de fora. note=%q", nota)
	}
	// E a frase de sucesso descreve o que foi VERIFICADO, não mais: a
	// comparação é unidirecional, então "mostram o mesmo conjunto" afirmaria o
	// que o próprio note desmente.
	m, _ := e["meaning"].(string)
	if strings.Contains(m, "mesmo conjunto") {
		t.Errorf("a frase de agree afirma 'mesmo conjunto', que a comparação "+
			"unidirecional não verifica: %q", m)
	}
}

// Divergência é divergência mesmo quando a segunda testemunha falhou depois.
//
// Um socket oculto já encontrado não vira "não comparado" porque a leitura foi
// cortada em seguida: o ACHADO sobrevive à lacuna. Só a AUSÊNCIA é que não.
func TestAchadoSobreviveALacuna(t *testing.T) {
	c := facts.CrossView{
		SocketProc: 3, SocketDiag: 4, SocketDiagLido: true,
		SocketProtos: protosCompared(), SocketDiagCortado: true,
		SocketOcultos: []facts.SocketOculto{{}},
	}
	e := eixoDeSockets(&c)
	if e["state"] != "disagree" {
		t.Errorf("socket oculto encontrado e state=%v: a truncagem apagou um "+
			"achado que já existia", e["state"])
	}
	if e["divergences_total"] != 1 {
		t.Errorf("divergences_total=%v, queria 1", e["divergences_total"])
	}
}

// O alcance faz parte da afirmação.
//
// "Nenhum processo oculto até 4.194.304" e "até 65.536" são frases diferentes,
// e a segunda quase não é frase. Quando a sondagem parou antes do pid_max do
// host, a resposta tem de DIZER onde parou — senão o leitor completa sozinho, e
// completa para o lado errado.
func TestAlcanceParcialApareceNaFrase(t *testing.T) {
	f := &facts.Facts{Cross: facts.CrossView{
		ProcListLida: true, ProcListN: 300,
		ProbeAte: 65536, ProbeProcfsAte: 65536, PidMax: 4194304}}
	m, _ := eixoDeProcessos(f)["meaning"].(string)
	if !strings.Contains(m, "65536") || !strings.Contains(m, "4194304") {
		t.Errorf("a sondagem parou em 65536 num host com pid_max 4194304 e a "+
			"resposta não diz isso: %q", m)
	}
}

// A divergência é cortada no teto, e o total nunca some.
//
// Esta é a tool que diz "o kernel mente?" — ela não pode ser a que falha
// inteira por tamanho justamente quando há mais o que mostrar. Acima do teto, a
// lista é cortada SEMANTICAMENTE, o corte é declarado, e divergences_total
// carrega o número real.
func TestDivergenciaGrandeEhCortadaComTotal(t *testing.T) {
	muitos := make([]facts.SocketOculto, maxDivergencias+50)
	c := facts.CrossView{SocketDiagLido: true, SocketProtos: protosCompared(),
		SocketOcultos: muitos}
	e := eixoDeSockets(&c)
	if e["divergences_total"] != maxDivergencias+50 {
		t.Errorf("divergences_total=%v, queria %d — o número real sumiu no corte",
			e["divergences_total"], maxDivergencias+50)
	}
	if got := len(e["divergences"].([]map[string]any)); got != maxDivergencias {
		t.Errorf("a lista devolveu %d, o teto é %d", got, maxDivergencias)
	}
	if e["divergences_truncated"] != true {
		t.Error("o corte não foi declarado")
	}
}

// porCrossView adapta um eixo que precisa do Facts inteiro para a tabela, que
// escreve só o CrossView. O eixo de processos precisa da LISTAGEM, que mora
// fora do CrossView — e a tabela continua legível.
func porCrossView(fn func(*facts.Facts) map[string]any) func(*facts.CrossView) map[string]any {
	return func(c *facts.CrossView) map[string]any {
		return fn(&facts.Facts{Cross: *c})
	}
}

// P1 #1: trust_broken É DO MOTOR, NÃO DOS EIXOS.
//
// O caso que expõe o defeito: um host cujo ÚNICO quebra-confiança é BPF — um
// programa eBPF citado por referência viva que a enumeração do kernel não
// devolve. Os quatro eixos de processo/socket/módulo concordam; só o motor,
// via cross.bpf_hidden, sabe que a confiança quebrou.
//
// O código antigo varria os eixos por "disagree" e não tinha eixo de BPF: ele
// responderia trust_broken=false enquanto coverage.get, lendo o MESMO retrato,
// diria kernel_trust_broken != []. Duas verdades oficiais sobre o mesmo host, e
// a que governa toda leitura de ausência era a errada.
//
// A propriedade travada aqui é exata: crossview.get.trust_broken ==
// len(Relatorio().KernelTrustBroken) > 0.
func TestTrustBrokenVemDoMotorNaoDosEixos(t *testing.T) {
	f := fatosDeTeste()
	// Cross LIDO e limpo: os quatro eixos não-bpf concordam.
	f.Cross = facts.CrossView{
		ProcListLida: true, ProcListN: 2,
		ProbeAte: 4194304, ProbeProcfsAte: 4194304, PidMax: 4194304,
		ModProcLido: true, ModSysLido: true,
		ModProc: []string{"a"}, ModSys: []string{"a"},
		ModFtraceLido:  true,
		SocketDiagLido: true, SocketProtos: protosCompared(),
	}
	// O ÚNICO defeito: um id de eBPF oculto, confirmado. Faz cross.bpf_hidden
	// disparar CRITICAL, e é kernelBreaker. fatosDeTeste tem Source live, que é
	// o que invalidarAusencias exige.
	f.BPF = facts.BPF{Enumerado: true, Ocultos: []uint32{123}, OcultosConfirmados: true}

	s, r := servidorDeTeste(t, f)
	rel := r.Relatorio()
	if len(rel.KernelTrustBroken) == 0 {
		t.Fatal("o cenário não produziu KernelTrustBroken: o teste não exercita " +
			"o que promete — cross.bpf_hidden não disparou")
	}

	m := chamar(t, s, "crossview.get", "{}")
	data := m["data"].(map[string]any)
	if data["trust_broken"] != true {
		t.Errorf("trust_broken=%v, mas o motor tem KernelTrustBroken=%v.\n"+
			"O booleano foi recalculado dos eixos em vez de vir do Report: é a "+
			"segunda verdade que a revisão bloqueou.", data["trust_broken"],
			rel.KernelTrustBroken)
	}
	// E nenhum eixo NÃO-bpf disagree — prova que o booleano não veio de varrer
	// os eixos, porque não havia disagree entre eles para varrer.
	for _, ax := range data["axes"].([]any) {
		a := ax.(map[string]any)
		if a["axis"] != "bpf" && a["state"] == "disagree" {
			t.Errorf("eixo %v em disagree — o cenário deveria ter só o bpf "+
				"quebrado", a["axis"])
		}
	}
	// breakers carrega a lista autoritativa, ao lado dos eixos.
	if _, ok := data["breakers"]; !ok {
		t.Error("trust_broken sem breakers: o modelo vê o booleano e não o motivo")
	}
}

// O eixo de BPF fala os três estados a partir dos fatos de enumeração.
func TestEixoBPF(t *testing.T) {
	casos := []struct {
		nome  string
		bpf   facts.BPF
		quero string
	}{
		{"enumeração não rodou (sem CAP_BPF)",
			facts.BPF{Enumerado: false}, "not_compared"},
		{"id oculto confirmado",
			facts.BPF{Enumerado: true, Ocultos: []uint32{7}, OcultosConfirmados: true},
			"disagree"},
		{"id citado mas NÃO confirmado é inconclusivo",
			facts.BPF{Enumerado: true, Ocultos: []uint32{7}, OcultosConfirmados: false},
			"not_compared"},
		{"enumerou e nada oculto",
			facts.BPF{Enumerado: true}, "agree"},
	}
	for _, c := range casos {
		f := &facts.Facts{BPF: c.bpf}
		if s := eixoDeBPF(f)["state"]; s != c.quero {
			t.Errorf("%s: state=%v, queria %v", c.nome, s, c.quero)
		}
	}
}

// protosCompared é o estado de sockets em que os quatro protocolos inet foram
// confrontados — o único que sustenta agree.
func protosCompared() map[string]string {
	return map[string]string{"tcp": "compared", "tcp6": "compared",
		"udp": "compared", "udp6": "compared"}
}

// protosProcIlegivel: netlink leu, /proc/net deu EACCES em todos — nenhum
// protocolo confrontado.
func protosProcIlegivel() map[string]string {
	return map[string]string{"tcp": "proc_unreadable", "tcp6": "proc_unreadable",
		"udp": "proc_unreadable", "udp6": "proc_unreadable"}
}

// P1: COBERTURA PARCIAL DE SOCKETS NÃO VIRA agree.
//
// O confronto é por protocolo. Se um protocolo não foi confrontado — /proc/net
// ilegível nele, ou o netlink o pulou para não autocarregar o handler de diag —
// então "nenhum socket oculto" naquele protocolo é a ausência de uma
// comparação, não o resultado dela. O caso comum é udp_diag não estar carregado:
// tcp/tcp6 comparam, udp/udp6 são pulados, e o eixo NÃO pode dizer agree com
// metade da superfície de socket sem ninguém ter olhado.
func TestCoberturaParcialDeSocketsNaoEhAgree(t *testing.T) {
	casos := []struct {
		nome   string
		protos map[string]string
	}{
		{"udp/udp6 pulados (udp_diag não carregado)", map[string]string{
			"tcp": "compared", "tcp6": "compared",
			"udp": "diag_skipped", "udp6": "diag_skipped"}},
		{"udp6 com /proc/net ilegível", map[string]string{
			"tcp": "compared", "tcp6": "compared",
			"udp": "compared", "udp6": "proc_unreadable"}},
	}
	for _, c := range casos {
		e := eixoDeSockets(&facts.CrossView{SocketDiagLido: true, SocketProtos: c.protos})
		if e["state"] != "not_compared" {
			t.Errorf("%s: state=%v, queria not_compared.\n"+
				"Um protocolo não confrontado não pode virar agree — um socket "+
				"escondido dele passaria despercebido.", c.nome, e["state"])
		}
	}
	// E os quatro comparados É agree.
	full := eixoDeSockets(&facts.CrossView{SocketDiagLido: true, SocketProtos: protosCompared()})
	if full["state"] != "agree" {
		t.Errorf("quatro protocolos comparados e sem divergência: state=%v, queria agree",
			full["state"])
	}
}

// P1: state É OBSERVAÇÃO, trust_breaking É INTERPRETAÇÃO DO MOTOR.
//
// Uma divergência WARN — thread_count com corrida residual, ou hidden_pid visto
// só por sondagem — deixa o eixo em disagree SEM quebrar a confiança do kernel.
// O motor não lista essas em KernelTrustBroken; só um CRITICAL kernelBreaker
// entra. A tool tem de espelhar isso: disagree com trust_breaking=false, e a
// mensagem top-level não pode dizer "nada contradiz o kernel" ao lado de um eixo
// em disagree.
func TestDisagreeFracoNaoQuebraConfianca(t *testing.T) {
	f := fatosDeTeste()
	f.Cross = facts.CrossView{
		ProcListLida: true, ProcListN: 2,
		ProbeAte: 4194304, ProbeProcfsAte: 4194304, PidMax: 4194304,
		ModProcLido: true, ModSysLido: true, ModProc: []string{"a"}, ModSys: []string{"a"},
		ModFtraceLido:  true,
		SocketDiagLido: true, SocketProtos: protosCompared(),
		// Uma divergência de contagem de threads: WARN, não kernelBreaker.
		Threads: []facts.ThreadDiff{{PID: 4242, Status: 8, Task: 7}},
	}
	s, r := servidorDeTeste(t, f)
	if len(r.Relatorio().KernelTrustBroken) != 0 {
		t.Fatal("thread_count não deveria quebrar a confiança do kernel — o " +
			"cenário não isola o que promete")
	}

	m := chamar(t, s, "crossview.get", "{}")
	data := m["data"].(map[string]any)
	if data["trust_broken"] != false {
		t.Errorf("trust_broken=%v: uma divergência WARN não desqualifica o kernel",
			data["trust_broken"])
	}
	var proc map[string]any
	for _, ax := range data["axes"].([]any) {
		a := ax.(map[string]any)
		if a["axis"] == "processes" {
			proc = a
		}
	}
	if proc["state"] != "disagree" {
		t.Fatalf("processes state=%v, esperava disagree (há ThreadDiff)", proc["state"])
	}
	if proc["trust_breaking"] != false {
		t.Errorf("processes disagree mas trust_breaking=%v — uma divergência de "+
			"observação WARN virou quebra de confiança", proc["trust_breaking"])
	}
	// E a mensagem top-level não pode afirmar que nada contradiz o kernel.
	if msg, _ := data["meaning"].(string); strings.Contains(msg, "nada aqui contradiz o kernel") {
		t.Errorf("há eixo em disagree e a mensagem diz 'nada contradiz o kernel': "+
			"mistura observação com interpretação\nmeaning=%q", msg)
	}
}

// O outro lado: um hidden_pid CRITICAL por PPID SOBE trust_breaking no eixo.
func TestDisagreeForteQuebraConfianca(t *testing.T) {
	f := fatosDeTeste()
	f.Cross = facts.CrossView{
		ProcListLida: true, ProcListN: 2,
		ProbeAte: 4194304, ProbeProcfsAte: 4194304, PidMax: 4194304,
		ModProcLido: true, ModSysLido: true, ModProc: []string{"a"}, ModSys: []string{"a"},
		ModFtraceLido:  true,
		SocketDiagLido: true, SocketProtos: protosCompared(),
		// PID oculto detectado por PPID — a via que o motor sobe a CRITICAL.
		Hidden: []facts.HiddenPid{{PID: 31337, Como: "ppid", Comm: "x"}},
	}
	s, r := servidorDeTeste(t, f)
	if len(r.Relatorio().KernelTrustBroken) == 0 {
		// t.Fatal, não t.Skip: a via ppid é CRITICAL DETERMINÍSTICO no check
		// (viaPPID → SevCritical, sem gate de reconfirmação — a reconfirmação
		// mora no coletor, antes do fato existir). Se isto zerar, cross.hidden_pid
		// saiu de kernelBreakers, e é exatamente a regressão que este teste existe
		// para pegar — pular aqui a esconderia.
		t.Fatal("HiddenPid por ppid não quebrou a confiança: cross.hidden_pid " +
			"deixou de ser kernelBreaker, ou o ppid deixou de ser CRITICAL")
	}
	m := chamar(t, s, "crossview.get", "{}")
	data := m["data"].(map[string]any)
	if data["trust_broken"] != true {
		t.Fatalf("trust_broken=%v com KernelTrustBroken != []", data["trust_broken"])
	}
	for _, ax := range data["axes"].([]any) {
		a := ax.(map[string]any)
		if a["axis"] == "processes" && a["trust_breaking"] != true {
			t.Errorf("hidden_pid CRITICAL e processes.trust_breaking=%v",
				a["trust_breaking"])
		}
	}
}

// P1: BPF com enumeração TRUNCADA não vira agree.
//
// A truncagem significa enumeração incompleta: um id citado por referência viva
// pode ter ficado depois do teto, e o coletor se recusa a chamá-lo de oculto
// (Ocultos=nil, lacuna). "agree" ali afirmaria um confronto completo que a
// truncagem impediu — a mesma inversão que o socket cortado já evita.
func TestBPFTruncadoNaoEhAgree(t *testing.T) {
	f := &facts.Facts{BPF: facts.BPF{Enumerado: true, ProgramasCortado: true}}
	if s := eixoDeBPF(f)["state"]; s != "not_compared" {
		t.Errorf("enumeração de eBPF truncada e state=%v, queria not_compared: "+
			"um id além do teto não distingue oculto de não-enumerado", s)
	}
}

// P2: SocketProtos ausente ou incompleto FALHA FECHADO.
//
// A partição corre sobre os quatro protocolos fixos, não sobre as chaves que o
// mapa por acaso tem. Um SocketProtos nil — dump adulterado, ou de versão que
// não o preenchia — não pode virar "zero pendentes → agree": fonte que não
// afirmou o estado do protocolo é protocolo NÃO confrontado.
func TestSocketProtosAusenteFalhaFechado(t *testing.T) {
	casos := []struct {
		nome   string
		protos map[string]string
	}{
		{"nil", nil},
		{"incompleto (só tcp)", map[string]string{"tcp": "compared"}},
		{"estado desconhecido", map[string]string{
			"tcp": "compared", "tcp6": "compared",
			"udp": "compared", "udp6": "??"}},
	}
	for _, c := range casos {
		e := eixoDeSockets(&facts.CrossView{SocketDiagLido: true, SocketProtos: c.protos})
		if e["state"] != "not_compared" {
			t.Errorf("%s: state=%v, queria not_compared — mapa incompleto virou "+
				"agree por falhar aberto", c.nome, e["state"])
		}
	}
}
