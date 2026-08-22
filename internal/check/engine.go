package check

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

// NotChecked registra um check que não pôde rodar. Isto NÃO é "nada
// encontrado": é "não foi possível olhar", e a diferença é o motivo de a
// ferramenta existir.
type NotChecked struct {
	ID     string `json:"id"`
	Ref    string `json:"ref"`
	Title  string `json:"title"`
	Reason string `json:"reason"`
	// Manual é o que o operador pode rodar à mão para cobrir esta lacuna.
	Manual []string `json:"manual,omitempty"`

	// Escopo marca o check que não roda porque a pergunta NÃO EXISTE neste
	// host — o kernel não oferece o mecanismo, e nenhuma permissão o faria
	// aparecer. Continua listado, porque silenciar seria esconder o que a
	// execução não cobriu; o que ele NÃO faz é entrar no denominador da
	// cobertura. Marcá-lo como lacuna fazia toda varredura naquele host sair
	// INCOMPLETE com exit 1, inclusive a de um host limpo — a mesma confusão
	// entre escopo e lacuna que o bootloader em contêiner e o nsswitch em musl
	// já custaram.
	Escopo bool `json:"out_of_scope,omitempty"`
}

// Partial é um check que rodou, mas não cobriu tudo.
type Partial struct {
	ID      string   `json:"id"`
	Ref     string   `json:"ref"`
	Reasons []string `json:"reasons"`
}

// Coverage é o rodapé obrigatório. O denominador é o conjunto SELECIONADO para
// esta execução, não o catálogo inteiro (SPEC 7.9).
type Coverage struct {
	Total      int          `json:"total"`
	Complete   int          `json:"complete"`
	Partial    []Partial    `json:"partial,omitempty"`
	NotChecked []NotChecked `json:"not_checked,omitempty"`

	// CollectorGaps é o que a COLETA não conseguiu ler — eixo diferente dos
	// checks, e por isso fora da aritmética completos+parciais+não verificados.
	// "Não consegui ler o fd de 250 processos" degrada a cobertura mesmo que
	// todos os checks tenham rodado.
	CollectorGaps []string `json:"collector_gaps,omitempty"`
}

// Incomplete diz se algo deixou de cobrir o que deveria. Parcial conta como
// não-completo: um check que rodou sem /root não cobriu o que deveria. Falha de
// coleta também conta — é literalmente "não olhei".
func (c Coverage) Incomplete() bool {
	return c.Complete < c.Total || len(c.CollectorGaps) > 0
}

// NaoVerificados separa as duas listas que moram em NotChecked: o que é LACUNA
// (não rodou e devia) e o que é ESCOPO (a pergunta não existe neste host).
//
// Sem essa separação o rodapé se contradizia na mesma linha — "105/105
// completos · 2 não verificados" —, porque o escopo sai do denominador e
// continuava sendo contado na lista.
func (c Coverage) NaoVerificados() (lacunas, escopo []NotChecked) {
	for _, nc := range c.NotChecked {
		if nc.Escopo {
			escopo = append(escopo, nc)
		} else {
			lacunas = append(lacunas, nc)
		}
	}
	return lacunas, escopo
}

// Report é o resultado de uma execução.
type Report struct {
	Findings []Finding
	Coverage Coverage

	// TrustBroken lista os motivos pelos quais achados de binário do host
	// foram rebaixados nesta execução.
	TrustBroken []string

	// KernelTrustBroken lista as demonstrações de que o KERNEL entregou visões
	// inconsistentes. Quando não está vazio, toda ausência de achado nesta
	// execução foi respondida por uma fonte desqualificada — ver
	// invalidarAusencias.
	KernelTrustBroken []string

	// CriticosForaDaJanela conta os achados CRÍTICOS que a janela removeu.
	//
	// Existe para o exit code, e a razão é a promessa central da ferramenta:
	// exit 0 significa "não há o que ver". Se a varredura ACHOU um crítico e o
	// recorte pedido o deixou de fora, há o que ver — e um `verdict: OK` ali
	// mandaria a automação de frota arquivar um host comprometido.
	CriticosForaDaJanela int
}

// trustBreakers são os IDs cujo disparo invalida a confiança em resultado vindo
// de binário do host. É a propriedade emergente de ter Origin no modelo
// (SPEC 7.5).
var trustBreakers = map[string]string{
	"persist.ld_preload_global": "/etc/ld.so.preload presente: o loader injeta biblioteca em todo processo dinâmico",
	"proc.ld_preload_env":       "LD_PRELOAD definido no environ de um processo",
}

// kernelBreakers são os IDs cujo disparo mostra que o KERNEL entregou visões
// INCONSISTENTES de si mesmo.
//
// A diferença para os de cima é a fonte, e ela muda o que fica inválido. Um
// LD_PRELOAD invalida o que veio de binário do host; um kernel que se
// contradiz invalida tudo que foi lido ATRAVÉS dele — /proc, /sys, tracefs,
// bpf(2) e o próprio filesystem, que ele também serve.
//
// E o efeito que importa não é sobre os achados: é sobre as AUSÊNCIAS. "vi
// algo estranho" continua valendo depois disto — vale mais, aliás. "não vi
// nada estranho" deixa de valer, porque quem responderia já demonstrou
// responder o que quer.
//
// Só entram aqui os checks cuja natureza é COMPARAR duas visões e achá-las
// discordantes. Um achado de conteúdo (módulo estranho, hook de ftrace) é
// motivo para desconfiar do host; não é demonstração de que a interface mente.
var kernelBreakers = map[string]string{
	"cross.bpf_hidden": "um programa eBPF existe e a enumeração do kernel não o mostrou: " +
		"a interface que responde por eBPF omitiu um objeto que ela mesma entrega quando perguntada direto",
	"cross.hidden_pid": "um PID responde a /proc/<pid> e não apareceu na listagem de /proc: " +
		"a mesma interface deu duas respostas incompatíveis",
	// A tabela de conexões é servida por `tcp4_seq_show`; o netlink responde a
	// mesma pergunta por outro caminho de código. Um socket que só aparece no
	// segundo é a demonstração de que a fonte que o `ss` e o `netstat` leem
	// omitiu o que o kernel entrega quando perguntado de outro jeito.
	"cross.socket_view": "um socket existe pelo netlink e não aparece em /proc/net: " +
		"duas interfaces do mesmo kernel deram respostas incompatíveis sobre a " +
		"tabela de conexões",
	// Genérico DE PROPÓSITO: cross.module_view carrega DUAS evidências — a
	// divergência /proc/modules × /sys/module, e a divergência ftrace × proc (o
	// módulo escondido das duas primeiras que o ftrace ainda delata). A mensagem
	// antiga só descrevia a primeira, e afirmava "aparece em /proc/modules" no
	// caso em que ele NÃO aparece em /proc/modules nenhum — descrevia evidência
	// que não ocorreu.
	"cross.module_view": "interfaces independentes do kernel deram respostas " +
		"incompatíveis sobre os módulos carregados (/proc/modules, /sys/module ou ftrace)",
	// cross.thread_count NÃO entra: ele compara duas visões, mas emite SevWarn
	// (a divergência de contagem de threads tem corrida real e não é
	// reconfirmada), e invalidarAusencias só age sobre SevCritical. Deixá-lo no
	// mapa era um contrato quebrado — estava listado como quebra-confiança e não
	// tinha como quebrar. Só invalida tudo quem PROVA que o kernel mente; um
	// aviso com corrida não prova. Os três acima emitem SevCritical.
}

// runGuarded isola a falha de um check. Um defeito em um não pode calar os
// outros 46 nem falsificar o veredito da execução inteira.
func runGuarded(c Check, f *facts.Facts, e *env.Env) (res Result, panicked string) {
	defer func() {
		if r := recover(); r != nil {
			panicked = fmt.Sprint(r)
			res = Result{}
		}
	}()
	return c.Run(c, f, e), ""
}

// RunOptions são os limites da execução, não a apresentação dela.
type RunOptions struct {
	// Deadline é o teto do `wtf` (SPEC 6.1). Zero = sem teto.
	//
	// O que estourar o prazo vira NÃO VERIFICADO, nunca "nada encontrado": um
	// overview que fica rápido calando check é pior que um overview lento,
	// porque a mentira sai com cara de resposta.
	Deadline time.Time
	// Budget é só para o texto do motivo.
	Budget time.Duration
}

// Run executa a seleção e monta o relatório.
func Run(checks []Check, f *facts.Facts, e *env.Env) *Report {
	return RunWith(checks, f, e, RunOptions{})
}

// RunWith é o Run com limites.
func RunWith(checks []Check, f *facts.Facts, e *env.Env, o RunOptions) *Report {
	// Um Facts vindo de dump ainda não tem índice, e sem ele as buscas por PID
	// e por inode voltam a ser lineares dentro de um laço sobre processos.
	f.Index()

	r := &Report{Coverage: Coverage{Total: len(checks)}}
	// completos guarda os checks que rodaram e nada acharam. Se o kernel se
	// contradisser mais adiante, é a ausência DELES que deixa de valer.
	var completos []Check

	// Coleta VOLÁTIL não sustenta check nenhum, e a recusa é em voz alta.
	//
	// O amostrador do `watch` lê só /proc e sockets porque é nove vezes mais
	// barato. Rodar os checks sobre esse Facts faria um check de unit encontrar
	// zero units e reportar "nada encontrado" — a mentira que esta ferramenta
	// existe para não contar, entrando por uma otimização de custo. Aqui ela
	// vira o que de fato é: NÃO VERIFICADO, com o motivo dito.
	if f.Volatil {
		for _, c := range checks {
			r.Coverage.NotChecked = append(r.Coverage.NotChecked, NotChecked{
				ID: c.ID, Ref: c.Ref, Title: c.Title,
				Reason: "coleta volátil (amostragem do watch): só /proc e sockets foram lidos",
				Manual: []string{"rode `aletheia scan`, que faz a coleta completa"},
			})
		}
		r.Coverage.CollectorGaps = LacunasDeColeta(f)
		return r
	}

	for _, c := range checks {
		if !o.Deadline.IsZero() && time.Now().After(o.Deadline) {
			r.Coverage.NotChecked = append(r.Coverage.NotChecked, NotChecked{
				ID: c.ID, Ref: c.Ref, Title: c.Title,
				Reason: "orçamento de " + o.Budget.String() + " esgotado antes deste check",
				Manual: []string{"rode `aletheia scan`, que não tem teto de tempo"},
			})
			continue
		}
		// SEM COMPARAÇÃO NÃO HÁ PERGUNTA, e ela sai do DENOMINADOR.
		//
		// Um check de drift sobre fatos sem drift não acha nada — e "não achei"
		// aqui significaria "ninguém pediu comparação", que é decisão de quem
		// roda e não lacuna do host. Marcá-lo como lacuna tornaria o exit 0
		// inalcançável em toda execução sem `--drift`, e uma lacuna que nunca
		// fecha é uma que as pessoas aprendem a ignorar (ver NotChecked.Escopo).
		if c.Drift && !f.TemDrift() {
			r.Coverage.NotChecked = append(r.Coverage.NotChecked, NotChecked{
				ID: c.ID, Ref: c.Ref, Title: c.Title,
				Reason: "nenhum estado anterior foi informado: não há o que comparar",
				Escopo: true,
				Manual: []string{"`aletheia drift ANTES.json` ou `--drift ANTES.json` " +
					"compara este host com um retrato dele"},
			})
			r.Coverage.Total--
			continue
		}
		if c.Sources&e.Source == 0 {
			r.Coverage.NotChecked = append(r.Coverage.NotChecked, NotChecked{
				ID: c.ID, Ref: c.Ref, Title: c.Title,
				Reason: "não se aplica ao modo " + e.Source.String(),
			})
			continue
		}
		if missing := e.Missing(c.Requires); missing != 0 {
			nc := NotChecked{
				ID: c.ID, Ref: c.Ref, Title: c.Title,
				Reason: e.Reason(missing),
			}
			// ESCOPO sai do denominador; lacuna fica nele. Ver NotChecked.Escopo.
			if e.SemMecanismo(missing) {
				nc.Escopo = true
				r.Coverage.Total--
			}
			r.Coverage.NotChecked = append(r.Coverage.NotChecked, nc)
			continue
		}

		res, panicked := runGuarded(c, f, e)
		if panicked != "" {
			// Sem isto, o panic aborta o processo com status 2 — que o contrato
			// desta ferramenta define como "CRITICAL: indicador de alta
			// confiança". O modo de falha que ela existe para distinguir
			// ("não consegui ver") sairia como a afirmação positiva mais forte
			// possível, e a automação de frota marcaria o host como
			// comprometido. Um check que quebra vira NÃO VERIFICADO.
			r.Coverage.NotChecked = append(r.Coverage.NotChecked, NotChecked{
				ID: c.ID, Ref: c.Ref, Title: c.Title,
				Reason: "o check falhou durante a execução: " + panicked,
				Manual: []string{"defeito na ferramenta — verifique esta seção do runbook à mão"},
			})
			continue
		}

		// Capacidade opcional ausente vira cobertura degradada, não perda do
		// check inteiro: §7 do runbook roda quase toda sem root, e só /root e
		// /etc/shadow falham.
		if missing := e.Missing(c.Optional); missing != 0 {
			res.Partial = append(res.Partial, e.Reason(missing))
		}

		for i := range res.Findings {
			if res.Findings[i].Origin == "" {
				res.Findings[i].Origin = OriginNative
			}
			if len(res.Findings[i].FalsePositives) == 0 {
				res.Findings[i].FalsePositives = c.FalsePositives
			}
		}
		r.Findings = append(r.Findings, res.Findings...)

		if len(res.Partial) > 0 {
			r.Coverage.Partial = append(r.Coverage.Partial, Partial{
				ID: c.ID, Ref: c.Ref, Reasons: res.Partial,
			})
		} else {
			r.Coverage.Complete++
			completos = append(completos, c)
		}
	}

	r.applyTrustDowngrade()
	// Depois do trust de userland e ANTES da resolução de atores: se o kernel
	// se contradisse, a ausência de achado em todo o resto deixa de ser
	// resposta.
	r.invalidarAusencias(e.Source, completos)
	// Depois de TODOS os checks, porque a resolução precisa ver os achados uns
	// dos outros — é um achado nomear o caminho que autoriza a fusão.
	resolverAtores(r, f)
	// DEPOIS dos atores: o binário resolvido de um `pid=N` também é alvo, e é
	// assim que "o executável deste processo mudou" alcança o achado que fala
	// do processo.
	marcarDrift(r, f)
	// DEPOIS de tudo: a falha de COLETA é o eixo que não passa por check
	// nenhum, e sem ela um relatório pode sair completo tendo lido metade do
	// host.
	r.Coverage.CollectorGaps = LacunasDeColeta(f)
	r.sortFindings()
	return r
}

// lacunasDeColeta move a falha de COLETA para o eixo próprio dela: não é um
// check que deixou de rodar, é dado que não pôde ser lido. Sai da aritmética de
// checks e continua impedindo um veredito de OK.
//
// # Por que ela mora AQUI, e não em quem chama
//
// Ela era uma função de `package main`, chamada à mão nos cinco pontos que
// rodam checks — três deles indiretamente, por `emitir`. Funcionava, e tinha
// duas consequências ruins. A primeira é que um sexto ponto de chamada nasceria
// sem ela, e o sintoma seria uma cobertura silenciosamente melhor que a
// verdade: nada quebra, o número sobe, o veredito melhora. A segunda apareceu
// quando o servidor MCP precisou da mesma cobertura — de `internal/`, aquela
// função não existe, e a saída óbvia seria reescrevê-la. Duas implementações da
// mesma contabilidade divergem em silêncio, que foi exatamente o que aconteceu
// com o agrupamento de achados antes de GroupByIDSev existir.
//
// Montar a cobertura É o que este motor produz. Aqui dentro, ninguém pode
// esquecer.
// Ela é PURA e devolve a lista: quem monta a cobertura é o motor, mas quem só
// precisa saber o que a coleta não leu — o servidor MCP respondendo um dossiê,
// sem rodar check nenhum — não deveria ter de fabricar um Report para descobrir.
func LacunasDeColeta(f *facts.Facts) []string {
	if f == nil || len(f.Partial) == 0 {
		return nil
	}
	// Ordem FIXA: `f.Partial` é mapa, e a lista sai daqui para o JSONL e para a
	// baseline. Sem ordenar, duas execuções idênticas produzem arquivos
	// diferentes — e comparar dois JSONL por diff é como se audita frota.
	coletores := make([]string, 0, len(f.Partial))
	for c := range f.Partial {
		coletores = append(coletores, c)
	}
	sort.Strings(coletores)
	var out []string
	for _, coletor := range coletores {
		for _, razao := range f.Partial[coletor] {
			out = append(out, coletor+": "+razao)
		}
	}
	return out
}

// applyTrustDowngrade marca retroativamente os achados que dependeram de um
// binário do host, quando algo nesta execução mostrou que o userland não é
// confiável.
func (r *Report) applyTrustDowngrade() {
	for _, f := range r.Findings {
		// Só achado CRÍTICO quebra a confiança. O mesmo check pode disparar em
		// injeção legítima — o sandbox do Firefox usa LD_PRELOAD, e nove
		// processos dele fariam toda varredura de desktop imprimir "confiança
		// rebaixada". Rebaixar tudo por suspeita é a mesma perda de sinal que
		// gritar lobo.
		if f.Sev != SevCritical {
			continue
		}
		if reason, ok := trustBreakers[f.ID]; ok {
			r.TrustBroken = append(r.TrustBroken, reason)
		}
	}
	if len(r.TrustBroken) == 0 {
		return
	}
	for i := range r.Findings {
		if r.Findings[i].Origin.IsTool() {
			r.Findings[i].Downgraded = true
		}
	}
}

// invalidarAusencias transforma "não achei" em "não posso saber" depois que o
// kernel demonstrou entregar visões inconsistentes de si mesmo.
//
// É a tese central da ferramenta aplicada um nível acima. A cobertura já
// separa "não achei" de "não consegui olhar"; falta o terceiro estado, que só
// existe quando a AUTORIDADE que respondeu foi desqualificada: olhei, ela
// respondeu, e a resposta não vale.
//
// Vale para o modo LIVE inteiro, e não só para os checks de /proc. Um kernel
// que mente sobre a lista de PIDs também serve o VFS: o `openat` que lê
// /etc/crontab passa por ele. O único modo que sobrevive é o de imagem
// montada, onde o kernel é o do analista (§35.6).
func (r *Report) invalidarAusencias(fonte env.Source, completos []Check) {
	var motivos []string
	for _, f := range r.Findings {
		if f.Sev < SevCritical {
			continue
		}
		if m, ok := kernelBreakers[f.ID]; ok {
			motivos = append(motivos, m)
		}
	}
	if len(motivos) == 0 || fonte != env.SourceLive {
		return
	}
	r.KernelTrustBroken = dedupe(motivos)

	// Os que NÃO produziram achado deixam de contar como completos: a ausência
	// deles foi respondida por uma fonte desqualificada.
	comAchado := map[string]bool{}
	for _, f := range r.Findings {
		comAchado[f.ID] = true
	}
	// TER achado NÃO devolve a completude. Um check que viu 1 processo suspeito
	// provou que ele existe — o positivo continua valendo, e vale mais —, mas
	// "não há OUTROS que o kernel escondeu" já não se sustenta: quem responderia
	// isso é a fonte que acabou de mentir. Então a COBERTURA do check cai para
	// parcial mesmo com achado; só o veredito positivo fica. Antes, quem tinha
	// achado seguia Complete, e o relatório certificava uma enumeração completa
	// que o kernel já não garantia.
	semAchado := "o kernel demonstrou entregar visões inconsistentes de si mesmo " +
		"nesta execução: a AUSÊNCIA de achado aqui foi respondida por ele, e não " +
		"vale como resposta"
	comAchadoRazao := "o kernel demonstrou mentir nesta execução: o ACHADO deste " +
		"check continua valendo, mas a completude da enumeração não — pode haver " +
		"mais que a fonte desqualificada escondeu"
	for _, c := range completos {
		razao := semAchado
		if comAchado[c.ID] {
			razao = comAchadoRazao
		}
		r.Coverage.Partial = append(r.Coverage.Partial, Partial{
			ID: c.ID, Ref: c.Ref, Reasons: []string{razao},
		})
		r.Coverage.Complete--
	}
}

func dedupe(ss []string) []string {
	visto := map[string]bool{}
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		if !visto[s] {
			visto[s] = true
			out = append(out, s)
		}
	}
	return out
}

func (r *Report) sortFindings() {
	sort.SliceStable(r.Findings, func(i, j int) bool {
		a, b := r.Findings[i], r.Findings[j]
		if a.Sev != b.Sev {
			return a.Sev > b.Sev
		}
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		return a.Subject < b.Subject
	})
}

// Irreversible devolve os achados cujo passo seguinte se perde se for pulado.
func (r *Report) Irreversible() []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if f.Irreversible {
			out = append(out, f)
		}
	}
	return out
}

// Counts devolve a contagem por severidade.
func (r *Report) Counts() (critical, warn, manual, info int) {
	for _, f := range r.Findings {
		switch f.Sev {
		case SevCritical:
			critical++
		case SevWarn:
			warn++
		case SevManual:
			manual++
		case SevInfo:
			info++
		}
	}
	return
}

// Exit implementa SPEC 7.9: zero exige achado nenhum E cobertura completa.
// Uma execução sem root, sem debugfs e sem bpftool NÃO sai zero — seria a
// ferramenta contradizendo o próprio nome.
func (r *Report) Exit() int {
	crit, warn, _, _ := r.Counts()
	switch {
	case crit > 0:
		return 2
	case warn > 0:
		return 1
	case r.Coverage.Incomplete():
		return 1
	case r.CriticosForaDaJanela > 0:
		// O crítico existe e foi recortado a pedido: o relatório fica limpo, o
		// exit NÃO. Quem escolheu a janela lê o bloco JANELA; quem lê só o exit
		// continua sabendo que há algo para olhar.
		return 1
	default:
		return 0
	}
}

// Verdict é a palavra do RESULT.
func (r *Report) Verdict() string {
	crit, warn, _, _ := r.Counts()
	switch {
	case crit > 0:
		return "CRITICAL"
	case warn > 0:
		return "WARNING"
	case r.Coverage.Incomplete(), r.CriticosForaDaJanela > 0:
		return "INCOMPLETE"
	default:
		return "OK"
	}
}

// GroupedFindings agrupa por ID para a saída compacta: "8× exe em local
// suspeito" no lugar de oito linhas. O tamanho do relatório deixa de crescer
// com o tamanho do incidente.
type Group struct {
	Findings []Finding
}

func (g Group) First() Finding { return g.Findings[0] }
func (g Group) N() int         { return len(g.Findings) }

// Subjects resume os alvos do grupo.
func (g Group) Subjects(max int) string {
	var ss []string
	for i, f := range g.Findings {
		if i >= max {
			ss = append(ss, "…")
			break
		}
		if f.Subject != "" {
			ss = append(ss, f.Subject)
		}
	}
	return strings.Join(ss, ", ")
}

// Grouped compacta por ID E SEVERIDADE.
//
// A severidade entra na chave porque agrupar só por ID juntava um crítico e um
// aviso do mesmo check e imprimia a marca do primeiro valendo pelos dois: o
// cabeçalho dizia "1 crítico" e a linha dizia "⛔ 2×". Quem lê acredita na linha.
func (r *Report) Grouped() []Group { return GroupByIDSev(r.Findings) }

// GroupByIDSev é a única implementação de agrupamento. Existia uma cópia no
// pacote de relatório com semântica diferente, e as duas divergiram em silêncio.
func GroupByIDSev(fs []Finding) []Group {
	type chave struct {
		id  string
		sev Severity
	}
	var order []chave
	por := map[chave][]Finding{}
	for _, f := range fs {
		k := chave{f.ID, f.Sev}
		if _, ok := por[k]; !ok {
			order = append(order, k)
		}
		por[k] = append(por[k], f)
	}
	out := make([]Group, 0, len(order))
	for _, k := range order {
		out = append(out, Group{Findings: por[k]})
	}
	return out
}

// SubjectGroup são os achados que apontam para o MESMO alvo — o mesmo pid, o
// mesmo arquivo.
type SubjectGroup struct {
	Subject  string
	Findings []Finding
}

// Sev é a maior severidade do grupo: um implante com três avisos e um crítico
// é um crítico.
//
// E é MÁXIMO, não soma. A tentação seguinte, depois que o ator passou a juntar
// três avisos num alvo só, é promover o grupo por contagem — "três sinais no
// mesmo binário é crítico". Uma medição mata a ideia: um agente compilado
// localmente em /usr/local produz exatamente esses três, e legitimamente —
// nenhum pacote o reivindica, ele fala com a internet, e tem uma unit que o
// inicia. Promover por contagem quebraria o exit code em todo host que instala
// software fora do gerenciador de pacotes, que é a maioria dos servidores.
//
// A correlação melhora a LEITURA, não a acusação. Os sinais que não têm
// história legítima — caminho oculto, atributo imutável, exe apagado, memfd,
// rastro removido — já entram como críticos por conta própria, e sobem o grupo
// pelo máximo sem precisar de aritmética nova.
func (g SubjectGroup) Sev() Severity {
	s := SevInfo
	for _, f := range g.Findings {
		if f.Sev > s {
			s = f.Sev
		}
	}
	return s
}

// Refs devolve as seções do runbook envolvidas, sem repetir.
func (g SubjectGroup) Refs() []string {
	var out []string
	seen := map[string]bool{}
	for _, f := range g.Findings {
		if f.Ref != "" && !seen[f.Ref] {
			seen[f.Ref] = true
			out = append(out, f.Ref)
		}
	}
	return out
}

// Correlate separa os achados em duas leituras:
//
//	grupos    o mesmo ALVO visto por checks diferentes — "um implante com
//	          quatro sinais", que é a forma de um incidente de verdade
//	resto     todo o resto, para a compactação por ID de sempre
//
// Existe porque um comprometimento real dispara vários checks no mesmo pid, e
// listá-los soltos conta quatro fatos onde há UMA história. O operador precisa
// da história para decidir; os fatos soltos ele já teria com grep.
//
// O corte é em DOIS checks distintos, não em dois achados: o mesmo check
// disparando duas vezes no mesmo alvo é repetição, não correlação.
//
// Isto é decisão de EXIBIÇÃO. O JSONL nunca é afetado, senão a agregação de
// frota passaria a depender de como o relatório foi renderizado (SPEC 7.1).
func (r *Report) Correlate() ([]SubjectGroup, []Finding) {
	porAlvo := map[string][]Finding{}
	posDoAlvo := map[string][]int{}
	var ordem []string
	for i, f := range r.Findings {
		if f.Subject == "" || f.Sev == SevInfo {
			continue
		}
		// O ATOR vence o sujeito quando existe: `pid=17`, `sshd.service` e o
		// caminho do binário são três sujeitos de UM alvo, e sem esta linha o
		// invasor que espalha sinais por tipos diferentes de sujeito nunca
		// forma grupo. Vazio é o normal, e aí é o sujeito de sempre.
		alvo := f.Subject
		if f.Ator != "" {
			alvo = f.Ator
		}
		if _, ok := porAlvo[alvo]; !ok {
			ordem = append(ordem, alvo)
		}
		porAlvo[alvo] = append(porAlvo[alvo], f)
		posDoAlvo[alvo] = append(posDoAlvo[alvo], i)
	}

	// agrupado é marcado por POSIÇÃO, não por alvo. Marcar por alvo descartava
	// do resto qualquer achado que compartilhasse o alvo sem ter entrado no
	// grupo — um INFO, por exemplo, sumia do relatório inteiro.
	agrupado := map[int]bool{}
	var grupos []SubjectGroup
	for _, subj := range ordem {
		fs := porAlvo[subj]
		ids := map[string]bool{}
		for _, f := range fs {
			ids[f.ID] = true
		}
		if len(ids) < 2 {
			continue
		}
		for _, i := range posDoAlvo[subj] {
			agrupado[i] = true
		}
		grupos = append(grupos, SubjectGroup{Subject: subj, Findings: fs})
	}

	// Mais severo primeiro; empatando, quem tem mais sinais.
	sort.SliceStable(grupos, func(i, j int) bool {
		if a, b := grupos[i].Sev(), grupos[j].Sev(); a != b {
			return a > b
		}
		return len(grupos[i].Findings) > len(grupos[j].Findings)
	})

	var resto []Finding
	for i, f := range r.Findings {
		if !agrupado[i] {
			resto = append(resto, f)
		}
	}
	return grupos, resto
}
