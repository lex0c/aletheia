package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/lex0c/aletheia/internal/activity"
	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/dump"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
	"github.com/lex0c/aletheia/internal/progress"
	"github.com/lex0c/aletheia/internal/report"
)

// runActivity reconstrói o que aconteceu no host — e não conclui nada.
//
// O `scan` responde "há evidência de comprometimento AGORA?" e o `wtf` responde
// "por onde eu começo?". Esta é a terceira pergunta, e ela aparece toda vez que
// alguém entra numa VM depois de um alerta: *o que houve aqui?*
//
// Hoje ela se responde encadeando `last`, `lastb`, `who`, `journalctl`,
// `ausearch` e `grep`, e cruzando a saída na cabeça. O que este comando
// acrescenta sobre aquilo:
//
//	junta       o registro binário e o log em texto viram UM evento, com as
//	            duas testemunhas nomeadas — e a força da ligação declarada
//	declara     toda saída diz até onde do passado alguém olhou, POR FONTE
//	filtra      janela, conta, origem e tipo, sobre a mesma linha do tempo
//
// Ele NÃO tem severidade e NÃO tem veredito: sai 0 sempre, salvo erro de
// invocação. É a mesma separação que o `info` sustenta — juntar os fatos sem
// transformar o dossiê em acusação. Quem acusa é o `scan`, que traz os falsos
// positivos junto.
func runActivity(args []string) int {
	fs := flag.NewFlagSet("activity", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var (
		since   = fs.String("since", "24h", "janela: duração (24h, 7d) ou instante (2026-08-25T03:00Z)")
		until   = fs.String("until", "", "fim da janela")
		around  = fs.String("around", "", "centrar a janela num instante (o horário do alerta)")
		window  = fs.Duration("window", 15*time.Minute, "raio do --around")
		user    = fs.String("user", "", "só os eventos desta conta")
		ip      = fs.String("ip", "", "só os eventos desta origem")
		kind    = fs.String("kind", "", "só este tipo, casado por PREFIXO: auth, auth.login, privilege.sudo")
		groupBy = fs.String("group-by", "", "tabela agregada por ip | user | kind")
		resumo  = fs.Bool("summary", false, "só os agregados, sem a lista de eventos")
		de      = fs.String("from", "", "responder sobre um retrato (o arquivo do collect)")
		root    = fs.String("root", "", "responder sobre uma imagem montada em PATH")
		jsonOut = fs.String("json", "", "a mesma reconstrução em JSON ('-' = stdout)")
		noProg  = fs.Bool("no-progress", false, "não mostrar o progresso da coleta")
	)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	if err := fs.Parse(args); err != nil {
		return 3
	}
	if recusaPosicional(fs, "activity") {
		return 3
	}
	if *groupBy != "" && !eixoValido(*groupBy) {
		fmt.Fprintf(os.Stderr, "activity --group-by: %q não é um eixo — use ip, user ou kind\n", *groupBy)
		return 3
	}
	// RECUSAR, e não devolver lista vazia. Um --kind com erro de digitação
	// caía na mensagem tranquilizadora de "nenhum evento no recorte pedido",
	// que é a pior resposta possível para um erro de invocação.
	if *kind != "" && !activity.PrefixoValido(*kind) {
		fmt.Fprintf(os.Stderr, "activity --kind: %q não casa tipo nenhum. Conhecidos:\n", *kind)
		for _, k := range activity.TodosOsKinds {
			fmt.Fprintf(os.Stderr, "  %s\n", k)
		}
		return 3
	}
	if *window <= 0 {
		fmt.Fprintln(os.Stderr, "activity --window: o raio precisa ser positivo")
		return 3
	}
	if *root != "" {
		if fi, err := os.Stat(*root); err != nil || !fi.IsDir() {
			fmt.Fprintf(os.Stderr, "--root: %s não é um diretório acessível\n", *root)
			return 3
		}
	}

	f, e, code := fatosParaAtividade(*de, *root, *noProg)
	if code != 0 {
		return code
	}
	defer e.Close()

	// A janela é medida contra o relógio da COLETA, e não contra o de agora.
	//
	// Num `--from` de um retrato de três semanas atrás, `--since 24h` significa
	// as 24 horas anteriores ÀQUELE retrato: medir contra hoje devolveria lista
	// vazia sobre um dump cheio de eventos — silêncio com cara de resposta.
	agora := e.Now.UTC()
	fl, solicitado, code := recorte(*since, *until, *around, *window, agora, fs)
	if code != 0 {
		return code
	}
	fl.User, fl.IP, fl.Kind = *user, *ip, *kind

	ev, fontes := activity.Linha(f, fl)

	// Com `--json -`, o JSON é o produto do stdout e o texto vai para stderr: é
	// a convenção do scan e do info, e é o que faz `… --json - > x.json`
	// produzir um arquivo válido.
	w := io.Writer(os.Stdout)
	if *jsonOut == "-" {
		w = os.Stderr
	}
	cor := corHabilitada(w)

	fmt.Fprintf(w, "%s · %s · %s\n\n",
		report.Safe(nz(f.Host.Hostname, "host-desconhecido")),
		report.Safe(nz(f.CollectedAt, "sem data")), f.Source)

	var grupos []activity.Grupo
	sumario := activity.Sumarizar(ev)
	switch {
	case *groupBy != "":
		grupos = activity.Agrupar(ev, *groupBy)
		report.ActivityGrupos(w, grupos, *groupBy, cor)
	case *resumo:
		report.ActivitySumario(w, sumario, cor)
	default:
		report.ActivityLinha(w, ev, cor)
	}
	// O rodapé sai em TODAS as saídas, e é obrigatório: uma lista de eventos sem
	// o alcance de quem os testemunhou é a forma mais convincente de afirmar que
	// nada aconteceu.
	report.ActivityCobertura(w, fontes, f, agora, solicitado, fl.Desde, cor)

	return comJSONAtividade(*jsonOut, saidaDeAtividade{
		Solicitado: solicitado, Desde: fl.Desde, Ate: fl.Ate,
		User: fl.User, IP: fl.IP, Kind: fl.Kind, Eixo: *groupBy,
		Fontes: fontes, Eventos: ev, Grupos: grupos, Sumario: sumario,
	})
}

func eixoValido(s string) bool {
	switch s {
	case activity.PorOrigem, activity.PorUsuario, activity.PorKind:
		return true
	}
	return false
}

// recorte traduz as flags de tempo numa janela. `--around` é a flag de
// incidente: descobre-se "o alerta foi 03:17" e pergunta-se o que houve em
// volta.
//
// Combinar `--around` com `--since`/`--until` é RECUSADO, e não interpretado:
// as duas formas descrevem janelas diferentes, e escolher uma em silêncio
// devolveria um recorte que não é o que ninguém pediu. É a mesma recusa que
// ParseJanela faz com um formato que não reconhece.
func recorte(since, until, around string, raio time.Duration, agora time.Time,
	fs *flag.FlagSet) (activity.Filtro, string, int) {

	usou := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { usou[f.Name] = true })

	if around != "" {
		if usou["since"] || usou["until"] {
			fmt.Fprintln(os.Stderr, "activity: --around não combina com --since/--until — "+
				"os dois descrevem janelas diferentes, e escolher uma em silêncio "+
				"devolveria um recorte que ninguém pediu")
			return activity.Filtro{}, "", 3
		}
		c, err := check.ParseJanela(around, agora)
		if err != nil || !c.Ativa {
			fmt.Fprintf(os.Stderr, "activity --around: %v\n", check.ErrJanela)
			return activity.Filtro{}, "", 3
		}
		fl := activity.Filtro{
			Desde: c.Desde.Add(-raio).UTC().Format(time.RFC3339),
			Ate:   c.Desde.Add(raio).UTC().Format(time.RFC3339),
		}
		return fl, "--around " + around + " --window " + activity.Duracao(raio), 0
	}

	fl := activity.Filtro{}
	rotulo := "tudo"

	// O `--since` PADRÃO não se aplica quando o operador pediu só um `--until`.
	//
	// Com ele herdado, `--until 2026-08-01` virava a janela [agora-24h,
	// 2026-08-01] — invertida, sempre vazia, e respondida com "nenhum evento no
	// recorte pedido" e exit 0. O operador era mandado ao rodapé de cobertura
	// para explicar um silêncio que era da invocação, não do host.
	if usou["since"] || !usou["until"] {
		j, err := check.ParseJanela(since, agora)
		if err != nil {
			fmt.Fprintf(os.Stderr, "activity --since: %v\n", err)
			return activity.Filtro{}, "", 3
		}
		if j.Ativa {
			fl.Desde = j.Desde.Format(time.RFC3339)
			rotulo = "--since " + since
		}
	}
	if until != "" {
		u, err := check.ParseJanela(until, agora)
		if err != nil {
			fmt.Fprintf(os.Stderr, "activity --until: %v\n", err)
			return activity.Filtro{}, "", 3
		}
		fl.Ate = u.Desde.Format(time.RFC3339)
		rotulo += " --until " + until
	}
	// Janela invertida é ERRO DE INVOCAÇÃO, e recusá-la é a mesma disciplina
	// que ParseJanela aplica a um formato que não reconhece: interpretar em
	// silêncio devolveria uma resposta vazia com cara de resposta.
	if fl.Desde != "" && fl.Ate != "" && fl.Desde > fl.Ate {
		fmt.Fprintf(os.Stderr, "activity: a janela está invertida — %s começa "+
			"DEPOIS de %s, e nenhum evento pode cair nela\n", fl.Desde, fl.Ate)
		return activity.Filtro{}, "", 3
	}
	return fl, strings.TrimSpace(rotulo), 0
}

// fatosParaAtividade é irmão de fatosParaInfo, com uma diferença que define o
// comando: a coleta VIVA aqui é o perfil estreito das testemunhas do passado.
//
// Rodar facts.Collect para reconstruir uma linha do tempo custaria a varredura
// de filesystem inteira — e transformaria o `activity` num segundo `scan` com
// outro nome.
func fatosParaAtividade(de, root string, noProg bool) (*facts.Facts, *env.Env, int) {
	if de != "" {
		d, err := dump.Carregar(de)
		if err != nil {
			fmt.Fprintf(os.Stderr, "activity --from: %v\n", err)
			return nil, nil, 3
		}
		e, err := d.Env(nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "activity: %v\n", err)
			return nil, nil, 3
		}
		return d.Facts, e, 0
	}
	inicio := time.Now()
	aoInterromper()
	e := env.Probe(env.Options{Root: root, Version: version})
	if e.Source == env.SourceImage && !e.Has(env.CapFilesystem) {
		fmt.Fprintf(os.Stderr, "não foi possível abrir --root com raiz travada: %v\n", e.RootErr)
		e.Close()
		return nil, nil, 3
	}
	prog := progress.New(os.Stderr, inicio, noProg, corHabilitada(os.Stderr))
	e.Progress = prog
	f := facts.CollectAtividade(e)
	prog.Stop()
	return f, e, 0
}

// saidaDeAtividade é o documento do --json. Ele carrega os eventos E a
// cobertura, porque separá-los permitiria consumir a lista sem o alcance dela.
type saidaDeAtividade struct {
	Solicitado string `json:"window_requested"`
	Desde      string `json:"window_since,omitempty"`
	Ate        string `json:"window_until,omitempty"`
	User       string `json:"filter_user,omitempty"`
	IP         string `json:"filter_remote_ip,omitempty"`
	Kind       string `json:"filter_kind,omitempty"`
	// Eixo e Grupos são o --group-by. Sem eles a saída de MÁQUINA respondia uma
	// pergunta diferente da que a flag fez: o terminal mostrava a tabela
	// agregada e o JSON entregava a lista de eventos crua.
	Eixo    string            `json:"group_by,omitempty"`
	Fontes  []activity.Fonte  `json:"sources"`
	Eventos []activity.Evento `json:"events"`
	Grupos  []activity.Grupo  `json:"groups,omitempty"`
	Sumario activity.Sumario  `json:"summary"`
}

func comJSONAtividade(destino string, doc saidaDeAtividade) int {
	if destino == "" {
		return 0
	}
	return comJSON(destino, doc, 0)
}
