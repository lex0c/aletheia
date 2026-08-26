package activity

import (
	"strings"
	"testing"
	"time"

	"github.com/lex0c/aletheia/internal/facts"
)

func at(h, m int) string {
	return agora.Add(-(time.Duration(h)*time.Hour + time.Duration(m)*time.Minute)).
		Format(carimbo)
}

// fonteAuth declara o auth.log lido e com o parser entendendo o arquivo. É o
// estado normal, e os testes que querem o contrário o degradam.
func fonteAuth(desde, ate string) facts.FonteDeLog {
	return facts.FonteDeLog{
		Path: "/var/log/auth.log", Familias: []string{"auth"}, Estado: facts.FonteLida,
		CobertoDesde: desde, CobertoAte: ate,
		LinhasCandidatas: 100, LinhasReconhecidas: 90,
	}
}

func hostComLog(logins []facts.Login, evs []facts.EventoDeLog, fontes ...facts.FonteDeLog) *facts.Facts {
	f := hostCom(logins)
	f.EventosDeLog = evs
	f.FontesDeLog = fontes
	f.LogEstado = facts.LogColetado
	f.FusoDoAlvoLido = true
	return f
}

// O produto do comando: as duas testemunhas do MESMO login viram um evento só,
// e a fusão entrega o que nenhuma das duas tem sozinha — o método e o
// fingerprint vêm do texto, o instante exato vem do epoch do utmp.
func TestLoginComMesmoPIDFundeNumEventoSo(t *testing.T) {
	f := hostComLog(
		[]facts.Login{{Tipo: facts.TipoLoginUsuario, User: "deploy",
			Origem: "185.44.1.7", Linha: "pts/2", PID: 4211, QuandoU: at(2, 0)}},
		[]facts.EventoDeLog{{Kind: "auth.accepted", At: at(2, 0), AtKnown: true,
			User: "deploy", RemoteIP: "185.44.1.7", PID: 4211,
			Metodo: "publickey", Fingerprint: "SHA256:abc", File: "/var/log/auth.log"}},
		fonteAuth(at(48, 0), at(0, 0)),
	)

	ev, _ := Linha(f, Filtro{})
	if len(ev) != 1 {
		t.Fatalf("saíram %d eventos, queria 1 — o mesmo login em duas fontes é "+
			"UM evento com duas testemunhas: %+v", len(ev), ev)
	}
	e := ev[0]
	if e.Fusao != FusaoIdentidade {
		t.Errorf("Fusao = %v, queria identidade: o ut_pid do wtmp É o pid do "+
			"sshd, e a ligação é por identificador", e.Fusao)
	}
	if len(e.Testemunhas) != 2 {
		t.Errorf("Testemunhas = %v, queria wtmp e o log", e.Testemunhas)
	}
	if e.Metodo != "publickey" || e.Fingerprint != "SHA256:abc" {
		t.Errorf("o que SÓ o log tem não sobreviveu à fusão: metodo=%q fp=%q",
			e.Metodo, e.Fingerprint)
	}
	if e.Linha != "pts/2" {
		t.Errorf("a tty, que só o utmp tem, não sobreviveu: %q", e.Linha)
	}
	if e.AtConfianca != DataExata {
		t.Errorf("AtConfianca = %q: o epoch do utmp não infere ano nem fuso, e é "+
			"ele que deve mandar no tempo do evento fundido", e.AtConfianca)
	}
}

// PID é identidade DENTRO de uma janela, nunca globalmente.
//
// Em host com uptime grande e muitos sshd o número recicla. Sem a guarda, um
// login de terça funde com uma linha de quinta que herdou o pid — e a linha do
// tempo passa a afirmar uma sessão que nunca existiu.
func TestPIDRecicladoNaoFunde(t *testing.T) {
	f := hostComLog(
		[]facts.Login{{Tipo: facts.TipoLoginUsuario, User: "deploy",
			Origem: "10.0.0.9", PID: 4211, QuandoU: at(5, 0)}},
		[]facts.EventoDeLog{{Kind: "auth.accepted", At: at(2, 0), AtKnown: true,
			User: "outro", RemoteIP: "10.0.0.8", PID: 4211, File: "/var/log/auth.log"}},
		fonteAuth(at(48, 0), at(0, 0)),
	)
	ev, _ := Linha(f, Filtro{})
	if len(ev) != 2 {
		t.Fatalf("saíram %d eventos, queria 2: três horas separam os dois "+
			"registros, e o pid igual ali é reciclagem", len(ev))
	}
	for _, e := range ev {
		if e.Fusao == FusaoIdentidade {
			t.Errorf("evento fundido por pid fora da guarda: %+v", e)
		}
	}
}

// Sem o fuso do ALVO, a data do log foi suposta em UTC e o erro real chega a
// horas. Dois logins legítimos do mesmo usuário e da mesma origem — um de manhã
// e outro à noite — colapsariam num evento só, e um deles sumiria da
// reconstrução. Ligação fraca RELACIONA; nunca funde.
func TestSemFusoDoAlvoOMesmoDiaRelacionaMasNaoFunde(t *testing.T) {
	f := hostComLog(
		[]facts.Login{{Tipo: facts.TipoLoginUsuario, User: "deploy",
			Origem: "10.0.0.9", QuandoU: at(11, 0)}},
		[]facts.EventoDeLog{{Kind: "auth.accepted", At: at(2, 0), AtKnown: true,
			AtFusoInferido: true, User: "deploy", RemoteIP: "10.0.0.9",
			File: "/var/log/auth.log"}},
		fonteAuth(at(48, 0), at(0, 0)),
	)
	f.FusoDoAlvoLido = false

	ev, _ := Linha(f, Filtro{})
	if len(ev) != 2 {
		t.Fatalf("saíram %d eventos, queria 2: sem o fuso do alvo, 'mesmo dia' "+
			"não prova que os dois registros são o mesmo login", len(ev))
	}
	for _, e := range ev {
		if e.Fusao != FusaoRelacionada {
			t.Errorf("os dois precisam sair marcados como RELACIONADOS — a "+
				"ligação existe, o que não existe é a prova de identidade: %+v", e)
		}
		if len(e.Relacionados) == 0 {
			t.Errorf("sem a referência cruzada, quem lê a linha do tempo vê dois "+
				"eventos soltos: %+v", e)
		}
	}
}

// A ausência da outra testemunha só vira DIVERGÊNCIA sob condições estreitas, e
// a estreiteza é a entrega: manipulação de log, rotação, parser cego,
// configuração de syslog e ssh não-interativo produzem todos a MESMA forma.
func TestDivergenciaExigeAsCondicoes(t *testing.T) {
	// Um login de rede no wtmp que o auth.log não registrou, com o auth.log
	// cobrindo o instante, sem lacuna, e já tendo registrado login de rede.
	base := func() *facts.Facts {
		return hostComLog(
			[]facts.Login{
				{Tipo: facts.TipoLoginUsuario, User: "outro", Origem: "10.0.0.1",
					PID: 900, QuandoU: at(20, 0)},
				{Tipo: facts.TipoLoginUsuario, User: "deploy", Origem: "10.0.0.9",
					PID: 4211, QuandoU: at(2, 0)},
			},
			[]facts.EventoDeLog{{Kind: "auth.accepted", At: at(20, 0), AtKnown: true,
				User: "outro", RemoteIP: "10.0.0.1", PID: 900, File: "/var/log/auth.log"}},
			fonteAuth(at(48, 0), at(0, 0)),
		)
	}

	acha := func(t *testing.T, f *facts.Facts, user string) Evento {
		t.Helper()
		ev, _ := Linha(f, Filtro{User: user})
		if len(ev) != 1 {
			t.Fatalf("queria 1 evento de %s, veio %d", user, len(ev))
		}
		return ev[0]
	}

	t.Run("todas valem", func(t *testing.T) {
		if got := acha(t, base(), "deploy").Divergente; got != DivergenteAusente {
			t.Errorf("Divergente = %q, queria %q", got, DivergenteAusente)
		}
	})

	t.Run("fora da cobertura não afirma nada", func(t *testing.T) {
		f := base()
		// O auth.log só alcança os últimos 30 minutos: o login de 2h atrás está
		// antes dele, e a ausência ali é ROTAÇÃO.
		f.FontesDeLog[0] = fonteAuth(at(0, 30), at(0, 0))
		if got := acha(t, f, "deploy").Divergente; got != "" {
			t.Errorf("Divergente = %q: fora da cobertura não há pergunta, e "+
				"marcar poria ressalva em todo host cujo wtmp guarda mais "+
				"passado que o auth.log — ou seja, todos", got)
		}
	})

	t.Run("lacuna declarada pelos FATOS não confirma", func(t *testing.T) {
		f := base()
		s := fonteAuth(at(48, 0), at(0, 0))
		// Quem decide se o parser entendeu o arquivo é a camada de fatos
		// (declaraCapacidadeDoParser), com limiar calibrado. Aqui só se LÊ o
		// veredito dela.
		s.Lacuna = "/var/log/auth.log: de 400 linha(s) … só 3 foram compreendidas"
		f.FontesDeLog[0] = s
		if got := acha(t, f, "deploy").Divergente; got != DivergenteNaoConfirmado {
			t.Errorf("Divergente = %q, queria %q: com lacuna declarada na fonte, "+
				"a ausência pode ser do parser e não do host",
				got, DivergenteNaoConfirmado)
		}
	})

	t.Run("fonte que nunca produziu este tipo não confirma", func(t *testing.T) {
		f := base()
		f.EventosDeLog = []facts.EventoDeLog{{Kind: "auth.sudo", At: at(20, 0),
			AtKnown: true, User: "outro", File: "/var/log/auth.log"}}
		if got := acha(t, f, "deploy").Divergente; got != DivergenteNaoConfirmado {
			t.Errorf("Divergente = %q, queria %q", got, DivergenteNaoConfirmado)
		}
	})
}

// A CONFIANÇA DA DATA da cobertura decide se a ausência é afirmável.
//
// O ano de uma linha de syslog tradicional é inferido do mtime do arquivo, e um
// `touch -d` no rotacionado reescreve o mtime: o intervalo de cobertura passa a
// ter as pontas escolhidas por quem se quer acusar, e o erro é de MESES.
// Afirmar "esta fonte cobria o instante e não registrou" sobre isso é entregar
// a afirmação mais forte do comando ao alvo.
func TestCoberturaComDataInferidaNaoSustentaAcusacao(t *testing.T) {
	base := func(inferido bool) *facts.Facts {
		s := fonteAuth(at(48, 0), at(0, 0))
		s.CoberturaAnoInferido = inferido
		return hostComLog(
			[]facts.Login{
				{Tipo: facts.TipoLoginUsuario, User: "outro", Origem: "10.0.0.1",
					PID: 900, QuandoU: at(20, 0)},
				{Tipo: facts.TipoLoginUsuario, User: "deploy", Origem: "10.0.0.9",
					PID: 4211, QuandoU: at(2, 0)},
			},
			[]facts.EventoDeLog{{Kind: "auth.accepted", At: at(20, 0), AtKnown: true,
				User: "outro", RemoteIP: "10.0.0.1", PID: 900, File: "/var/log/auth.log"}},
			s)
	}
	pega := func(t *testing.T, f *facts.Facts) string {
		t.Helper()
		ev, _ := Linha(f, Filtro{User: "deploy"})
		if len(ev) != 1 {
			t.Fatalf("queria 1 evento, veio %d", len(ev))
		}
		return ev[0].Divergente
	}
	if got := pega(t, base(false)); got != DivergenteAusente {
		t.Errorf("com data exata: %q, queria %q", got, DivergenteAusente)
	}
	if got := pega(t, base(true)); got != DivergenteNaoConfirmado {
		t.Errorf("com ano INFERIDO: %q, queria %q — o intervalo tem as pontas "+
			"escolhidas pelo alvo", got, DivergenteNaoConfirmado)
	}
}

// A capacidade de registrar tem de vir da MESMA fonte que cobre o instante.
// Com a chave só por tipo, um auth.log que registrou logins ontem "provava" a
// capacidade de outro arquivo que cobre hoje.
func TestCapacidadeVemDaFonteQueCobreOInstante(t *testing.T) {
	// O arquivo que COBRE o instante nunca registrou login aceito; quem
	// registrou foi outro, que não cobre.
	velho := fonteAuth(at(200, 0), at(100, 0))
	velho.Path = "/var/log/auth.log.1"
	f := hostComLog(
		[]facts.Login{
			{Tipo: facts.TipoLoginUsuario, User: "outro", Origem: "10.0.0.1",
				QuandoU: at(150, 0)},
			{Tipo: facts.TipoLoginUsuario, User: "deploy", Origem: "10.0.0.9",
				QuandoU: at(2, 0)},
		},
		[]facts.EventoDeLog{{Kind: "auth.accepted", At: at(150, 0), AtKnown: true,
			User: "outro", RemoteIP: "10.0.0.1", File: "/var/log/auth.log.1"}},
		fonteAuth(at(48, 0), at(0, 0)), velho)

	ev, _ := Linha(f, Filtro{User: "deploy"})
	if len(ev) != 1 {
		t.Fatalf("queria 1 evento, veio %d", len(ev))
	}
	if ev[0].Divergente == DivergenteAusente {
		t.Error("a acusação se apoiou em dois arquivos: a capacidade veio do " +
			"rotacionado e a cobertura do vivo")
	}
}

// AMBIGUIDADE SE DECLARA, NÃO SE RESOLVE. Dois logins do mesmo usuário e da
// mesma origem a 50s um do outro cabem os dois em ±90s de uma linha de log, e a
// versão anterior escolhia o mais próximo — deixando a identidade forense
// depender da ordem de iteração.
func TestFusaoTemporalAmbiguaNaoEscolhe(t *testing.T) {
	f := hostComLog(
		[]facts.Login{
			{Tipo: facts.TipoLoginUsuario, User: "deploy", Origem: "10.0.0.9", QuandoU: at(2, 0)},
			{Tipo: facts.TipoLoginUsuario, User: "deploy", Origem: "10.0.0.9", QuandoU: at(2, 1)},
		},
		[]facts.EventoDeLog{{Kind: "auth.accepted", At: at(2, 0), AtKnown: true,
			User: "deploy", RemoteIP: "10.0.0.9", File: "/var/log/auth.log"}},
		fonteAuth(at(48, 0), at(0, 0)))

	ev, _ := Linha(f, Filtro{})
	if len(ev) != 3 {
		t.Fatalf("saíram %d eventos, queria 3: com dois candidatos compatíveis a "+
			"identidade é ambígua, e escolher um apagaria o outro", len(ev))
	}
	for _, e := range ev {
		if e.Fusao == FusaoIdentidade || e.Fusao == FusaoTemporal {
			t.Errorf("houve fusão sobre par ambíguo: %+v", e)
		}
	}
}

// Sem o fuso do ALVO lido não há fusão NENHUMA — nem por pid. A igualdade do
// número não depende do relógio, mas a garantia de NÃO-RECICLAGEM depende: num
// bastion, o pid 4211 de manhã e o da noite são dois processos.
func TestSemFusoNemMesmoOPIDFunde(t *testing.T) {
	f := hostComLog(
		[]facts.Login{{Tipo: facts.TipoLoginUsuario, User: "deploy",
			Origem: "10.0.0.9", PID: 4211, QuandoU: at(2, 0)}},
		[]facts.EventoDeLog{{Kind: "auth.accepted", At: at(2, 0), AtKnown: true,
			AtFusoInferido: true, User: "deploy", RemoteIP: "10.0.0.9", PID: 4211,
			File: "/var/log/auth.log"}},
		fonteAuth(at(48, 0), at(0, 0)))
	f.FusoDoAlvoLido = false

	ev, _ := Linha(f, Filtro{})
	if len(ev) != 2 {
		t.Fatalf("saíram %d eventos, queria 2: fundir removeria a segunda "+
			"representação da linha do tempo", len(ev))
	}
	for _, e := range ev {
		if e.Fusao == FusaoIdentidade {
			t.Errorf("fusão por identidade sem relógio confiável: %+v", e)
		}
	}
}

// RECUSA NUNCA É DIVERGÊNCIA, e este é o falso positivo mais caro que a
// primeira versão produzia.
//
// btmp e auth.log não são 1:1: uma conexão de bot escreve N linhas de log —
// auth.failed e auth.invalid_user viram o mesmo tipo aqui — contra um registro
// de btmp. Num host com SSH exposto isso saía como milhares de acusações de
// adulteração de log por hora, sobre o clima da internet.
func TestRecusaNuncaViraDivergencia(t *testing.T) {
	var evs []facts.EventoDeLog
	for i := 0; i < 5; i++ {
		evs = append(evs, facts.EventoDeLog{
			Kind: "auth.invalid_user", At: at(2, i), AtKnown: true,
			User: "admin", RemoteIP: "185.44.1.7", File: "/var/log/auth.log"})
	}
	f := hostComLog(
		[]facts.Login{{Tipo: facts.TipoLoginUsuario, User: "root",
			Origem: "185.44.1.7", Falhou: true, QuandoU: at(2, 30)}},
		evs, fonteAuth(at(48, 0), at(0, 0)))

	ev, _ := Linha(f, Filtro{})
	for _, e := range ev {
		if e.Divergente != "" {
			t.Errorf("recusa saiu marcada como %q: btmp e auth.log não têm "+
				"correspondência 1:1, e a falta de um par não diz nada — "+
				"%+v", e.Divergente, e)
		}
	}
}

// LOGIN DE CONSOLE NÃO É ADULTERAÇÃO DE LOG.
//
// O parser só produz auth.accepted do prefixo "Accepted " do sshd. login(1) em
// tty1, gdm e lightdm escrevem wtmp e não escrevem aquela linha — então um
// auth.log cheio de login de REDE não prova nada sobre a falta de um login de
// CONSOLE. A chave da condição inclui a FORMA da origem justamente por isso.
func TestLoginDeConsoleNaoEhAcusadoDeAdulteracao(t *testing.T) {
	f := hostComLog(
		[]facts.Login{
			{Tipo: facts.TipoLoginUsuario, User: "deploy", Origem: "10.0.0.9",
				PID: 900, QuandoU: at(20, 0)},
			// Entrada por console: sem origem de rede.
			{Tipo: facts.TipoLoginUsuario, User: "lex", Linha: "tty1", QuandoU: at(2, 0)},
		},
		[]facts.EventoDeLog{{Kind: "auth.accepted", At: at(20, 0), AtKnown: true,
			User: "deploy", RemoteIP: "10.0.0.9", PID: 900, File: "/var/log/auth.log"}},
		fonteAuth(at(48, 0), at(0, 0)))

	ev, _ := Linha(f, Filtro{User: "lex"})
	if len(ev) != 1 {
		t.Fatalf("queria 1 evento, veio %d", len(ev))
	}
	if ev[0].Divergente == DivergenteAusente {
		t.Errorf("o login de console foi acusado de adulteração do auth.log — " +
			"aquele arquivo nunca registrou entrada de console neste host")
	}
}

// A direção OPOSTA — auth.log viu e o wtmp não — não é afirmável, e a razão é
// rotina: scp, rsync, git e ansible produzem "Accepted publickey" sem sessão, e
// portanto sem registro de wtmp. Acusar ali marcaria todo host com backup.
func TestLogSemRegistroBinarioNaoEhAfirmavel(t *testing.T) {
	f := hostComLog(
		[]facts.Login{{Tipo: facts.TipoLoginUsuario, User: "outro",
			Origem: "10.0.0.1", PID: 900, QuandoU: at(2, 0)}},
		[]facts.EventoDeLog{
			{Kind: "auth.accepted", At: at(2, 0), AtKnown: true, User: "outro",
				RemoteIP: "10.0.0.1", PID: 900, File: "/var/log/auth.log"},
			// O backup, sem par no wtmp.
			{Kind: "auth.accepted", At: at(1, 0), AtKnown: true, User: "backup",
				RemoteIP: "10.0.0.50", PID: 7000, File: "/var/log/auth.log"},
		},
		fonteAuth(at(48, 0), at(0, 0)))

	ev, _ := Linha(f, Filtro{User: "backup"})
	if len(ev) != 1 {
		t.Fatalf("queria 1 evento, veio %d", len(ev))
	}
	if ev[0].Divergente == DivergenteAusente {
		t.Error("ssh não-interativo foi acusado de wtmp adulterado")
	}
}

// O filtro de tipo casa por PREFIXO, para o namespace poder crescer sem que
// cada consumidor precise listar os filhos.
func TestFiltroDeKindCasaPorPrefixo(t *testing.T) {
	f := hostComLog(
		[]facts.Login{{Tipo: facts.TipoLoginUsuario, User: "deploy", QuandoU: at(2, 0)}},
		[]facts.EventoDeLog{
			{Kind: "auth.sudo", At: at(1, 0), AtKnown: true, User: "deploy",
				Alvos: []string{"/bin/bash"}, File: "/var/log/auth.log"},
		},
		fonteAuth(at(48, 0), at(0, 0)),
	)

	casos := map[string]int{
		"auth":            1, // só o login
		"auth.login":      1,
		"privilege":       1, // só o sudo
		"privilege.sudo":  1,
		"exec":            0,
		"auth.login.open": 0,
	}
	for prefixo, quer := range casos {
		ev, _ := Linha(f, Filtro{Kind: prefixo})
		if len(ev) != quer {
			t.Errorf("--kind %s casou %d eventos, queria %d", prefixo, len(ev), quer)
		}
	}
}

// Evento sem data vai para o FIM, num bloco próprio. Interpolá-lo numa posição
// plausível seria inventar quando aquilo aconteceu.
func TestEventoSemDataNaoEhInterpoladoNemRecortado(t *testing.T) {
	f := hostComLog(
		[]facts.Login{
			{Tipo: facts.TipoLoginUsuario, User: "sem-data", QuandoU: ""},
			{Tipo: facts.TipoLoginUsuario, User: "deploy", QuandoU: at(2, 0)},
			{Tipo: facts.TipoLoginUsuario, User: "antigo", QuandoU: at(30, 0)},
		},
		nil, fonteAuth(at(48, 0), at(0, 0)),
	)
	ev, _ := Linha(f, Filtro{Desde: at(24, 0)})

	if len(ev) != 2 {
		t.Fatalf("saíram %d eventos, queria 2 (o de 30h fora, o sem data DENTRO)", len(ev))
	}
	if ev[len(ev)-1].User != "sem-data" {
		t.Errorf("o evento sem data precisa ir para o fim, e não para uma "+
			"posição fabricada: %+v", ev)
	}
	if ev[0].User != "deploy" {
		t.Errorf("a ordem dos datados é crescente: %+v", ev)
	}
}

// O campo de origem do registro de BOOT carrega a versão do kernel. Deixá-lo em
// Origem faz um filtro por IP casar com texto de kernel.
func TestBootNaoPoeVersaoDoKernelEmOrigem(t *testing.T) {
	f := hostCom([]facts.Login{
		{Tipo: facts.TipoBoot, User: "reboot", Origem: "6.12.104-1-MANJARO", QuandoU: at(5, 0)},
	})
	ev, _ := Linha(f, Filtro{})
	if len(ev) != 1 {
		t.Fatalf("queria 1 evento, veio %d", len(ev))
	}
	if ev[0].Origem != "" {
		t.Errorf("Origem = %q: a versão do kernel não é endereço", ev[0].Origem)
	}
	if !strings.Contains(ev[0].Trecho, "MANJARO") {
		t.Errorf("a versão precisa sobreviver, como TRECHO: %+v", ev[0])
	}
}

// A RAJADA DE FORÇA BRUTA não pode ser colapsada — e era, porque a junção não
// distinguia "o mesmo registro em dois arquivos" de "dois registros no mesmo
// arquivo".
//
// Seis senhas erradas dentro de uma conexão SSH (MaxAuthTries) escrevem seis
// registros de btmp com o mesmo pid, o mesmo usuário, o mesmo `ssh:notty` e o
// mesmo segundo. `lastb` mostra 6; a primeira versão disto mostrava 1.
func TestRajadaNoMesmoArquivoNaoEhColapsada(t *testing.T) {
	var logins []facts.Login
	for i := 0; i < 6; i++ {
		logins = append(logins, facts.Login{
			Tipo: facts.TipoLoginUsuario, User: "root", Linha: "ssh:notty",
			Origem: "185.44.1.7", PID: 4211, Falhou: true, QuandoU: at(2, 0)})
	}
	ev, _ := Linha(hostCom(logins), Filtro{})
	if len(ev) != 6 {
		t.Fatalf("saíram %d eventos, queria 6: seis registros do MESMO arquivo "+
			"são seis tentativas, e apagá-las esconde justamente a rajada", len(ev))
	}
	for _, e := range ev {
		if len(e.Testemunhas) != 1 {
			t.Errorf("testemunha duplicada num registro só: %v", e.Testemunhas)
		}
	}
}

// O boot aparece no wtmp E no /run/utmp: ali a junção DEVE acontecer, porque é
// o mesmo registro em dois arquivos. É o contraponto do teste acima.
func TestMesmoRegistroEmDoisArquivosEhUmEventoSo(t *testing.T) {
	l := facts.Login{Tipo: facts.TipoBoot, User: "reboot", Origem: "6.12.0", QuandoU: at(5, 0)}
	agoraL := l
	agoraL.Agora = true
	ev, _ := Linha(hostCom([]facts.Login{l, agoraL}), Filtro{})
	if len(ev) != 1 {
		t.Fatalf("saíram %d eventos, queria 1", len(ev))
	}
	if len(ev[0].Testemunhas) != 2 {
		t.Errorf("Testemunhas = %v, queria wtmp e utmp", ev[0].Testemunhas)
	}
}

// O DESLIGAMENTO some da linha do tempo se o tipo de registro não for
// traduzido, e o intervalo entre ele e o boot seguinte é exatamente o que
// alguém precisa delimitar: o tempo em que o host não observou nada.
//
// Neste host de desenvolvimento são 13 registros de 59.
func TestDesligamentoEntraNaLinhaDoTempo(t *testing.T) {
	f := hostCom([]facts.Login{
		{Tipo: facts.TipoRunLevel, User: "shutdown", Origem: "6.12.0", Linha: "~", QuandoU: at(6, 0)},
		{Tipo: facts.TipoBoot, User: "reboot", Origem: "6.12.0", Linha: "~", QuandoU: at(5, 0)},
	})
	ev, _ := Linha(f, Filtro{})
	if len(ev) != 2 {
		t.Fatalf("saíram %d eventos, queria 2", len(ev))
	}
	if ev[0].Kind != KindDesligamento {
		t.Errorf("Kind = %q, queria %q", ev[0].Kind, KindDesligamento)
	}
	// Mesma disciplina do boot: a versão do kernel não é endereço nem tty.
	if ev[0].Origem != "" || ev[0].Linha != "" {
		t.Errorf("o desligamento carregou versão de kernel como origem/tty: %+v", ev[0])
	}
}

// O TIPO decide antes do ARQUIVO. O /run/utmp guarda LOGIN_PROCESS (um getty
// ocioso, ut_user="LOGIN") e slots que retêm o usuário anterior: com o teste do
// arquivo primeiro, um servidor com getty@tty1..6 anunciava seis sessões
// abertas de um usuário chamado LOGIN — enquanto o bloco do `wtf`, que exige o
// tipo, dizia nenhuma.
func TestGettyOciosoNaoEhSessaoAberta(t *testing.T) {
	f := hostCom([]facts.Login{
		{Tipo: 6, User: "LOGIN", Linha: "tty1", Agora: true, QuandoU: at(9, 0)},
		{Tipo: facts.TipoLoginUsuario, User: "deploy", Linha: "pts/3", Agora: true, QuandoU: at(1, 0)},
	})
	ev, _ := Linha(f, Filtro{Kind: "auth.session"})
	if len(ev) != 1 || ev[0].User != "deploy" {
		t.Fatalf("as sessões abertas saíram como %+v — só a de tipo "+
			"USER_PROCESS é sessão", ev)
	}
	// E o que não virou evento é DECLARADO, não sumido.
	_, fontes := Linha(f, Filtro{})
	for _, s := range fontes {
		if s.Papel == facts.PapelSessoes && s.NaoInterpretados != 1 {
			t.Errorf("NaoInterpretados = %d, queria 1: o getty foi lido e não "+
				"virou evento, e a cobertura precisa dizer isso", s.NaoInterpretados)
		}
	}
}

// A ORIGEM é "o que só o log tem" quando o registro binário não a traz — e num
// caso de abuso de credencial é o campo que mais importa. Sem carregá-la, a
// fusão publicava `remote_ip` vazio como se fosse a única observação.
func TestFusaoCarregaAOrigemQueSoOLogTinha(t *testing.T) {
	f := hostComLog(
		[]facts.Login{{Tipo: facts.TipoLoginUsuario, User: "deploy",
			Linha: "pts/2", PID: 4242, QuandoU: at(2, 0)}},
		[]facts.EventoDeLog{{Kind: "auth.accepted", At: at(2, 0), AtKnown: true,
			User: "deploy", RemoteIP: "185.44.1.7", PID: 4242, File: "/var/log/auth.log"}},
		fonteAuth(at(48, 0), at(0, 0)))

	ev, _ := Linha(f, Filtro{IP: "185.44.1.7"})
	if len(ev) != 1 {
		t.Fatalf("--ip não casou o login fundido: a origem se perdeu na fusão")
	}
}

// Origem CONFLITANTE não funde: a chave por pid não exige acordo sobre o
// endereço, e sem esta recusa a reciclagem de pid apagava um dos dois.
func TestOrigensDiferentesNaoFundemPorPID(t *testing.T) {
	f := hostComLog(
		[]facts.Login{{Tipo: facts.TipoLoginUsuario, User: "deploy",
			Origem: "10.0.0.9", PID: 4242, QuandoU: at(2, 0)}},
		[]facts.EventoDeLog{{Kind: "auth.accepted", At: at(2, 0), AtKnown: true,
			User: "deploy", RemoteIP: "185.44.1.7", PID: 4242, File: "/var/log/auth.log"}},
		fonteAuth(at(48, 0), at(0, 0)))

	ev, _ := Linha(f, Filtro{})
	if len(ev) != 2 {
		t.Errorf("saíram %d eventos, queria 2: dois endereços diferentes com o "+
			"mesmo pid são reciclagem, e fundi-los apaga um deles", len(ev))
	}
}

// A ligação FRACA é 1:1 como as fortes. Sem consumir, uma linha de log
// sobrevivente "explicava" quantos registros binários quisesse — e como
// marcarDivergencia pula quem tem relacionado, quem apagasse 49 de 50 linhas do
// próprio login saía com zero divergência.
func TestLigacaoFracaNaoLavaVariosRegistros(t *testing.T) {
	var logins []facts.Login
	for i := 0; i < 5; i++ {
		logins = append(logins, facts.Login{
			Tipo: facts.TipoLoginUsuario, User: "deploy", Origem: "10.0.0.9",
			QuandoU: at(2, i)})
	}
	f := hostComLog(logins,
		[]facts.EventoDeLog{{Kind: "auth.accepted", At: at(9, 0), AtKnown: true,
			AtFusoInferido: true, User: "deploy", RemoteIP: "10.0.0.9",
			File: "/var/log/auth.log"}},
		fonteAuth(at(48, 0), at(0, 0)))
	f.FusoDoAlvoLido = false

	ev, _ := Linha(f, Filtro{})
	ligados := 0
	for _, e := range ev {
		if e.Fusao == FusaoRelacionada {
			ligados++
		}
	}
	// Um registro binário e o evento de texto: dois eventos ligados, não seis.
	if ligados != 2 {
		t.Errorf("%d eventos saíram ligados, queria 2: uma linha de log só pode "+
			"ser a contraparte de UM registro", ligados)
	}
}

// O RELÓGIO QUE SALTA destrói a comparabilidade dos carimbos, e com ela a
// alegação de alcance. O utmp registra o par OLD_TIME/NEW_TIME, então o fato
// está ali — faltava consultá-lo.
//
// Não precisa de atacante: `date -s`, salto de NTP, restore de snapshot de VM e
// relógio de hardware quebrado produzem a mesma forma.
func TestRelogioAlteradoDerrubaAAlegacaoDeAlcance(t *testing.T) {
	// Poucas horas de atividade real, com o relógio voltando três dias no meio.
	// O mínimo dos carimbos passa a ser de três dias atrás, e sem esta guarda
	// ele "provava" cobertura de 24h.
	f := hostCom([]facts.Login{
		{Tipo: facts.TipoLoginUsuario, User: "lex", QuandoU: at(2, 0)},
		{Tipo: facts.TipoTempoAntigo, Linha: "~", QuandoU: at(1, 30)},
		{Tipo: facts.TipoTempoNovo, Linha: "~", QuandoU: em(74)},
		{Tipo: facts.TipoLoginUsuario, User: "lex", QuandoU: em(73)},
	})
	r := Resumir(f, agora, 24*time.Hour)
	h, _ := r.Fonte(facts.PapelHistorico)
	if !h.RelogioAlterado {
		t.Fatal("o par OLD_TIME/NEW_TIME não foi notado")
	}
	if h.CobreJanela {
		t.Error("os registros dos dois lados do salto foram carimbados por " +
			"relógios diferentes: comparar o mínimo deles com o começo da " +
			"janela é somar duas réguas")
	}
	// E o evento continua na linha do tempo, explicando por quê.
	ev, _ := Linha(f, Filtro{Kind: "sistema.clock_changed"})
	if len(ev) != 2 {
		t.Errorf("os dois registros de mudança de relógio precisam aparecer: %v", ev)
	}
}

// Duas testemunhas que DISCORDAM sobre a conta não podem virar uma só. Com o
// mesmo pid, a mesma origem e o mesmo instante, o par era único dos dois lados
// e fundia — e `juntar` preserva o campo do binário, então a conta do log
// sumia. Uma contradição saía impressa como corroboração.
func TestMesmoPIDComUsuarioDiferenteNaoFunde(t *testing.T) {
	f := hostComLog(
		[]facts.Login{{Tipo: facts.TipoLoginUsuario, User: "deploy",
			Origem: "185.1.2.3", PID: 4211, QuandoU: at(2, 0)}},
		[]facts.EventoDeLog{{Kind: "auth.accepted", At: at(2, 0), AtKnown: true,
			User: "root", RemoteIP: "185.1.2.3", PID: 4211, File: "/var/log/auth.log"}},
		fonteAuth(at(48, 0), at(0, 0)))

	ev, _ := Linha(f, Filtro{})
	if len(ev) != 2 {
		t.Fatalf("saíram %d eventos, queria 2: as duas fontes discordam sobre a "+
			"conta, e fundir apagaria uma delas", len(ev))
	}
	contas := map[string]bool{}
	for _, e := range ev {
		contas[e.User] = true
	}
	if !contas["deploy"] || !contas["root"] {
		t.Errorf("uma das contas sumiu: %v", contas)
	}
}

// RUN_LVL é mudança de RUNLEVEL. Chamar todo ele de desligamento faria um
// `telinit 3` virar uma parada do host na reconstrução histórica.
func TestRunlevelSoEhDesligamentoQuandoODizEmUtUser(t *testing.T) {
	f := hostCom([]facts.Login{
		{Tipo: facts.TipoRunLevel, User: "shutdown", Linha: "~", QuandoU: at(5, 0)},
		{Tipo: facts.TipoRunLevel, User: "runlevel", Linha: "~", QuandoU: at(4, 0)},
	})
	ev, _ := Linha(f, Filtro{})
	if len(ev) != 2 {
		t.Fatalf("queria 2 eventos, veio %d", len(ev))
	}
	if ev[0].Kind != KindDesligamento {
		t.Errorf("ut_user=shutdown precisa virar %q, veio %q", KindDesligamento, ev[0].Kind)
	}
	if ev[1].Kind != KindRunlevel {
		t.Errorf("ut_user=runlevel não é parada do host: veio %q", ev[1].Kind)
	}
}
