package check

import (
	"strings"
	"testing"
	"time"

	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

// liveEnv monta um ambiente sintético. Todo teste deste pacote roda sem root e
// sem host comprometido — é a promessa da separação coleta/avaliação.
func liveEnv(caps env.Cap) *env.Env {
	e := &env.Env{
		Source:    env.SourceLive,
		Caps:      caps,
		CapReason: map[string]string{},
		Now:       time.Date(2026, 4, 30, 21, 44, 3, 0, time.UTC),
	}
	for _, missing := range []struct {
		c env.Cap
		r string
	}{
		{env.CapRoot, "não estamos como root"},
		{env.CapDebugfs, "debugfs não montado"},
		{env.CapBPF, "bpftool ausente"},
		{env.CapPkgDB, "sem base de pacotes"},
	} {
		if caps&missing.c == 0 {
			for _, n := range missing.c.Names() {
				e.CapReason[n] = missing.r
			}
		}
	}
	return e
}

func mkCheck(id string, opts ...func(*Check)) Check {
	c := Check{
		ID: id, Ref: "1.1", Title: "t", Group: "g",
		Mode: ModeAuto, Sources: env.SourceLive,
		FalsePositives: []string{"nenhum: teste"},
		Run:            func(Check, *facts.Facts, *env.Env) Result { return Result{} },
	}
	for _, o := range opts {
		o(&c)
	}
	return c
}

// O denominador da cobertura é o conjunto SELECIONADO para aquela execução, não
// o catálogo inteiro. Sem esta regra, `wtf` e `--only` sairiam sempre
// INCOMPLETE e o exit code deixaria de significar algo (SPEC 7.9).
func TestCoberturaUsaConjuntoSelecionado(t *testing.T) {
	checks := []Check{mkCheck("a"), mkCheck("b")}
	r := Run(checks, &facts.Facts{}, liveEnv(env.CapProcfs))

	if r.Coverage.Total != 2 {
		t.Errorf("Total = %d, quer 2 (o conjunto selecionado)", r.Coverage.Total)
	}
	if r.Coverage.Complete != 2 {
		t.Errorf("Complete = %d, quer 2", r.Coverage.Complete)
	}
	if r.Coverage.Incomplete() {
		t.Error("cobertura completa não pode ser reportada como incompleta")
	}
	if got := r.Exit(); got != 0 {
		t.Errorf("Exit = %d, quer 0 (sem achado E cobertura completa)", got)
	}
}

// Requires ausente NÃO é "nada encontrado": é "não foi possível olhar", e a
// diferença é o motivo de a ferramenta existir.
func TestRequiresAusenteViraNotChecked(t *testing.T) {
	c := mkCheck("precisa-debugfs", func(c *Check) { c.Requires = env.CapDebugfs })
	r := Run([]Check{c}, &facts.Facts{}, liveEnv(env.CapProcfs))

	if r.Coverage.Complete != 0 {
		t.Errorf("Complete = %d, quer 0", r.Coverage.Complete)
	}
	if len(r.Coverage.NotChecked) != 1 {
		t.Fatalf("NotChecked = %d, quer 1", len(r.Coverage.NotChecked))
	}
	if !strings.Contains(r.Coverage.NotChecked[0].Reason, "debugfs") {
		t.Errorf("motivo não explica a falta: %q", r.Coverage.NotChecked[0].Reason)
	}
	if r.Verdict() != "INCOMPLETE" {
		t.Errorf("Verdict = %q, quer INCOMPLETE", r.Verdict())
	}
	if r.Exit() == 0 {
		t.Error("exit 0 com check não verificado seria a ferramenta contradizendo o próprio nome")
	}
}

// Optional ausente degrada a cobertura sem perder o check inteiro: a §7 do
// runbook roda quase toda sem root, e só /root e /etc/shadow falham. Binário
// demais custaria 90% de cobertura por 10% de dependência.
func TestOptionalAusenteViraParcial(t *testing.T) {
	ran := false
	c := mkCheck("quase-tudo-sem-root", func(c *Check) {
		c.Optional = env.CapRoot
		c.Run = func(Check, *facts.Facts, *env.Env) Result {
			ran = true
			return Result{}
		}
	})
	r := Run([]Check{c}, &facts.Facts{}, liveEnv(env.CapProcfs))

	if !ran {
		t.Fatal("check com Optional ausente deve RODAR mesmo assim")
	}
	if len(r.Coverage.Partial) != 1 {
		t.Fatalf("Partial = %d, quer 1", len(r.Coverage.Partial))
	}
	if r.Coverage.Complete != 0 {
		t.Errorf("parcial NÃO conta como completo: Complete = %d, quer 0", r.Coverage.Complete)
	}
	if !r.Coverage.Incomplete() {
		t.Error("parcial deve tornar a cobertura incompleta")
	}
}

// Falha de coleta vive num eixo próprio — não é check que deixou de rodar, é
// dado que não pôde ser lido. Mas continua impedindo um veredito de OK.
func TestCollectorGapImpedeOK(t *testing.T) {
	r := Run([]Check{mkCheck("a")}, &facts.Facts{}, liveEnv(env.CapProcfs))
	if r.Verdict() != "OK" {
		t.Fatalf("pré-condição: Verdict = %q", r.Verdict())
	}
	r.Coverage.CollectorGaps = []string{"proc: 250 processos com fds ilegíveis"}

	if !r.Coverage.Incomplete() {
		t.Error("lacuna de coleta deve tornar a cobertura incompleta")
	}
	if r.Verdict() != "INCOMPLETE" {
		t.Errorf("Verdict = %q, quer INCOMPLETE", r.Verdict())
	}
	if r.Exit() != 1 {
		t.Errorf("Exit = %d, quer 1", r.Exit())
	}
	// A aritmética de CHECKS continua fechando: a lacuna é de outro eixo.
	if r.Coverage.Complete != r.Coverage.Total {
		t.Errorf("lacuna de coleta não pode mexer na contagem de checks: %d/%d",
			r.Coverage.Complete, r.Coverage.Total)
	}
}

// Achado que invalida a confiança no userland rebaixa RETROATIVAMENTE tudo que
// veio de binário do host (SPEC 7.5).
func TestRebaixamentoDeConfianca(t *testing.T) {
	preload := mkCheck("persist.ld_preload_global", func(c *Check) {
		c.Run = func(self Check, _ *facts.Facts, _ *env.Env) Result {
			return Result{Findings: []Finding{self.F(SevCritical, "path=/etc/ld.so.preload", "")}}
		}
	})
	pkg := mkCheck("integrity.pkg", func(c *Check) {
		c.Run = func(self Check, _ *facts.Facts, _ *env.Env) Result {
			f := self.F(SevWarn, "path=/usr/bin/ss", "")
			f.Origin = ToolOrigin("dpkg")
			return Result{Findings: []Finding{f}}
		}
	})
	native := mkCheck("proc.nativo", func(c *Check) {
		c.Run = func(self Check, _ *facts.Facts, _ *env.Env) Result {
			return Result{Findings: []Finding{self.F(SevWarn, "pid=1", "")}}
		}
	})

	r := Run([]Check{preload, pkg, native}, &facts.Facts{}, liveEnv(env.CapProcfs))

	if len(r.TrustBroken) == 0 {
		t.Fatal("ld.so.preload deve quebrar a confiança em binário do host")
	}
	for _, f := range r.Findings {
		switch {
		case f.Origin.IsTool() && !f.Downgraded:
			t.Errorf("%s veio de %s e deveria estar rebaixado", f.ID, f.Origin)
		case !f.Origin.IsTool() && f.Downgraded:
			t.Errorf("%s é leitura nativa e NÃO deveria ser rebaixado", f.ID)
		}
	}
}

func TestSemQuebraDeConfiancaNadaEhRebaixado(t *testing.T) {
	pkg := mkCheck("integrity.pkg", func(c *Check) {
		c.Run = func(self Check, _ *facts.Facts, _ *env.Env) Result {
			f := self.F(SevWarn, "path=/usr/bin/ss", "")
			f.Origin = ToolOrigin("dpkg")
			return Result{Findings: []Finding{f}}
		}
	})
	r := Run([]Check{pkg}, &facts.Facts{}, liveEnv(env.CapProcfs))
	if r.Findings[0].Downgraded {
		t.Error("sem quebra de confiança, achado de tool não deve ser rebaixado")
	}
}

func TestExitCodePorSeveridade(t *testing.T) {
	cases := []struct {
		name string
		sev  Severity
		want int
	}{
		{"critico", SevCritical, 2},
		{"aviso", SevWarn, 1},
		{"manual não decide sozinho", SevManual, 0},
		{"info não decide sozinho", SevInfo, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sev := c.sev
			chk := mkCheck("x", func(k *Check) {
				k.Run = func(self Check, _ *facts.Facts, _ *env.Env) Result {
					return Result{Findings: []Finding{self.F(sev, "s", "")}}
				}
			})
			r := Run([]Check{chk}, &facts.Facts{}, liveEnv(env.CapProcfs))
			if got := r.Exit(); got != c.want {
				t.Errorf("Exit = %d, quer %d", got, c.want)
			}
		})
	}
}

// A saída compacta agrupa por ID para que o tamanho do relatório não cresça com
// o tamanho do incidente.
func TestAgrupamentoPorID(t *testing.T) {
	chk := mkCheck("proc.suspeito", func(c *Check) {
		c.Run = func(self Check, _ *facts.Facts, _ *env.Env) Result {
			var out []Finding
			for _, pid := range []string{"pid=10", "pid=20", "pid=30"} {
				out = append(out, self.F(SevWarn, pid, ""))
			}
			return Result{Findings: out}
		}
	})
	r := Run([]Check{chk}, &facts.Facts{}, liveEnv(env.CapProcfs))

	groups := r.Grouped()
	if len(groups) != 1 {
		t.Fatalf("grupos = %d, quer 1", len(groups))
	}
	if groups[0].N() != 3 {
		t.Errorf("N = %d, quer 3", groups[0].N())
	}
	if s := groups[0].Subjects(2); !strings.Contains(s, "…") {
		t.Errorf("Subjects deve truncar e sinalizar: %q", s)
	}
}

// Ordenação por severidade: crítico primeiro, senão o operador rola a tela
// atrás do que importa.
func TestOrdenacaoPorSeveridade(t *testing.T) {
	chk := mkCheck("x", func(c *Check) {
		c.Run = func(self Check, _ *facts.Facts, _ *env.Env) Result {
			return Result{Findings: []Finding{
				self.F(SevInfo, "i", ""),
				self.F(SevCritical, "c", ""),
				self.F(SevWarn, "w", ""),
			}}
		}
	})
	r := Run([]Check{chk}, &facts.Facts{}, liveEnv(env.CapProcfs))
	want := []Severity{SevCritical, SevWarn, SevInfo}
	for i, w := range want {
		if r.Findings[i].Sev != w {
			t.Errorf("posição %d = %s, quer %s", i, r.Findings[i].Sev, w)
		}
	}
}

// Check declarado só para modo image não roda em live, e vice-versa.
func TestSourceIncompativelViraNotChecked(t *testing.T) {
	c := mkCheck("so-imagem", func(c *Check) { c.Sources = env.SourceImage })
	r := Run([]Check{c}, &facts.Facts{}, liveEnv(env.CapProcfs))
	if len(r.Coverage.NotChecked) != 1 {
		t.Fatalf("NotChecked = %d, quer 1", len(r.Coverage.NotChecked))
	}
	if !strings.Contains(r.Coverage.NotChecked[0].Reason, "live") {
		t.Errorf("motivo deve citar o modo: %q", r.Coverage.NotChecked[0].Reason)
	}
}

// O orçamento do wtf não pode virar silêncio. Um check que não coube no prazo é
// NÃO VERIFICADO — se virasse "nada encontrado", o overview ficaria rápido
// mentindo, que é pior que ficar lento.
func TestOrcamentoEstouradoViraNaoVerificado(t *testing.T) {
	disparar := func(c *Check) {
		c.Run = func(self Check, f *facts.Facts, e *env.Env) Result {
			return Result{Findings: []Finding{self.F(SevCritical, "x", "")}}
		}
	}
	checks := []Check{mkCheck("a", disparar), mkCheck("b", disparar), mkCheck("c", disparar)}

	// Prazo já vencido: nenhum check chega a rodar.
	r := RunWith(checks, &facts.Facts{}, liveEnv(env.CapProcfs),
		RunOptions{Deadline: time.Now().Add(-time.Second), Budget: 2 * time.Second})

	if len(r.Findings) != 0 {
		t.Fatalf("achados = %d: nenhum check devia ter rodado", len(r.Findings))
	}
	if len(r.Coverage.NotChecked) != 3 {
		t.Fatalf("não verificados = %d, quer 3", len(r.Coverage.NotChecked))
	}
	if !strings.Contains(r.Coverage.NotChecked[0].Reason, "orçamento") {
		t.Errorf("o motivo precisa dizer que foi o prazo: %q", r.Coverage.NotChecked[0].Reason)
	}
	// E o veredito jamais pode ser OK: 0 de 3 cobertos.
	if v := r.Verdict(); v != "INCOMPLETE" {
		t.Errorf("veredito = %s, quer INCOMPLETE", v)
	}
	if r.Exit() == 0 {
		t.Error("exit 0 com 0/3 cobertos é a mentira que a ferramenta existe para não contar")
	}
}

// Sem prazo, RunWith é o Run de sempre.
func TestSemPrazoNadaEhCortado(t *testing.T) {
	r := RunWith([]Check{mkCheck("a")}, &facts.Facts{}, liveEnv(env.CapProcfs), RunOptions{})
	if len(r.Coverage.NotChecked) != 0 || r.Coverage.Complete != 1 {
		t.Errorf("cobertura = %d/%d, não verificados = %d",
			r.Coverage.Complete, r.Coverage.Total, len(r.Coverage.NotChecked))
	}
}

// Um comprometimento real dispara vários checks no MESMO pid. Listá-los soltos
// conta quatro fatos onde há uma história — e é a história que o operador
// precisa para decidir; os fatos soltos ele teria com grep.
func TestCorrelatePorAlvo(t *testing.T) {
	fd := func(id, subj string, sev Severity) Finding {
		return Finding{ID: id, Ref: "1", Title: "t de " + id, Subject: subj, Sev: sev}
	}
	r := &Report{Findings: []Finding{
		fd("correlate.revshell", "pid=19", SevCritical),
		fd("proc.suspicious_path", "pid=19", SevWarn),
		fd("proc.env_tool_marker", "pid=19", SevCritical),
		fd("proc.suspicious_path", "pid=77", SevWarn), // sozinho: não correlaciona
		fd("persist.timer_frequent", "beacon.timer", SevWarn),
	}}

	grupos, resto := r.Correlate()
	if len(grupos) != 1 || grupos[0].Subject != "pid=19" {
		t.Fatalf("grupos = %+v", grupos)
	}
	if len(grupos[0].Findings) != 3 {
		t.Errorf("sinais = %d, quer 3", len(grupos[0].Findings))
	}
	// A severidade do grupo é a MAIOR: um implante com dois críticos e um aviso
	// é um crítico.
	if grupos[0].Sev() != SevCritical {
		t.Errorf("Sev = %s, quer CRITICAL", grupos[0].Sev())
	}
	// Cada achado aparece exatamente UMA vez entre grupos e resto.
	if len(resto) != 2 {
		t.Errorf("resto = %d, quer 2 (os dois alvos com um sinal só)", len(resto))
	}
}

// O mesmo check disparando duas vezes no mesmo alvo é repetição, não
// correlação: agrupar isso prometeria uma história que não existe.
func TestCorrelateExigeChecksDISTINTOS(t *testing.T) {
	r := &Report{Findings: []Finding{
		{ID: "proc.x", Subject: "pid=1", Sev: SevWarn},
		{ID: "proc.x", Subject: "pid=1", Sev: SevWarn},
	}}
	if grupos, _ := r.Correlate(); len(grupos) != 0 {
		t.Errorf("dois achados do MESMO check não são correlação: %+v", grupos)
	}
}

func TestCorrelateIgnoraAlvoVazio(t *testing.T) {
	r := &Report{Findings: []Finding{
		{ID: "a.b", Subject: "", Sev: SevWarn},
		{ID: "c.d", Subject: "", Sev: SevWarn},
	}}
	grupos, resto := r.Correlate()
	if len(grupos) != 0 {
		t.Error("achado sem alvo não pode ser correlacionado com outro sem alvo")
	}
	if len(resto) != 2 {
		t.Errorf("resto = %d, quer 2", len(resto))
	}
}

// Um achado que NÃO entrou em grupo nenhum tem de sair no resto — inclusive
// INFO. Marcar por ALVO em vez de por posição descartava do resto qualquer
// achado que compartilhasse o alvo sem ter entrado no grupo, e ele sumia do
// relatório inteiro.
func TestCorrelateNaoPerdeAchadoDeAlvoAgrupado(t *testing.T) {
	r := &Report{Findings: []Finding{
		{ID: "a.b", Subject: "pid=1", Sev: SevCritical},
		{ID: "c.d", Subject: "pid=1", Sev: SevWarn},
		{ID: "e.f", Subject: "pid=1", Sev: SevInfo}, // mesmo alvo, fora do grupo
	}}
	grupos, resto := r.Correlate()
	if len(grupos) != 1 || len(grupos[0].Findings) != 2 {
		t.Fatalf("grupos = %+v", grupos)
	}
	if len(resto) != 1 || resto[0].ID != "e.f" {
		t.Errorf("o INFO precisa sobrar para o resto, não sumir: %+v", resto)
	}
	// Nenhum achado pode aparecer duas vezes nem desaparecer.
	if len(grupos[0].Findings)+len(resto) != len(r.Findings) {
		t.Error("a soma de grupos e resto tem de ser o total")
	}
}

// Agrupar só por ID juntava um crítico e um aviso do mesmo check, e a linha
// imprimia a marca do primeiro valendo pelos dois.
func TestGroupedSeparaPorSeveridade(t *testing.T) {
	gs := GroupByIDSev([]Finding{
		{ID: "x.y", Sev: SevCritical, Subject: "a"},
		{ID: "x.y", Sev: SevWarn, Subject: "b"},
		{ID: "x.y", Sev: SevWarn, Subject: "c"},
	})
	if len(gs) != 2 {
		t.Fatalf("grupos = %d, quer 2", len(gs))
	}
	if gs[0].N() != 1 || gs[1].N() != 2 {
		t.Errorf("tamanhos = %d e %d", gs[0].N(), gs[1].N())
	}
}
