package checks

import (
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/facts"
	"github.com/lex0c/aletheia/internal/tools"
)

// O catálogo é a parte que envelhece se ninguém cuidar. Estas invariantes são o
// que impede uma entrada nova de virar ruído sem querer.
func TestCatalogoDeFamiliasEhUtilizavel(t *testing.T) {
	if len(tools.All) < 5 {
		t.Fatalf("catálogo com %d famílias", len(tools.All))
	}
	nomes := map[string]bool{}
	bins := map[string]string{}
	for _, f := range tools.All {
		if nomes[f.Name] {
			t.Errorf("família duplicada: %q", f.Name)
		}
		nomes[f.Name] = true

		// Sem rota, a entrada não encontra nada.
		if len(f.Env)+len(f.Paths)+len(f.Bins) == 0 {
			t.Errorf("%s: sem Env, Paths nem Bins — não encontra nada", f.Name)
		}
		// Sem nota, o nome não redireciona a investigação, e é SÓ para isso
		// que ele serve (runbook §5.10).
		if len(f.Nota) < 40 {
			t.Errorf("%s: a nota precisa dizer o que o nome MUDA na resposta", f.Name)
		}
		if f.Risk != tools.RiskAlto && f.Risk != tools.RiskMedio {
			t.Errorf("%s: risco inválido %q", f.Name, f.Risk)
		}
		// Nome de binário colidindo entre famílias faria o achado apontar a
		// família errada.
		for _, b := range f.Bins {
			if outra, ok := bins[b]; ok {
				t.Errorf("binário %q em duas famílias: %s e %s", b, outra, f.Name)
			}
			bins[b] = f.Name
		}
		// Um binário de nome genérico transformaria host normal em achado.
		for _, b := range f.Bins {
			for _, generico := range []string{"sh", "bash", "nc", "curl", "wget",
				"python", "perl", "ssh", "node", "docker"} {
				if b == generico {
					t.Errorf("%s: %q é nome genérico demais para catálogo", f.Name, b)
				}
			}
		}
	}
}

func TestArtefatoEmDiscoAgrupaPorFamilia(t *testing.T) {
	f := &facts.Facts{ToolArtifacts: []facts.ToolArtifact{
		{Family: "rclone", Path: "/root/.config/rclone", IsDir: true},
		{Family: "rclone", Path: "/etc/rclone.conf"},
		{Family: "XMRig", Path: "/etc/xmrig", IsDir: true},
	}}
	r := toolArtifact.Run(toolArtifact, f, imgEnv())
	if len(r.Findings) != 2 {
		t.Fatalf("achados = %d, quer 2 (uma linha por família)", len(r.Findings))
	}
	ev := strings.Join(r.Findings[0].Evidence, " ")
	if !strings.Contains(ev, "/etc/rclone.conf") || !strings.Contains(ev, "/root/.config/rclone") {
		t.Errorf("os dois caminhos precisam aparecer no mesmo achado: %s", ev)
	}
	// rclone é ferramenta legítima; XMRig não tem por que existir num servidor.
	sevs := map[string]check.Severity{}
	for _, fd := range r.Findings {
		sevs[fd.Subject] = fd.Sev
	}
	if sevs["rclone"] != check.SevWarn || sevs["XMRig"] != check.SevCritical {
		t.Errorf("severidades = %v", sevs)
	}
}

// A rota de unit é a que funciona em IMAGEM: pega a ferramenta que não está
// rodando agora mas roda no próximo boot.
func TestBinarioEncontraProcessoEUnit(t *testing.T) {
	f := &facts.Facts{
		Processes: []facts.Process{
			{PID: 10, Comm: "xmrig", Exe: "/usr/local/bin/xmrig"},
			{PID: 11, Comm: "nginx", Exe: "/usr/sbin/nginx"},
		},
		Units: []facts.Unit{{
			Name: "frp.service", Path: "/etc/systemd/system/frp.service",
			Exec: []facts.ExecLine{{Key: "ExecStart", Cmd: "/usr/local/bin/frpc -c /etc/frp/frpc.ini"}},
		}},
	}
	r := toolBinary.Run(toolBinary, f, imgEnv())
	if len(r.Findings) != 2 {
		t.Fatalf("achados = %d, quer 2 (xmrig em processo, frpc em unit)", len(r.Findings))
	}
	todos := strings.Join(append(r.Findings[0].Evidence, r.Findings[1].Evidence...), " ")
	if !strings.Contains(todos, "pid=10") || !strings.Contains(todos, "frp.service") {
		t.Errorf("as duas rotas precisam aparecer: %s", todos)
	}
}

// Cinco workers da mesma ferramenta são UM fato, não cinco.
func TestBinarioAgrupaProcessosDaMesmaFamilia(t *testing.T) {
	f := &facts.Facts{}
	for i := 0; i < 5; i++ {
		f.Processes = append(f.Processes, facts.Process{
			PID: 10 + i, Comm: "rclone", Exe: "/usr/bin/rclone"})
	}
	r := toolBinary.Run(toolBinary, f, imgEnv())
	if len(r.Findings) != 1 {
		t.Fatalf("achados = %d, quer 1", len(r.Findings))
	}
}

// Renomear o binário derrota o catálogo por completo — e isso É esperado. O
// catálogo é o atalho da §5.10, não a detecção: quem pega o implante renomeado
// é o check ESTRUTURAL. Confundir os dois levaria a "melhorar" a ferramenta
// engordando a lista de nomes, que é a estratégia que envelhece pior.
func TestCatalogoNaoPegaBinarioRenomeado(t *testing.T) {
	f := &facts.Facts{Processes: []facts.Process{
		{PID: 10, Comm: "systemd-netlinkd", Exe: "/usr/local/sbin/systemd-netlinkd"},
	}}
	if r := toolBinary.Run(toolBinary, f, imgEnv()); len(r.Findings) != 0 {
		t.Error("o catálogo não deveria reconhecer nome arbitrário — se passou a " +
			"reconhecer, alguém acrescentou um padrão genérico demais")
	}
}

func TestBinarioContaExeIlegivel(t *testing.T) {
	f := &facts.Facts{Processes: []facts.Process{
		{PID: 1, ExeDenied: true}, {PID: 2, ExeDenied: true},
	}}
	r := toolBinary.Run(toolBinary, f, imgEnv())
	if len(r.Partial) == 0 || !strings.Contains(r.Partial[0], "2") {
		t.Errorf("exe ilegível precisa virar cobertura parcial: %v", r.Partial)
	}
}

// Corte silencioso é a regra que o resto do código não quebra.
func TestBinarioDizQuantasOcorrenciasNaoListou(t *testing.T) {
	f := &facts.Facts{}
	for i := 0; i < 20; i++ {
		f.Processes = append(f.Processes, facts.Process{
			PID: 10 + i, Comm: "rclone", Exe: "/usr/bin/rclone"})
	}
	r := toolBinary.Run(toolBinary, f, imgEnv())
	if len(r.Findings) != 1 {
		t.Fatalf("achados = %d", len(r.Findings))
	}
	if !strings.Contains(strings.Join(r.Findings[0].Evidence, " "), "e mais 14 ocorrências") {
		t.Errorf("vinte viraram seis sem dizer quantas sobraram: %v", r.Findings[0].Evidence)
	}
}

// "Não pude olhar" não é "não existe". Sem esta distinção, uma varredura sem
// root reporta cobertura completa tendo ficado cega para /root e para o home
// dos outros — e em modo imagem não há check de /proc para salvar o veredito.
func TestArtefatoDeclaraCaminhoIlegivel(t *testing.T) {
	f := &facts.Facts{PersistDenied: map[string][]string{
		"artifact": {"2 caminhos de ferramenta conhecida não puderam ser lidos"},
	}}
	r := toolArtifact.Run(toolArtifact, f, imgEnv())
	if len(r.Partial) == 0 {
		t.Fatal("caminho ilegível precisa virar cobertura parcial")
	}
	rep := check.Run([]check.Check{toolArtifact}, f, imgEnv())
	if !rep.Coverage.Incomplete() {
		t.Error("e a cobertura da execução não pode sair completa")
	}
}

// O Explorer do runZero se instala como `runzero-agent-<uuid da organização>`,
// e o uuid muda a cada instalação. Um catálogo que só casa nome INTEIRO passa
// direto por ele em todo host real — o sufixo é justamente o que não pode ser
// a chave.
func TestBinarioComSufixoVariavelEhReconhecido(t *testing.T) {
	f := &facts.Facts{Processes: []facts.Process{{
		PID: 900,
		Exe: "/opt/runzero/bin/runzero-agent-aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
	}}}
	f.Index()
	r := check.Run([]check.Check{toolBinary}, f, testEnv())
	if len(r.Findings) == 0 {
		t.Fatal("o Explorer com uuid no nome precisa ser reconhecido: o sufixo " +
			"muda a cada organização, e é por isso que ele não serve de chave")
	}
	if !temEvidencia(r, "runZero") {
		t.Errorf("a família precisa ser nomeada: %v", evidencias(r))
	}
}

// E o prefixo não pode virar peneira: um nome que apenas COMEÇA parecido, sem
// nada depois, não é o binário.
func TestPrefixoNaoCasaNomeIncompleto(t *testing.T) {
	f := &facts.Facts{Processes: []facts.Process{
		{PID: 901, Exe: "/usr/bin/runzero-agent-"},
		{PID: 902, Exe: "/usr/bin/runzero-agentic-coisa"},
	}}
	f.Index()
	r := check.Run([]check.Check{toolBinary}, f, testEnv())
	for _, ev := range evidencias(r) {
		if strings.Contains(ev, "pid=901") {
			t.Errorf("prefixo SEM sufixo não é instalação nenhuma: %q", ev)
		}
		if strings.Contains(ev, "pid=902") {
			t.Errorf("`runzero-agentic-coisa` só começa parecido: %q", ev)
		}
	}
}
