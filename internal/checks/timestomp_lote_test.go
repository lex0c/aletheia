package checks

import (
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/facts"
)

// A EVASÃO MAIS BARATA DO CATÁLOGO, e ela existia por causa do conserto de um
// falso positivo.
//
// O FP era real: numa debian:12 saudável este check gritava doze CRITICAL sobre
// /etc/apt/apt.conf.d/docker-*, porque a camada da imagem carimba o mesmo ctime
// em tudo. A resposta foi descartar o candidato quando quatro ou mais
// compartilhavam o ctime — e o ctime é truncado a SEGUNDOS. Custo do atacante
// para apagar a evidência: `touch -d` em quatro arquivos, um comando.
//
// Agora o lote REBAIXA. O achado continua existindo, com a severidade dizendo o
// que se sabe, e nada some em silêncio.
func TestTimestompEmLoteRebaixaEmVezDeSumir(t *testing.T) {
	// Quatro alvos de persistência com o MESMO ctime: a forma da extração em
	// massa, e também a do atacante que aprendeu a regra.
	var ts []facts.Timestomp
	var trig []facts.Trigger
	for _, p := range []string{"/etc/rc.local", "/etc/a.sh", "/etc/b.sh", "/etc/c.sh"} {
		ts = append(ts, facts.Timestomp{
			Path: p, ModUTC: "2020-01-01T00:00:00Z",
			MetaUTC: "2026-01-01T00:00:00Z", DeltaH: 52000, Cluster: 4,
		})
		trig = append(trig, facts.Trigger{File: p, Kind: "rc", When: "boot", Exec: true})
	}
	f := &facts.Facts{Timestomps: ts, Triggers: trig}

	r := dataFalsificada.Run(dataFalsificada, f, testEnv())
	if len(r.Findings) != 1 {
		t.Fatalf("o lote vira UMA linha de contexto — nem quatro achados (parede), "+
			"nem zero (era assim que quatro `touch -d` no mesmo segundo limpavam o "+
			"rastro). Achados: %d", len(r.Findings))
	}
	fd := r.Findings[0]
	if fd.Sev != check.SevInfo {
		t.Errorf("sev=%v, queria INFO — sem corroboração forte, lote é contexto", fd.Sev)
	}
	ev := strings.Join(fd.Evidence, " ")
	if !strings.Contains(ev, "extração em massa") || !strings.Contains(ev, "4 arquivo") {
		t.Errorf("a linha precisa dizer QUANTOS e POR QUÊ: %s", ev)
	}
}

// E a corroboração forte VENCE o lote: build de imagem não deixa processo
// rodando nem põe bit setuid em arquivo de configuração. Sem esta metade, o
// atacante recuperaria a evasão só acrescentando vizinhos ao cluster.
func TestTimestompComCorroboracaoForteIgnoraOLote(t *testing.T) {
	f := &facts.Facts{
		Timestomps: []facts.Timestomp{{
			Path: "/usr/local/sbin/implante", ModUTC: "2020-01-01T00:00:00Z",
			MetaUTC: "2026-01-01T00:00:00Z", DeltaH: 52000, Cluster: 40,
		}},
		Suid: []facts.SuidFile{{Path: "/usr/local/sbin/implante"}},
	}
	r := dataFalsificada.Run(dataFalsificada, f, testEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevCritical {
		t.Fatalf("SETUID vence o lote: %+v", r.Findings)
	}
}

// Cluster pequeno (o A4 planta dois) não é lote e não rebaixa nada.
func TestTimestompClusterPequenoContinuaCritico(t *testing.T) {
	f := &facts.Facts{
		Timestomps: []facts.Timestomp{{
			Path: "/etc/rc.local", ModUTC: "2020-01-01T00:00:00Z",
			MetaUTC: "2026-01-01T00:00:00Z", DeltaH: 52000, Cluster: 2,
		}},
		Triggers: []facts.Trigger{{File: "/etc/rc.local", Kind: "rc", When: "boot", Exec: true}},
	}
	r := dataFalsificada.Run(dataFalsificada, f, testEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevCritical {
		t.Fatalf("cluster de 2 não é extração em massa: %+v", r.Findings)
	}
}

// pkg_hook é o gatilho onde PRESENÇA não é execução, e confundir os dois
// promovia um host limpo a comprometido.
//
// /etc/apt/apt.conf.d/50unattended-upgrades tem a forma exata de um timestomp —
// mtime na data de build do pacote (anos atrás), ctime na hora em que a camada
// da imagem foi criada, e nenhum pacote reivindicando o arquivo no dump. Mas ele
// só define OPÇÃO (Unattended-Upgrade::*, APT::Periodic::*): não roda comando
// nenhum. Tratá-lo como alvo de persistência o fazia CRITICAL de timestomp num
// servidor de produção intocado — o T1 da suíte de cenários caía exatamente
// aqui.
//
// Um pkg_hook só tem poder se define um HOOK que executa. Sem hook, o timestomp
// dele não é promovido; com hook, continua sendo — este teste prova os dois
// lados na MESMA forma temporal, para que a diferença seja só o conteúdo.
func TestPkgHookSoTemPoderSeRodaComando(t *testing.T) {
	ts := func(p string) facts.Timestomp {
		return facts.Timestomp{Path: p, ModUTC: "2022-12-31T20:59:00Z",
			MetaUTC: "2026-08-23T16:00:31Z", DeltaH: 31939, Cluster: 1}
	}
	// Só opção — a forma do 50unattended-upgrades.
	soOpcao := facts.Trigger{
		File: "/etc/apt/apt.conf.d/50unattended-upgrades", Kind: "pkg_hook",
		When: "a cada operação do gerenciador de pacotes",
		Lines: []facts.TriggerLine{
			{N: 1, Text: `APT::Periodic::Unattended-Upgrade "1";`},
			{N: 2, Text: `Unattended-Upgrade::Origins-Pattern {`},
			// Um EXEMPLO de hook comentado, como a config padrão traz: casar
			// aqui reintroduziria o FP por outra porta.
			{N: 3, Text: `//  DPkg::Pre-Install-Pkgs {"/usr/bin/foo";};`},
		},
	}
	f := &facts.Facts{Timestomps: []facts.Timestomp{ts(soOpcao.File)},
		Triggers: []facts.Trigger{soOpcao}}
	r := dataFalsificada.Run(dataFalsificada, f, testEnv())
	if len(r.Findings) != 0 {
		t.Errorf("um apt.conf.d só de OPÇÃO virou achado de timestomp (%d): é o FP "+
			"que fazia o servidor de produção limpo sair CRITICAL", len(r.Findings))
	}

	// Mesma forma temporal, mas com um HOOK que roda comando: continua CRITICAL.
	comHook := soOpcao
	comHook.File = "/etc/apt/apt.conf.d/99backdoor"
	comHook.Lines = []facts.TriggerLine{
		{N: 1, Text: `DPkg::Pre-Install-Pkgs {"/usr/local/bin/x || true";};`},
	}
	f2 := &facts.Facts{Timestomps: []facts.Timestomp{ts(comHook.File)},
		Triggers: []facts.Trigger{comHook}}
	r2 := dataFalsificada.Run(dataFalsificada, f2, testEnv())
	if len(r2.Findings) != 1 || r2.Findings[0].Sev != check.SevCritical {
		t.Errorf("um apt hook que RODA comando, com data mexida, deixou de ser "+
			"CRITICAL: a correção do FP não pode cegar a detecção real. Achados: %d",
			len(r2.Findings))
	}
}

// O comentário do apt tem três formas, e um exemplo de hook comentado NÃO
// executa. O parser de Trigger só descarta a linha que começa com #; o // no
// meio e o bloco /* … */ multi-linha ficam, e a config padrão do apt traz
// exemplos de hook comentados nas três formas. Casar dentro deles fabricaria um
// CRITICAL de timestomp sobre configuração inerte.
func TestPkgHookIgnoraComentarioDeBloco(t *testing.T) {
	ts := func(p string) facts.Timestomp {
		return facts.Timestomp{Path: p, ModUTC: "2022-01-01T00:00:00Z",
			MetaUTC: "2026-08-23T16:00:31Z", DeltaH: 40000, Cluster: 1}
	}
	casos := []struct {
		nome    string
		linhas  []string
		querAch bool
	}{
		{"hook dentro de bloco /* */ multi-linha", []string{
			"/*", `DPkg::Pre-Install-Pkgs {"/usr/local/bin/x";};`, "*/"}, false},
		{"hook comentado com // no meio", []string{
			`Foo "bar";  // DPkg::Pre-Invoke {"/x";};`}, false},
		{"hook comentado com # no meio", []string{
			`Foo "bar";  # APT::Update::Post-Invoke {"/x";};`}, false},
		{"hook REAL com comentário depois", []string{
			`DPkg::Pre-Invoke {"/usr/local/bin/real";};  // roda mesmo`}, true},
	}
	for _, c := range casos {
		var lns []facts.TriggerLine
		for i, txt := range c.linhas {
			lns = append(lns, facts.TriggerLine{N: i + 1, Text: txt})
		}
		trig := facts.Trigger{File: "/etc/apt/apt.conf.d/99x", Kind: "pkg_hook",
			When: "a cada operação do gerenciador de pacotes", Lines: lns}
		f := &facts.Facts{Timestomps: []facts.Timestomp{ts(trig.File)},
			Triggers: []facts.Trigger{trig}}
		r := dataFalsificada.Run(dataFalsificada, f, testEnv())
		tem := len(r.Findings) > 0 && r.Findings[0].Sev == check.SevCritical
		if tem != c.querAch {
			t.Errorf("%s: CRITICAL=%v, queria %v", c.nome, tem, c.querAch)
		}
	}
}

// dnf/yum plugin config compartilha o kind pkg_hook mas não tem gramática de
// hook do apt: dar poder a ele pela gramática errada seria falso sinal. O
// arquivo de config só liga um plugin cujo código mora noutro lugar.
func TestPkgHookForaDoAptNaoTemPoder(t *testing.T) {
	trig := facts.Trigger{File: "/etc/dnf/plugins/evil.conf", Kind: "pkg_hook",
		When: "a cada operação do gerenciador de pacotes",
		Lines: []facts.TriggerLine{
			{N: 1, Text: "[main]"},
			// Linha ATIVA (sem comentário) contendo a string: só o escopo por
			// caminho — não é apt.conf.d — impede o match. Sem o guard, a
			// gramática do apt casaria aqui e promoveria um config inerte.
			{N: 2, Text: "post-invoke=/usr/local/bin/x"}}}
	f := &facts.Facts{
		Timestomps: []facts.Timestomp{{Path: trig.File, ModUTC: "2022-01-01T00:00:00Z",
			MetaUTC: "2026-08-23T16:00:31Z", DeltaH: 40000, Cluster: 1}},
		Triggers: []facts.Trigger{trig}}
	r := dataFalsificada.Run(dataFalsificada, f, testEnv())
	if len(r.Findings) != 0 {
		t.Errorf("config de plugin dnf virou achado de timestomp (%d): a gramática "+
			"do apt foi aplicada fora do apt.conf.d", len(r.Findings))
	}
}
