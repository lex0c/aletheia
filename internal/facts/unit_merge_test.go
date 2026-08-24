package facts

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/env"
)

func coletarUnits(t *testing.T, arqs map[string]string, links map[string]string) []Unit {
	t.Helper()
	raiz := t.TempDir()
	for p, c := range arqs {
		full := filepath.Join(raiz, p)
		os.MkdirAll(filepath.Dir(full), 0o755)
		if err := os.WriteFile(full, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for p, alvo := range links {
		full := filepath.Join(raiz, p)
		os.MkdirAll(filepath.Dir(full), 0o755)
		if err := os.Symlink(alvo, full); err != nil {
			t.Fatal(err)
		}
	}
	e := env.Probe(env.Options{Root: raiz, Version: "test"})
	t.Cleanup(func() { e.Close() })
	f := &Facts{}
	collectUnits(f, e)
	return f.Units
}

func acharUnit(us []Unit, path string) *Unit {
	for i := range us {
		if us[i].Path == path {
			return &us[i]
		}
	}
	return nil
}

// item 2: precedência. A base em /etc vence a de /usr/lib de mesmo nome; a de
// /usr/lib fica Shadowed e os checks de execução a pulam.
func TestMerge_PrecedenciaSombreia(t *testing.T) {
	us := coletarUnits(t, map[string]string{
		"etc/systemd/system/api.service":     "[Service]\nExecStart=/usr/bin/api\n",
		"usr/lib/systemd/system/api.service": "[Service]\nExecStart=/tmp/old-backdoor\n",
	}, nil)
	vencedora := acharUnit(us, "/etc/systemd/system/api.service")
	perdedora := acharUnit(us, "/usr/lib/systemd/system/api.service")
	if vencedora == nil || perdedora == nil {
		t.Fatalf("units: %+v", us)
	}
	if vencedora.Shadowed {
		t.Error("a de /etc é de MAIOR precedência: não pode ser sombreada")
	}
	if !perdedora.Shadowed || perdedora.Efetiva() {
		t.Error("a de /usr/lib é sobrescrita: Shadowed e não-efetiva")
	}
}

// item 2: máscara. Link para /dev/null desliga a unit e o grupo.
func TestMerge_MascaraDesliga(t *testing.T) {
	us := coletarUnits(t,
		map[string]string{"usr/lib/systemd/system/foo.service": "[Service]\nExecStart=/usr/bin/foo\n"},
		map[string]string{"etc/systemd/system/foo.service": "/dev/null"},
	)
	mask := acharUnit(us, "/etc/systemd/system/foo.service")
	if mask == nil || !mask.Masked || mask.Efetiva() {
		t.Fatalf("link para /dev/null devia marcar Masked e não-efetiva: %+v", mask)
	}
}

// item 9: ordem entre drop-ins. `10-mal` põe um EnvironmentFile; `20-reset` o
// limpa — o LD_PRELOAD do 10-mal NÃO deve sobreviver.
func TestMerge_ResetEnvEntreDropIns(t *testing.T) {
	us := coletarUnits(t, map[string]string{
		"etc/a.env":                                      "LD_PRELOAD=/tmp/.x.so\n",
		"usr/lib/systemd/system/svc.service":             "[Service]\nExecStart=/usr/bin/svc\n",
		"etc/systemd/system/svc.service.d/10-mal.conf":   "[Service]\nEnvironmentFile=/etc/a.env\n",
		"etc/systemd/system/svc.service.d/20-reset.conf": "[Service]\nEnvironmentFile=\n",
	}, nil)
	// nenhuma unit do grupo pode carregar o LD_PRELOAD do 10-mal
	for _, u := range us {
		if u.Name != "svc.service" {
			continue
		}
		for _, ev := range u.Environment {
			if ev.Key == "LD_PRELOAD" {
				t.Fatalf("20-reset devia limpar o EnvironmentFile do 10-mal: %+v em %s", ev, u.Path)
			}
		}
	}
}

// item 9 inverso: `10-reset` antes de `20-mal` — o LD_PRELOAD do 20-mal
// SOBREVIVE (o reset veio antes).
func TestMerge_ResetAntesNaoLimpaPosterior(t *testing.T) {
	us := coletarUnits(t, map[string]string{
		"etc/a.env":                                      "LD_PRELOAD=/tmp/.x.so\n",
		"usr/lib/systemd/system/svc.service":             "[Service]\nExecStart=/usr/bin/svc\n",
		"etc/systemd/system/svc.service.d/10-reset.conf": "[Service]\nEnvironmentFile=\n",
		"etc/systemd/system/svc.service.d/20-mal.conf":   "[Service]\nEnvironmentFile=/etc/a.env\n",
	}, nil)
	achou := false
	for _, u := range us {
		if u.Name != "svc.service" {
			continue
		}
		for _, ev := range u.Environment {
			if ev.Key == "LD_PRELOAD" {
				achou = true
			}
		}
	}
	if !achou {
		t.Error("o EnvironmentFile do 20-mal veio DEPOIS do reset: deve sobreviver")
	}
}

// P0: a ordem de precedência REAL do systemd — transient e control vencem
// /etc/systemd/system. A unit efêmera do systemd-run em /run/systemd/transient
// é a que EXECUTA; marcá-la Shadowed (e a de /etc efetiva) é FN da unit ativa.
func TestMerge_TransientVenceEtc(t *testing.T) {
	us := coletarUnits(t, map[string]string{
		"etc/systemd/system/x.service":    "[Service]\nExecStart=/usr/bin/legit\n",
		"run/systemd/transient/x.service": "[Service]\nExecStart=/tmp/.implant\n",
	}, nil)
	transient := acharUnit(us, "/run/systemd/transient/x.service")
	etc := acharUnit(us, "/etc/systemd/system/x.service")
	if transient == nil || etc == nil {
		t.Fatalf("units: %+v", us)
	}
	if transient.Shadowed || !transient.Efetiva() {
		t.Error("transient VENCE /etc: é a unit que o systemd executa")
	}
	if !etc.Shadowed {
		t.Error("a de /etc é sobrescrita pela transient")
	}
}

// P0: /usr/local/lib vence /usr/lib (o admin sobre a distro).
func TestMerge_LocalVenceUsrLib(t *testing.T) {
	us := coletarUnits(t, map[string]string{
		"usr/local/lib/systemd/system/y.service": "[Service]\nExecStart=/usr/local/bin/y\n",
		"usr/lib/systemd/system/y.service":       "[Service]\nExecStart=/usr/bin/y\n",
	}, nil)
	local := acharUnit(us, "/usr/local/lib/systemd/system/y.service")
	lib := acharUnit(us, "/usr/lib/systemd/system/y.service")
	if local == nil || lib == nil {
		t.Fatalf("units: %+v", us)
	}
	if !local.Efetiva() {
		t.Error("/usr/local/lib vence /usr/lib")
	}
	if !lib.Shadowed {
		t.Error("a de /usr/lib fica Shadowed")
	}
}

// P0/P1: drop-in de MESMO nome em árvores diferentes. O systemd aplica só o de
// maior precedência (/etc > /usr/lib). Aqui o /etc reseta o Exec e planta
// /tmp/.evil; o /usr/lib de mesmo nome tentaria resetar e voltar ao legítimo.
// Se os DOIS aplicassem, o /usr/lib clobava o /tmp/.evil = FN. Só o /etc vale.
func TestMerge_DropinMesmoNomeSoOMaiorAplica(t *testing.T) {
	us := coletarUnits(t, map[string]string{
		"usr/lib/systemd/system/x.service":             "[Service]\nExecStart=/usr/bin/x\n",
		"etc/systemd/system/x.service.d/10-o.conf":     "[Service]\nExecStart=\nExecStart=/tmp/.evil\n",
		"usr/lib/systemd/system/x.service.d/10-o.conf": "[Service]\nExecStart=\nExecStart=/usr/bin/x\n",
	}, nil)
	etc := acharUnit(us, "/etc/systemd/system/x.service.d/10-o.conf")
	usr := acharUnit(us, "/usr/lib/systemd/system/x.service.d/10-o.conf")
	if etc == nil || usr == nil {
		t.Fatalf("units: %+v", us)
	}
	if etc.Shadowed {
		t.Error("o drop-in de /etc é o de maior precedência: deve valer")
	}
	if !usr.Shadowed {
		t.Error("o drop-in de /usr/lib de MESMO nome é descartado pelo systemd")
	}
	// o Exec efetivo do grupo tem de conter /tmp/.evil (do /etc), não o legítimo
	var alvos []string
	for _, u := range us {
		if u.Name == "x.service" && u.Efetiva() {
			for _, ex := range u.Exec {
				alvos = append(alvos, ex.AlvoUnico())
			}
		}
	}
	temEvil, temLegit := false, false
	for _, a := range alvos {
		if a == "/tmp/.evil" {
			temEvil = true
		}
		if a == "/usr/bin/x" {
			temLegit = true
		}
	}
	if !temEvil {
		t.Errorf("o Exec efetivo perdeu /tmp/.evil do drop-in vencedor: %v", alvos)
	}
	_ = temLegit
}

// P1 (filosofia central): "não consegui ler" ≠ "unit vazia". Um .service
// ilegível (EACCES) sem gap virava unit sem Exec — benigna aos olhos dos
// checks. FN. Tem de virar cobertura parcial DECLARADA.
func TestUnitIlegivelViraGap(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root lê 0o000: o gap por permissão não se reproduz como root")
	}
	raiz := t.TempDir()
	p := filepath.Join(raiz, "etc/systemd/system/x.service")
	os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, []byte("[Service]\nExecStart=/tmp/.x\n"), 0o000); err != nil {
		t.Fatal(err)
	}
	e := env.Probe(env.Options{Root: raiz, Version: "test"})
	t.Cleanup(func() { e.Close() })
	f := &Facts{}
	collectUnits(f, e)
	achou := false
	for _, m := range f.Partial["persist"] {
		if strings.Contains(m, "x.service") && strings.Contains(m, "NÃO foi avaliado") {
			achou = true
		}
	}
	if !achou {
		t.Errorf("unit ilegível deve virar gap declarado, não silêncio: %v", f.Partial["persist"])
	}
}

// P1 #4: o ExecSearchPath de um DROP-IN alcança o ExecStart da BASE. Por-arquivo
// a base (ExecStart=agent, sem searchpath próprio) via só "agent"; é o drop-in
// ExecSearchPath=/tmp/.hidden que faz o systemd rodar /tmp/.hidden/agent. A
// resolução na EffectiveUnit (pós-merge) fecha esse bypass.
func TestMerge_ExecSearchPathDeDropinAlcancaBase(t *testing.T) {
	us := coletarUnits(t, map[string]string{
		"usr/lib/systemd/system/x.service":            "[Service]\nExecStart=agent\n",
		"etc/systemd/system/x.service.d/10-path.conf": "[Service]\nExecSearchPath=/tmp/.hidden\n",
		"tmp/.hidden/agent":                           "x",
	}, nil)
	base := acharUnit(us, "/usr/lib/systemd/system/x.service")
	if base == nil || len(base.Exec) != 1 {
		t.Fatalf("base: %+v", base)
	}
	if base.Exec[0].AlvoUnico() != "/tmp/.hidden/agent" {
		t.Errorf("o ExecStart da base deve resolver contra o ExecSearchPath do drop-in: Target=%q, Cmd=%q",
			base.Exec[0].AlvoUnico(), base.Exec[0].Cmd)
	}
}

// P1/P2 #8: drop-in POR PADRÃO. O systemd aplica também de TYPE.d/ (type-wide) e
// PREFIX-.service.d/ (por dash), não só de NAME.service.d/. Um `service.d/` que
// altera TODA service, ou um `foo-.service.d/`, passava invisível.
func TestMerge_DropinPorPadrao(t *testing.T) {
	us := coletarUnits(t, map[string]string{
		"usr/lib/systemd/system/foo.service":             "[Service]\nExecStart=/usr/bin/foo\n",
		"usr/lib/systemd/system/foo-bar.service":         "[Service]\nExecStart=/usr/bin/foobar\n",
		"etc/systemd/system/service.d/50-global.conf":    "[Service]\nExecStartPre=/tmp/.global\n",
		"etc/systemd/system/foo-.service.d/50-pref.conf": "[Service]\nExecStartPre=/tmp/.pref\n",
	}, nil)
	tem := func(unit, alvo string) bool {
		for _, u := range us {
			if u.Name == unit && u.Efetiva() {
				for _, ex := range u.Exec {
					if ex.AlvoUnico() == alvo {
						return true
					}
				}
			}
		}
		return false
	}
	if !tem("foo.service", "/tmp/.global") || !tem("foo-bar.service", "/tmp/.global") {
		t.Error("type-wide service.d/ deve alcançar TODA service")
	}
	if !tem("foo-bar.service", "/tmp/.pref") {
		t.Error("prefixo foo-.service.d/ deve alcançar foo-bar.service")
	}
	if tem("foo.service", "/tmp/.pref") {
		t.Error("prefixo foo-.service.d/ NÃO alcança foo.service (não casa o dash)")
	}
}

// P2 #8 (parte a): o load path de user por-home inclui ~/.local/share/systemd/
// user e o user.control, não só ~/.config/systemd/user. Uma unit de backdoor
// nesses cantos precisa ser COLETADA (visível aos checks).
func TestColeta_UserXDGLocalShare(t *testing.T) {
	raiz := t.TempDir()
	os.MkdirAll(filepath.Join(raiz, "etc"), 0o755)
	os.WriteFile(filepath.Join(raiz, "etc/passwd"),
		[]byte("dev:x:1000:1000::/home/dev:/bin/bash\n"), 0o644)
	dir := filepath.Join(raiz, "home/dev/.local/share/systemd/user")
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "backdoor.service"), []byte("[Service]\nExecStart=/tmp/.x\n"), 0o644)

	e := env.Probe(env.Options{Root: raiz, Version: "test"})
	t.Cleanup(func() { e.Close() })
	f := &Facts{}
	collectUnits(f, e)
	for _, u := range f.Units {
		if u.Name == "backdoor.service" && u.Scope == "user" {
			return
		}
	}
	t.Errorf("unit em ~/.local/share/systemd/user deve ser coletada; veio %d units", len(f.Units))
}

// #4 (regressão): uma unit MASCARADA não pode virar lacuna. O parseUnitFile
// declara gap quando o ReadFile falha (EACCES é "não consegui ler") — mas
// /dev/null devolve ErrNaoEhArquivo, que EhLacuna também classifica como gap.
// Sem detectar a máscara ANTES do parse, a unit saía Masked E "não consegui
// ler" ao mesmo tempo: cobertura parcial falsa. Cobre link/dev/null e o
// arquivo de tamanho-zero, que o systemd também trata como máscara.
func TestMerge_MascaraNaoGeraLacuna(t *testing.T) {
	raiz := t.TempDir()
	os.MkdirAll(filepath.Join(raiz, "etc/systemd/system"), 0o755)
	if err := os.Symlink("/dev/null", filepath.Join(raiz, "etc/systemd/system/foo.service")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(raiz, "etc/systemd/system/bar.service"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	e := env.Probe(env.Options{Root: raiz, Version: "test"})
	defer e.Close()
	f := &Facts{}
	collectUnits(f, e)

	foo := acharUnit(f.Units, "/etc/systemd/system/foo.service")
	if foo == nil || !foo.Masked || foo.Efetiva() {
		t.Fatalf("link /dev/null devia sair Masked e não-efetiva: %+v", foo)
	}
	bar := acharUnit(f.Units, "/etc/systemd/system/bar.service")
	if bar == nil || !bar.Masked || bar.Efetiva() {
		t.Fatalf("arquivo vazio é máscara para o systemd: Masked e não-efetiva: %+v", bar)
	}
	for cat, motivos := range f.PersistDenied {
		for _, m := range motivos {
			if strings.Contains(m, "foo.service") || strings.Contains(m, "bar.service") {
				t.Fatalf("máscara é config conhecida, não lacuna — gap falso em %q: %q", cat, m)
			}
		}
	}
}

// #6 (regressão): a expansão de drop-in POR PADRÃO é O(bases × padrões). Um
// punhado de drop-ins type-wide (service.d/) sobre centenas de services
// materializaria dezenas de milhares de Unit — e o maxUnits da COLETA não pega
// isso porque roda antes da expansão. O teto aqui corta e DECLARA a lacuna.
func TestExpandirDropins_TetoDeExpansaoDeclaraLacuna(t *testing.T) {
	const nBases, nPadroes = 100, 40 // 100 × 40 = 4000 > maxUnits (3000)
	var units []Unit
	for i := 0; i < nBases; i++ {
		s := strconv.Itoa(i)
		units = append(units, Unit{
			Name: "svc" + s + ".service", Scope: "system",
			Path: "/usr/lib/systemd/system/svc" + s + ".service",
		})
	}
	for j := 0; j < nPadroes; j++ {
		s := strconv.Itoa(j)
		units = append(units, Unit{
			Name: "service.d/" + s + "-wide.conf", DropInFor: "service", Scope: "system",
			Path: "/etc/systemd/system/service.d/" + s + "-wide.conf",
		})
	}
	f := &Facts{}
	out := expandirDropins(f, units)
	if len(f.Partial["persist"]) == 0 {
		t.Fatal("estouro do teto de expansão devia declarar lacuna em Partial[persist]")
	}
	if len(out) > maxUnits {
		t.Fatalf("sem teto a saída seria %d; o teto devia limitar a <= %d, veio %d",
			nBases+nBases*nPadroes, maxUnits, len(out))
	}
}

// #2 (FN): um drop-in que RESETA o ExecSearchPath e re-aponta para um diretório
// oculto MOVE o alvo efetivo. A resolução por-arquivo já tinha fixado o Cmd da
// base no diretório dela (com "/"), e o resolverNomeNu pós-merge era no-op sobre
// caminho já resolvido — então a aletheia reportava o binário LEGÍTIMO e perdia
// o dropado. Resolver a partir do RawCmd cura: o alvo tem de ser o do drop-in.
func TestMerge_DropinResetaSearchPathMoveAlvo(t *testing.T) {
	us := coletarUnits(t, map[string]string{
		"usr/lib/systemd/system/svc.service":         "[Service]\nExecStart=agent\nExecSearchPath=/opt/real/bin\n",
		"opt/real/bin/agent":                         "#!/bin/sh\n",
		"etc/systemd/system/svc.service.d/10-x.conf": "[Service]\nExecSearchPath=\nExecSearchPath=/tmp/.oculto\n",
		"tmp/.oculto/agent":                          "#!/bin/sh\n",
	}, nil)
	svc := acharUnit(us, "/usr/lib/systemd/system/svc.service")
	if svc == nil || len(svc.Exec) == 0 {
		t.Fatalf("svc.service sem Exec: %+v", us)
	}
	alvo := svc.Exec[0].AlvoUnico()
	if !strings.Contains(alvo, "/tmp/.oculto/agent") {
		t.Fatalf("reset+re-aponta do drop-in devia mover o alvo para /tmp/.oculto/agent, veio %q", alvo)
	}
	if strings.Contains(alvo, "/opt/real/bin") {
		t.Fatalf("o alvo não podia ficar no diretório da base após o reset: %q", alvo)
	}
}

// #1 (FN): ExecStart de nome NU, SEM ExecSearchPath e SEM PATH próprio. O
// systemd resolve contra um PATH fixo; se o binário está num diretório desse
// PATH onde o atacante teve escrita (/usr/local/bin), o alvo efetivo é ele. Sem
// resolver, o alvo ficava no nome nu "shellserver" e o check de dono nem via o
// binário — candidatosDePropriedade rejeita quem não tem "/". FN de evasão barata.
func TestMerge_NomeNuResolveContraPathPadrao(t *testing.T) {
	// O binário dropado num diretório de PACOTE (/usr/sbin): é lá que o sistema
	// espera SÓ arquivos de pacote, e o check sem-dono dispara. Com o nome nu não
	// resolvido, o alvo ficava "shellserver" — sem "/", fora de dirDePacote — e o
	// check nem perguntava por ele.
	us := coletarUnits(t, map[string]string{
		"usr/lib/systemd/system/web.service": "[Service]\nExecStart=shellserver --port 8080\n",
		"usr/sbin/shellserver":               "#!/bin/sh\n",
	}, nil)
	web := acharUnit(us, "/usr/lib/systemd/system/web.service")
	if web == nil || len(web.Exec) == 0 {
		t.Fatalf("web.service sem Exec: %+v", us)
	}
	if alvo := web.Exec[0].AlvoUnico(); alvo != "/usr/sbin/shellserver" {
		t.Fatalf("nome nu devia resolver contra o PATH fixo do systemd para /usr/sbin/shellserver, veio %q", alvo)
	}
}

// #1 contra-prova: um PATH PRÓPRIO (Environment=PATH=) desliga a resolução — é
// ele que o systemd consultaria, e não o modelamos. Resolver contra o PATH fixo
// aqui acusaria um diretório que o systemd não olharia: FP. O nome nu fica cru.
func TestMerge_PathProprioNaoResolveContraPadrao(t *testing.T) {
	us := coletarUnits(t, map[string]string{
		"usr/lib/systemd/system/web.service": "[Service]\nEnvironment=PATH=/opt/app/bin\nExecStart=shellserver\n",
		"usr/local/bin/shellserver":          "#!/bin/sh\n",
	}, nil)
	web := acharUnit(us, "/usr/lib/systemd/system/web.service")
	if web == nil || len(web.Exec) == 0 {
		t.Fatalf("web.service sem Exec: %+v", us)
	}
	if alvo := web.Exec[0].AlvoUnico(); alvo != "shellserver" {
		t.Fatalf("com PATH próprio o nome nu fica cru (não modelamos esse PATH), veio %q", alvo)
	}
}

// #5 (FN): unit de USUÁRIO por-home era coletada com um caminhador pela metade
// (só arquivos isUnitName), então um drop-in em ~/.config/systemd/user/agent.service.d/
// passava invisível — persistência que roda no login do usuário. Agora o user
// usa a MESMA varredura da árvore de sistema (coletarDirDeUnits): o ExecStartPre
// do drop-in tem de chegar à base efetiva.
func TestUserUnit_DropinEhVistoEEfetivo(t *testing.T) {
	us := coletarUnits(t, map[string]string{
		"etc/passwd": "root:x:0:0::/root:/bin/sh\nana:x:1000:1000::/home/ana:/bin/sh\n",
		"home/ana/.config/systemd/user/agent.service":             "[Service]\nExecStart=/usr/bin/agent\n",
		"home/ana/.config/systemd/user/agent.service.d/10-x.conf": "[Service]\nExecStartPre=/tmp/.evil\n",
	}, nil)
	// A base e o drop-in são units efetivas SEPARADAS (o merge não funde os
	// slices — os checks iteram todas as Efetiva()). O que importa: o
	// ExecStartPre=/tmp/.evil do drop-in está visível e efetivo. Antes da
	// varredura compartilhada o drop-in de user nem era coletado.
	temBase, temPre := false, false
	for _, u := range us {
		if u.Scope != "user" || u.Name != "agent.service" || !u.Efetiva() {
			continue
		}
		if u.DropInFor == "" {
			temBase = true
		}
		for _, ex := range u.Exec {
			if ex.Key == "ExecStartPre" && strings.Contains(ex.Cmd, "/tmp/.evil") {
				temPre = true
			}
		}
	}
	if !temBase {
		t.Fatalf("base de usuário agent.service não coletada/efetiva: %+v", us)
	}
	if !temPre {
		t.Fatalf("o drop-in de usuário .service.d/ (ExecStartPre=/tmp/.evil) devia estar visível e efetivo: %+v", us)
	}
}

// #5 (o mesmo caminhador traz a máscara): uma unit de usuário linkada a
// /dev/null é DESLIGADA. Antes o loop de user chamava parseUnitFile direto (sem
// detectarMascara) e ela não saía Masked; agora sai.
func TestUserUnit_MascaraEhVista(t *testing.T) {
	us := coletarUnits(t,
		map[string]string{"etc/passwd": "ana:x:1000:1000::/home/ana:/bin/sh\n"},
		map[string]string{"home/ana/.config/systemd/user/agent.service": "/dev/null"},
	)
	m := acharUnit(us, "/home/ana/.config/systemd/user/agent.service")
	if m == nil || !m.Masked || m.Efetiva() {
		t.Fatalf("máscara /dev/null de unit de usuário devia sair Masked e não-efetiva: %+v", m)
	}
}

// #3: dois drop-ins de MESMO nome de arquivo (10-x.conf) na MESMA árvore (/etc),
// um EXATO (zoo.service.d/) e um TYPE-WIDE (service.d/). O systemd aplica só o
// mais específico — o exato. Antes o empate na árvore era resolvido pela ordem
// de coleta. O nome "zoo" é lexicalmente MAIOR que "service": sem o critério de
// especificidade, o desempate lexical escolheria o type-wide (errado) — então o
// teste morre se a especificidade sumir.
func TestMerge_DropinMesmaArvoreEspecificidadeVence(t *testing.T) {
	us := coletarUnits(t, map[string]string{
		"usr/lib/systemd/system/zoo.service":         "[Service]\nExecStart=/usr/bin/zoo\n",
		"etc/systemd/system/zoo.service.d/10-x.conf": "[Service]\nExecStart=\nExecStart=/tmp/.evil\n",
		"etc/systemd/system/service.d/10-x.conf":     "[Service]\nExecStart=\nExecStart=/usr/bin/legit\n",
	}, nil)
	exato := acharUnit(us, "/etc/systemd/system/zoo.service.d/10-x.conf")
	wide := acharUnit(us, "/etc/systemd/system/service.d/10-x.conf")
	if exato == nil || wide == nil {
		t.Fatalf("drop-ins não coletados: %+v", us)
	}
	if exato.Shadowed {
		t.Error("o drop-in EXATO (zoo.service.d/) é o mais específico: deve vencer")
	}
	if !wide.Shadowed {
		t.Error("o type-wide (service.d/) de MESMO nome de arquivo é o descartado")
	}
	var alvos []string
	for _, u := range us {
		if u.Name == "zoo.service" && u.Efetiva() {
			for _, ex := range u.Exec {
				alvos = append(alvos, ex.AlvoUnico())
			}
		}
	}
	temEvil, temLegit := false, false
	for _, a := range alvos {
		if a == "/tmp/.evil" {
			temEvil = true
		}
		if a == "/usr/bin/legit" {
			temLegit = true
		}
	}
	if !temEvil || temLegit {
		t.Errorf("o vencedor devia ser o exato (/tmp/.evil), não o type-wide (/usr/bin/legit): %v", alvos)
	}
}

// Environment=PATH=/tmp/.cache + ExecStart=agent: o nome nu tem de resolver
// contra o PATH PRÓPRIO da unit (é ele que o systemd consulta), não ficar cru.
// Sem isto, /tmp/.cache/agent escapava dos checks de dono e caminho suspeito.
func TestMerge_EnvironmentPATHResolveNomeNu(t *testing.T) {
	us := coletarUnits(t, map[string]string{
		"etc/systemd/system/svc.service": "[Service]\nEnvironment=PATH=/tmp/.cache\nExecStart=agent --daemon\n",
		"tmp/.cache/agent":               "x",
	}, nil)
	u := acharUnit(us, "/etc/systemd/system/svc.service")
	if u == nil {
		t.Fatalf("unit não coletada: %+v", us)
	}
	if len(u.Exec) != 1 || u.Exec[0].Cmd != "/tmp/.cache/agent --daemon" {
		t.Fatalf("Environment=PATH deve resolver o nome nu contra o path próprio: %+v", u.Exec)
	}
	if u.Exec[0].AlvoUnico() != "/tmp/.cache/agent" {
		t.Errorf("alvo efetivo deve ser /tmp/.cache/agent, veio %q", u.Exec[0].AlvoUnico())
	}
}

// FN de multi-usuário: alice/foo.service e bob/foo.service são arquivos
// DIFERENTES de gerenciadores diferentes. Sem o Manager na chave, um sombreava
// o outro e o Exec da sombreada não era avaliado. Agora as duas sobrevivem, cada
// uma com seu ExecStart.
func TestMerge_UserUnitsPorManagerNaoColidem(t *testing.T) {
	us := coletarUnits(t, map[string]string{
		"etc/passwd": "root:x:0:0::/root:/bin/sh\n" +
			"alice:x:1000:1000::/home/alice:/bin/sh\n" +
			"bob:x:1001:1001::/home/bob:/bin/sh\n",
		"home/alice/.config/systemd/user/foo.service": "[Service]\nExecStart=/tmp/alice-thing\n",
		"home/bob/.config/systemd/user/foo.service":   "[Service]\nExecStart=/tmp/bob-thing\n",
	}, nil)

	var alice, bob *Unit
	for i := range us {
		if us[i].Manager == "alice" && us[i].Name == "foo.service" {
			alice = &us[i]
		}
		if us[i].Manager == "bob" && us[i].Name == "foo.service" {
			bob = &us[i]
		}
	}
	if alice == nil || bob == nil {
		t.Fatalf("as DUAS units de usuário têm de existir com Manager próprio: %+v", us)
	}
	if alice.Shadowed || bob.Shadowed {
		t.Error("nenhuma pode sombrear a outra — são gerenciadores diferentes")
	}
	if len(alice.Exec) != 1 || alice.Exec[0].Cmd != "/tmp/alice-thing" {
		t.Errorf("alice manteve o próprio Exec? %+v", alice.Exec)
	}
	if len(bob.Exec) != 1 || bob.Exec[0].Cmd != "/tmp/bob-thing" {
		t.Errorf("bob manteve o próprio Exec? %+v", bob.Exec)
	}
}

// FN do wrapper: `ExecStart=/usr/bin/env agent` roda `agent` via PATH, mas o
// nome nu embrulhado não era resolvido — o alvo ficava "agent" (nu), fora do
// check de dono. Agora o alvo efetivo é resolvido contra o PATH.
func TestMerge_NomeNuAtrasDeWrapperResolve(t *testing.T) {
	us := coletarUnits(t, map[string]string{
		"etc/systemd/system/svc.service": "[Service]\nExecStart=/usr/bin/env agent --daemon\n",
		"usr/local/bin/agent":            "x",
	}, nil)
	u := acharUnit(us, "/etc/systemd/system/svc.service")
	if u == nil || len(u.Exec) != 1 {
		t.Fatalf("unit/exec: %+v", us)
	}
	// /usr/local/bin está no PATH fixo do systemd.exec(5): o agente embrulhado
	// resolve para lá, não fica nome nu.
	if u.Exec[0].AlvoUnico() != "/usr/local/bin/agent" {
		t.Errorf("alvo atrás de env deve resolver: quer /usr/local/bin/agent, veio %q", u.Exec[0].AlvoUnico())
	}
}

// RootDirectory=/jail: o systemd executa /jail/usr/bin/x, não o /usr/bin/x do
// host. O alvo efetivo tem de vir prefixado pelo chroot.
func TestMerge_RootDirectoryPrefixaAlvo(t *testing.T) {
	us := coletarUnits(t, map[string]string{
		"etc/systemd/system/jailed.service": "[Service]\nRootDirectory=/jail\nExecStart=/usr/bin/x\n",
		"jail/usr/bin/x":                    "bin",
	}, nil)
	u := acharUnit(us, "/etc/systemd/system/jailed.service")
	if u == nil || len(u.Exec) != 1 {
		t.Fatalf("unit/exec: %+v", us)
	}
	if u.Exec[0].AlvoUnico() != "/jail/usr/bin/x" {
		t.Errorf("RootDirectory deve prefixar o alvo: quer /jail/usr/bin/x, veio %q", u.Exec[0].AlvoUnico())
	}
}

// RootImage=: o binário vive numa imagem não montada; a unit é PULADA pelos
// checks de arquivo e a lacuna é declarada. Sem isto, o check avaliaria o
// /usr/bin/x do host — arquivo errado.
func TestMerge_RootImageDeclaraLacuna(t *testing.T) {
	raiz := t.TempDir()
	os.MkdirAll(filepath.Join(raiz, "etc/systemd/system"), 0o755)
	os.WriteFile(filepath.Join(raiz, "etc/systemd/system/img.service"),
		[]byte("[Service]\nRootImage=/srv/app.raw\nExecStart=/usr/bin/x\n"), 0o644)
	e := env.Probe(env.Options{Root: raiz, Version: "test"})
	t.Cleanup(func() { e.Close() })
	f := &Facts{}
	collectUnits(f, e)
	u := acharUnit(f.Units, "/etc/systemd/system/img.service")
	if u == nil || u.RootImage != "/srv/app.raw" {
		t.Fatalf("RootImage deve ser parseado: %+v", u)
	}
	var achou bool
	for _, p := range f.PersistDenied["unit"] {
		if strings.Contains(p, "RootImage=/srv/app.raw") {
			achou = true
		}
	}
	if !achou {
		t.Errorf("RootImage deve declarar lacuna: %v", f.PersistDenied["unit"])
	}
}
