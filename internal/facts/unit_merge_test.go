package facts

import (
	"os"
	"path/filepath"
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
				alvos = append(alvos, ex.Target)
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
