package facts

import (
	"os"
	"path/filepath"
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
