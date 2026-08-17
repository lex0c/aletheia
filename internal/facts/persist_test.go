package facts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/env"
)

// imagem monta um rootfs de mentira e o varre com --root — que é como se
// analisa snapshot montado, e o único modo em que estes checks funcionam sem
// depender do kernel do alvo.
func imagem(t *testing.T, arquivos map[string]string) *Facts {
	t.Helper()
	raiz := t.TempDir()
	for p, corpo := range arquivos {
		full := filepath.Join(raiz, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if corpo == "<dir>" {
			if err := os.MkdirAll(full, 0o755); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.WriteFile(full, []byte(corpo), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	e := env.Probe(env.Options{Root: raiz})
	t.Cleanup(func() { e.Close() })
	return Collect(e)
}

func TestLoaderLePreloadConfEEnvironment(t *testing.T) {
	f := imagem(t, map[string]string{
		"etc/ld.so.preload":        "/usr/lib/evil.so\n# comentário\n\n/lib/outra.so\n",
		"etc/ld.so.conf":           "include /etc/ld.so.conf.d/*.conf\n/usr/lib\n",
		"etc/ld.so.conf.d/zz.conf": "/tmp/libs\n",
		"etc/environment":          "PATH=/usr/bin\nLD_PRELOAD=\"/dev/shm/x.so\"\n",
	})

	if !f.Loader.PreloadExists {
		t.Fatal("ld.so.preload existe e não foi detectado")
	}
	if len(f.Loader.PreloadLibs) != 2 {
		t.Errorf("libs = %v, quer 2 (comentário e linha vazia não contam)", f.Loader.PreloadLibs)
	}
	// "include ..." não é diretório de busca.
	var dirs []string
	for _, d := range f.Loader.SearchDirs {
		dirs = append(dirs, d.Dir)
	}
	if strings.Contains(strings.Join(dirs, " "), "include") {
		t.Errorf("linha de include virou diretório de busca: %v", dirs)
	}
	if len(f.Loader.EnvVars) != 1 || f.Loader.EnvVars[0].Value != "/dev/shm/x.so" {
		t.Errorf("LD_PRELOAD do /etc/environment = %v", f.Loader.EnvVars)
	}
}

// A ausência é o caso NORMAL. Confundi-la com erro faria todo host limpo virar
// achado.
func TestLoaderAusenteNaoEhAchadoNemLacuna(t *testing.T) {
	f := imagem(t, map[string]string{"etc/hostname": "x\n"})
	if f.Loader.PreloadExists {
		t.Error("arquivo ausente não pode ser reportado como existente")
	}
	for _, rs := range f.Partial {
		for _, r := range rs {
			if strings.Contains(r, "ld.so.preload") {
				t.Errorf("ausência virou lacuna de cobertura: %q", r)
			}
		}
	}
}

func TestEnvAssign(t *testing.T) {
	casos := []struct {
		linha, quer string
		ok          bool
	}{
		{`LD_PRELOAD=/a/b.so`, "/a/b.so", true},
		{`export LD_PRELOAD="/a/b.so"`, "/a/b.so", true},
		{`LD_PRELOAD DEFAULT=/a/b.so`, "/a/b.so", true}, // formato do pam_env
		{`LD_PRELOAD OVERRIDE=/c.so`, "/c.so", true},
		{`#LD_PRELOAD=/a.so`, "", false},
		{`LD_PRELOAD_EXTRA=/a.so`, "", false}, // prefixo não é a chave
		{`PATH=/usr/bin`, "", false},
	}
	for _, c := range casos {
		got, ok := envAssign(c.linha, "LD_PRELOAD")
		if ok != c.ok || got != c.quer {
			t.Errorf("envAssign(%q) = %q,%v — quer %q,%v", c.linha, got, ok, c.quer, c.ok)
		}
	}
}

func TestUnitParsing(t *testing.T) {
	f := imagem(t, map[string]string{
		"etc/systemd/system/x.service": `# comentário
[Unit]
Description=x

[Service]
ExecStartPre=/bin/true
ExecStart=/usr/bin/foo \
  --flag
Restart=always
User=nobody

[Install]
WantedBy=multi-user.target
`,
		"etc/systemd/system/multi-user.target.wants/x.service": "link",
		"etc/systemd/system/x.service.d/over.conf":             "[Service]\nExecStart=\nExecStart=/tmp/.y\n",
		"etc/systemd/system/b.timer":                           "[Timer]\nOnUnitActiveSec=45s\nOnCalendar=*-*-* *:*:00\n",
		"usr/lib/systemd/system/vendor.service":                "[Service]\nExecStart=/usr/bin/vendor\n",
	})

	byPath := map[string]*Unit{}
	for i := range f.Units {
		byPath[f.Units[i].Path] = &f.Units[i]
	}

	u := byPath["/etc/systemd/system/x.service"]
	if u == nil {
		t.Fatalf("unit não coletada; units = %d", len(f.Units))
	}
	if len(u.Exec) != 2 {
		t.Fatalf("Exec = %v, quer 2 (ExecStartPre e ExecStart)", u.Exec)
	}
	// Continuação com "\" precisa juntar as linhas: cortar ali perderia o
	// argumento, que é onde o payload costuma estar.
	if !strings.Contains(u.Exec[1].Cmd, "--flag") {
		t.Errorf("continuação perdida: %q", u.Exec[1].Cmd)
	}
	if u.Restart != "always" || u.User != "nobody" {
		t.Errorf("Restart=%q User=%q", u.Restart, u.User)
	}
	if !u.Enabled() {
		t.Error("symlink em multi-user.target.wants não marcou a unit como habilitada")
	}
	if u.Vendor {
		t.Error("unit em /etc não vem de pacote")
	}
	if v := byPath["/usr/lib/systemd/system/vendor.service"]; v == nil || !v.Vendor {
		t.Error("unit em /usr/lib precisa ser marcada como de pacote")
	}

	// "ExecStart=" vazio RESETA: é assim que um drop-in SUBSTITUI o comando.
	// Guardar os dois faria o relatório mostrar um comando que não roda mais.
	d := byPath["/etc/systemd/system/x.service.d/over.conf"]
	if d == nil {
		t.Fatal("drop-in não coletado")
	}
	if d.DropInFor != "x.service" {
		t.Errorf("DropInFor = %q", d.DropInFor)
	}
	if len(d.Exec) != 1 || d.Exec[0].Cmd != "/tmp/.y" {
		t.Errorf("o ExecStart vazio devia ter zerado a lista: %v", d.Exec)
	}

	tm := byPath["/etc/systemd/system/b.timer"]
	if tm == nil || tm.Kind != "timer" || tm.OnUnitActiveSec != "45s" {
		t.Errorf("timer mal lido: %+v", tm)
	}
}

// Unit de usuário mora no home e é o esconderijo da §7.3 — e o home sai do
// passwd DO ALVO, nunca do host do analista.
func TestUnitDeUsuarioSaiDoPasswdDoAlvo(t *testing.T) {
	f := imagem(t, map[string]string{
		"etc/passwd": "root:x:0:0::/root:/bin/sh\napp:x:1000:1000::/home/app:/bin/sh\n",
		"home/app/.config/systemd/user/agent.service": "[Service]\nExecStart=/tmp/.a\n",
	})
	for _, u := range f.Units {
		if u.Name == "agent.service" && u.Scope == "user" {
			return
		}
	}
	t.Errorf("unit de usuário não coletada; units = %d", len(f.Units))
}

// "Um componente do caminho não é diretório" significa que o caminho não pode
// existir — não que faltou permissão. O Alpine usa /dev/null como home de conta
// de sistema, e tratar ENOTDIR como negativa fazia TODO host Alpine reportar
// lacuna de cobertura falsa. É a mesma classe de gritar-lobo que a distinção
// entre "processo terminou" e "processo ilegível" existe para evitar.
func TestHomeQueNaoEhDiretorioNaoViraLacuna(t *testing.T) {
	f := imagem(t, map[string]string{
		"etc/passwd": "root:x:0:0::/root:/bin/sh\n" +
			"nobody:x:65534:65534::/dev/null:/sbin/nologin\n" +
			"bin:x:1:1::/bin:/sbin/nologin\n",
		"root":     "<dir>",
		"dev/null": "", // arquivo, não diretório
		"bin":      "<dir>",
	})
	for cat, motivos := range f.PersistDenied {
		for _, m := range motivos {
			if strings.Contains(m, "/dev/null") {
				t.Errorf("home que não é diretório virou lacuna [%s]: %s", cat, m)
			}
		}
	}
	// A asserção é sobre o /dev/null, não sobre lacuna nenhuma: a fixture não
	// tem /etc/shadow, e o coletor declara ESSA lacuna com razão.
	if _, temStartup := f.PersistDenied["startup"]; temStartup {
		t.Errorf("home legível não pode gerar lacuna de startup: %v", f.PersistDenied["startup"])
	}
}
