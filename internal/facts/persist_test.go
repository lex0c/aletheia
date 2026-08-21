package facts

import (
	"os"
	"path/filepath"
	"strconv"
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
		// x.service NÃO tem drop-in de reset: verifica o PARSING (continuação,
		// duas diretivas Exec, Restart, User).
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
		// y.service + drop-in de reset: verifica a FUSÃO. O ExecStart= vazio do
		// drop-in reseta a lista de ExecStart da base — mas NÃO o ExecStartPre.
		"etc/systemd/system/y.service":             "[Service]\nExecStartPre=/bin/prep\nExecStart=/tmp/old\n",
		"etc/systemd/system/y.service.d/over.conf": "[Service]\nExecStart=\nExecStart=/tmp/.y\n",
		"etc/systemd/system/b.timer":               "[Timer]\nOnUnitActiveSec=45s\nOnCalendar=*-*-* *:*:00\n",
		"usr/lib/systemd/system/vendor.service":    "[Service]\nExecStart=/usr/bin/vendor\n",
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

	// "ExecStart=" vazio RESETA: o drop-in SUBSTITUI o ExecStart.
	d := byPath["/etc/systemd/system/y.service.d/over.conf"]
	if d == nil {
		t.Fatal("drop-in não coletado")
	}
	if d.DropInFor != "y.service" {
		t.Errorf("DropInFor = %q", d.DropInFor)
	}
	if len(d.Exec) != 1 || d.Exec[0].Cmd != "/tmp/.y" {
		t.Errorf("o ExecStart vazio devia ter zerado a lista: %v", d.Exec)
	}
	// FUSÃO ciente de diretiva: o reset do drop-in tira o ExecStart /tmp/old da
	// BASE, mas o ExecStartPre /bin/prep SOBREVIVE (listas independentes).
	yb := byPath["/etc/systemd/system/y.service"]
	if yb == nil {
		t.Fatal("y.service base não coletada")
	}
	if len(yb.Exec) != 1 || yb.Exec[0].Key != "ExecStartPre" {
		t.Errorf("o reset de ExecStart do drop-in devia limpar só o ExecStart da base, "+
			"preservando o ExecStartPre: %+v", yb.Exec)
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

// Sob usrmerge /lib é link para usr/lib, e /lib/systemd/system é o MESMO
// diretório que /usr/lib/systemd/system. Os dois estão na lista porque em
// distribuição sem usrmerge são árvores diferentes — mas em Debian 12, Fedora e
// Arch ler as duas coletava cada unit de sistema duas vezes.
//
// O sintoma no cenário com serviços de verdade foi "2× ssh.socket" onde havia
// um socket só: um fato virando dois achados, inflando a contagem de avisos que
// a frota lê.
func TestUnitsNaoDuplicamSobUsrMerge(t *testing.T) {
	raiz := t.TempDir()
	if err := os.MkdirAll(filepath.Join(raiz, "usr/lib/systemd/system"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(raiz, "usr/lib/systemd/system/a.service"),
		[]byte("[Service]\nExecStart=/usr/bin/a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// o link RELATIVO, do jeito que a distribuição o cria
	if err := os.Symlink("usr/lib", filepath.Join(raiz, "lib")); err != nil {
		t.Fatal(err)
	}

	e := env.Probe(env.Options{Root: raiz})
	t.Cleanup(func() { e.Close() })
	f := Collect(e)

	var n int
	for i := range f.Units {
		if f.Units[i].Name == "a.service" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("a mesma unit foi coletada %d vezes: /lib e /usr/lib são o mesmo diretório", n)
	}
}

// E a dedução não pode ir longe demais: sem usrmerge as duas árvores são
// DIFERENTES, e ler só uma perderia metade das units num host antigo — que é
// exatamente onde a ferramenta precisa funcionar.
func TestUnitsLeAsDuasArvoresSemUsrMerge(t *testing.T) {
	raiz := t.TempDir()
	for _, d := range []string{"usr/lib/systemd/system", "lib/systemd/system"} {
		if err := os.MkdirAll(filepath.Join(raiz, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(raiz, "usr/lib/systemd/system/a.service"),
		[]byte("[Service]\nExecStart=/usr/bin/a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(raiz, "lib/systemd/system/b.service"),
		[]byte("[Service]\nExecStart=/usr/bin/b\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	e := env.Probe(env.Options{Root: raiz})
	t.Cleanup(func() { e.Close() })
	f := Collect(e)

	vistos := map[string]bool{}
	for i := range f.Units {
		vistos[f.Units[i].Name] = true
	}
	if !vistos["a.service"] || !vistos["b.service"] {
		t.Errorf("as duas árvores separadas têm que ser lidas: %v", vistos)
	}
}

// O teto de include do ld.so.conf (maxConfsLoader) não pode cortar em silêncio:
// um diretório de busca gravável declarado além dele viraria "não há" quando o
// certo é "parei de olhar". Com mais arquivos que o teto, a lacuna é declarada.
func TestLoaderTetoDeIncludeDeclaraLacuna(t *testing.T) {
	arqs := map[string]string{
		"etc/ld.so.conf": "/usr/lib\n",
	}
	for i := 0; i < maxConfsLoader+8; i++ {
		arqs["etc/ld.so.conf.d/"+strconv.Itoa(i)+".conf"] = "/opt/lib" + strconv.Itoa(i) + "\n"
	}
	f := imagem(t, arqs)
	achou := false
	for _, m := range f.PersistDenied["loader"] {
		if strings.Contains(m, "teto") {
			achou = true
		}
	}
	if !achou {
		t.Errorf("cadeia acima do teto tem de declarar lacuna: %v", f.PersistDenied["loader"])
	}
}

// ExecSearchPath: ExecStart de nome NU resolve contra o dir customizado. Sem
// isso, o alvo real (/tmp/.cache/bin/agent) some — o parser via só "agent".
func TestExecSearchPathResolveNomeNu(t *testing.T) {
	raiz := t.TempDir()
	os.MkdirAll(filepath.Join(raiz, "tmp/.cache/bin"), 0o755)
	os.WriteFile(filepath.Join(raiz, "tmp/.cache/bin/agent"), []byte("x"), 0o755)
	os.WriteFile(filepath.Join(raiz, "svc.service"),
		[]byte("[Service]\nExecSearchPath=/tmp/.cache/bin\nExecStart=agent --daemon\nRestart=always\n"), 0o644)
	e := env.Probe(env.Options{Root: raiz, Version: "test"})
	t.Cleanup(func() { e.Close() })
	u := parseUnitFile(&Facts{}, e, "/svc.service", "system", kindOf("/svc.service"), false)
	if len(u.Exec) != 1 || u.Exec[0].Cmd != "/tmp/.cache/bin/agent --daemon" {
		t.Fatalf("nome nu deve resolver contra ExecSearchPath: %+v", u.Exec)
	}
}
