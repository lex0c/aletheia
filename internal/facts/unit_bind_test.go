package facts

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/lex0c/aletheia/internal/env"
)

// BindPaths é a irmã do RootDirectory pelo caminho do mount namespace, e a mais
// perigosa das duas: o RootDirectory ao menos desloca o alvo para um prefixo
// visível no host, enquanto o bind TROCA o arquivo sob um caminho que continua
// parecendo legítimo.
func TestUnitParseBindPaths(t *testing.T) {
	raiz := t.TempDir()
	os.WriteFile(filepath.Join(raiz, "svc.service"), []byte(
		"[Service]\n"+
			"BindReadOnlyPaths=/tmp/.implant:/usr/bin/agent\n"+
			"BindPaths=/var/lib/app -/opt/x:/srv/y:rbind\n"+
			"ExecStart=/usr/bin/agent\n"), 0o644)
	e := env.Probe(env.Options{Root: raiz, Version: "test"})
	t.Cleanup(func() { e.Close() })

	u := parseUnitFile(&Facts{}, e, "/svc.service", "system", kindOf("/svc.service"), false)
	if len(u.Binds) != 3 {
		t.Fatalf("binds = %+v, queria 3", u.Binds)
	}
	if b := u.Binds[0]; b.Origem != "/tmp/.implant" || b.Destino != "/usr/bin/agent" || !b.SomenteL {
		t.Errorf("o bind que troca o arquivo saiu errado: %+v", b)
	}
	// Sem destino o caminho é o MESMO dentro e fora: disponibiliza, não troca.
	if b := u.Binds[1]; b.Origem != "/var/lib/app" || b.Destino != "" {
		t.Errorf("bind sem destino: %+v", b)
	}
	// O `-` inicial é "ignore se faltar", e as opções depois do destino não
	// mudam qual arquivo aparece.
	if b := u.Binds[2]; b.Origem != "/opt/x" || b.Destino != "/srv/y" {
		t.Errorf("prefixo `-` e opções: %+v", b)
	}
}

// Atribuição vazia RESETA, como nas outras listas — é assim que um drop-in tira
// o bind da unit original, e não honrar isso deixaria a ferramenta afirmando
// uma troca que o systemd já desfez.
func TestUnitBindVazioReseta(t *testing.T) {
	raiz := t.TempDir()
	os.WriteFile(filepath.Join(raiz, "svc.service"), []byte(
		"[Service]\nBindPaths=/tmp/.a:/usr/bin/x\nBindPaths=\nExecStart=/bin/true\n"), 0o644)
	e := env.Probe(env.Options{Root: raiz, Version: "test"})
	t.Cleanup(func() { e.Close() })

	if u := parseUnitFile(&Facts{}, e, "/svc.service", "system", kindOf("/svc.service"), false); len(u.Binds) != 0 {
		t.Errorf("bind vazio tem de resetar: %+v", u.Binds)
	}
}

// E a seção vale aqui como em todo o resto: bind numa seção que o systemd
// ignora não pode entrar no modelo, senão o conserto das seções teria deixado
// uma porta aberta atrás de si.
func TestUnitBindRespeitaSecao(t *testing.T) {
	raiz := t.TempDir()
	os.WriteFile(filepath.Join(raiz, "svc.service"), []byte(
		"[Service]\nExecStart=/bin/true\n\n[X-Q]\nBindPaths=/tmp/.a:/usr/bin/x\n"), 0o644)
	e := env.Probe(env.Options{Root: raiz, Version: "test"})
	t.Cleanup(func() { e.Close() })

	if u := parseUnitFile(&Facts{}, e, "/svc.service", "system", kindOf("/svc.service"), false); len(u.Binds) != 0 {
		t.Errorf("bind de seção ignorada entrou no modelo: %+v", u.Binds)
	}
}
