package facts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/env"
)

// A INVARIANTE CENTRAL desta ferramenta, mecanizada.
//
// "Não consegui olhar" nunca pode virar "não há". O projeto inteiro é escrito
// em cima disso, e mesmo assim a regra vazou oito vezes numa única rodada de
// revisão — wtmp com EACCES, candidato de propriedade, mapa de erros do
// BPF_PROG_QUERY, dois no binfmt, quatro no initramfs, dois no cgroup. Todas
// foram achadas por LEITURA: nenhum cenário e nenhum teste as pegou, porque
// nenhum instrumento perguntava isto.
//
// O harness pergunta. Para cada coletor: monta uma raiz onde os caminhos que
// ele lê EXISTEM e são ILEGÍVEIS (modo 000, que é EACCES e não ENOENT), roda o
// coletor, e exige que ele tenha DECLARADO a lacuna em algum lugar. Um coletor
// que volta com os dois mapas vazios está afirmando ausência sobre um disco que
// não conseguiu ler.
type coletorIlegivel struct {
	nome string
	// dirs e arquivos são criados e tornados ilegíveis. Precisam EXISTIR: um
	// caminho ausente é resposta legítima ("este host não tem systemd"), e não
	// é isso que está sendo testado.
	dirs     []string
	arquivos []string
	rodar    func(*Facts, *env.Env)
}

func raizIlegivel(t *testing.T, c coletorIlegivel) *Facts {
	t.Helper()
	raiz := t.TempDir()
	var travar []string
	for _, d := range c.dirs {
		full := filepath.Join(raiz, d)
		if err := os.MkdirAll(full, 0o755); err != nil {
			t.Fatal(err)
		}
		travar = append(travar, full)
	}
	for _, a := range c.arquivos {
		full := filepath.Join(raiz, a)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		// 384 bytes, e não dois: é múltiplo do registro utmp de 32 bits e de
		// 64 bits, então o arquivo passa em qualquer checagem de TAMANHO e a
		// única coisa que pode falhar é a LEITURA. Com dois bytes, o coletor de
		// login declarava lacuna por tamanho ímpar e o teste passava pelo
		// motivo errado — que é pior que não testar.
		if err := os.WriteFile(full, make([]byte, 384), 0o644); err != nil {
			t.Fatal(err)
		}
		travar = append(travar, full)
	}
	// 000 DEPOIS de tudo criado, e destravado no fim para o TempDir poder ser
	// removido.
	for _, p := range travar {
		if err := os.Chmod(p, 0o000); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, p := range travar {
			os.Chmod(p, 0o755)
		}
	})

	e := env.Probe(env.Options{Root: raiz, Version: "test"})
	t.Cleanup(func() { e.Close() })
	f := &Facts{}
	c.rodar(f, e)
	return f
}

func lacunasDe(f *Facts) []string {
	var out []string
	for cat, ls := range f.Partial {
		for _, l := range ls {
			out = append(out, cat+": "+l)
		}
	}
	for cat, ls := range f.PersistDenied {
		for _, l := range ls {
			out = append(out, cat+"(deny): "+l)
		}
	}
	return out
}

func TestColetorIlegivelDeclaraLacuna(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("como root o modo 000 não impede leitura: este teste precisa rodar sem privilégio")
	}
	casos := []coletorIlegivel{
		{"loader", nil, []string{"etc/ld.so.preload", "etc/ld.so.conf"}, collectLoader},
		{"units", []string{"etc/systemd/system", "usr/lib/systemd/system"}, nil, collectUnits},
		{"cron", []string{"etc/cron.d", "var/spool/cron"}, []string{"etc/crontab"}, collectCron},
		{"ssh", nil, []string{"etc/ssh/sshd_config"}, collectSSH},
		{"triggers", nil, []string{"etc/profile", "etc/rc.local", "etc/bash.bashrc"}, collectTriggers},
		{"modprobe", []string{"etc/modprobe.d", "lib/modules"}, nil, collectModprobe},
		{"binfmt", []string{"etc/binfmt.d"}, nil, collectBinfmtConfig},
		{"initramfs", []string{"usr/lib/dracut/modules.d", "etc/dracut.conf.d", "etc/mkinitcpio.conf.d"},
			[]string{"etc/mkinitcpio.conf"}, collectInitramfs},
		{"users", nil, []string{"etc/passwd", "etc/group", "etc/sudoers"}, collectUsers},
		{"logins", nil, []string{"var/log/wtmp", "var/log/btmp", "run/utmp"}, collectLogins},
		{"boot", []string{"boot"}, []string{"etc/default/grub"}, collectBoot},
		{"mac", []string{"etc/selinux"}, []string{"etc/apparmor.d/x"}, collectMAC},
		{"trust", []string{"usr/local/share/ca-certificates", "etc/pki"},
			[]string{"etc/hosts", "etc/resolv.conf"}, collectTrust},
		{"logs", []string{"var/log"}, nil, collectLogs},
		{"auditoria", []string{"etc/audit/rules.d"},
			[]string{"etc/audit/auditd.conf", "etc/audit/audit.rules"}, collectAuditoria},
		{"interpretador", nil,
			[]string{"etc/environment", "etc/security/pam_env.conf"}, collectInterpretador},
		{"suid", []string{"usr/bin", "usr/local/bin"}, nil, collectSuid},
	}
	// AINDA FORA da tabela, e a razão importa mais que a ausência:
	//
	//	credenciais, historico   varrem os HOMES, que saem de /etc/passwd. Com o
	//	                         passwd ilegível não há home para varrer, e a
	//	                         lacuna certa é a do passwd — que collectUsers já
	//	                         declara. Cobri-los exige uma fixture com passwd
	//	                         legível apontando para um home ilegível.
	//	segredos, gitHooks       varrem árvore a partir de raízes derivadas de
	//	                         outros coletores; a fixture precisa montar essa
	//	                         cadeia antes.
	//	helpers                  lê /proc, que não existe sob --root: o coletor é
	//	                         live-only e este harness roda em modo image.
	//
	// Dívida declarada, não esquecimento — é a mesma regra que o código aplica
	// a si mesmo.
	for _, c := range casos {
		t.Run(c.nome, func(t *testing.T) {
			f := raizIlegivel(t, c)
			ls := lacunasDe(f)
			if len(ls) == 0 {
				t.Errorf("o coletor %q leu ZERO e não declarou lacuna nenhuma: "+
					"ausência afirmada a partir de disco ilegível", c.nome)
				return
			}
			t.Logf("%-10s %d lacuna(s): %s", c.nome, len(ls), primeira(ls))
		})
	}
}

func primeira(ls []string) string {
	s := ls[0]
	if i := strings.IndexByte(s, '\n'); i > 0 {
		s = s[:i]
	}
	if len(s) > 110 {
		s = s[:107] + "…"
	}
	return s
}
