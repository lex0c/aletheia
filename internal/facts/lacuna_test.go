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
	nome string //nolint
	// dirs e arquivos são criados e tornados ilegíveis. Precisam EXISTIR: um
	// caminho ausente é resposta legítima ("este host não tem systemd"), e não
	// é isso que está sendo testado.
	dirs     []string
	arquivos []string
	// legiveis são criados e ficam LEGÍVEIS. Existem para montar a cadeia de
	// que o coletor depende antes de chegar ao que está travado: quem varre
	// home precisa de um /etc/passwd que possa ler, senão o teste mede a
	// lacuna do passwd e não a do home.
	legiveis map[string]string
	rodar    func(*Facts, *env.Env)
}

// passwdDeTeste dá UM home real para os coletores que varrem home.
const passwdDeTeste = "root:x:0:0::/root:/bin/sh\nana:x:1000:1000::/home/ana:/bin/sh\n"

func raizIlegivel(t *testing.T, c coletorIlegivel) *Facts {
	t.Helper()
	raiz := t.TempDir()
	for rel, conteudo := range c.legiveis {
		full := filepath.Join(raiz, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(conteudo), 0o644); err != nil {
			t.Fatal(err)
		}
	}
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
		{nome: "loader", arquivos: []string{"etc/ld.so.preload", "etc/ld.so.conf"}, rodar: collectLoader},
		{nome: "units", dirs: []string{"etc/systemd/system", "usr/lib/systemd/system"}, rodar: collectUnits},
		{nome: "cron", dirs: []string{"etc/cron.d", "var/spool/cron"}, arquivos: []string{"etc/crontab"}, rodar: collectCron},
		{nome: "ssh", arquivos: []string{"etc/ssh/sshd_config"}, rodar: collectSSH},
		{nome: "triggers", arquivos: []string{"etc/profile", "etc/rc.local", "etc/bash.bashrc"}, rodar: collectTriggers},
		{nome: "modprobe", dirs: []string{"etc/modprobe.d", "lib/modules"}, rodar: collectModprobe},
		{nome: "binfmt", dirs: []string{"etc/binfmt.d"}, rodar: collectBinfmtConfig},
		{nome: "initramfs", dirs: []string{"usr/lib/dracut/modules.d", "etc/dracut.conf.d", "etc/mkinitcpio.conf.d"}, arquivos: []string{"etc/mkinitcpio.conf"}, rodar: collectInitramfs},
		// passwd LEGÍVEL: senão collectUsers para nele e nunca chega aos outros
		// (short-circuit legítimo). Os alvos ilegíveis são shadow, group e sudoers.
		{nome: "users/shadow", legiveis: map[string]string{"etc/passwd": passwdDeTeste},
			arquivos: []string{"etc/shadow"}, rodar: collectUsers},
		{nome: "users/group", legiveis: map[string]string{"etc/passwd": passwdDeTeste},
			arquivos: []string{"etc/group"}, rodar: collectUsers},
		{nome: "users/sudoers", legiveis: map[string]string{"etc/passwd": passwdDeTeste},
			arquivos: []string{"etc/sudoers"}, rodar: collectUsers},
		{nome: "logins", arquivos: []string{"var/log/wtmp", "var/log/btmp", "run/utmp"}, rodar: collectLogins},
		{nome: "boot", dirs: []string{"boot"}, arquivos: []string{"etc/default/grub"}, rodar: collectBoot},
		{nome: "mac", dirs: []string{"etc/selinux"}, arquivos: []string{"etc/apparmor.d/x"}, rodar: collectMAC},
		{nome: "trust/hosts", arquivos: []string{"etc/hosts"}, rodar: collectTrust},
		{nome: "trust/resolv", arquivos: []string{"etc/resolv.conf"}, rodar: collectTrust},
		{nome: "trust/ca", dirs: []string{"usr/local/share/ca-certificates"}, rodar: collectTrust},
		{nome: "logs", dirs: []string{"var/log"}, rodar: collectLogs},
		// auditd.conf NÃO é LIDO por collectAuditoria (só e.Exists checa presença);
		// injetá-lo ilegível testaria o que o coletor não faz. O que é lido é
		// audit.rules e rules.d.
		{nome: "auditoria", dirs: []string{"etc/audit/rules.d"}, arquivos: []string{"etc/audit/audit.rules"}, rodar: collectAuditoria},
		{nome: "interpretador", arquivos: []string{"etc/environment", "etc/security/pam_env.conf"}, rodar: collectInterpretador},
		{nome: "suid", dirs: []string{"usr/bin", "usr/local/bin"}, rodar: collectSuid},
		{nome: "mounts", arquivos: []string{"proc/self/mountinfo"}, rodar: collectMounts},
		// limitesDeRede fica FORA: o que ele lê alimenta só o `info`, que exibe
		// sem julgar — nenhum check consome ConntrackLido, então não existe
		// achado que o silêncio possa esconder. O invariante vale onde a
		// ausência de achado pode ser lida como ausência de problema.

		// Os que varrem HOME precisam de um /etc/passwd legível apontando para
		// um home travado: sem isso o teste mediria a lacuna do passwd, que é
		// de outro coletor.
		{nome: "credenciais", dirs: []string{"home/ana/.ssh"},
			legiveis: map[string]string{"etc/passwd": passwdDeTeste}, rodar: collectCredenciais},
		// O home INTEIRO travado, não só o arquivo: lstat de um arquivo modo 000
		// funciona (a permissão vem do diretório), então travar o arquivo não
		// reproduz o EACCES que interessa.
		{nome: "historico", dirs: []string{"home/ana"},
			legiveis: map[string]string{"etc/passwd": passwdDeTeste}, rodar: collectHistorico},
		{nome: "segredos", dirs: []string{"home/ana/.aws", "srv", "opt"},
			legiveis: map[string]string{"etc/passwd": passwdDeTeste}, rodar: collectSegredos},
	}
	// AINDA FORA da tabela, e a razão importa mais que a ausência:
	//
	//	gitHooks   parte de raízes que outros coletores derivam (repositórios
	//	           achados na varredura de aplicação); a fixture precisa montar
	//	           essa cadeia antes.
	//	helpers    lê /proc, que não existe sob --root: o coletor é live-only e
	//	           este harness roda em modo image. Cobri-lo exige injeção de
	//	           falha na camada de leitura, não uma raiz travada.
	//
	// Dívida declarada, não esquecimento — é a mesma regra que o código aplica
	// a si mesmo.
	for _, c := range casos {
		t.Run(c.nome, func(t *testing.T) {
			f := raizIlegivel(t, c)
			ls := lacunasDe(f)
			todas := strings.Join(ls, "\n")

			// RIGOR: cada caminho ilegível injetado tem de aparecer, POR NOME,
			// em alguma lacuna. Sem isso, um caso com vários arquivos passava se
			// UM deles declarasse — mascarando que os outros são silenciosos. Foi
			// exatamente assim que o silêncio do /etc/ld.so.conf se escondeu atrás
			// do denyPersist do /etc/ld.so.preload.
			//
			// O casamento é pelo BASENAME (o coletor pode citar o caminho sob a
			// raiz temporária, não o absoluto do sistema).
			for _, caminho := range append(append([]string{}, c.arquivos...), c.dirs...) {
				base := caminho[strings.LastIndexByte(caminho, '/')+1:]
				if !strings.Contains(todas, base) {
					t.Errorf("%s: %q é ILEGÍVEL e NÃO aparece em nenhuma lacuna — "+
						"ausência afirmada a partir de disco que não foi lido.\nlacunas:\n%s",
						c.nome, caminho, todas)
				}
			}
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
