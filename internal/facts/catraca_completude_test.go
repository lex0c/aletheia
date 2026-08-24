package facts

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/env"
)

// A CATRACA DA COMPLETUDE POR FONTE.
//
// # A pergunta que nenhuma das outras faz
//
// As catracas anteriores subiram um degrau de cada vez. A do SchemaVersion pega
// o campo novo; a de extração pega o campo que decide e não sai; a de chave de
// lacuna pega DUAS FAMÍLIAS dependendo da mesma chave. Nenhuma delas pega o que
// produziu a última rodada inteira de defeitos:
//
//	UMA FONTE derruba o fato de completude de OUTRA.
//
// Foram três, e todos passaram por todas as catracas existentes. O
// `LoaderPathCompleto` era derrubado pelo pam_env.conf, que alimenta outra
// superfície — e as duas escritas estavam na MESMA função, então nem uma
// conferência por arquivo pegaria. A chave `modprobe` tinha dois escritores com
// significados diferentes, e o campo onde alguém deveria ter conferido isso à
// mão dizia, por escrito, o contrário. O `HelpersLidos` nem existia: a fonte
// não existe em modo imagem, e a lista vazia passava por estado.
//
// # A forma da conferência
//
// Não dá para checar isto lendo o código — a pergunta "esta fonte é a mesma
// daquela?" é semântica. Dá para checar RODANDO: monta-se uma raiz onde TUDO
// está legível, tranca-se UMA fonte de cada vez, e mede-se quais fatos caem.
// Se cai um que não é o dela nem uma dependência DECLARADA, é o defeito.
//
// A dependência declarada é a outra metade, e ela é o que este arquivo
// acrescenta ao repositório em conhecimento: sem /etc/passwd não há lista de
// homes, então a varredura de authorized_keys deixa de ser exaustiva — e isso é
// CERTO. O que a catraca exige é que esteja escrito.
type fonteDeCompletude struct {
	// Fato é o nome do campo em Facts.
	Fato string
	// Sites são os caminhos que ESTA fonte lê, relativos à raiz. Trancá-los é
	// o experimento.
	Sites []string
	// Depende são os outros fatos que caem JUNTO, legitimamente, porque esta
	// fonte alimenta a varredura deles. Cada um precisa de motivo no comentário
	// da entrada — é a linha que separa dependência de vazamento.
	Depende []string
	// SoVivo é o motivo de a fonte não poder ser exercida sob --root. Entrada
	// com SoVivo sai do experimento e continua obrigada a existir aqui: o que
	// não se mede também precisa de resposta escrita.
	SoVivo string
}

var fontesDeCompletude = []fonteDeCompletude{
	// /etc/passwd é a raiz de várias varreduras: ele é quem diz onde os homes
	// ficam. Sem ele não há authorized_keys de usuário para varrer, nem
	// ~/.ssh/config, nem ~/.rhosts — e as três deixam de ser exaustivas de
	// verdade.
	{Fato: "PasswdLido", Sites: []string{"etc/passwd"},
		Depende: []string{"SSHChavesCompleto", "SSHClienteCompleto", "HostTrustCompleto"}},
	{Fato: "GroupLido", Sites: []string{"etc/group"}},
	{Fato: "ShadowLido", Sites: []string{"etc/shadow"}},
	{Fato: "SudoersLido", Sites: []string{"etc/sudoers", "etc/sudoers.d"}},
	{Fato: "DoasLido", Sites: []string{"etc/doas.conf", "etc/doas.d"}},

	{Fato: "SSHServerCompleto", Sites: []string{"etc/ssh/sshd_config", "etc/ssh/sshd_config.d"}},
	{Fato: "SSHChavesCompleto", Sites: []string{"root/.ssh/authorized_keys"}},
	{Fato: "SSHClienteCompleto", Sites: []string{"etc/ssh/ssh_config", "root/.ssh/config"}},

	{Fato: "CACertsCompleto", Sites: []string{"usr/local/share/ca-certificates"}},
	{Fato: "HostsLido", Sites: []string{"etc/hosts"}},
	{Fato: "ResolverLido", Sites: []string{"etc/resolv.conf"}},
	{Fato: "HostTrustCompleto", Sites: []string{"etc/hosts.equiv", "root/.rhosts"}},

	{Fato: "NSSLido", Sites: []string{"etc/nsswitch.conf"}},

	// As TRÊS do loader, que são o caso que motivou esta catraca.
	{Fato: "LoaderPreloadLido", Sites: []string{"etc/ld.so.preload"}},
	{Fato: "LoaderPathCompleto", Sites: []string{"etc/ld.so.conf", "etc/ld.so.conf.d"}},
	{Fato: "LoaderEnvCompleto", Sites: []string{"etc/environment", "etc/security/pam_env.conf"}},

	{Fato: "BinfmtConfigCompleto", Sites: []string{"etc/binfmt.d", "usr/lib/binfmt.d", "run/binfmt.d"}},
	{Fato: "ModuleConfigCompleto", Sites: []string{"etc/modules", "etc/modprobe.d", "etc/modules-load.d"}},

	{Fato: "BootConfigLido", Sites: []string{"boot/grub/grub.cfg"}},
	{Fato: "HistoricoDeLoginLido", Sites: []string{"var/log/wtmp"}},

	// As TRÊS do conteúdo de log. Elas são o caso que a catraca pegou ANTES de
	// existirem: a primeira versão derivava as duas primeiras do estado global
	// da coleta, e assim um audit.log ilegível derrubava o fato do log em TEXTO
	// — que podia ter sido lido inteiro. Cada uma responde pela sua fonte.
	{Fato: "LogTextoCompleto", Sites: []string{"var/log/auth.log"}},
	{Fato: "AuditLogCompleto", Sites: []string{"var/log/audit/audit.log"}},
	// O fuso é fonte de terceiro tipo: ele não é log nenhum, e derrubá-lo não
	// impede a leitura de linha alguma — só faz as datas serem supostas em UTC.
	{Fato: "FusoDoAlvoLido", Sites: []string{"etc/localtime"}},

	// --- fontes que não existem sob --root ---
	{Fato: "ModulosLidos", SoVivo: "/proc/modules só existe no host vivo; em imagem " +
		"não há kernel rodando para listar módulo carregado"},
	{Fato: "ArvoreDeModulos", SoVivo: "depende de haver .ko em /lib/modules, e a raiz " +
		"de teste teria de carregar uma árvore de módulos inteira para o " +
		"experimento dizer alguma coisa"},
	{Fato: "BinfmtVivoCompleto", SoVivo: "/proc/sys/fs/binfmt_misc é o registro VIVO " +
		"do kernel; o irmão em arquivo é o BinfmtConfigCompleto, que está acima"},
	{Fato: "HelpersLidos", SoVivo: "/proc/sys/kernel e /sys/kernel: o coletor sai na " +
		"porta fora do modo live, e é justamente esse o fato que ele registra"},
}

// coletoresDaRaiz são os que rodam sob --root, e é o conjunto que o experimento
// executa. Rodar TODOS de uma vez é de propósito: o vazamento que esta catraca
// procura só aparece quando as fontes convivem.
func coletoresDaRaiz(f *Facts, e *env.Env) {
	collectUsers(f, e)
	collectSudoers(f, e)
	collectDoas(f, e)
	collectSSH(f, e)
	collectTrust(f, e)
	collectConfiancaDeHost(f, e)
	collectNSS(f, e)
	collectLoader(f, e)
	collectBinfmtConfig(f, e)
	collectModprobe(f, e)
	collectBoot(f, e)
	collectLogins(f, e)
	// collectLogs ANTES: é ele quem inventaria as gerações de /var/log, e é do
	// inventário que sai a lista de arquivos que o coletor de eventos abre.
	collectLogs(f, e)
	collectEventosDeLog(f, e)
}

// raizSemeada é a raiz onde TUDO está legível. Cada arquivo aqui existe para
// que o fato correspondente saia verdadeiro no caso de controle — sem isso o
// experimento mediria a ausência, e ausência não é lacuna.
var raizSemeada = map[string]string{
	"etc/passwd":    "root:x:0:0:root:/root:/bin/sh\n",
	"etc/group":     "root:x:0:\n",
	"etc/shadow":    "root:!:19000:0:99999:7:::\n",
	"etc/sudoers":   "root ALL=(ALL) ALL\n#includedir /etc/sudoers.d\n",
	"etc/doas.conf": "permit nopass :wheel\n",

	"etc/ssh/sshd_config":       "PermitRootLogin no\n",
	"etc/ssh/ssh_config":        "Host *\n    HashKnownHosts yes\n",
	"root/.ssh/config":          "Host *\n    ServerAliveInterval 60\n",
	"root/.ssh/authorized_keys": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExemploDeChave root@h\n",

	"usr/local/share/ca-certificates/x.crt": "não é PEM\n",
	"etc/hosts":                             "127.0.0.1 localhost\n",
	"etc/resolv.conf":                       "nameserver 1.1.1.1\n",
	"etc/hosts.equiv":                       "# vazio\n",
	"root/.rhosts":                          "# vazio\n",

	"etc/nsswitch.conf": "passwd: files\nhosts: files dns\n",

	"etc/ld.so.preload":         "\n",
	"etc/ld.so.conf":            "include /etc/ld.so.conf.d/*.conf\n",
	"etc/ld.so.conf.d/x.conf":   "/usr/lib\n",
	"etc/environment":           "PATH=/usr/bin\n",
	"etc/security/pam_env.conf": "# vazio\n",

	"etc/binfmt.d/x.conf":     ":qemu:M::MZ::/usr/bin/qemu:\n",
	"usr/lib/binfmt.d/y.conf": "# vazio\n",
	"run/binfmt.d/z.conf":     "# vazio\n",

	"etc/modules":               "loop\n",
	"etc/modprobe.d/x.conf":     "install foo /bin/true\n",
	"etc/modules-load.d/x.conf": "br_netfilter\n",

	"boot/grub/grub.cfg": "linux /vmlinuz root=/dev/sda1 ro quiet\n",
	"var/log/wtmp":       "",

	// Conteúdo de log: uma linha reconhecível em cada família, mais o TZif do
	// alvo. Sem elas o controle já sairia falso, e o experimento mediria a
	// ausência do arquivo em vez da leitura dele.
	"var/log/auth.log": "Aug 24 01:20:33 h sshd[1]: Accepted password for ana " +
		"from 10.0.0.1 port 5 ssh2\n",
	"var/log/audit/audit.log": "type=SYSCALL msg=audit(1755990137.123:456): syscall=59 " +
		"pid=1 uid=0 comm=\"sh\"\ntype=EXECVE msg=audit(1755990137.123:456): argc=1 " +
		"a0=\"/bin/sh\"\n",
	"etc/localtime": "",
}

func montarRaizSemeada(t *testing.T) string {
	t.Helper()
	raiz := t.TempDir()
	for rel, c := range raizSemeada {
		full := filepath.Join(raiz, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		conteudo := []byte(c)
		if rel == "etc/localtime" {
			// TZif de verdade: um arquivo vazio não decodifica, e o fato sairia
			// falso no controle por FORMATO — medindo outra coisa.
			conteudo = tzifDe(-3*3600, "-03")
		}
		if rel == "var/log/wtmp" {
			// múltiplo do registro utmp nas duas larguras: o coletor recusa
			// tamanho ímpar por FORMATO, e aí o teste mediria outra coisa.
			conteudo = make([]byte, 384)
		}
		if err := os.WriteFile(full, conteudo, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// os diretórios que precisam existir para poderem ser trancados
	for _, d := range []string{"etc/sudoers.d", "etc/doas.d", "etc/ssh/sshd_config.d"} {
		if err := os.MkdirAll(filepath.Join(raiz, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return raiz
}

func colher(f *Facts) map[string]bool {
	v := reflect.ValueOf(*f)
	out := map[string]bool{}
	for _, fc := range fontesDeCompletude {
		out[fc.Fato] = v.FieldByName(fc.Fato).Bool()
	}
	return out
}

// PRIMEIRA METADE: a tabela não pode ficar para trás dos fatos.
//
// A definição é mecânica de propósito — campo bool cujo nome JSON termina em
// `_read` ou `_complete` É um fato de completude, e não há como acrescentar um
// sem cair aqui. O contrário também: entrada para campo que não existe mais é
// lixo que dá impressão de cobertura.
func TestTodoFatoDeCompletudeTemFonteDeclarada(t *testing.T) {
	declarados := map[string]bool{}
	tp := reflect.TypeOf(Facts{})
	for _, fc := range fontesDeCompletude {
		if _, ok := tp.FieldByName(fc.Fato); !ok {
			t.Errorf("a fonte declara o fato `%s`, que não existe em Facts", fc.Fato)
		}
		if declarados[fc.Fato] {
			t.Errorf("o fato `%s` está declarado duas vezes", fc.Fato)
		}
		declarados[fc.Fato] = true
		if len(fc.Sites) == 0 && fc.SoVivo == "" {
			t.Errorf("`%s` não declara nem sites nem o motivo de não ser mensurável",
				fc.Fato)
		}
	}
	for i := 0; i < tp.NumField(); i++ {
		campo := tp.Field(i)
		nome := strings.Split(campo.Tag.Get("json"), ",")[0]
		if campo.Type.Kind() != reflect.Bool {
			continue
		}
		if !strings.HasSuffix(nome, "_read") && !strings.HasSuffix(nome, "_complete") {
			continue
		}
		if !declarados[campo.Name] {
			t.Errorf("o fato de completude `%s` (json %q) não declara a FONTE dele.\n\n"+
				"Um fato de completude responde por UMA fonte. Sem a declaração, "+
				"ninguém confere que outra fonte não o derruba — que foi o defeito "+
				"do LoaderPathCompleto, do ModuleConfigCompleto e do HelpersLidos, "+
				"os três invisíveis para todas as outras catracas.",
				campo.Name, nome)
		}
	}
}

// SEGUNDA METADE, e é ela que mede: trancar UMA fonte derruba o fato dela e
// mais nada além do declarado.
func TestFalhaDeUmaFonteNaoDerrubaOutra(t *testing.T) {
	// CONTROLE. Se um fato já sai falso com tudo legível, o experimento inteiro
	// mede ruído — e o mais provável é faltar arquivo na raiz semeada.
	raiz := montarRaizSemeada(t)
	e := env.Probe(env.Options{Root: raiz, Version: "test"})
	base := &Facts{}
	coletoresDaRaiz(base, e)
	e.Close()
	controle := colher(base)
	for _, fc := range fontesDeCompletude {
		if fc.SoVivo != "" {
			continue
		}
		if !controle[fc.Fato] {
			t.Fatalf("`%s` já sai falso com a raiz inteira legível: a semeadura "+
				"não cobre a fonte dele, e sem isso o experimento não mede nada",
				fc.Fato)
		}
	}

	for _, fc := range fontesDeCompletude {
		if fc.SoVivo != "" {
			continue
		}
		t.Run(fc.Fato, func(t *testing.T) {
			raiz := montarRaizSemeada(t)
			for _, site := range fc.Sites {
				p := filepath.Join(raiz, site)
				if _, err := os.Stat(p); err != nil {
					t.Fatalf("o site %q não existe na raiz semeada: trancar o que "+
						"não existe mede ausência, não lacuna", site)
				}
				if err := os.Chmod(p, 0o000); err != nil {
					t.Fatal(err)
				}
				defer os.Chmod(p, 0o755)
			}
			e := env.Probe(env.Options{Root: raiz, Version: "test"})
			defer e.Close()
			f := &Facts{}
			coletoresDaRaiz(f, e)
			got := colher(f)

			if got[fc.Fato] {
				t.Errorf("a fonte de `%s` está trancada e o fato continuou "+
					"VERDADEIRO: a família que o lê afirmaria conjunto exaustivo "+
					"sobre o que não conseguiu ler", fc.Fato)
			}
			permitido := map[string]bool{fc.Fato: true}
			for _, d := range fc.Depende {
				permitido[d] = true
			}
			for _, outra := range fontesDeCompletude {
				if outra.SoVivo != "" || permitido[outra.Fato] {
					continue
				}
				if !got[outra.Fato] {
					t.Errorf("trancar a fonte de `%s` derrubou `%s`.\n\n"+
						"Ou as duas leem a MESMA fonte — e aí sobra um fato —, ou "+
						"uma escrita vazou para o fato da outra, e a família de "+
						"`%s` vai recusar uma comparação que estava perfeitamente "+
						"lida. Se a dependência for real, declare-a em Depende "+
						"COM O MOTIVO.",
						fc.Fato, outra.Fato, outra.Fato)
				}
			}
		})
	}
}
