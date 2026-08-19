package facts

import (
	"os"

	"github.com/lex0c/aletheia/internal/env"
	"sort"
	"strconv"
	"strings"
)

// Quem VIGIA arquivo neste host (runbook §7.12, §19).
//
// # A pergunta que isto responde
//
// "Removi o backdoor e ele voltou."
//
// É das frustrações mais comuns de uma resposta a incidente, e o mecanismo
// quase nunca é mágica: um processo com watch de inotify no arquivo — ou no
// diretório dele — recria o que foi apagado, em milissegundos, sem cron, sem
// unit e sem abrir porta. A §19 manda remover persistência ANTES de matar
// processo justamente por isso, e para obedecer é preciso SABER que o vigia
// existe.
//
// # De onde sai
//
//	/proc/<pid>/fd/<n>       anon_inode:inotify | anon_inode:[fanotify]
//	/proc/<pid>/fdinfo/<n>   uma linha por watch, com o INODE observado
//
// fanotify pesa mais que inotify por duas razões: exige CAP_SYS_ADMIN, e sabe
// vigiar uma MONTAGEM inteira — um watch só cobrindo todo o filesystem. Ele
// também sabe BLOQUEAR a operação (FAN_*_PERM), o que transforma o vigia em
// porteiro.
//
// # O limite, e ele é do formato
//
// O fdinfo dá inode e dispositivo, não caminho. O dispositivo NÃO é comparável
// com o `st_dev` do stat em todo filesystem — no btrfs, cada subvolume recebe
// um dispositivo anônimo no stat enquanto o fdinfo mostra o do superbloco, e os
// dois números não batem. Por isso o casamento é por INODE, dentro do conjunto
// de caminhos que a varredura já conhece; o que não casar fica registrado como
// inode sem nome, e não é descartado.

// Vigia é um descritor de observação de arquivo, com o que ele observa.
type Vigia struct {
	PID  int    `json:"pid"`
	Comm string `json:"comm,omitempty"`
	Exe  string `json:"exe,omitempty"`
	// Tipo é "inotify" ou "fanotify".
	Tipo string `json:"kind"`
	// Watches é quantos alvos este descritor observa.
	Watches int `json:"watches"`
	// MontagemInteira marca o fanotify que vigia uma MONTAGEM, e não arquivos:
	// um watch só que cobre tudo que estiver montado ali.
	MontagemInteira bool `json:"whole_mount,omitempty"`
	// Bloqueia marca o fanotify com permissão de VETO: ele não só observa, ele
	// decide se a operação acontece.
	Bloqueia bool `json:"blocking,omitempty"`

	// Alvos são os inodes observados que a varredura conseguiu NOMEAR.
	Alvos []AlvoVigiado `json:"targets,omitempty"`
	// SemNome conta os inodes observados que não casaram com caminho nenhum
	// conhecido. Eles existem — só não foi possível dizer o quê.
	SemNome int `json:"unresolved,omitempty"`
}

// AlvoVigiado é um caminho sob observação.
type AlvoVigiado struct {
	Caminho string `json:"path"`
	// Persistencia marca o caminho que EXECUTA ou que decide quem entra: é a
	// diferença entre vigiar um diretório de cache e vigiar o crontab.
	Persistencia bool `json:"persistence,omitempty"`
}

const (
	// maxWatchesPorFD limita a leitura por descritor. Um gerenciador de
	// arquivos ou um IDE tem milhares de watches, e ler todos custaria mais que
	// o resto da coleta junto.
	maxWatchesPorFD = 4096
	// maxVigias limita os descritores examinados no host inteiro.
	maxVigias = 512
)

func collectVigias(f *Facts, e *env.Env) {
	nomePorInode := indiceDeInodes(f, e)

	var lidos int
	for i := range f.Processes {
		p := &f.Processes[i]
		if p.Self || p.Vanished {
			continue
		}
		for _, fd := range p.FDs {
			tipo := tipoDeVigia(fd.Target)
			if tipo == "" {
				continue
			}
			if lidos >= maxVigias {
				f.partial("vigia", "a leitura de vigias de arquivo parou em "+
					strconv.Itoa(maxVigias)+" descritores: o excedente NÃO foi examinado")
				return
			}
			lidos++
			v := lerVigia(p, fd.N, tipo, nomePorInode, f)
			if v != nil {
				f.Vigias = append(f.Vigias, *v)
			}
		}
	}
	sort.Slice(f.Vigias, func(i, j int) bool {
		if len(f.Vigias[i].Alvos) != len(f.Vigias[j].Alvos) {
			return len(f.Vigias[i].Alvos) > len(f.Vigias[j].Alvos)
		}
		return f.Vigias[i].PID < f.Vigias[j].PID
	})
}

func tipoDeVigia(alvo string) string {
	switch {
	case strings.Contains(alvo, "inotify"):
		return "inotify"
	case strings.Contains(alvo, "fanotify"):
		return "fanotify"
	}
	return ""
}

func lerVigia(p *Process, fd int, tipo string, porHandle map[string][]string, f *Facts) *Vigia {
	b, err := os.ReadFile(procPath(p.PID, "fdinfo/"+strconv.Itoa(fd)))
	if err != nil {
		return nil
	}
	v := &Vigia{PID: p.PID, Comm: p.Comm, Exe: p.Exe, Tipo: tipo}
	visto := map[string]bool{}

	for _, ln := range strings.Split(string(b), "\n") {
		campos := strings.Fields(ln)
		if len(campos) < 2 {
			continue
		}
		switch campos[0] {
		case "inotify", "fanotify":
		case "fanotify-flags:":
			continue
		default:
			continue
		}
		kv := mapaDeCampos(campos[1:])

		// fanotify sem `ino:` vigia a MONTAGEM inteira: um watch só cobrindo
		// tudo que estiver montado ali.
		if tipo == "fanotify" {
			if _, temFlags := kv["flags"]; temFlags {
				// A linha de cabeçalho do fanotify traz as flags do grupo. O
				// bit de permissão é o que separa observar de VETAR.
				if n, ok := hexDe(kv["flags"]); ok && n&fanClassePerm != 0 {
					v.Bloqueia = true
				}
				continue
			}
			if _, temIno := kv["ino"]; !temIno {
				v.MontagemInteira = true
				v.Watches++
				continue
			}
		}

		if _, temIno := kv["ino"]; !temIno {
			continue
		}
		v.Watches++
		if v.Watches > maxWatchesPorFD {
			f.partial("vigia", "pid "+strconv.Itoa(p.PID)+" observa mais de "+
				strconv.Itoa(maxWatchesPorFD)+" alvos: o excedente NÃO foi nomeado")
			break
		}
		// O casamento é pelo FILE HANDLE, que é a identidade do próprio
		// filesystem — nem inode sozinho (colide entre filesystems) nem
		// inode+sdev (o sdev do fdinfo não é o st_dev no btrfs).
		var caminhos []string
		if tipoH, ok := hexDe(kv["fhandle-type"]); ok && kv["f_handle"] != "" {
			caminhos = porHandle[chaveDeHandle(uint32(tipoH), kv["f_handle"])]
		}
		if len(caminhos) == 0 {
			// Sem handle comparável, resta (dispositivo, inode) — que é o que
			// funciona em contêiner.
			dev, okD := hexDe(kv["sdev"])
			ino, okI := hexDe(kv["ino"])
			if okD && okI {
				caminhos = porHandle[chaveDeDevInoBruta(dev, ino)]
			}
		}
		if len(caminhos) == 0 {
			v.SemNome++
			continue
		}
		for _, c := range caminhos {
			if visto[c] {
				continue
			}
			visto[c] = true
			v.Alvos = append(v.Alvos, AlvoVigiado{Caminho: c, Persistencia: ehDePersistencia(c)})
		}
	}
	if v.Watches == 0 {
		return nil
	}
	sort.Slice(v.Alvos, func(i, j int) bool {
		if v.Alvos[i].Persistencia != v.Alvos[j].Persistencia {
			return v.Alvos[i].Persistencia
		}
		return v.Alvos[i].Caminho < v.Alvos[j].Caminho
	})
	return v
}

// fanClassePerm é o bit de classe de PERMISSÃO do fanotify: com ele o grupo não
// observa, ele DECIDE se a operação acontece.
const fanClassePerm = 0x0000000c // FAN_CLASS_CONTENT | FAN_CLASS_PRE_CONTENT

func mapaDeCampos(campos []string) map[string]string {
	out := make(map[string]string, len(campos))
	for _, c := range campos {
		if k, v, ok := strings.Cut(c, ":"); ok {
			out[k] = v
		}
	}
	return out
}

func hexDe(s string) (uint64, bool) {
	if s == "" {
		return 0, false
	}
	n, err := strconv.ParseUint(s, 16, 64)
	return n, err == nil
}

// caminhosDePersistencia são os que EXECUTAM ou decidem quem entra. Vigiar um
// deles é o que separa "programa observa arquivo" de "algo garante que este
// arquivo volte".
var prefixosDePersistencia = []string{
	"/etc/cron", "/var/spool/cron", "/etc/systemd", "/usr/lib/systemd",
	"/lib/systemd", "/etc/init.d", "/etc/rc", "/etc/profile", "/etc/bash",
	"/etc/ld.so", "/etc/modprobe.d", "/etc/modules", "/etc/sudoers",
	"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/ssh", "/root/.ssh",
	"/etc/pam.d", "/etc/udev", "/usr/local/sbin", "/usr/local/bin",
	"/etc/apparmor.d", "/etc/selinux", "/etc/periodic", "/etc/crontabs",
}

// caminhosDePersistencia são caminhos REAIS a indexar. A lista de prefixos
// acima serve para CLASSIFICAR o que foi resolvido; esta serve para resolver.
//
// As duas são diferentes de propósito, e confundi-las foi o defeito da
// primeira versão: `/etc/cron` é prefixo útil e caminho que não existe, então
// indexar a lista de prefixos deixava /etc/cron.d de fora — e um vigia em cima
// dele saía como alvo NÃO NOMEADO, que é o resultado que este código existe
// para evitar.
var caminhosDePersistencia = []string{
	"/etc/crontab", "/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily",
	"/etc/cron.weekly", "/etc/cron.monthly", "/etc/crontabs",
	"/etc/periodic/15min", "/etc/periodic/hourly", "/etc/periodic/daily",
	"/etc/periodic/weekly", "/etc/periodic/monthly",
	"/var/spool/cron", "/var/spool/cron/crontabs", "/var/spool/at",

	"/etc/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system",
	"/etc/init.d", "/etc/rc.local", "/etc/rc.d",

	"/etc/profile", "/etc/profile.d", "/etc/bash.bashrc", "/etc/bashrc",
	"/etc/environment", "/etc/ld.so.preload", "/etc/ld.so.conf.d",
	"/etc/modprobe.d", "/etc/modules-load.d", "/etc/modules",

	"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
	"/etc/sudoers", "/etc/sudoers.d", "/etc/pam.d",
	"/etc/ssh", "/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d",
	"/root/.ssh", "/root/.ssh/authorized_keys",

	"/etc/udev/rules.d", "/usr/local/sbin", "/usr/local/bin",
	"/etc/apparmor.d", "/etc/selinux",
}

func ehDePersistencia(p string) bool {
	if strings.Contains(p, "/.ssh") || strings.HasSuffix(p, "/authorized_keys") {
		return true
	}
	for _, pre := range prefixosDePersistencia {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	return false
}

// indiceDeInodes mapeia inode → caminho, para os caminhos que a varredura JÁ
// conhece.
//
// Não é um índice do filesystem: construir um custaria uma travessia inteira
// para responder uma pergunta lateral. O conjunto aqui é o que a ferramenta já
// citou — o que executa, o que está agendado, o que carrega privilégio, o que
// decide quem entra — mais os DIRETÓRIOS deles, porque quem vigia um arquivo
// para recriá-lo vigia o diretório: o inode do arquivo apagado deixa de existir,
// o do diretório não.
func indiceDeInodes(f *Facts, e *env.Env) map[string][]string {
	out := map[string][]string{}
	visto := map[string]bool{}

	add := func(p string) {
		if p == "" || visto[p] {
			return
		}
		visto[p] = true
		fi, err := e.Lstat(p)
		if err != nil {
			return
		}
		// DUAS chaves, porque as duas falham em lugares diferentes e nenhuma
		// das duas produz colisão entre filesystems:
		//
		//	handle       exato e nativo do filesystem, e a única que funciona
		//	             no btrfs — onde o sdev do fdinfo é o do superbloco e o
		//	             st_dev é o anônimo do subvolume, e os dois não batem
		//	(dev, ino)   funciona em ext4, xfs e overlayfs, e é a única que
		//	             sobra em CONTÊINER: `name_to_handle_at` devolve
		//	             EOPNOTSUPP no overlayfs padrão do Docker
		//
		// O que NÃO se faz é casar por inode sozinho: ele colide entre
		// filesystems, e a primeira versão desta leitura pôs o `gvfsd-trash`
		// deste host "vigiando /etc/ssh" por causa disso.
		if k, ok := handleDe(e.Path(p)); ok {
			out[k] = append(out[k], p)
		}
		if k, ok := chaveDeDevIno(fi); ok {
			out[k] = append(out[k], p)
		}
	}

	for i := range f.Ownership {
		add(f.Ownership[i].Path)
	}
	for i := range f.Suid {
		add(f.Suid[i].Path)
	}
	for i := range f.Cron {
		add(f.Cron[i].File)
	}
	for i := range f.Units {
		add(f.Units[i].Path)
	}
	for i := range f.SSHKeys {
		add(f.SSHKeys[i].File)
	}
	for i := range f.Triggers {
		add(f.Triggers[i].File)
	}
	for _, p := range caminhosDePersistencia {
		add(p)
	}

	// E o DIRETÓRIO de cada um: é ele que sobrevive ao `rm`, e é nele que um
	// vigia de recriação se pendura.
	//
	// As chaves saem para uma slice ANTES do laço porque `add` escreve em
	// `visto`: inserir num mapa enquanto se itera sobre ele é comportamento
	// indefinido pelo spec do Go — a entrada nova pode ou não ser produzida.
	// O efeito era o índice ganhar avós de caminho de forma não determinística,
	// e o mesmo host, na mesma varredura repetida, ora nomear o alvo de um
	// fanotify sobre diretório de persistência, ora contabilizá-lo em SemNome.
	caminhos := make([]string, 0, len(visto))
	for p := range visto {
		caminhos = append(caminhos, p)
	}
	for _, p := range caminhos {
		if i := strings.LastIndexByte(p, '/'); i > 0 {
			add(p[:i])
		}
	}
	return out
}
