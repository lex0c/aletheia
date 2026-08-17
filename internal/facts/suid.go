package facts

import (
	"io/fs"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/lex0c/aletheia/internal/env"
)

// SUID e SGID (runbook §7.11).
//
// A retenção de root mais antiga que existe, e ainda a mais usada: com QUALQUER
// foothold sem privilégio, um binário com o bit setuid deixa a volta pronta.
//
//	cp /bin/bash /usr/local/bin/.x && chmod 4755 /usr/local/bin/.x
//
// Não deixa processo, não deixa conexão, não deixa agendamento. Sobrevive a
// reboot, a limpeza de cron e a troca de senha. Nenhum dos outros vinte checks
// de persistência olha para isto, porque nenhum deles olha para o FILESYSTEM em
// busca do que está parado.
//
// É a diferença entre os dois modos de procurar. Os outros coletores vão a
// lugares NOMEADOS — /etc/cron.d, /etc/systemd/system — e leem o que está lá.
// Este varre, e varrer tem custo e tem limite. Os dois estão declarados.

const (
	// Teto de diretórios visitados. Medido num host real: 40 mil diretórios em
	// ~350ms com o cache quente. O que passar disso vira lacuna DECLARADA — a
	// varredura truncada em silêncio diria "nenhum SUID inesperado" quando o
	// que houve foi parar antes.
	maxSuidDirs  = 40000
	maxSuidDepth = 12

	// Profundidade menor sob HOME, e a razão é onde o custo mora.
	//
	// As árvores de sistema são pequenas e valem por inteiro. O home de uma
	// estação de trabalho tem centenas de milhares de diretórios de código e
	// dependência — 270 mil numa medição real, contra 40 mil de teto —, e sem
	// um limite a varredura truncava por CONTAGEM, que é o pior corte possível:
	// cai num lugar diferente a cada host e não diz onde parou.
	//
	// O limite de profundidade é declarado e igual em toda máquina. Cobre os
	// lugares onde uma retenção de root de fato fica — ~/bin, ~/.config/x,
	// ~/.local/bin —, e o que fica de fora é dito em voz alta.
	maxSuidDepthHome = 5
)

// suidRaizes são as árvores onde binário executável mora. É deliberadamente uma
// LISTA e não "/" inteiro: varrer a raiz arrasta montagem de rede, volume de
// dados e diretório de contêiner, e o custo explode sem acrescentar sinal.
//
// /tmp, /var/tmp e /dev/shm entram porque é justamente ali que um SUID nunca
// deveria estar — e é onde ele aparece.
var suidRaizes = []string{
	"/bin", "/sbin", "/lib", "/lib64",
	"/usr", "/opt", "/srv", "/root", "/home",
	"/var/tmp", "/var/www", "/var/lib", "/tmp", "/dev/shm", "/etc",
}

// pularPorNome são diretórios que não se percorre EM PROFUNDIDADE ALGUMA:
// dependência de projeto, cache de gerenciador e árvore de build.
//
// Sem eles a varredura afogava. Num home de desenvolvedor são 270 mil
// diretórios, o teto de 40 mil estourava, e o resultado era uma varredura
// arbitrariamente truncada em 15% — o pior dos dois mundos, porque um corte por
// contagem não diz ONDE parou.
//
// Pular árvore NOMEADA é melhor que truncar: a exclusão é conhecida, está
// escrita e é a mesma em todo host, enquanto o teto por contagem cai num lugar
// diferente a cada máquina.
var pularPorNome = map[string]bool{
	"node_modules": true, ".git": true, ".cache": true, ".npm": true,
	".cargo": true, ".rustup": true, ".gradle": true, ".m2": true,
	"site-packages": true, "venv": true, ".venv": true, "__pycache__": true,
	".pnpm-store": true, ".yarn": true, "vendor": true, ".terraform": true,
	".mozilla": true,
}

// suidPular são árvores dentro das raízes que só geram custo. /usr/share é
// documentação e dado; /var/lib/docker é o filesystem de outros contêineres,
// que não é este host.
var suidPular = map[string]bool{
	"/usr/share/doc": true, "/usr/share/man": true, "/usr/share/locale": true,
	"/usr/src": true, "/usr/share/icons": true, "/usr/share/fonts": true,
	"/var/lib/docker": true, "/var/lib/containers": true, "/var/lib/lxc": true,
	"/var/lib/flatpak": true, "/var/lib/snapd": true,
}

// SuidFile é um executável com bit setuid ou setgid.
type SuidFile struct {
	Path string `json:"path"`

	// Setuid e Setgid separados: setgid raramente dá root sozinho, e a
	// diferença muda o peso do achado.
	Setuid bool `json:"setuid,omitempty"`
	Setgid bool `json:"setgid,omitempty"`

	// UID e GID donos. Um setuid de dono não-root não escala para root — vale
	// para AQUELA identidade, e isso é outra conversa.
	UID int `json:"uid"`
	GID int `json:"gid"`

	Size   int64  `json:"size"`
	ModUTC string `json:"mod_utc,omitempty"`
}

func collectSuid(f *Facts, e *env.Env) {
	// A varredura não ATRAVESSA montagem, como o `-xdev` do find: um NFS ou um
	// volume de rede transforma meio segundo em minutos, e o que se acha ali é
	// de OUTRO host.
	//
	// Mas a baseline é POR RAIZ, não a do "/". Comparar tudo contra o
	// dispositivo do "/" fazia a varredura parar na porta de toda árvore que
	// tem filesystem próprio — e as duas mais comuns são justamente as que
	// importam: /home em partição separada (a norma em servidor) e /tmp em
	// tmpfs (o padrão do systemd). Nesses hosts, SUID em home de usuário ou em
	// subdiretório de /tmp nunca seria encontrado.
	//
	// Com a baseline por raiz, cada árvore listada é percorrida inteira, e o
	// que continua fora é só o que estiver montado DENTRO dela.
	visitados := 0
	truncado := false
	profundoDemais := false
	var outroFS []string
	for _, raiz := range suidRaizes {
		// Raiz que é SYMLINK não entra.
		//
		// Com usrmerge, /bin, /sbin e /lib apontam para dentro de /usr. Entrar
		// pelos dois faz a varredura visitar cada arquivo duas vezes, com dois
		// caminhos diferentes — e o mesmo binário aparece como /bin/su e
		// /usr/bin/su, dobrando os achados e confundindo a pergunta de
		// propriedade.
		fi, err := e.Lstat(raiz)
		if err != nil || fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
			continue
		}
		dev, temDev := dispositivoDeInfo(fi)
		teto := maxSuidDepth
		if raiz == "/home" || raiz == "/root" {
			teto = maxSuidDepthHome
		}
		varrerSuid(f, e, raiz, 0, teto, dev, temDev, &visitados, &truncado, &profundoDemais, &outroFS)
	}

	if truncado {
		f.denyPersist("suid", "a varredura de SUID parou em "+
			strconv.Itoa(maxSuidDirs)+" diretórios: o excedente NÃO foi examinado")
	}
	if profundoDemais {
		f.denyPersist("suid", "a varredura de SUID desceu no máximo "+
			strconv.Itoa(maxSuidDepthHome)+" níveis dentro de /home e /root: "+
			"SUID mais fundo que isso NÃO foi procurado")
	}
	// A lacuna de escopo só vale se algo foi REALMENTE pulado.
	//
	// Declará-la sempre deixaria toda varredura permanentemente incompleta, e um
	// parcial que nunca sai não informa nada — pior, gasta o sinal de cobertura,
	// que é justamente o que esta ferramenta usa para separar "não achei" de
	// "não consegui olhar". Com os caminhos nomeados, o operador sabe o que
	// examinar por fora.
	if len(outroFS) > 0 {
		if len(outroFS) > 6 {
			outroFS = append(outroFS[:6], "…")
		}
		f.denyPersist("suid", "a varredura de SUID não atravessou montagem: "+
			strings.Join(outroFS, ", ")+" NÃO foram examinados")
	}
}

func varrerSuid(f *Facts, e *env.Env, dir string, prof, teto int, dev uint64, temDev bool,
	visitados *int, truncado, profundoDemais *bool, outroFS *[]string) {

	if prof > teto {
		// A lacuna só vale se algo foi REALMENTE cortado. Declará-la sempre que
		// /home existe deixaria todo servidor permanentemente degradado por uma
		// escolha de escopo que nunca chegou a excluir nada — e um parcial que
		// nunca sai gasta o sinal de cobertura.
		*profundoDemais = true
		return
	}
	if *truncado || suidPular[dir] {
		return
	}
	if *visitados >= maxSuidDirs {
		*truncado = true
		return
	}
	*visitados++

	ents, err := e.ReadDir(dir)
	if err != nil {
		return // sem permissão neste galho: o resto da árvore continua
	}
	for _, ent := range ents {
		p := dir + "/" + ent.Name()
		if dir == "/" {
			p = "/" + ent.Name()
		}

		// Lstat, não Stat: um symlink para /bin/bash não é um SUID, e seguir
		// links faria a varredura contar o mesmo arquivo muitas vezes — e entrar
		// em ciclo.
		fi, err := e.Lstat(p)
		if err != nil {
			continue
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			continue
		}
		if fi.IsDir() {
			if temDev {
				if d, ok := dispositivoDeInfo(fi); ok && d != dev {
					// Outro filesystem: fora do escopo, e o caminho é NOMEADO
					// para o operador saber o que examinar por fora.
					*outroFS = append(*outroFS, p)
					continue
				}
			}
			varrerSuid(f, e, p, prof+1, teto, dev, temDev, visitados, truncado, profundoDemais, outroFS)
			continue
		}
		if !fi.Mode().IsRegular() {
			continue
		}
		setuid := fi.Mode()&os.ModeSetuid != 0
		setgid := fi.Mode()&os.ModeSetgid != 0
		if !setuid && !setgid {
			continue
		}

		s := SuidFile{
			Path: p, Setuid: setuid, Setgid: setgid,
			Size: fi.Size(), UID: -1, GID: -1,
		}
		if !fi.ModTime().IsZero() {
			s.ModUTC = fi.ModTime().UTC().Format("2006-01-02T15:04:05Z")
		}
		s.UID, s.GID = donoDe(fi)
		f.Suid = append(f.Suid, s)
	}
}

// DirGravavelPorTodos diz se o caminho está numa árvore em que qualquer usuário
// escreve. Um SUID ali não é configuração incomum: é a forma do backdoor.
func DirGravavelPorTodos(p string) bool {
	for _, d := range []string{"/tmp/", "/var/tmp/", "/dev/shm/"} {
		if strings.HasPrefix(p, d) {
			return true
		}
	}
	return false
}

// dispositivoDeInfo extrai o número do dispositivo. Falhar aqui não é erro: em
// modo image sobre um rootfs exportado a informação pode não vir, e a varredura
// simplesmente não aplica o limite de filesystem.
func dispositivoDeInfo(fi fs.FileInfo) (uint64, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint64(st.Dev), true
}

// donoDe devolve uid e gid do arquivo. Um setuid de dono NÃO-root não escala
// para root — vale para aquela identidade, e é outra conversa.
func donoDe(fi fs.FileInfo) (int, int) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return -1, -1
	}
	return int(st.Uid), int(st.Gid)
}
