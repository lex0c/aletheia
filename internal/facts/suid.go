package facts

import (
	"io/fs"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
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

	// Teto de trabalhadores da varredura. O mesmo do coletor de processos:
	// acima disso a disputa por I/O custa mais do que o paralelismo rende.
	maxSuidWorkers = 8
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

// As árvores que a varredura de SUID não percorre.
//
// Por que a exclusão de imagem é necessária, medido num desktop com containerd: cada
// camada de imagem traz o conjunto setuid inteiro de uma distribuição — su,
// mount, passwd, sudo, chsh, chfn, gpasswd —, nenhum deles é reivindicado pelo
// pacman do host (correto: não foi o pacman que os entregou), e o ctime é o da
// extração da camada enquanto o mtime é o da construção do pacote meses antes.
// Os três sinais disparam juntos em cada binário de cada camada. Vinte
// snapshots renderam 310 CRÍTICOS, e um relatório com 310 críticos falsos não
// é um relatório ruim: é um relatório que ninguém lê.
//
// containerd FALTAVA nesta lista, e é o armazenamento do Docker moderno e de
// todo Kubernetes — docker, podman e lxc estavam aqui desde o começo.
//
// O que se perde é DECLARADO: um implante plantado dentro de uma camada de
// imagem não é procurado aqui. Ele é problema da imagem, e a imagem se varre
// como imagem — `aletheia scan --root <camada>`, onde o kernel é o do analista
// (§35.6).
//
// São DOIS motivos diferentes, e a diferença decide se o pulo vira lacuna
// declarada ou não.
//
// suidPularCusto é conteúdo DESTE host que só gera custo: documentação, dado de
// localização, fonte. A exclusão é fixa, igual em toda máquina, e está escrita
// no limite de escopo do próprio check — do mesmo jeito que node_modules e
// .cache estão. Declará-la a cada execução tornaria "cobertura completa"
// impossível em todo host do mundo, e o sinal do exit code morreria junto.
var suidPularCusto = map[string]bool{
	"/usr/share/doc": true, "/usr/share/man": true, "/usr/share/locale": true,
	"/usr/src": true, "/usr/share/icons": true, "/usr/share/fonts": true,
}

// suidPularImagem é armazenamento de imagem de contêiner: o filesystem de
// OUTRAS máquinas, empilhado em camadas dentro deste disco. Isto SIM vira
// lacuna declarada — a árvore existe, não foi examinada, e há uma forma certa
// de examiná-la que o relatório precisa dizer.
var suidPularImagem = map[string]bool{
	"/var/lib/docker": true, "/var/lib/containerd": true,
	"/var/lib/containers": true, "/var/lib/lxc": true, "/var/lib/lxd": true,
	"/var/lib/flatpak": true, "/var/lib/snapd": true,
	// k3s e k0s embutem o próprio containerd numa árvore própria.
	"/var/lib/rancher": true, "/var/lib/k0s": true,
	// buildkit guarda as camadas intermediárias de build, com a mesma forma.
	"/var/lib/buildkit": true,
}

// SuidFile é um executável que CARREGA PRIVILÉGIO — por bit setuid/setgid ou
// por capability em atributo estendido.
//
// As duas formas são a mesma coisa para quem responde a incidente, e só uma
// delas aparece num `find -perm -4000`. O /usr/bin/ping das distribuições
// modernas não tem bit setuid nenhum: o poder dele vem de `security.capability`
// no xattr. Um `setcap cap_setuid+ep /usr/local/bin/.x` cria retenção de root
// que nenhuma varredura por MODO enxerga.
type SuidFile struct {
	Path string `json:"path"`

	// Setuid e Setgid separados: setgid raramente dá root sozinho, e a
	// diferença muda o peso do achado.
	Setuid bool `json:"setuid,omitempty"`
	Setgid bool `json:"setgid,omitempty"`

	// CapPerm é a máscara de capabilities PERMITIDAS gravada no arquivo, e
	// CapEfetivo diz se elas já sobem efetivas na execução (o `+ep` do setcap).
	// Zero significa que o arquivo não carrega capability nenhuma.
	CapPerm    uint64 `json:"cap_permitted,omitempty"`
	CapEfetivo bool   `json:"cap_effective,omitempty"`

	// UID e GID donos. Um setuid de dono não-root não escala para root — vale
	// para AQUELA identidade, e isso é outra conversa.
	UID int `json:"uid"`
	GID int `json:"gid"`

	Size   int64  `json:"size"`
	ModUTC string `json:"mod_utc,omitempty"`

	// DirModo é o modo MEDIDO do diretório que contém o arquivo, e DirLido diz
	// se ele chegou a ser lido.
	//
	// Existem porque a resposta era dada por PREFIXO: tudo abaixo de /tmp
	// recebia a frase "está em diretório gravável por qualquer usuário". A
	// frase é evidência num achado CRITICAL, e ela era falsa para todo
	// subdiretório 0700 dentro de /tmp — que é o que systemd-private,
	// /tmp/ssh-*, e qualquer mktemp -d criam.
	DirModo uint32 `json:"dir_mode,omitempty"`
	DirLido bool   `json:"dir_mode_read,omitempty"`
}

// DirGravavelPorTodos diz se o arquivo está num diretório em que QUALQUER
// usuário escreve. Um SUID ali não é configuração incomum: é a forma do
// backdoor.
//
// Quando o modo foi medido, ele é a resposta. Quando não foi — dump antigo, ou
// imagem montada onde a permissão vem achatada —, vale o prefixo, que é a
// aproximação de antes e continua certa para o caso comum de arquivo solto em
// /tmp.
func (s SuidFile) DirGravavelPorTodos() bool {
	if s.DirLido {
		return s.DirModo&0o002 != 0
	}
	return prefixoDeArvoreGravavel(s.Path)
}

func collectSuid(f *Facts, e *env.Env) {
	// A varredura é PARALELA, e a razão é medida: /usr e /home somam sete
	// décimos de segundo num desktop, e o trabalho é readdir mais stat — que é
	// syscall, e syscall reparte entre núcleos como o hash repartiu.
	//
	// A recursão sequencial anterior usava um núcleo enquanto os outros onze
	// esperavam.
	trab := &varredura{
		e:      e,
		f:      f,
		fila:   make([]tarefaDir, 0, 256),
		limite: maxSuidDirs,
	}

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
		trab.fila = append(trab.fila, tarefaDir{dir: raiz, teto: teto, dev: dev, temDev: temDev})
	}

	// O índice de montagens é montado ANTES de largar os trabalhadores.
	//
	// A construção preguiçosa dentro de `ehOutroFilesystem` era segura enquanto
	// a varredura era sequencial; com fila e vários trabalhadores virou corrida
	// de dados — vários escrevendo o mesmo mapa. Paralelizar não muda só a
	// velocidade: muda quem pode tocar em quê.
	f.devPorPonto()

	trab.rodar(e.Workers(maxSuidWorkers))

	if trab.truncado {
		f.denyPersist("suid", "a varredura de SUID parou em "+
			strconv.Itoa(maxSuidDirs)+" diretórios: o excedente NÃO foi examinado")
	}
	if trab.profundoDemais {
		f.denyPersist("suid", "a varredura de SUID desceu no máximo "+
			strconv.Itoa(maxSuidDepthHome)+" níveis dentro de /home e /root: "+
			"SUID mais fundo que isso NÃO foi procurado")
	}
	if len(trab.puladas) > 0 {
		sort.Strings(trab.puladas)
		f.denyPersist("suid", "a varredura de SUID NÃO entrou em "+
			strconv.Itoa(len(trab.puladas))+" árvore(s) de armazenamento de imagem "+
			"de contêiner: "+resumoCaminhos(trab.puladas)+" — o conteúdo delas é o "+
			"filesystem de OUTRAS máquinas, e se varre como imagem "+
			"(`aletheia scan --root <camada>`), onde o kernel é o do analista")
	}
	if len(trab.negados) > 0 {
		sort.Strings(trab.negados)
		f.denyPersist("suid", "a varredura de SUID não conseguiu abrir "+
			strconv.Itoa(len(trab.negados))+" diretórios: "+
			resumoCaminhos(trab.negados)+" — SUID lá dentro NÃO foi procurado")
	}
	if len(trab.outroFS) > 0 {
		lista := trab.outroFS
		sort.Strings(lista)
		if len(lista) > 6 {
			lista = append(lista[:6:6], "…")
		}
		f.denyPersist("suid", "a varredura de SUID não atravessou montagem: "+
			strings.Join(lista, ", ")+" NÃO foram examinados")
	}
	// Ordem estável: a fila é consumida por vários trabalhadores, e sem isto o
	// relatório mudaria de forma entre execuções idênticas.
	sort.Slice(f.Suid, func(i, j int) bool { return f.Suid[i].Path < f.Suid[j].Path })
	sort.Strings(f.ExecOculto)
}

// tarefaDir é um diretório a percorrer, com o que a decisão precisa saber.
type tarefaDir struct {
	dir    string
	prof   int
	teto   int
	dev    uint64
	temDev bool
}

// varredura é a fila compartilhada e o que sai dela.
type varredura struct {
	e *env.Env
	f *Facts

	mu   sync.Mutex
	fila []tarefaDir
	// ativos conta quem está processando. A fila vazia só significa FIM quando
	// ninguém está trabalhando: um trabalhador ocupado ainda pode empilhar
	// subdiretórios, e parar antes dele perderia galhos inteiros em silêncio.
	ativos int

	visitados      int
	limite         int
	truncado       bool
	profundoDemais bool
	outroFS        []string

	// puladas são as árvores excluídas de propósito — ver suidPularImagem. Elas
	// existem no disco e NÃO foram examinadas, e isso precisa aparecer.
	puladas []string

	// negados são os diretórios que a varredura não conseguiu ABRIR. Sem esta
	// lista, um galho inteiro sumia com a mesma cara de galho sem SUID — e
	// /home costuma ser 0700 por usuário, que é justamente onde um setuid
	// plantado sobreviveria à faxina.
	negados []string
}

func (v *varredura) rodar(n int) {
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				t, ok := v.proxima()
				if !ok {
					return
				}
				v.visitar(t)
				v.terminou()
			}
		}()
	}
	wg.Wait()
}

// proxima entrega o próximo diretório, ou diz que acabou.
func (v *varredura) proxima() (tarefaDir, bool) {
	for {
		v.mu.Lock()
		if len(v.fila) > 0 {
			t := v.fila[len(v.fila)-1]
			v.fila = v.fila[:len(v.fila)-1]
			v.ativos++
			v.mu.Unlock()
			return t, true
		}
		ativos := v.ativos
		v.mu.Unlock()
		if ativos == 0 {
			return tarefaDir{}, false
		}
		// Alguém ainda trabalha e pode empilhar. Ceder a vez é mais barato que
		// uma variável de condição para um laço que dura milissegundos.
		runtime.Gosched()
	}
}

func (v *varredura) terminou() {
	v.mu.Lock()
	v.ativos--
	v.mu.Unlock()
}

func (v *varredura) visitar(t tarefaDir) {
	if suidPularCusto[t.dir] {
		return
	}
	if suidPularImagem[t.dir] {
		// Pular o filesystem de outra máquina é decisão, e decisão se DECLARA.
		// Voltar em silêncio fazia a varredura estreitar o próprio escopo sem
		// dizer — o mesmo erro que esta ferramenta existe para não cometer,
		// cometido do lado de dentro dela.
		v.mu.Lock()
		v.puladas = append(v.puladas, t.dir)
		v.mu.Unlock()
		return
	}

	v.mu.Lock()
	if v.truncado || v.visitados >= v.limite {
		v.truncado = true
		v.mu.Unlock()
		return
	}
	v.visitados++
	v.mu.Unlock()

	ents, err := v.e.ReadDir(t.dir)
	if err != nil {
		// O galho para aqui e o resto da árvore continua — mas o que ficou
		// para trás precisa ser DITO. Diretório que sumiu no meio da varredura
		// não conta: ausência é resposta, corrida de arquivo é ruído.
		if env.EhLacuna(err) {
			v.mu.Lock()
			v.negados = append(v.negados, t.dir)
			v.mu.Unlock()
		}
		return
	}

	var novos []tarefaDir
	var achados []SuidFile
	var achadosOcultos []string
	var fora []string
	// O modo do diretório é lido no MÁXIMO uma vez por diretório, e só quando
	// algum arquivo lá dentro pede — a varredura visita dezenas de milhares de
	// diretórios e quase nenhum tem SUID.
	var modoDir uint32
	var lidoDir bool

	for _, ent := range ents {
		p := t.dir + "/" + ent.Name()
		if t.dir == "/" {
			p = "/" + ent.Name()
		}

		// O TIPO vem do readdir, sem syscall nenhuma: o kernel devolve d_type
		// junto com o nome. Chamar stat em toda entrada só para descobrir que
		// aquilo era um symlink é uma syscall por arquivo do host.
		//
		// Symlink é descartado: um link para /bin/bash não é um SUID, e
		// segui-lo faria a varredura contar o mesmo arquivo muitas vezes e
		// entrar em ciclo.
		tipo := ent.Type()
		if tipo&os.ModeSymlink != 0 {
			continue
		}
		if tipo.IsDir() {
			// A PODA não vale em árvore temporária.
			//
			// Ela existe por volume: um home de desenvolvedor tem 270 mil
			// diretórios, quase todos em `node_modules` e `.cache`. /tmp e
			// /var/tmp não têm volume nenhum — e `.cache` ali é exatamente onde
			// um esconderijo se põe.
			//
			// Sem esta exceção, a lista que acelerou a varredura cegava o check
			// que procura executável em diretório oculto: as duas decisões
			// colidiam num ponto só, e a mais antiga vencia em silêncio.
			if pularPorNome[ent.Name()] && !emArvoreTemporaria(t.dir) {
				continue
			}
			if t.prof+1 > t.teto {
				v.mu.Lock()
				v.profundoDemais = true
				v.mu.Unlock()
				continue
			}
			// PONTO DE MONTAGEM vem da tabela, não de um stat por diretório: o
			// dispositivo só muda em ponto de montagem, e a tabela já está em
			// memória.
			if t.temDev && v.f.ehOutroFilesystem(p, t.dev) {
				fora = append(fora, p)
				continue
			}
			novos = append(novos, tarefaDir{dir: p, prof: t.prof + 1, teto: t.teto,
				dev: t.dev, temDev: t.temDev})
			continue
		}
		if !tipo.IsRegular() {
			continue
		}

		// Só AQUI vale a syscall: modo, tamanho e dono só existem no stat.
		fi, err := v.e.Lstat(p)
		if err != nil {
			continue
		}
		setuid := fi.Mode()&os.ModeSetuid != 0
		setgid := fi.Mode()&os.ModeSetgid != 0

		// EXECUTÁVEL DENTRO DE DIRETÓRIO OCULTO, em árvore temporária.
		//
		// A varredura já percorre /tmp, /var/tmp e /dev/shm, então isto sai de
		// graça — e fecha um limite que estava escrito no check de propriedade:
		// "um binário largado em disco e nunca executado não entra".
		//
		// Diretório oculto sozinho é ruído: `.X11-unix` e `.ICE-unix` vêm de
		// fábrica. Medido no host, NENHUM deles contém executável — o que os
		// separa é o cruzamento, não o nome.
		if fi.Mode()&0o111 != 0 && emDiretorioOculto(p) && !inerteDeFabrica(ent.Name()) {
			achadosOcultos = append(achadosOcultos, p)
		}

		// A capability só é perguntada em arquivo EXECUTÁVEL: xattr em arquivo
		// que ninguém executa não confere poder a ninguém.
		var capPerm uint64
		var capEf bool
		if fi.Mode()&0o111 != 0 {
			capPerm, capEf = capabilityDoArquivo(v.e, p)
		}
		if !setuid && !setgid && capPerm == 0 {
			continue
		}

		s := SuidFile{
			Path: p, Setuid: setuid, Setgid: setgid,
			CapPerm: capPerm, CapEfetivo: capEf,
			Size: fi.Size(), UID: -1, GID: -1,
		}
		if !fi.ModTime().IsZero() {
			s.ModUTC = fi.ModTime().UTC().Format("2006-01-02T15:04:05Z")
		}
		s.UID, s.GID = donoDe(fi)
		s.DirModo, s.DirLido = modoDoDiretorio(v.e, t.dir, &modoDir, &lidoDir)
		achados = append(achados, s)
	}

	// Um bloqueio por DIRETÓRIO e não por entrada: com doze trabalhadores e
	// centenas de milhares de arquivos, travar por arquivo transformaria o
	// paralelismo em fila.
	if len(novos) > 0 || len(achados) > 0 || len(fora) > 0 || len(achadosOcultos) > 0 {
		v.mu.Lock()
		v.fila = append(v.fila, novos...)
		v.f.Suid = append(v.f.Suid, achados...)
		v.f.ExecOculto = append(v.f.ExecOculto, achadosOcultos...)
		v.outroFS = append(v.outroFS, fora...)
		v.mu.Unlock()
	}
}

// prefixoDeArvoreGravavel é a aproximação LÉXICA, usada só quando o modo do
// diretório não pôde ser medido.
func prefixoDeArvoreGravavel(p string) bool {
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

// capabilityDoArquivo lê `security.capability` e devolve a máscara permitida.
//
// O formato é o `vfs_cap_data` do kernel, em little-endian:
//
//	0..3    magic_etc: versão nos bits altos, flags nos baixos
//	4..7    permitted, 32 bits baixos
//	8..11   inheritable, 32 bits baixos
//	12..15  permitted, 32 bits altos   (a partir da versão 2)
//	16..19  inheritable, 32 bits altos
//	20..23  rootid                     (versão 3, namespace de usuário)
//
// O bit EFETIVO no magic é o que separa `cap_setuid+p` de `cap_setuid+ep`: com
// ele, a capability já sobe ativa na execução e o binário não precisa nem
// pedir. É a diferença entre um programa que PODE elevar e um que JÁ elevou.
func capabilityDoArquivo(e *env.Env, p string) (uint64, bool) {
	// Em modo image o caminho é relativo à raiz travada, e o xattr é lido do
	// arquivo real — a raiz do os.Root não intercepta xattr, então o caminho
	// precisa ser o do sistema de arquivos.
	buf := make([]byte, 24)
	n, err := syscall.Getxattr(e.Path(p), "security.capability", buf)
	if err != nil || n < 12 {
		return 0, false
	}
	magic := le32(buf[0:])
	perm := uint64(le32(buf[4:]))
	if n >= 20 {
		perm |= uint64(le32(buf[12:])) << 32
	}
	const flagEfetivo = 0x000001
	return perm, magic&flagEfetivo != 0
}

func le32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

// devPorPonto é a tabela de montagem indexada por ponto, montada UMA vez.
//
// A primeira versão varria o slice de montagens a cada diretório. Com dezenas
// de montagens e dezenas de milhares de diretórios isso é milhões de
// comparações de string — trocar uma syscall por uma busca linear não é
// otimizar, é mudar de credor.
func (f *Facts) devPorPonto() map[string]uint64 {
	if f.idxMount != nil {
		return f.idxMount
	}
	f.idxMount = make(map[string]uint64, len(f.Mounts))
	for i := range f.Mounts {
		f.idxMount[f.Mounts[i].Ponto] = f.Mounts[i].Dev
	}
	return f.idxMount
}

// ehOutroFilesystem diz se o caminho é um ponto de montagem de dispositivo
// diferente do da árvore que está sendo percorrida.
//
// O dispositivo só muda em ponto de montagem, e a tabela já foi lida no começo
// da coleta: perguntar ao kernel o dispositivo de cada diretório percorrido é
// pagar por informação que já está em memória.
func (f *Facts) ehOutroFilesystem(p string, dev uint64) bool {
	d, ehPonto := f.devPorPonto()[p]
	// Não é ponto de montagem: continua no mesmo filesystem, sem perguntar.
	// E ponto de montagem sem dispositivo resolvido desce mesmo assim — perder
	// um galho por engano é pior que percorrer um a mais.
	return ehPonto && d != 0 && d != dev
}

// inerteDeFabrica reconhece arquivo que vem executável e NUNCA é executado.
//
// O git entrega quatorze hooks de exemplo em `.git/hooks`, todos em modo 755, e
// não roda nenhum: o sufixo `.sample` é o que os desativa. Num host com
// diretório de build do gerenciador de pacotes — repositórios clonados em
// /var/tmp — isso rendeu dois achados de catorze arquivos cada.
//
// A regra não é nova nesta base: o coletor de hooks de git já pula `.sample`
// pelo mesmo motivo. Ela é que não tinha sido aplicada aqui.
func inerteDeFabrica(nome string) bool {
	return strings.HasSuffix(nome, ".sample")
}

// emDiretorioOculto diz se algum componente do caminho, DEPOIS da árvore
// temporária, começa com ponto.
//
// A restrição às árvores temporárias é o que torna isto utilizável: home de
// usuário é cheio de diretório oculto com executável dentro — `.local/bin`,
// `.cargo/bin`, `.nvm` —, e tudo isso é legítimo. Em /tmp não é.
func emDiretorioOculto(p string) bool {
	for _, raiz := range []string{"/tmp/", "/var/tmp/", "/dev/shm/"} {
		resto, ok := strings.CutPrefix(p, raiz)
		if !ok {
			continue
		}
		// O último componente é o arquivo; só os DIRETÓRIOS contam. Um binário
		// chamado `.x` solto em /tmp já é achado do check de caminho.
		partes := strings.Split(resto, "/")
		for _, d := range partes[:max(0, len(partes)-1)] {
			if strings.HasPrefix(d, ".") {
				return true
			}
		}
		return false
	}
	return false
}

// emArvoreTemporaria diz se o caminho está sob /tmp, /var/tmp ou /dev/shm.
func emArvoreTemporaria(p string) bool {
	for _, raiz := range []string{"/tmp", "/var/tmp", "/dev/shm"} {
		if p == raiz || strings.HasPrefix(p, raiz+"/") {
			return true
		}
	}
	return false
}

// idDeDiretorio identifica um diretório pelo par (dev, ino).
//
// É como se responde "estes dois caminhos são o mesmo diretório?" sem tabela de
// equivalência: sob usrmerge /lib/systemd/system e /usr/lib/systemd/system caem
// no mesmo inode, e a fusão varia entre distribuições. O Stat segue link de
// propósito — o que interessa é ONDE o caminho chega, não se ele é um link.
func idDeDiretorio(e *env.Env, dir string) ([2]uint64, bool) {
	fi, err := e.Stat(dir)
	if err != nil || !fi.IsDir() {
		return [2]uint64{}, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return [2]uint64{}, false
	}
	return [2]uint64{uint64(st.Dev), uint64(st.Ino)}, true
}

// modoDoDiretorio devolve o modo do diretório, medindo-o na primeira vez e
// reaproveitando depois. O booleano diz se a medida existe: sem ele, "modo
// zero" seria indistinguível de "diretório sem permissão nenhuma".
func modoDoDiretorio(e *env.Env, dir string, cache *uint32, lido *bool) (uint32, bool) {
	if !*lido {
		fi, err := e.Lstat(dir)
		if err != nil {
			return 0, false
		}
		*cache = uint32(fi.Mode().Perm())
		*lido = true
	}
	return *cache, true
}
