package facts

import (
	"bufio"
	"sort"
	"strconv"
	"strings"

	"github.com/lex0c/aletheia/internal/env"
)

// Propriedade de pacote (runbook §24).
//
// A pergunta é uma só: ALGUM pacote reivindica este arquivo? É o discriminador
// que faltava para separar `/usr/local/sbin/systemd-oomd-helper` de um serviço
// legítimo — o nome imita, o caminho é de sistema, o comando é limpo, e nenhum
// pacote o instalou.
//
// # Por que NATIVO, e não `dpkg -V`
//
// A SPEC previu marcar achado vindo de binário do host como `origin:tool` e
// rebaixá-lo. Mas dpkg e apk guardam a lista de arquivos em TEXTO, e ler texto
// é mais barato que gerenciar desconfiança: o resultado passa a valer como
// prova, e funciona sobre imagem montada — que é o caminho da §35.6 quando o
// userland do alvo não é confiável.
//
// O rpm não dá essa opção: a base é binária. Ali a resposta é NÃO SEI, dita em
// voz alta, e não um silêncio que parece limpeza.
//
// # Por que não varremos o filesystem
//
// Perguntar "quem é o dono de cada arquivo do host" exigiria caminhar tudo. A
// pergunta útil é mais estreita: quem é o dono do que está RODANDO e do que
// algum gatilho EXECUTA. Isso são dezenas de caminhos, não milhões.

// PkgDB é a base de pacotes encontrada.
type PkgDB struct {
	Kind string `json:"kind"` // dpkg | apk | rpm | none
	Path string `json:"path,omitempty"`

	// Consultavel diz se dá para responder "quem é o dono". Falso no rpm, e a
	// diferença entre "nenhum pacote reivindica" e "não pude perguntar" é a
	// razão de ser desta ferramenta.
	Consultavel bool   `json:"queryable"`
	Motivo      string `json:"reason,omitempty"`
}

// ReivindicacaoEstranha é um caminho que a base de pacotes DIZ pertencer a um
// pacote, num lugar onde distribuição nenhuma instala.
//
// A FHS reserva /usr/local ao administrador local, e a política do Debian
// proíbe explicitamente que pacote escreva ali. O mesmo vale, com ainda mais
// força, para /tmp e /home. Uma linha dessas na base significa que a BASE foi
// editada — e editar a base é como se derrota a pergunta de propriedade, que é
// a defesa em que cinco checks desta ferramenta se apoiam.
type ReivindicacaoEstranha struct {
	Path string `json:"path"`
	File string `json:"file"`
}

// territorioNaoEmpacotado são as árvores onde pacote de distribuição não
// instala. Uma reivindicação aqui é adulteração, não configuração.
var territorioNaoEmpacotado = []string{
	"/usr/local/", "/tmp/", "/var/tmp/", "/dev/shm/", "/home/", "/root/",
}

func reivindicacaoEstranha(caminho, arquivo string, f *Facts) {
	// DIRETÓRIO não é reivindicação estranha.
	//
	// O pacote `filesystem` do Arch cria /home, /root e /usr/local — é ele que
	// entrega a árvore da FHS, e por isso reivindica esses diretórios de
	// fábrica. Contá-los rendeu vinte e um críticos num host limpo.
	//
	// O que não tem explicação é um ARQUIVO reivindicado dentro deles.
	if strings.HasSuffix(caminho, "/") {
		return
	}
	for _, d := range territorioNaoEmpacotado {
		if !strings.HasPrefix(caminho, d) {
			continue
		}
		// E precisa estar DENTRO da árvore, não ser a árvore. "/usr/local/bin"
		// sem barra final ainda é um diretório da FHS que o pacote entrega.
		resto := strings.TrimPrefix(caminho, d)
		if resto == "" || !strings.Contains(resto, "/") {
			return
		}
		f.PkgEstranho = append(f.PkgEstranho, ReivindicacaoEstranha{
			Path: caminho, File: arquivo,
		})
		return
	}
}

// Ownership é a resposta para um caminho.
type Ownership struct {
	Path  string   `json:"path"`
	Owned bool     `json:"owned"`
	Onde  []string `json:"where,omitempty"` // por que perguntamos por ele

	// Pacote é QUEM entregou. Guardá-lo é o que torna a verificação de hash
	// barata: em vez de decomprimir a base inteira, lê-se a fonte de hash
	// apenas dos pacotes que entregaram algum candidato — tipicamente meia
	// dúzia, contra os milhares instalados.
	Pacote string `json:"package,omitempty"`
}

func collectPkg(f *Facts, e *env.Env) {
	f.Pkg = detectarPkgDB(e)

	candidatos := candidatosDePropriedade(f, e)
	if len(candidatos) == 0 {
		return
	}
	if !f.Pkg.Consultavel {
		f.denyPersist("pkg", "propriedade de pacote não pôde ser consultada ("+
			f.Pkg.Motivo+"): "+strconv.Itoa(len(candidatos))+
			" binários em execução ou agendados NÃO foram verificados")
		return
	}

	donos := map[string]string{}
	switch f.Pkg.Kind {
	case "dpkg":
		donosDpkg(f, e, candidatos, donos)
	case "apk":
		donosApk(f, e, candidatos, donos)
	case "pacman":
		donosPacman(f, e, candidatos, donos)
	}

	verificarHashes(f, e, donos)

	caminhos := make([]string, 0, len(candidatos))
	for p := range candidatos {
		caminhos = append(caminhos, p)
	}
	sort.Strings(caminhos)
	for _, p := range caminhos {
		f.Ownership = append(f.Ownership, Ownership{
			Path: p, Owned: donos[p] != "", Pacote: donos[p], Onde: candidatos[p],
		})
	}
	// Depois de Ownership estar montado: a comparação de datas só vale nos
	// arquivos SEM dono de pacote, e os atributos de inode são lidos sobre o
	// conjunto de que a ferramenta FALA.
	coletarTimestomp(f, e)
	coletarAtributos(f, e)
}

func detectarPkgDB(e *env.Env) PkgDB {
	switch {
	case e.IsDir("/var/lib/dpkg/info"):
		return PkgDB{Kind: "dpkg", Path: "/var/lib/dpkg/info", Consultavel: true}
	case e.Exists("/lib/apk/db/installed"):
		return PkgDB{Kind: "apk", Path: "/lib/apk/db/installed", Consultavel: true}
	case e.IsDir("/var/lib/pacman/local"):
		return PkgDB{Kind: "pacman", Path: "/var/lib/pacman/local", Consultavel: true}
	case e.Exists("/var/lib/rpm"), e.Exists("/usr/lib/sysimage/rpm"):
		return PkgDB{
			Kind: "rpm", Path: "/var/lib/rpm", Consultavel: false,
			Motivo: "a base do rpm é binária e não é lida nativamente; " +
				"`rpm -qf` responderia, mas viria do binário do host",
		}
	}
	return PkgDB{Kind: "none", Consultavel: false,
		Motivo: "nenhuma base de pacotes encontrada"}
}

// candidatosDePropriedade é a pergunta estreita: quem é dono do que está
// RODANDO e do que algum gatilho EXECUTA.
func candidatosDePropriedade(f *Facts, e *env.Env) map[string][]string {
	out := map[string][]string{}
	add := func(p, onde string) {
		if !strings.HasPrefix(p, "/") || strings.ContainsAny(p, "*?[]()|;&$\"'`<>") {
			return
		}
		// O arquivo precisa EXISTIR.
		//
		// Uma unit instalada cujo binário opcional não está no host aponta para
		// um caminho que não existe — `netctl-ifplugd@.service` referenciando
		// /usr/bin/ifplugd é o exemplo que apareceu num host real, e rendeu
		// vinte e uma acusações de "nenhum pacote reivindica". Nenhum pacote
		// reivindica mesmo: não há arquivo. Unit apontando para binário ausente
		// é unit QUEBRADA, que é outra conversa e outra severidade.
		fi, err := e.Lstat(p)
		if err != nil {
			return
		}
		// E não pode ser DIRETÓRIO. Linha de agendamento e de unit cita caminho
		// que não é executável o tempo todo — `cd /srv/app`, `--report
		// /etc/cron.hourly`, `WorkingDirectory=` —, e perguntar quem empacotou
		// um diretório não tem resposta útil: nenhum pacote reivindica `/`.
		//
		// O ramo dos gatilhos, mais abaixo, já descartava diretório e explicava
		// por quê. Era a mesma decisão, tomada uma vez e aplicada num lugar só.
		//
		// O corte é em DIRETÓRIO e não em "não-regular" de propósito: /bin/sh é
		// link simbólico em quase toda distribuição, e exigir arquivo regular
		// aqui jogaria fora binário de verdade.
		if fi.IsDir() {
			return
		}
		out[p] = append(out[p], onde)
	}

	for i := range f.Processes {
		p := &f.Processes[i]
		if p.Self || p.Vanished || p.Exe == "" || p.ExeDeleted || p.ExeMemfd {
			continue
		}
		add(p.Exe, "processo pid="+strconv.Itoa(p.PID))
		// As bibliotecas que ele carregou. É o que faz o Ebury aparecer: a
		// biblioteca trocada NO LUGAR dela não executa nada, e nenhuma outra
		// fonte a traria para a pergunta.
		for _, lib := range p.MapsLibs {
			add(lib, "biblioteca carregada")
		}
	}
	for i := range f.Units {
		u := &f.Units[i]
		for _, ex := range u.Exec {
			add(primeiroToken(ex.Cmd), "unit "+u.Name)
		}
	}
	for i := range f.Cron {
		c := &f.Cron[i]
		add(primeiroToken(c.Cmd), "cron "+baseNome(c.File))
	}
	// sitecustomize.py e usercustomize.py são importados pelo python na
	// inicialização sem ninguém pedir. Acusar a PRESENÇA acusaria toda
	// instalação de python do mundo — o Debian entrega
	// /usr/lib/python3.11/sitecustomize.py pelo libpython3.11-minimal. Quem
	// responde é o gerenciador de pacotes, e por isso eles entram AQUI.
	for _, p := range hooksDePython(e) {
		add(p, "hook de inicialização do python")
	}
	// E o ALVO de cada hook de interpretador. Sem isto o check de hook não tem
	// como pesar o que encontrou: `NODE_OPTIONS=--require /opt/app/x.js` numa
	// unit é configuração de deploy quando o arquivo veio de um pacote, e é
	// implante quando não veio — e a diferença é a única coisa que separa os
	// dois. O check perguntava e a resposta era sempre "tem dono", porque
	// ninguém tinha perguntado.
	for i := range f.HooksInterp {
		for _, alvo := range CaminhosDoValor(f.HooksInterp[i].Value) {
			add(alvo, "hook de interpretador ("+f.HooksInterp[i].Key+")")
		}
	}
	// O ALVO do gatilho, e esta é a que faltava.
	//
	// Um gatilho de boot ou de login que executa /lib/libudev.so não casa com
	// padrão de conteúdo nenhum — não baixa nada, não tem pipe para shell, o
	// caminho parece de sistema. O que denuncia é a pergunta de propriedade
	// sobre o ALVO, e o próprio check já dizia isso nos falsos positivos sem
	// usar: "o que os separa é o caminho do que executam e o dono do pacote".
	//
	// Só entra o que EXISTE e é arquivo regular. Isso descarta `cd /srv/app`
	// (diretório) e `npm ci` (não é caminho absoluto), que são o ruído natural
	// de linha de script.
	for i := range f.Triggers {
		t := &f.Triggers[i]
		for _, ln := range t.Lines {
			alvo := PrimeiroCaminhoAbsoluto(ln.Text)
			if alvo == "" {
				continue
			}
			if fi, err := e.Lstat(alvo); err != nil || !fi.Mode().IsRegular() {
				continue
			}
			// /etc está FORA, e a razão é o que /etc é: o lugar onde
			// configuração local mora por definição. O gerenciador de pacotes só
			// reivindica o que ELE entregou ali, e o resto é a máquina sendo
			// administrada. "Sem dono" em /etc não significa nada — no Ubuntu
			// 14.04 acusaria o próprio /etc/rc.local, que a distribuição cria
			// na instalação sem empacotar.
			//
			// Em /lib e /usr/bin a mesma resposta significa tudo, e é por isso
			// que o corte é por território e não por regra geral.
			if strings.HasPrefix(alvo, "/etc/") {
				continue
			}
			add(alvo, "gatilho "+baseNome(t.File))
		}
		// E o PRÓPRIO arquivo do gatilho. Um script em /etc/cron.daily entregue
		// pela distribuição não é achado; um acrescentado ali é — e a diferença
		// é exatamente a pergunta de propriedade.
		if fi, err := e.Lstat(t.File); err == nil && fi.Mode().IsRegular() {
			add(t.File, "arquivo de gatilho")
		}
	}
	// O arquivo de configuração de módulo, e o MÓDULO em si.
	//
	// A diretiva `install` legítima existe: o driver TrueScale da Intel encadeia
	// carga chamando um script em /usr/lib/rdma, e isso vem de pacote. O que
	// separa dela um implante é a mesma pergunta.
	//
	// E o .ko: um módulo de kernel que nenhum pacote entregou é dos fatos mais
	// altos que existem — é a camada em que o invasor passa a mentir para tudo
	// que estiver acima, inclusive para esta ferramenta.
	for i := range f.Modules {
		add(f.Modules[i].File, "config de módulo")
	}
	// Só os módulos CARREGADOS ou configurados para carregar.
	//
	// A árvore de um kernel moderno tem doze mil arquivos. Perguntar por todos
	// custa doze mil `Lstat` e trinta mil entradas de mapa por varredura, para
	// responder sobre arquivos que não estão rodando nem agendados — o mesmo
	// recorte que esta ferramenta aplica em todo lugar diz que o que interessa
	// é o que faz alguma coisa.
	//
	// E não se perde o caso que importa: um módulo plantado só age depois de
	// carregado, e para carregar no boot ele precisa estar configurado — o que
	// o traz de volta para esta lista.
	relevantes := modulosRelevantes(f)
	for _, ko := range f.ModuleFiles {
		if relevantes[ko] {
			add(ko, "módulo de kernel")
		}
	}
	// SUID é o caso em que a pergunta de propriedade vale MAIS: o conjunto
	// legítimo de binários com setuid é pequeno, conhecido e vem todo de
	// pacote. Um que não vem é a resposta inteira.
	for i := range f.Suid {
		add(f.Suid[i].Path, "setuid/setgid")
	}
	return out
}

// donosDpkg percorre as listas de arquivos, que são texto puro: um caminho
// absoluto por linha.
//
// A armadilha aqui é o usrmerge: o dpkg lista `/bin/cat`, e o processo roda
// `/usr/bin/cat`. Sem casar as duas formas, TODO binário de /usr/bin apareceria
// sem dono — um falso positivo catastrófico, em todo host Debian moderno.
func donosDpkg(f *Facts, e *env.Env, cand map[string][]string, donos map[string]string) {
	cacheDir := map[string]string{}
	// forma no arquivo -> caminhos perguntados. A LISTA importa: com usrmerge
	// duas formas do mesmo arquivo podem ser perguntadas ao mesmo tempo
	// (/bin/su e /usr/bin/su), e as duas geram as MESMAS chaves aqui. Guardando
	// um caminho só, a segunda inserção sobrescrevia a primeira e um dos dois
	// saía como "sem dono" — um binário de sistema acusado de não vir de pacote.
	procurados := map[string][]string{}
	for p := range cand {
		for _, v := range formasResolvidas(e, p, cacheDir) {
			procurados[v] = append(procurados[v], p)
		}
	}

	for _, n := range e.ReadDirNames("/var/lib/dpkg/info") {
		if !strings.HasSuffix(n, ".list") {
			continue
		}
		b, err := e.ReadFile("/var/lib/dpkg/info/" + n)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(strings.NewReader(string(b)))
		sc.Buffer(make([]byte, 0, 4096), 64*1024)
		for sc.Scan() {
			ln := sc.Text()
			reivindicacaoEstranha(ln, "/var/lib/dpkg/info/"+n, f)
			for _, alvo := range procurados[ln] {
				donos[alvo] = strings.TrimSuffix(n, ".list")
			}
		}
	}
}

// donosApk lê /lib/apk/db/installed. O formato é de blocos: `F:` fixa o
// diretório corrente e `R:` é um arquivo dentro dele.
func donosApk(f *Facts, e *env.Env, cand map[string][]string, donos map[string]string) {
	cacheDir := map[string]string{}
	// Lista, e não valor único: duas grafias do mesmo arquivo podem ser
	// perguntadas ao mesmo tempo e geram as MESMAS chaves aqui. Guardando um
	// caminho só, a segunda inserção sobrescreve a primeira e um dos dois sai
	// como "sem dono" — é o mesmo defeito que já apareceu no lado do dpkg.
	procurados := map[string][]string{}
	for p := range cand {
		for _, v := range formasResolvidas(e, p, cacheDir) {
			procurados[v] = append(procurados[v], p)
		}
	}

	b, err := e.ReadFile("/lib/apk/db/installed")
	if err != nil {
		return
	}
	dir, pacote := "", ""
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	sc.Buffer(make([]byte, 0, 4096), 256*1024)
	for sc.Scan() {
		ln := sc.Text()
		if len(ln) < 2 || ln[1] != ':' {
			continue
		}
		switch ln[0] {
		case 'F':
			dir = "/" + ln[2:]
		case 'P':
			pacote = ln[2:]
		case 'R':
			cheio := dir + "/" + ln[2:]
			reivindicacaoEstranha(cheio, "/lib/apk/db/installed", f)
			for _, alvo := range procurados[cheio] {
				donos[alvo] = pacote
			}
		}
	}
}

// formasUsrMerge devolve as grafias equivalentes de um caminho sob usrmerge.
// /usr/bin/cat e /bin/cat são o MESMO arquivo em distribuição moderna, e as
// bases de pacote não concordam sobre qual escrever.
func formasUsrMerge(p string) []string {
	out := []string{p}
	for _, d := range []string{"/bin/", "/sbin/", "/lib/", "/lib64/"} {
		if strings.HasPrefix(p, d) {
			out = append(out, "/usr"+p)
			return out
		}
		if strings.HasPrefix(p, "/usr"+d) {
			out = append(out, strings.TrimPrefix(p, "/usr"))
			return out
		}
	}
	return out
}

// formasResolvidas acrescenta a forma com o DIRETÓRIO resolvido pelos symlinks
// reais do host.
//
// A normalização de usrmerge acima é uma tabela, e tabela erra: o Arch funde
// /sbin em /usr/bin, coisa que nenhuma regra escrita para Debian prevê. Com ela
// sozinha, vinte e dois binários de sistema do host apareceram como "nenhum
// pacote reivindica" — a ferramenta acusando a própria distribuição.
//
// Resolver o diretório é exato em vez de adivinhado, e funciona em qualquer
// esquema de fusão presente ou futuro. O custo é um readlink por diretório
// distinto, com cache.
func formasResolvidas(e *env.Env, p string, cache map[string]string) []string {
	out := formasUsrMerge(p)
	i := strings.LastIndex(p, "/")
	if i <= 0 {
		return out
	}
	dir, base := p[:i], p[i+1:]
	real, visto := cache[dir]
	if !visto {
		real = dir
		// Um nível basta: os esquemas de fusão apontam diretório para
		// diretório, sem cadeia.
		if alvo, err := e.Readlink(dir); err == nil && alvo != "" {
			if strings.HasPrefix(alvo, "/") {
				real = alvo
			} else {
				// Link RELATIVO resolve contra o diretório PAI, não contra a
				// raiz. `/usr/sbin -> bin` significa /usr/bin, e resolver como
				// /bin fazia dezessete binários de sistema virarem achado.
				pai := "/"
				if i := strings.LastIndex(dir, "/"); i > 0 {
					pai = dir[:i] + "/"
				}
				real = pai + strings.TrimPrefix(alvo, "./")
			}
		}
		cache[dir] = real
	}
	if real != dir {
		out = append(out, real+"/"+base)
	}
	return out
}

func primeiroToken(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, " \t"); i > 0 {
		s = s[:i]
	}
	return strings.TrimLeft(s, "-@+!:")
}

func baseNome(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

// PrimeiroCaminhoAbsoluto extrai o programa que a linha executa: o primeiro
// token absoluto, ignorando o que o shell põe na frente.
//
// Devolve vazio diante de metacaractere no token, que é o sinal de que aquilo
// não é um caminho — é `case` pattern, redirecionamento ou expansão.
func PrimeiroCaminhoAbsoluto(linha string) string {
	for _, tok := range strings.Fields(linha) {
		switch tok {
		case "exec", "nohup", "sudo", "setsid", "eval", "source", ".":
			continue // prefixo do shell: o programa vem depois
		}
		// SÓ o primeiro token que não é prefixo.
		//
		// Varrer a linha inteira atrás de qualquer caminho absoluto pega o
		// argumento em vez do programa: `[ -f /etc/default/foo ] && ...`
		// devolveria /etc/default/foo, que não executa nada. No Ubuntu 14.04
		// isso rendeu dez acusações contra arquivos de configuração.
		if !strings.HasPrefix(tok, "/") {
			return ""
		}
		if strings.ContainsAny(tok, "*?[]()|;&$\"'`<>") {
			return ""
		}
		return tok
	}
	return ""
}

// donosPacman percorre a base do pacman, que é texto puro: um diretório por
// pacote, e dentro dele um arquivo `files` com a seção %FILES%.
//
// Os caminhos vêm SEM a barra inicial ("usr/bin/su"), e diretórios aparecem com
// barra no fim. Sem suporte a pacman a pergunta de propriedade ficava muda em
// todo host Arch — e ficar mudo enfraquece meia dúzia de checks em silêncio,
// que é a coisa que esta ferramenta existe para não fazer.
func donosPacman(f *Facts, e *env.Env, cand map[string][]string, donos map[string]string) {
	cacheDir := map[string]string{}
	procurados := map[string][]string{}
	for p := range cand {
		for _, v := range formasResolvidas(e, p, cacheDir) {
			procurados[strings.TrimPrefix(v, "/")] = append(
				procurados[strings.TrimPrefix(v, "/")], p)
		}
	}

	for _, dir := range e.ReadDirNames("/var/lib/pacman/local") {
		b, err := e.ReadFile("/var/lib/pacman/local/" + dir + "/files")
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(strings.NewReader(string(b)))
		sc.Buffer(make([]byte, 0, 4096), 64*1024)
		dentro := false
		for sc.Scan() {
			ln := sc.Text()
			if strings.HasPrefix(ln, "%") {
				dentro = ln == "%FILES%"
				continue
			}
			if !dentro || ln == "" {
				continue
			}
			reivindicacaoEstranha("/"+ln, "/var/lib/pacman/local/"+dir+"/files", f)
			for _, alvo := range procurados[ln] {
				donos[alvo] = dir
			}
		}
	}
}
