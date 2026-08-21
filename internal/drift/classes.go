package drift

import (
	"sort"
	"strconv"
	"strings"

	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
	"github.com/lex0c/aletheia/internal/redact"
)

// A REDAÇÃO ENTRA AQUI, NOS DOIS LADOS, SEMPRE — e não porque um dos lados
// possa vir de dump.
//
// O dump é redigido ao ser escrito (dump.go: redact.Linha no Exec das units e
// no comando do cron). O host vivo não é. Comparar um contra o outro sem
// normalizar inventa drift, e o primeiro teste contra este host provou isso em
// nove units de uma vez:
//
//	antes (dump)  ExecStartPre=-p<redacted> --wait quit
//	depois (vivo) ExecStartPre=-plymouth --wait quit
//
// O `-p` de `-plymouth` casa a forma de uma flag de senha, e o redator — que
// está certo em ser paranoico — comeu o resto da palavra. Nenhum ExecStartPre
// mudou; o que mudou foi quem estava olhando.
//
// A redação é uma projeção que PERDE informação, então a única representação
// estável dos dois lados é a projetada. Aplicá-la aqui torna as três
// comparações possíveis — dump×dump, vivo×vivo e vivo×dump — idênticas entre
// si. O preço, que já estava dito no topo do pacote, é que drift em campo
// redigido é invisível: se o segredo mudar, ninguém vê.

// classes é o registro. Cada entrada é uma decisão sobre TRÊS coisas, e as três
// custam a mesma atenção:
//
//	o que identifica esta entidade entre execuções
//	o que nela é ESTADO (o resto não é extraído, e por isso não vira ruído)
//	de que capacidade a enumeração dela depende
//
// A primeira leva das quatro é deliberada: são as superfícies onde o retorno
// ao host é escrito, e onde a mudança de UM campo já é a história inteira.
// Processos, pacotes e árvore de arquivos ficam para depois — são as três de
// maior ruído medido, e cada uma exige a própria normalização.
var classes = []Classe{
	unidadeSystemd,
	agendamento,
	regraDeSudo,
	chaveAutorizada,
	conta,
	grupo,
	precarga,
	hookDeInterpretador,
	bitSuid,
	portaEmEscuta,
	moduloCarregado,
	interpretadorDoKernel,
	linhaDeBoot,
	confiancaDeCertificado,
	moduloNSS,
	servicoNSS,
	programaEmExecucao,
}

// # systemd.unit
//
// A unit é o exemplo canônico do que só o drift alcança. Um `ExecStart` que
// deixa de apontar para `/usr/sbin/sshd` e passa a apontar para `/tmp/.sshd`
// dispara check hoje — o alvo é suspeito por forma. Mas um `ExecStart` que
// passa a apontar para OUTRO binário de sistema, ou um `User=` que deixa de ser
// uma conta de serviço e vira root, ou um drop-in novo que ninguém pediu: isso
// é legítimo em forma e não tem check possível. O que denuncia é a transição.
var unidadeSystemd = Classe{
	Tipo:     "systemd.unit",
	Titulo:   "unit do systemd",
	Requires: env.CapFilesystem,
	// Duas chaves porque o coletor de unit usa as duas: `unit` para o
	// diretório que não pôde ser listado, `persist` para o arquivo ilegível.
	Lacunas: []string{"unit", "persist"},
	// A varredura das árvores de unit é exaustiva quando o filesystem está
	// legível: as raízes são fixas e conhecidas. Por isso "sumiu" vale aqui —
	// e unit que some é tão interessante quanto unit que nasce (é como se
	// desliga um agente de segurança).
	Exaustiva: true,
	Decide: map[string]bool{
		"exec": true, "user": true, "enabled_by": true, "dropin_for": true,
		"root_directory": true, "root_image": true,
		"binds": true, "bind_reset": true,
		"listen": true, "watch_paths": true, "on_calendar": true,
		"masked": true, "environment": true,
	},
	Extrair: func(f *facts.Facts) []Entidade {
		out := make([]Entidade, 0, len(f.Units))
		for i := range f.Units {
			u := &f.Units[i]
			// A identidade inclui o CAMINHO, e não só o nome: duas units de
			// mesmo nome em árvores diferentes (a de /etc sombreando a de
			// /usr/lib) são arquivos diferentes, e tratá-las como a mesma
			// esconderia justamente a que foi acrescentada para sombrear.
			id := u.Name + "@" + u.Path
			if u.Manager != "" {
				id = u.Manager + "/" + id
			}
			var execs []string
			for _, ex := range u.Exec {
				execs = append(execs, ex.Key+"="+redact.Linha(ex.Cmd))
			}
			var envs []string
			for _, ev := range u.Environment {
				envs = append(envs, ev.Key+"="+redact.Valor(ev.Key, ev.Value))
			}
			// BIND MONTA CAMINHO DO HOST DENTRO DO NAMESPACE DA UNIT, e por
			// isso decide. Ele estava declarado em Decide e NÃO era extraído: a
			// mudança não produzia drift nem lacuna — silêncio limpo, que é o
			// pior modo de falha desta base. Foi achado conferindo Decide
			// contra o que o extrator emite, e o teste dessa conferência agora
			// roda na suíte.
			var binds []string
			for _, b := range u.Binds {
				modo := "rw"
				if b.SomenteL {
					modo = "ro"
				}
				binds = append(binds, b.Origem+":"+b.Destino+":"+modo)
			}
			out = append(out, Entidade{ID: id, Alvos: []string{u.Name, u.Path}, Campos: map[string]string{
				"exec":           juntarSequencia(execs),
				"user":           u.User,
				"enabled_by":     juntarConjunto(u.EnabledBy),
				"dropin_for":     u.DropInFor,
				"root_directory": u.RootDirectory,
				"root_image":     u.RootImage,
				"listen":         juntarConjunto(u.Listen),
				"watch_paths":    juntarConjunto(u.WatchPaths),
				"on_calendar":    juntarConjunto(u.OnCalendar),
				"environment":    juntarSequencia(envs),
				"binds":          juntarSequencia(binds),
				// BindReset (`BindPaths=` vazio) APAGA os binds herdados, e
				// some da lista acima sem deixar rastro: sem este campo, zerar
				// a lista e não ter lista nenhuma são o mesmo valor.
				"bind_reset": boolTxt(u.BindReset),
				"masked":     boolTxt(u.Masked),
				// CORROBORA, não decide: mtime muda em toda atualização de
				// pacote. Entra para a contagem e para a evidência de quem já
				// tem outro motivo para olhar.
				"mod_utc": u.ModUTC,
			}})
		}
		return out
	},
}

// # cron
//
// Mesma lógica da unit, e a identidade é mais delicada: o número da linha anda
// quando alguém edita o arquivo acima, então ele NÃO entra. O que identifica um
// agendamento é onde ele mora, para quem, e o gatilho — o comando é o estado.
var agendamento = Classe{
	Tipo:      "cron",
	Titulo:    "agendamento",
	Requires:  env.CapFilesystem,
	Lacunas:   []string{"cron"},
	Exaustiva: true,
	// DUAS LINHAS IDÊNTICAS NÃO SÃO A MESMA LINHA: o cron executa o job duas
	// vezes. O índice colapsa por ID e o valor fundido é igual ao original, então
	// passar de uma para duas era invisível — ver Classe.Multiplicidade.
	Multiplicidade: true,
	Decide: map[string]bool{
		"cmd": true, "user": true, "schedule": true, "_repeticoes": true,
	},
	Extrair: func(f *facts.Facts) []Entidade {
		out := make([]Entidade, 0, len(f.Cron))
		for i := range f.Cron {
			c := &f.Cron[i]
			id := c.File + "|" + c.Kind + "|" + c.User + "|" + c.Schedule
			out = append(out, Entidade{ID: id, Alvos: alvosDoCron(c), Campos: map[string]string{
				"cmd":      redact.Linha(c.Cmd),
				"user":     c.User,
				"schedule": c.Schedule,
				"mod_utc":  c.ModUTC,
			}})
		}
		return out
	},
}

// # sudoers
//
// Aqui a identidade É o texto da regra, e o campo de estado é a presença dela.
// A razão está no check.Finding.Chave, que aprendeu isto na marra: o número da
// linha anda, o texto não. Uma regra reescrita aparece como uma que sumiu mais
// uma que surgiu — e é assim que se lê mesmo, porque "a regra do deploy mudou"
// e "acrescentaram uma regra" são a mesma pergunta para quem investiga.
var regraDeSudo = Classe{
	Tipo:   "sudoers",
	Titulo: "regra de sudo",
	// SÓ CapFilesystem, e o resto é a lacuna MEDIDA.
	//
	// A versão anterior pedia CapRoot também, como procuração para "o sudoers é
	// 0440 e sem root não se lê". A procuração erra em modo imagem: sob
	// `--root`, os arquivos são legíveis sem ser root, e exigir a capacidade
	// suprimia as duas direções — que é o único sinal que esta família tem, já
	// que o estado dela é só "presente". Drift de sudoers ficava morto em modo
	// imagem, para sempre, sem nada dito.
	//
	// A lacuna `users` mede a coisa certa: o coletor declara "/etc/sudoers
	// ilegível" quando de fato não conseguiu ler. Onde a procuração e o fato
	// discordam, vence o fato.
	Requires:  env.CapFilesystem,
	Lacunas:   []string{"users"},
	Exaustiva: true,
	// SEM campo que decide, e de propósito: aqui a identidade É o texto da
	// regra, então não existe campo que possa mudar sem virar outra entidade.
	// O sinal desta família é a PRESENÇA, e ela é reportada por surgiu/sumiu —
	// que não passam pelo Decide. Um campo constante ("presente": "sim") só
	// existiria para satisfazer catraca, e catraca satisfeita com campo falso
	// não é catraca.
	Extrair: func(f *facts.Facts) []Entidade {
		out := make([]Entidade, 0, len(f.Sudoers))
		for i := range f.Sudoers {
			s := &f.Sudoers[i]
			out = append(out, Entidade{
				ID: s.File + "|" + strings.Join(strings.Fields(s.Text), " "),
				// O ALVO da regra é o sujeito do priv.sudo_nopasswd: é assim que
				// "esta regra é nova" encontra "esta regra concede root".
				Alvos:  []string{s.File, primeiroCampoDaLinha(s.Text)},
				Campos: map[string]string{},
			})
		}
		return out
	},
}

// # authorized_keys
//
// A chave é identificada pelo FINGERPRINT, e não pelo comentário nem pela
// posição: o comentário é texto livre que o dono edita, a posição anda a cada
// chave inserida acima. E o campo que decide é o `options` — é ali que moram o
// `command=`, o `restrict` e o `from=`, e tirá-los de uma chave existente é uma
// escalada silenciosa que não muda mais nada no arquivo.
var chaveAutorizada = Classe{
	Tipo:      "ssh.authorized_key",
	Titulo:    "chave autorizada de SSH",
	Requires:  env.CapFilesystem,
	Lacunas:   []string{"ssh"},
	Exaustiva: true,
	Decide:    map[string]bool{"options": true, "type": true},
	Extrair: func(f *facts.Facts) []Entidade {
		out := make([]Entidade, 0, len(f.SSHKeys))
		for i := range f.SSHKeys {
			k := &f.SSHKeys[i]
			// O fingerprint é a identidade certa: ele não muda quando alguém
			// edita o comentário nem quando uma chave é inserida acima.
			//
			// Sem ele — chave malformada, blob que não decodifica — a saída NÃO
			// é pular: pular esconderia justamente a linha estranha. Cai-se para
			// tipo+comentário, que é frágil mas continua estável sob inserção. A
			// posição é que não serve: com ela, uma chave nova no topo faria
			// todas as de baixo "mudarem".
			id := k.User + "@" + k.File + "|" + k.Fingerprint
			if k.Fingerprint == "" {
				id = k.User + "@" + k.File + "|sem-fingerprint|" + k.Type + "|" + k.Comment
			}
			out = append(out, Entidade{ID: id, Alvos: []string{k.User, k.File}, Campos: map[string]string{
				"options": k.Options,
				"type":    k.Type,
				"comment": k.Comment,
				"mod_utc": k.ModUTC,
			}})
		}
		return out
	},
}

// DUAS primitivas, porque "canonicalizar" não pode significar automaticamente
// "destruir ordem".
//
// Havia só a de conjunto, com esta justificativa: "a ordem da coleta já é
// determinística, mas depender disso faria uma mudança de ordem interna virar
// drift". A frase confunde ORDEM DA COLETA — artefato de como se varre um
// diretório — com ORDEM DO ARQUIVO, que é semântica. Para o `Exec` de uma unit
// a ordem no fato É a do arquivo, e ordenar apagava isto:
//
//	antes            depois
//	ExecStartPre=/usr/bin/a    ExecStartPre=/usr/bin/b
//	ExecStartPre=/usr/bin/b    ExecStartPre=/usr/bin/a
//
// A unit passa a executar outra coisa primeiro, e o drift não via nada. O mesmo
// vale para as libs de /etc/ld.so.preload, onde a ordem decide interposição de
// símbolo, e para Environment, onde a última atribuição vence.
func juntarConjunto(v []string) string {
	if len(v) == 0 {
		return ""
	}
	c := append([]string(nil), v...)
	sort.Strings(c)
	return strings.Join(c, "\x1f")
}

// juntarSequencia PRESERVA a ordem: use onde a posição tem significado.
func juntarSequencia(v []string) string {
	if len(v) == 0 {
		return ""
	}
	return strings.Join(v, "\x1f")
}

func boolTxt(b bool) string { return strconv.FormatBool(b) }

// Tipos devolve os tipos registrados, para o catálogo e para os testes.
func Tipos() []string {
	out := make([]string, 0, len(classes))
	for _, c := range classes {
		out = append(out, c.Tipo)
	}
	return out
}

// # contas e grupos
//
// A superfície mais antiga que existe, e a que menos muda num servidor: uma
// conta que nasce, um shell que deixa de ser `nologin`, um uid que vira 0, uma
// senha que fica vazia. Cada uma dessas transições é o passo final de uma
// escalada, e nenhuma delas tem forma suspeita quando olhada parada — `deploy`
// com shell `/bin/bash` é normal em metade dos hosts do mundo.
var conta = Classe{
	Tipo:      "conta",
	Titulo:    "conta local",
	Requires:  env.CapFilesystem,
	Lacunas:   []string{"users"},
	Exaustiva: true,
	Decide: map[string]bool{
		"uid": true, "gid": true, "shell": true, "home": true,
		"sem_senha": true, "bloqueada": true,
	},
	// OS CAMPOS DO SHADOW SÃO OBSERVACIONAIS, e a família mistura duas fontes
	// com privilégio diferente: `uid`, `gid`, `shell` e `home` saem do
	// /etc/passwd, que qualquer um lê; `sem_senha` e `bloqueada` saem do
	// /etc/shadow, que precisa de root.
	//
	// Sem isso, `false` significava as duas coisas ao mesmo tempo — "tem senha"
	// e "não consegui olhar" —, e dois retratos sem root comparavam
	// "não sei" com "não sei" concluindo "não mudou". O extrator agora emite
	// VAZIO quando o shadow não foi lido, que é o valor que esta comparação
	// entende como "não observado".
	Observacional: map[string]bool{"sem_senha": true, "bloqueada": true},
	Extrair: func(f *facts.Facts) []Entidade {
		out := make([]Entidade, 0, len(f.Accounts))
		for i := range f.Accounts {
			a := &f.Accounts[i]
			out = append(out, Entidade{
				ID: a.Name, Alvos: []string{a.Name},
				Campos: map[string]string{
					"uid":       strconv.Itoa(a.UID),
					"gid":       strconv.Itoa(a.GID),
					"shell":     a.Shell,
					"home":      a.Home,
					"sem_senha": seLido(f.ShadowLido, boolTxt(a.SemSenha)),
					"bloqueada": seLido(f.ShadowLido, boolTxt(a.Bloqueada)),
				},
			})
		}
		return out
	},
}

// O grupo importa pelos MEMBROS: entrar em `docker`, `sudo` ou `wheel` é
// escalada que não muda nada no /etc/passwd e não cria processo nenhum.
var grupo = Classe{
	Tipo:      "grupo",
	Titulo:    "grupo local",
	Requires:  env.CapFilesystem,
	Lacunas:   []string{"users"},
	Exaustiva: true,
	Decide:    map[string]bool{"membros": true, "gid": true},
	Extrair: func(f *facts.Facts) []Entidade {
		out := make([]Entidade, 0, len(f.Grupos))
		for i := range f.Grupos {
			g := &f.Grupos[i]
			out = append(out, Entidade{
				ID: g.Name, Alvos: []string{g.Name},
				Campos: map[string]string{
					"gid":     strconv.Itoa(g.GID),
					"membros": juntarConjunto(g.Members),
				},
			})
		}
		return out
	},
}

// # ld.so.preload e os hooks de interpretador
//
// Uma linha em /etc/ld.so.preload injeta código em TODO processo dinâmico do
// host, inclusive nos que a resposta a incidente vai rodar. É a superfície de
// maior alcance por byte escrito que existe em Linux, e a lista dela é curta —
// o que faz dela a classe de melhor razão valor/ruído do registro inteiro.
var precarga = Classe{
	Tipo:      "precarga",
	Titulo:    "pré-carga de código",
	Requires:  env.CapFilesystem,
	Lacunas:   []string{"loader"},
	Exaustiva: true,
	Decide:    map[string]bool{"libs": true, "existe": true},
	Extrair: func(f *facts.Facts) []Entidade {
		// As LIBS entram como alvo junto do arquivo: o achado que acusa a
		// pré-carga tem o caminho da lib como sujeito, e sem ele a mudança e o
		// achado ficariam em dois relatórios paralelos sobre a mesma linha.
		return []Entidade{{
			ID:    "/etc/ld.so.preload",
			Alvos: append([]string{"/etc/ld.so.preload"}, f.Loader.PreloadLibs...),
			Campos: map[string]string{
				"existe": boolTxt(f.Loader.PreloadExists),
				"libs":   juntarSequencia(f.Loader.PreloadLibs),
			},
		}}
	},
}

// O hook de interpretador é a mesma ideia num nível acima: `PERL5OPT`,
// `PYTHONSTARTUP` e parentes fazem o interpretador carregar código antes do
// script. Classe SEPARADA da pré-carga porque depende de OUTRO coletor — juntá-las
// faria uma lacuna em `interpretador` suprimir a direção do ld.so.preload, que
// não tem nada a ver.
var hookDeInterpretador = Classe{
	Tipo:      "hook_interp",
	Titulo:    "hook de interpretador",
	Requires:  env.CapFilesystem,
	Lacunas:   []string{"interpretador"},
	Exaustiva: true,
	Decide:    map[string]bool{"valor": true},
	Extrair: func(f *facts.Facts) []Entidade {
		out := make([]Entidade, 0, len(f.HooksInterp))
		for i := range f.HooksInterp {
			h := &f.HooksInterp[i]
			out = append(out, Entidade{
				ID: h.Fonte + "|" + h.Key, Alvos: []string{h.Fonte},
				Campos: map[string]string{"valor": redact.Valor(h.Key, h.Value)},
			})
		}
		return out
	},
}

// # o bit setuid
//
// `chmod u+s /usr/bin/find` não altera conteúdo, não altera dono e não aparece
// em verificação de hash nenhuma. É a porta que a varredura de integridade não
// vê, e a mudança do MODO é a única coisa que a denuncia.
var bitSuid = Classe{
	Tipo:      "suid",
	Titulo:    "arquivo com bit de privilégio",
	Requires:  env.CapFilesystem,
	Lacunas:   []string{"suid"},
	Exaustiva: true,
	Decide: map[string]bool{
		"setuid": true, "setgid": true, "uid": true, "gid": true, "caps": true,
	},
	Extrair: func(f *facts.Facts) []Entidade {
		out := make([]Entidade, 0, len(f.Suid))
		for i := range f.Suid {
			s := &f.Suid[i]
			out = append(out, Entidade{
				ID: s.Path, Alvos: []string{s.Path},
				Campos: map[string]string{
					"setuid": boolTxt(s.Setuid),
					"setgid": boolTxt(s.Setgid),
					"uid":    strconv.Itoa(s.UID),
					"gid":    strconv.Itoa(s.GID),
					"caps":   strconv.FormatUint(s.CapPerm, 16),
					// CORROBORA: tamanho e mtime mudam em toda atualização de
					// pacote, e é justamente por mudarem juntos que eles
					// separam "o pacote foi atualizado" de "alguém mexeu no
					// modo e em mais nada".
					"size":    strconv.FormatInt(s.Size, 10),
					"mod_utc": s.ModUTC,
				},
			})
		}
		return out
	},
}

// # o que este host EXPÕE
//
// Medido: entre duas coletas com segundos de intervalo, o conjunto de sockets
// mudava — e zerou depois de filtrar para LISTEN. Conexão efêmera é tráfego,
// não estado; o que ESCUTA é estado, e uma porta nova é a diferença entre um
// host que fala e um host que atende.
var portaEmEscuta = Classe{
	Tipo:     "porta",
	Titulo:   "porta em escuta",
	Requires: env.CapProcfs,
	// NÃO É a lacuna `net`, e não é a ausência dela — é a completude ESPECÍFICA
	// da tabela que esta família compara.
	//
	// A chave `net` é larga demais: carrega desde "o módulo de diagnóstico de
	// UDP não está carregado" até "o dono do socket não pôde ser lido", e
	// nenhuma das duas diz nada sobre o conjunto de quem escuta. Usá-la
	// suprimia a direção `surgiu` em praticamente todo host.
	//
	// Só que tirá-la e ficar com `Exaustiva: true` foi TROCAR UMA REGRA
	// GROSSEIRA E SEGURA POR UMA PRECISA E ERRADA. O comentário anterior
	// afirmava que "/proc/net/tcp{,6} é exaustivo sem root" — e é exatamente
	// esse arquivo que o coletor declara ilegível ou CORTADO no teto de linhas
	// (net.go). Com a tabela truncada, uma porta que continua lá saía como
	// REMOVIDA: "não vi" virando "não existe", que é a equivalência que esta
	// ferramenta existe para recusar.
	//
	// O que faltava era o coletor dizer especificamente O QUE não leu — ver
	// facts.SocketsIncompletos.
	Exaustiva: true,
	Incompleta: func(f *facts.Facts) string {
		var tcp []string
		for _, p := range f.SocketsIncompletos {
			if strings.HasPrefix(p, "tcp") {
				tcp = append(tcp, p)
			}
		}
		if len(tcp) == 0 {
			return ""
		}
		return "a tabela de " + strings.Join(tcp, " e ") + " não foi lida inteira " +
			"(ilegível ou cortada no teto de linhas): o conjunto de quem escuta " +
			"NÃO é exaustivo deste lado"
	},
	Decide:        map[string]bool{"comm": true, "uid": true},
	Observacional: map[string]bool{"comm": true, "uid": true},
	Extrair: func(f *facts.Facts) []Entidade {
		var out []Entidade
		for i := range f.Sockets {
			s := &f.Sockets[i]
			if s.State != "LISTEN" {
				continue
			}
			id := s.Proto + "/" + s.LocalIP + ":" + strconv.Itoa(s.LocalPort)
			out = append(out, Entidade{
				ID: id, Alvos: []string{id, s.Comm},
				Campos: map[string]string{
					// O DONO importa — a mesma porta atendida por outro programa é
					// outra coisa inteiramente —, mas ele é OBSERVACIONAL: sem root
					// sai vazio, e vazio ali não quer dizer que ninguém atende.
					"comm": s.Comm,
					"uid":  strconv.Itoa(s.UID),
				},
			})
		}
		return out
	},
}

// # o que o kernel tem dentro dele
//
// Módulo carregado é a única classe cujo estado não mora em arquivo nenhum: ele
// vem do kernel falando de si. Um módulo novo entre dois retratos é a coisa
// mais próxima de um rootkit que uma comparação de estado alcança.
var moduloCarregado = Classe{
	Tipo:      "modulo",
	Titulo:    "módulo carregado no kernel",
	Requires:  env.CapProcfs,
	Lacunas:   []string{"modulo"},
	Exaustiva: true,
	Decide:    map[string]bool{"arquivo": true, "taint": true},
	Extrair: func(f *facts.Facts) []Entidade {
		out := make([]Entidade, 0, len(f.Carregados))
		for i := range f.Carregados {
			m := &f.Carregados[i]
			out = append(out, Entidade{
				ID: m.Nome, Alvos: []string{m.Nome, m.Arquivo},
				Campos: map[string]string{
					"arquivo": m.Arquivo,
					"taint":   m.Letras,
					// Refs e tamanho mudam com o uso, não com a identidade.
					"refs": strconv.Itoa(m.Refs),
				},
			})
		}
		return out
	},
}

// binfmt_misc registra um INTERPRETADOR que o kernel chama por conta própria ao
// executar um arquivo com certa magia. Um registro novo faz o kernel executar
// um binário do atacante sem que nada no userland mude.
var interpretadorDoKernel = Classe{
	Tipo:      "binfmt",
	Titulo:    "interpretador registrado no kernel",
	Requires:  env.CapProcfs,
	Lacunas:   []string{"binfmt"},
	Exaustiva: true,
	Decide:    map[string]bool{"interpretador": true, "magia": true, "extensao": true},
	Extrair: func(f *facts.Facts) []Entidade {
		out := make([]Entidade, 0, len(f.Binfmt))
		for i := range f.Binfmt {
			b := &f.Binfmt[i]
			out = append(out, Entidade{
				ID: b.Nome, Alvos: []string{b.Nome, b.Interpreter},
				Campos: map[string]string{
					"interpretador": b.Interpreter,
					"magia":         b.Magic,
					"extensao":      b.Extensao,
				},
			})
		}
		return out
	},
}

// A LINHA DE COMANDO DO KERNEL responde à mesma pergunta que o binfmt — o que o
// kernel foi mandado ser —, e mesmo assim é classe própria: ela vem de outro
// coletor, e `init=`, `apparmor=0` e `module.sig_enforce=0` desligam defesa
// ANTES de o userland existir.
var linhaDeBoot = Classe{
	Tipo:      "boot",
	Titulo:    "linha de comando do kernel",
	Requires:  env.CapFilesystem,
	Lacunas:   []string{"boot"},
	Exaustiva: true,
	Decide:    map[string]bool{"valor": true},
	Extrair: func(f *facts.Facts) []Entidade {
		out := make([]Entidade, 0, len(f.Boot))
		for i := range f.Boot {
			b := &f.Boot[i]
			out = append(out, Entidade{
				ID: b.Fonte, Alvos: []string{b.Fonte},
				Campos: map[string]string{"valor": b.Valor},
			})
		}
		return out
	},
}

// # em quem este host confia
//
// Uma CA acrescentada ao armazém do sistema faz o host aceitar certificado
// forjado para qualquer nome: é interceptação de TLS que não deixa rastro no
// tráfego. E um módulo NSS novo entra no caminho de toda resolução de nome e de
// usuário do sistema.
var confiancaDeCertificado = Classe{
	Tipo:      "ca",
	Titulo:    "âncora de confiança de TLS",
	Requires:  env.CapFilesystem,
	Lacunas:   []string{"trust"},
	Exaustiva: true,
	// O QUE DECIDE É A CHAVE, e não o nome.
	//
	// A versão anterior identificava a entidade por `Subject@File` e decidia por
	// `emissor`/`auto_assinado` — todos campos de TEXTO que quem emite o
	// certificado escolhe. Substituir o arquivo por outro self-signed com o
	// mesmo `CN=Company Root CA` e chave diferente troca a autoridade INTEIRA do
	// host, e não mexia em nada que a comparação olhasse.
	//
	//	spki         DECIDE: é a chave. Não muda numa renovação, então mudar
	//	             significa que a autoridade é outra.
	//	fingerprint  CORROBORA: muda na renovação, que é rotina.
	Decide: map[string]bool{"spki": true, "emissor": true, "auto_assinado": true},
	// Dump gravado antes destes campos existirem não os traz. Vazio aqui é
	// "não observado" e não "sem chave" — embora o SchemaVersion já recuse
	// aquele dump, a declaração é o que torna a leitura verdadeira.
	Observacional: map[string]bool{"spki": true, "fingerprint": true},
	Extrair: func(f *facts.Facts) []Entidade {
		out := make([]Entidade, 0, len(f.CACerts))
		for i := range f.CACerts {
			c := &f.CACerts[i]
			out = append(out, Entidade{
				// O ARQUIVO é a identidade: é ele que o host carrega e é ele que
				// o atacante substitui. Com o Subject no ID, a troca aparecia
				// como uma âncora que sumiu mais outra que surgiu quando o DN
				// mudava — e como NADA quando ele não mudava, que é o caso que
				// interessa.
				ID: c.File, Alvos: []string{c.File},
				Campos: map[string]string{
					"spki":          c.SPKI,
					"fingerprint":   c.Fingerprint,
					"titular":       c.Subject,
					"emissor":       c.Issuer,
					"auto_assinado": boolTxt(c.AutoAssinado),
					"nao_depois":    c.NotAfter,
				},
			})
		}
		return out
	},
}

// # o módulo NSS: o inventário de quem PODE ser carregado
var moduloNSS = Classe{
	Tipo:      "nss",
	Titulo:    "módulo de resolução (NSS)",
	Requires:  env.CapFilesystem,
	Lacunas:   []string{"nss"},
	Exaustiva: true,
	Decide:    map[string]bool{"libs": true, "servicos": true},
	Extrair: func(f *facts.Facts) []Entidade {
		out := make([]Entidade, 0, len(f.NSSModules))
		for i := range f.NSSModules {
			n := &f.NSSModules[i]
			out = append(out, Entidade{
				ID: n.Fonte, Alvos: []string{n.Fonte},
				Campos: map[string]string{
					"libs": juntarConjunto(n.Paths),
					// EM QUAIS DATABASES esta fonte manda. Estava nos fatos e era
					// descartado: uma fonte já existente passando a atender
					// TAMBÉM o `shadow` não mudava lib nenhuma, e a comparação
					// não via nada — enquanto o host passava a perguntar a ela
					// quem tem qual senha.
					"servicos": juntarConjunto(n.Servicos),
				},
			})
		}
		return out
	},
}

// # a configuração EFETIVA do nsswitch, que é ORDEM
//
// A primeira fonte que responde encerra a consulta, então a ordem é a
// autoridade. E ela não sobrevive ao inventário por fonte:
//
//	passwd: files sss     →     passwd: sss files
//
// As mesmas fontes, as mesmas bibliotecas, e quem decide quem é usuário deste
// host trocado de lado. Nenhuma família anterior via isso, e é exatamente a
// transição legítima-em-forma que o drift existe para pegar.
var servicoNSS = Classe{
	Tipo:      "nss_servico",
	Titulo:    "cadeia de resolução (nsswitch)",
	Requires:  env.CapFilesystem,
	Lacunas:   []string{"nss"},
	Exaustiva: true,
	Decide:    map[string]bool{"cadeia": true},
	Extrair: func(f *facts.Facts) []Entidade {
		out := make([]Entidade, 0, len(f.NSSServicos))
		for i := range f.NSSServicos {
			sv := &f.NSSServicos[i]
			out = append(out, Entidade{
				ID: sv.Nome, Alvos: []string{sv.Nome},
				// SEQUÊNCIA, e é o ponto inteiro da família.
				Campos: map[string]string{"cadeia": juntarSequencia(sv.Cadeia)},
			})
		}
		return out
	},
}

// # o que está rodando
//
// A classe de MAIOR RUÍDO medido, e por isso a de identidade mais cuidadosa.
//
//	o PID não é identidade      muda a cada execução, e 160 de 315 processos
//	                            deste desktop diferiam entre duas coletas
//	o kthread não é identidade   `kworker/0:3-events` codifica o índice do pool
//	                            no NOME: 24 apareciam e 24 sumiam sem nada ter
//	                            acontecido. Ficam de fora por não terem exe —
//	                            eles não moram em disco, e é honesto dizer isso
//
// O que sobra é o EXECUTÁVEL, e o que se pergunta dele é sob que identidade ele
// roda. `redis-server` que passa a rodar como root é a forma que a proposta
// original desta feature pedia, e ela só aparece se o uid for CAMPO e não parte
// da identidade — senão a mudança vira um par surgiu+sumiu que ninguém liga.
//
// A família é EFÊMERA: um programa que não estava rodando no segundo retrato não
// "sumiu" do host, e um que apareceu não nasceu ali — foi o relógio. Sem isso,
// todo servidor movimentado viraria uma lista de "surgiu" a cada comparação, e
// o único sinal de verdade se perderia no meio.
var programaEmExecucao = Classe{
	Tipo:     "programa",
	Titulo:   "programa em execução",
	Requires: env.CapProcfs,
	Lacunas:  []string{"proc"},
	// EFÊMERA nos dois sentidos: ver Classe.Efemera. O sinal desta família é o
	// mesmo executável passando a rodar sob outra identidade, e não a lista de
	// quem estava rodando na hora da coleta.
	Efemera: true,
	Decide:  map[string]bool{"uids": true},
	Extrair: func(f *facts.Facts) []Entidade {
		porExe := map[string]map[int]bool{}
		for i := range f.Processes {
			p := &f.Processes[i]
			if p.Exe == "" {
				continue
			}
			if porExe[p.Exe] == nil {
				porExe[p.Exe] = map[int]bool{}
			}
			porExe[p.Exe][p.UID] = true
		}
		out := make([]Entidade, 0, len(porExe))
		for exe, uids := range porExe {
			lista := make([]string, 0, len(uids))
			for u := range uids {
				lista = append(lista, strconv.Itoa(u))
			}
			out = append(out, Entidade{
				ID: exe, Alvos: []string{exe},
				Campos: map[string]string{"uids": juntarConjunto(lista)},
			})
		}
		return out
	},
}

// alvosDoCron liga o agendamento ao arquivo dele e ao binário que ele chama —
// que é o sujeito com que os outros checks falam do mesmo comando.
func alvosDoCron(c *facts.CronEntry) []string {
	alvos := []string{c.File}
	if campos := strings.Fields(c.Cmd); len(campos) > 0 {
		alvos = append(alvos, campos[0])
	}
	return alvos
}

// primeiroCampoDaLinha é o alvo de uma regra de sudoers: o usuário ou %grupo.
func primeiroCampoDaLinha(texto string) string {
	campos := strings.Fields(texto)
	if len(campos) == 0 {
		return ""
	}
	return campos[0]
}

// seLido devolve vazio quando a fonte do campo não foi lida. Vazio é o valor
// que a comparação entende como "não observado" — ver Classe.Observacional.
func seLido(lido bool, v string) string {
	if !lido {
		return ""
	}
	return v
}
