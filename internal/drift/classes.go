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
	servidorSSH,
	hookDeClienteSSH,
	regraDeDoas,
	controleMAC,
	controleAudit,
	protecaoDoKernel,
	nomeEmHosts,
	resolvedor,
	confiancaDeHost,
	gatilhoDeExecucao,
	configDeModulo,
	helperDoKernel,
	configDeBinfmt,
	caminhoDoLoader,
	ordemDoLoader,
	envDoLoader,
	envDeUnit,
	configWeb,
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
	// UMA chave, e ela é a estreita.
	//
	// A `persist` estava aqui com a justificativa de cobrir "arquivo de unit
	// ilegível e expansão de drop-in" — e a justificativa era falsa: o
	// `denyPersist` alimenta `persist` a partir de DEZENOVE categorias, então
	// um authorized_keys de outro usuário sem permissão bastava para tornar a
	// família assimétrica e suprimir um `ExecStart=/tmp/.agent`. Os três sites
	// que só escreviam `persist` no coletor de unit passaram a escrever `unit`
	// também; nada se perdeu, e a dependência ficou do tamanho da fonte.
	Lacunas:         []string{"unit"},
	LacunaConferida: "chave do coletor de unit e só dele: diretório não listado, arquivo de unit ilegível, teto de units e teto de expansão de drop-in",
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
			// UM EnvironmentFile= ILEGÍVEL cega o campo `environment` DESTA
			// unit, e só dele.
			//
			// O arquivo entra no ambiente efetivo do serviço, e o que ele
			// define não foi lido — então a lista abaixo não é o ambiente, é a
			// parte dele que estava visível. A cegueira é do campo: o
			// `ExecStart` da mesma unit foi lido do arquivo da unit e continua
			// comparável, e as outras units não têm nada com isso.
			var naoObs map[string]bool
			if len(u.EnvFilesIlegiveis) > 0 {
				naoObs = map[string]bool{"environment": true}
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
			out = append(out, Entidade{ID: id, Alvos: []string{u.Name, u.Path},
				NaoObservado: naoObs, Campos: map[string]string{
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
	Tipo:            "cron",
	Titulo:          "agendamento",
	Requires:        env.CapFilesystem,
	Lacunas:         []string{"cron"},
	LacunaConferida: "a chave é escrita só pelo coletor de cron, em todos os diretórios e arquivos que ele varre — a fonte é uma",
	Exaustiva:       true,
	// DUAS LINHAS IDÊNTICAS NÃO SÃO A MESMA LINHA: o cron executa o job duas
	// vezes. Só o COMANDO conta repetição — `user` e `schedule` fazem parte do
	// ID e são iguais por construção dentro dele, então multiplicá-los fabricava
	// "o usuário mudou de root para root, root". Ver Classe.Multiplicidade.
	Multiplicidade: map[string]bool{"cmd": true},
	// E pela mesma razão eles não DECIDEM: variar `user` ou `schedule` produz
	// outra entidade, não uma mudança desta. O que varia dentro de um ID é o
	// comando.
	Decide: map[string]bool{"cmd": true},
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
	Requires: env.CapFilesystem,
	// A árvore INTEIRA precisa ter sido lida: uma regra que não abriu faz o
	// conjunto deixar de ser exaustivo, e o sinal desta família é a presença.
	// Consumir a chave `users` misturava isso com o shadow ilegível.
	Incompleta: func(f *facts.Facts) string {
		if f.SudoersLido {
			return ""
		}
		return "a árvore de sudoers não foi lida inteira: o conjunto de regras NÃO " +
			"é exaustivo deste lado"
	},
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
	Tipo:     "ssh.authorized_key",
	Titulo:   "chave autorizada de SSH",
	Requires: env.CapFilesystem,
	// A chave `ssh` cobre TRÊS fontes com donos diferentes, e usá-la aqui fazia
	// um authorized_keys de outro usuário ilegível suprimir a comparação das
	// chaves que FORAM lidas. Quinta vez a mesma lição.
	Incompleta: func(f *facts.Facts) string {
		if f.SSHChavesCompleto {
			return ""
		}
		return "nem todo authorized_keys pôde ser lido: o conjunto de chaves NÃO é " +
			"exaustivo deste lado"
	},
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
	Tipo:     "conta",
	Titulo:   "conta local",
	Requires: env.CapFilesystem,
	// NÃO consome a chave `users`, e este é o terceiro caso da mesma lição:
	// chave de lacuna larga demais para servir de dependência.
	//
	// `users` cobre /etc/passwd, /etc/shadow, /etc/group e a árvore de sudoers.
	// Sem root o shadow é SEMPRE ilegível, então a chave está sempre suja — e
	// consumi-la suprimia `surgiu`/`sumiu` desta família em todo host sem root.
	// Uma conta uid 0 acrescentada entre dois retratos ficava calada porque
	// OUTRO arquivo não abriu, com o /etc/passwd perfeitamente legível.
	//
	// A presença de uma conta vem do passwd. Os campos que vêm do shadow já são
	// observacionais (ver Observacional abaixo), que é a granularidade certa
	// para eles.
	Incompleta: func(f *facts.Facts) string {
		if f.PasswdLido {
			return ""
		}
		return "/etc/passwd não foi lido: a lista de contas NÃO é conhecida deste lado"
	},
	Exaustiva: true,
	Decide: map[string]bool{
		"uid": true, "gid": true, "shell": true, "home": true,
		"sem_senha": true, "bloqueada": true, "sem_shadow": true,
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
	Observacional: map[string]bool{
		"sem_senha": true, "bloqueada": true, "sem_shadow": true,
	},
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
					// A conta que está no passwd e NÃO no shadow é assinatura de
					// edição à mão — o `useradd` escreve nos dois, sempre. O
					// priv.account_no_shadow já acusa o estado; o que faltava era
					// a transição, que é outra informação: a inconsistência NÃO
					// existia no retrato anterior.
					"sem_shadow": seLido(f.ShadowLido, boolTxt(a.SemShadow)),
				},
			})
		}
		return out
	},
}

// O grupo importa pelos MEMBROS: entrar em `docker`, `sudo` ou `wheel` é
// escalada que não muda nada no /etc/passwd e não cria processo nenhum.
var grupo = Classe{
	Tipo:     "grupo",
	Titulo:   "grupo local",
	Requires: env.CapFilesystem,
	// Mesma razão da família de contas: a chave `users` está suja sem root por
	// causa do shadow, e entrar em `docker` ou `wheel` é escalada que o
	// /etc/group registra sozinho.
	Incompleta: func(f *facts.Facts) string {
		if f.GroupLido {
			return ""
		}
		return "/etc/group não foi lido: a lista de grupos NÃO é conhecida deste lado"
	},
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
	Tipo:     "precarga",
	Titulo:   "pré-carga de código",
	Requires: env.CapFilesystem,
	Incompleta: func(f *facts.Facts) string {
		if f.LoaderPreloadLido {
			return ""
		}
		return "/etc/ld.so.preload não pôde ser lido deste lado"
	},
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
	Tipo:            "hook_interp",
	Titulo:          "hook de interpretador",
	Requires:        env.CapFilesystem,
	Lacunas:         []string{"interpretador"},
	LacunaConferida: "chave de escritor único: o coletor de hooks de interpretador",
	Exaustiva:       true,
	Decide:          map[string]bool{"valor": true},
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
	Tipo:            "suid",
	Titulo:          "arquivo com bit de privilégio",
	Requires:        env.CapFilesystem,
	Lacunas:         []string{"suid"},
	LacunaConferida: "todos os sites são da varredura de SUID: teto de profundidade, diretório não aberto, árvore de contêiner pulada",
	Exaustiva:       true,
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
	Tipo:     "modulo",
	Titulo:   "módulo carregado no kernel",
	Requires: env.CapProcfs,
	// NÃO consome a chave `modulo`, e a razão é a mesma da família de portas:
	// aquela chave cobre DUAS coisas com dependências diferentes — "/proc/modules
	// ilegível" (o conjunto é desconhecido) e "a árvore em disco não foi lida"
	// (só o ARQUIVO de cada módulo é desconhecido).
	//
	// Consumi-la tinha um efeito perverso, medido numa VM: a lacuna da árvore só
	// nasce QUANDO HÁ MÓDULO CARREGADO. Carregar um módulo num guest sem
	// /lib/modules criava a lacuna, a lacuna ficava assimétrica entre os dois
	// retratos, e a assimetria suprimia justamente a comparação que denunciaria
	// o módulo. O ato de se esconder apagava o detector.
	Incompleta: func(f *facts.Facts) string {
		if f.ModulosLidos {
			return ""
		}
		return "/proc/modules não foi lido: o conjunto de módulos carregados NÃO é " +
			"conhecido deste lado"
	},
	Exaustiva: true,
	Decide:    map[string]bool{"arquivo": true, "taint": true},
	// O ARQUIVO vem da árvore em disco, e sai vazio quando ela não foi lida —
	// vazio ali é "não observado", não "não tem arquivo". Sem isso, comparar um
	// retrato com a árvore lida contra um sem ela afirmaria que todo módulo
	// perdeu o arquivo.
	Observacional: map[string]bool{"arquivo": true},
	Extrair: func(f *facts.Facts) []Entidade {
		out := make([]Entidade, 0, len(f.Carregados))
		for i := range f.Carregados {
			m := &f.Carregados[i]
			out = append(out, Entidade{
				ID: m.Nome, Alvos: []string{m.Nome, m.Arquivo},
				Campos: map[string]string{
					"arquivo": seLido(f.ArvoreDeModulos, m.Arquivo),
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
	Tipo:     "binfmt",
	Titulo:   "interpretador registrado no kernel",
	Requires: env.CapProcfs,
	Incompleta: func(f *facts.Facts) string {
		if f.BinfmtVivoCompleto {
			return ""
		}
		return "os registros vivos de binfmt_misc não puderam ser lidos inteiros deste lado"
	},
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
	Tipo:            "boot",
	Titulo:          "linha de comando do kernel",
	Requires:        env.CapFilesystem,
	Lacunas:         []string{"boot"},
	LacunaConferida: "todos os sites são da configuração de boot: grub.cfg, partição EFI, entradas do systemd-boot",
	Exaustiva:       true,
	Decide:          map[string]bool{"valor": true},
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
	Tipo:     "ca",
	Titulo:   "âncora de confiança de TLS",
	Requires: env.CapFilesystem,
	// A chave `trust` cobre QUATRO fontes independentes — âncoras de TLS,
	// /etc/hosts, o resolvedor e os arquivos de confiança entre hosts. Um
	// diretório de CA ilegível suprimia a comparação de um nome fixado que
	// tinha sido perfeitamente lido. Cada família pergunta pela SUA.
	Incompleta: func(f *facts.Facts) string {
		if f.CACertsCompleto {
			return ""
		}
		return "nem toda âncora de confiança pôde ser lida: o conjunto NÃO é exaustivo deste lado"
	},
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
	//
	// DÍVIDA DECLARADA: "mesma chave = mesma autoridade" não é universal. Um
	// certificado pode manter a chave e mudar `NameConstraints`,
	// `BasicConstraints`, `KeyUsage` ou políticas — e aí a autoridade que ele
	// concede é outra sem a chave mexer. Hoje isso altera só o fingerprint, que
	// vai para a contagem e não vira achado. Fechar exigiria modelar as
	// extensões que importam, e isso é família própria; enquanto não existe, o
	// limite fica escrito aqui em vez de descoberto no incidente.
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
	Tipo:     "nss",
	Titulo:   "módulo de resolução (NSS)",
	Requires: env.CapFilesystem,
	Incompleta: func(f *facts.Facts) string {
		if f.NSSLido {
			return ""
		}
		return "/etc/nsswitch.conf não foi lido deste lado"
	},
	Exaustiva: true,
	Decide:    map[string]bool{"libs": true, "servicos": true},
	Extrair: func(f *facts.Facts) []Entidade {
		var naoObsNSS map[string]bool
		if !f.LoaderPathCompleto {
			naoObsNSS = map[string]bool{"libs": true}
		}
		out := make([]Entidade, 0, len(f.NSSModules))
		for i := range f.NSSModules {
			n := &f.NSSModules[i]
			out = append(out, Entidade{
				ID: n.Fonte, Alvos: []string{n.Fonte},
				// `libs` DEPENDE DO LOADER, e `servicos` não.
				//
				// Localizar libnss_<fonte>.so.* usa os diretórios de busca que
				// o ld.so.conf declara: se aquela cadeia não foi lida inteira,
				// uma lib pode simplesmente não ter sido PROCURADA onde estava,
				// e a lista encolhe sem nada ter saído do host. `servicos` vem
				// só do nsswitch.conf e continua comparável — que é o motivo de
				// isto ser por campo e não por família.
				NaoObservado: naoObsNSS,
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
	Tipo:     "nss_servico",
	Titulo:   "cadeia de resolução (nsswitch)",
	Requires: env.CapFilesystem,
	Incompleta: func(f *facts.Facts) string {
		if f.NSSLido {
			return ""
		}
		return "/etc/nsswitch.conf não foi lido deste lado"
	},
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
	Tipo:            "programa",
	Titulo:          "programa em execução",
	Requires:        env.CapProcfs,
	Lacunas:         []string{"proc"},
	LacunaConferida: "todos os sites são da varredura de /proc, e a família é efêmera — só `mudou` conta nela",
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

// # A SEGUNDA LEVA DE SUPERFÍCIES: o que uma defesa desligada tem em comum
//
// As famílias abaixo respondem a uma pergunta que o catálogo de checks responde
// mal por construção: um controle DESLIGADO não tem forma suspeita nenhuma.
//
//	SELinux permissivo        metade dos hosts do mundo sempre foi assim
//	auditd parado             idem
//	PermitRootLogin yes       era o padrão até ontem em muita distribuição
//	ptrace_scope 0            é o padrão de várias
//
// Nenhuma dessas leituras, parada, distingue "este host é assim" de "alguém fez
// isto ontem". O check estático só pode dizer o estado, e por isso o
// kernel.protection_context desta base é declaradamente CONTEXTO e não achado.
// Com um retrato anterior, a TRANSIÇÃO deixa de ser contexto — e transição é
// exatamente o que o drift tem para oferecer.

// # sshd: a configuração do que atende a porta 22
//
// Quatro campos deste arquivo decidem quem entra, e todos os quatro são
// legítimos em alguma configuração do mundo. O que não é legítimo é a mudança.
var servidorSSH = Classe{
	Tipo:     "ssh.servidor",
	Titulo:   "configuração do servidor SSH",
	Requires: env.CapFilesystem,
	// AUSÊNCIA É RESPOSTA, ILEGIBILIDADE É LACUNA — e a primeira versão desta
	// família confundia as duas: ela usava `len(Files) > 0` como sinal de
	// completude, então um host SEM servidor SSH era lido como "não sei". Um
	// host que GANHA sshd entre dois retratos tinha o `surgiu` suprimido.
	//
	// Agora o coletor diz as duas coisas: Coletado (a pergunta foi feita) e
	// Completo (nada falhou na leitura).
	Incompleta: func(f *facts.Facts) string {
		if !f.SSHServerColetado {
			return "a configuração do servidor SSH não foi coletada deste lado"
		}
		if !f.SSHServerCompleto {
			return "nem todo sshd_config pôde ser lido: a configuração do servidor " +
				"NÃO é exaustiva deste lado"
		}
		return ""
	},
	Exaustiva: true,
	Decide: map[string]bool{
		"permit_root_login": true, "password_authentication": true,
		"authorized_keys_file": true, "authorized_keys_command": true,
		"authorized_keys_command_user": true, "ports": true, "presente": true,
	},
	Extrair: func(f *facts.Facts) []Entidade {
		if !f.SSHServerColetado {
			return nil
		}
		return []Entidade{{
			ID: "sshd", Alvos: append([]string{"sshd", "sshd.service"}, f.SSH.Files...),
			Campos: map[string]string{
				// PRESENTE é campo, e não a existência da entidade: um host que
				// passa a ter servidor SSH é uma MUDANÇA daquele host, e não uma
				// entidade que nasceu.
				"presente":                boolTxt(len(f.SSH.Files) > 0),
				"permit_root_login":       f.SSH.PermitRootLogin,
				"password_authentication": f.SSH.PasswordAuthentication,
				// O AuthorizedKeysCommand é um programa que o sshd EXECUTA para
				// decidir quem entra: apontá-lo para outro caminho troca a
				// autoridade sobre o acesso sem tocar em chave nenhuma.
				"authorized_keys_file":         f.SSH.AuthorizedKeysFile,
				"authorized_keys_command":      f.SSH.AuthorizedKeysCommand,
				"authorized_keys_command_user": f.SSH.AuthorizedKeysCommandUser,
				// CONJUNTO, e não sequência: o estado relevante é EM QUAIS portas
				// o daemon atende. `Port 22` seguido de `Port 2222` e o inverso
				// abrem as mesmas duas portas, e reordenar a diretiva não é
				// mudança de superfície.
				"ports": juntarConjunto(f.SSH.Ports),
			},
		}}
	},
}

// # os hooks de execução do CLIENTE ssh
//
// `ProxyCommand`, `LocalCommand`, `Match exec` e `KnownHostsCommand` fazem o
// cliente executar um programa — do usuário, sem privilégio nenhum, e em toda
// conexão. É persistência de conta comum, e o coletor já a tinha: o que faltava
// era dizer que ELA NÃO ESTAVA LÁ ONTEM.
var hookDeClienteSSH = Classe{
	Tipo:     "ssh.cliente_exec",
	Titulo:   "hook de execução do cliente SSH",
	Requires: env.CapFilesystem,
	Incompleta: func(f *facts.Facts) string {
		if f.SSHClienteCompleto {
			return ""
		}
		return "nem todo config de cliente pôde ser lido: o conjunto de hooks NÃO " +
			"é exaustivo deste lado"
	},
	Exaustiva: true,
	Decide:    map[string]bool{"comando": true, "ativacao": true},
	Extrair: func(f *facts.Facts) []Entidade {
		out := make([]Entidade, 0, len(f.SSHClientExec))
		for i := range f.SSHClientExec {
			h := &f.SSHClientExec[i]
			// A LINHA NÃO ENTRA na identidade: ela anda quando alguém edita o
			// arquivo acima. O que identifica é o arquivo, o BLOCO e a diretiva
			// — e o comando é o estado, para que trocá-lo apareça como mudança
			// e não como um par sumiu+surgiu.
			//
			// O bloco é essencial: a primeira versão usava a `Ativacao` no lugar
			// dele, que é outra coisa (a confirmação do PermitLocalCommand).
			// Dois ProxyCommand em `Host prod` e `Host dev` colidiam no mesmo
			// ID, e TROCAR os destinos entre si mantinha o conjunto de comandos
			// e invertia o comportamento por destino — sem mudança nenhuma.
			out = append(out, Entidade{
				ID:    h.File + "|" + h.Escopo + "|" + h.Directive,
				Alvos: []string{h.File, h.User},
				Campos: map[string]string{
					"comando": redact.Linha(h.Command),
					// A ativação vira CAMPO: ela decide se o LocalCommand roda, e
					// passar de "não confirmada" para "confirmada" é a mudança
					// que arma um hook que já estava escrito.
					"ativacao": h.Ativacao,
				},
			})
		}
		return out
	},
}

// # doas
//
// A ferramenta já compara regra de sudo. Sem esta família, Alpine e Arch —
// onde o doas é o mecanismo NORMAL de escalada — ficavam com metade da
// resposta: regra nova em sudoers virava drift, regra nova em doas.conf não.
var regraDeDoas = Classe{
	Tipo:     "doas",
	Titulo:   "regra de doas",
	Requires: env.CapFilesystem,
	// A QUARTA vez que a chave `users` cobria demais — ela junta passwd, shadow,
	// group, sudoers e doas, e sem root o shadow suja todas. Usá-la aqui
	// suprimia `surgiu` de regra de doas justamente em Alpine e Arch, onde o
	// doas É o mecanismo de escalada.
	Incompleta: func(f *facts.Facts) string {
		if f.DoasLido {
			return ""
		}
		return "as regras de doas não foram lidas: o conjunto NÃO é exaustivo deste lado"
	},
	Exaustiva: true,
	// Mesma modelagem do sudoers: a identidade É o texto da regra, então não há
	// campo que possa mudar sem virar outra entidade. O sinal é a presença.
	Extrair: func(f *facts.Facts) []Entidade {
		out := make([]Entidade, 0, len(f.Doas))
		for i := range f.Doas {
			d := &f.Doas[i]
			out = append(out, Entidade{
				ID:     d.File + "|" + strings.Join(strings.Fields(d.Text), " "),
				Alvos:  []string{d.File, d.Identidade},
				Campos: map[string]string{},
			})
		}
		return out
	},
}

// # MAC: SELinux e AppArmor
//
// `Configurado` é o que o arquivo pede; `Ativo` é o que o kernel está fazendo.
// Os dois decidem, e por motivos diferentes: mudar o arquivo é persistência
// (vale no próximo boot), mudar o runtime é agora.
var controleMAC = Classe{
	Tipo:     "mac",
	Titulo:   "controle de acesso obrigatório (MAC)",
	Requires: env.CapFilesystem,
	// SEM `Lacunas`, e a razão é a que motivou o NaoObservado existir.
	//
	// A chave `mac` agrega DUAS fontes com permissões diferentes:
	// /etc/selinux/config, que diz o que vale no próximo boot, e
	// /sys/fs/selinux/enforce, que diz o que vale agora. Como dependência de
	// família, ela fazia o securityfs ilegível suprimir a comparação do
	// ARQUIVO — que tinha sido lido perfeitamente, e cuja transição
	// `enforcing -> permissive` é justamente a que sobrevive ao reboot.
	//
	// Cada campo passa a responder pela SUA leitura, abaixo. A chave continua
	// no relatório, para o operador, que é para quem ela foi escrita.
	Exaustiva: true,
	Decide:    map[string]bool{"configurado": true, "ativo": true},
	Extrair: func(f *facts.Facts) []Entidade {
		if f.MAC.Configurado == "" && f.MAC.Ativo == "" {
			return nil
		}
		naoObs := map[string]bool{}
		if !f.MAC.ConfigLido {
			naoObs["configurado"] = true
		}
		if !f.MAC.RuntimeLido {
			naoObs["ativo"] = true
		}
		return []Entidade{{
			ID: "mac", Alvos: []string{"mac", "selinux", "apparmor"},
			Campos: map[string]string{
				"configurado": f.MAC.Configurado,
				"ativo":       f.MAC.Ativo,
			},
			NaoObservado: naoObs,
		}}
	},
}

// # auditoria
//
// Desligar o auditd é anti-forense por definição: o que ele deixa de gravar não
// volta. E a regra que COBRE EXEC é a que decide se a execução de um binário
// entra no log — tirá-la é apagar o rastro antes de ele existir.
var controleAudit = Classe{
	Tipo:            "audit",
	Titulo:          "auditoria do kernel (auditd)",
	Requires:        env.CapFilesystem,
	Lacunas:         []string{"audit"},
	LacunaConferida: "chave do coletor de auditoria e só dele",
	Exaustiva:       true,
	Decide: map[string]bool{
		"instalada": true, "desligada": true, "cobre_exec": true, "regras": true,
	},
	Extrair: func(f *facts.Facts) []Entidade {
		var regras []string
		for _, r := range f.Audit.Regras {
			regras = append(regras, strings.Join(strings.Fields(r.Texto), " "))
		}
		return []Entidade{{
			ID: "audit", Alvos: []string{"audit", "auditd", "auditd.service"},
			Campos: map[string]string{
				"instalada":  boolTxt(f.Audit.Instalada),
				"desligada":  boolTxt(f.Audit.Desligada),
				"cobre_exec": boolTxt(f.Audit.CobreExec),
				"regras":     juntarConjunto(regras),
			},
		}}
	},
}

// # o endurecimento do kernel
//
// O kernel.protection_context desta base é declaradamente CONTEXTO e não
// achado, e a razão está escrita lá: `ptrace_scope=0` e `lockdown=none` são o
// padrão de distribuição inteira, então acusá-los seria acusar o mundo.
//
// A TRANSIÇÃO é outra coisa. `lockdown: integrity -> none` e
// `module_sig_enforce: Y -> N` não são o estado de fábrica de ninguém: são
// alguém desligando a trava, e nenhuma delas exige tocar num arquivo que a
// varredura de persistência olhe.
var protecaoDoKernel = Classe{
	Tipo:     "kernel.protecao",
	Titulo:   "endurecimento do kernel",
	Requires: env.CapProcfs,
	// SEM `taint`, e a chave estava aqui por engano de leitura.
	//
	// Ela é escrita pelo coletor de taint — /proc/sys/kernel/tainted e
	// /proc/modules —, e nenhum dos dez campos desta família vem de lá. O
	// efeito era um `ptrace_scope: 1 -> 0` desaparecer porque o `tainted`
	// ficou ilegível de um lado: a trava que impede um processo de ler a
	// memória de outro sendo desligada, calada por um arquivo sem relação.
	//
	// O que responde por esta família é o Protecao.Lido() abaixo, mais os
	// campos observacionais — os dois olham exatamente a fonte dela.
	// O coletor desta superfície é VIVO: em modo imagem ele não roda, e os dez
	// campos vêm vazios dos dois lados. Sem esta pergunta, a cobertura diria
	// "comparada sem restrição" sobre uma família que ninguém coletou — que é a
	// forma mais educada de mentir que existe neste relatório.
	Incompleta: func(f *facts.Facts) string {
		if f.Protecao.Lido() {
			return ""
		}
		return "nada do endurecimento do kernel pôde ser lido deste lado (o coletor " +
			"é vivo: em modo imagem ele não roda)"
	},
	Exaustiva: true,
	Decide: map[string]bool{
		"lockdown": true, "module_sig_enforce": true, "modules_disabled": true,
		"secure_boot": true, "ima": true, "unprivileged_bpf_disabled": true,
		"ptrace_scope": true, "kptr_restrict": true, "dmesg_restrict": true,
	},
	// TODOS observacionais: `leOuRegistra` devolve vazio tanto para "o arquivo
	// não existe neste kernel" quanto para "não deu para ler", e vazio de um
	// lado só nunca é uma mudança de política.
	Observacional: map[string]bool{
		"lockdown": true, "module_sig_enforce": true, "modules_disabled": true,
		"secure_boot": true, "ima": true, "unprivileged_bpf_disabled": true,
		"ptrace_scope": true, "kptr_restrict": true, "dmesg_restrict": true,
	},
	Extrair: func(f *facts.Facts) []Entidade {
		p := f.Protecao
		return []Entidade{{
			ID: "kernel", Alvos: []string{"kernel"},
			Campos: map[string]string{
				"lockdown":           p.Lockdown,
				"module_sig_enforce": p.SigEnforce,
				"modules_disabled":   p.ModulesDisabled,
				"secure_boot":        p.SecureBoot,
				// O IMA vem do securityfs, e `boolTxt` nunca devolve vazio — então
				// `false` significava as duas coisas ao mesmo tempo: "não há IMA"
				// e "não olhei". Sem o gate, um retrato sem securityfs contra um
				// com ele afirmava `ima: false -> true`.
				"ima":                       seLido(p.SecurityFS, boolTxt(p.IMA)),
				"unprivileged_bpf_disabled": p.UnprivBPF,
				"ptrace_scope":              p.PtraceScope,
				"kptr_restrict":             p.KptrRestrict,
				"dmesg_restrict":            p.DmesgRestrict,
			},
		}}
	},
}

// # para onde os nomes resolvem
//
// A entidade é o NOME, e não a linha: é assim que
//
//	api.company.com: (ausente) -> 10.10.10.66
//
// aparece como MUDANÇA de um nome, e não como uma linha que surgiu. Junto de
// uma CA nova, os dois valem muito mais do que qualquer um sozinho — e é para
// isso que a correlação por alvo existe.
var nomeEmHosts = Classe{
	Tipo:     "hosts",
	Titulo:   "nome fixado em /etc/hosts",
	Requires: env.CapFilesystem,
	// A chave `trust` cobre QUATRO fontes independentes — âncoras de TLS,
	// /etc/hosts, o resolvedor e os arquivos de confiança entre hosts. Um
	// diretório de CA ilegível suprimia a comparação de um nome fixado que
	// tinha sido perfeitamente lido. Cada família pergunta pela SUA.
	Incompleta: func(f *facts.Facts) string {
		if f.HostsLido {
			return ""
		}
		return "/etc/hosts não foi lido: os nomes fixados NÃO são conhecidos deste lado"
	},
	Exaustiva: true,
	Decide:    map[string]bool{"ip": true},
	Extrair: func(f *facts.Facts) []Entidade {
		var out []Entidade
		for i := range f.Hosts {
			h := &f.Hosts[i]
			for _, nome := range h.Names {
				out = append(out, Entidade{
					ID: nome, Alvos: []string{nome, h.IP},
					Campos: map[string]string{"ip": h.IP},
				})
			}
		}
		return out
	},
}

// O resolvedor é SEQUÊNCIA: o primeiro servidor que responde encerra a
// consulta, então acrescentar um na frente é assumir a resolução do host.
var resolvedor = Classe{
	Tipo:     "resolver",
	Titulo:   "resolvedor de DNS",
	Requires: env.CapFilesystem,
	// A chave `trust` cobre QUATRO fontes independentes — âncoras de TLS,
	// /etc/hosts, o resolvedor e os arquivos de confiança entre hosts. Um
	// diretório de CA ilegível suprimia a comparação de um nome fixado que
	// tinha sido perfeitamente lido. Cada família pergunta pela SUA.
	Incompleta: func(f *facts.Facts) string {
		if f.ResolverLido {
			return ""
		}
		return "a configuração do resolvedor não foi lida deste lado"
	},
	Exaustiva: true,
	Decide:    map[string]bool{"nameservers": true},
	Extrair: func(f *facts.Facts) []Entidade {
		if f.Resolver.File == "" && len(f.Resolver.Nameservers) == 0 {
			return nil
		}
		return []Entidade{{
			ID: nz(f.Resolver.File, "/etc/resolv.conf"), Alvos: []string{f.Resolver.File},
			Campos: map[string]string{"nameservers": juntarSequencia(f.Resolver.Nameservers)},
		}}
	},
}

// `.rhosts` e `hosts.equiv` concedem login SEM senha a partir de outro host, e
// um `+` neles confia em qualquer um. É a superfície mais antiga desta lista.
var confiancaDeHost = Classe{
	Tipo:     "host_trust",
	Titulo:   "confiança entre hosts (rhosts/hosts.equiv)",
	Requires: env.CapFilesystem,
	// A chave `trust` cobre QUATRO fontes independentes — âncoras de TLS,
	// /etc/hosts, o resolvedor e os arquivos de confiança entre hosts. Um
	// diretório de CA ilegível suprimia a comparação de um nome fixado que
	// tinha sido perfeitamente lido. Cada família pergunta pela SUA.
	Incompleta: func(f *facts.Facts) string {
		if f.HostTrustCompleto {
			return ""
		}
		return "nem todo arquivo de confiança entre hosts pôde ser lido: o conjunto NÃO é exaustivo deste lado"
	},
	Exaustiva: true,
	Decide:    map[string]bool{"entradas": true, "curinga": true},
	Extrair: func(f *facts.Facts) []Entidade {
		out := make([]Entidade, 0, len(f.ConfiancaDeHost))
		for i := range f.ConfiancaDeHost {
			c := &f.ConfiancaDeHost[i]
			out = append(out, Entidade{
				ID: c.Path, Alvos: []string{c.Path, c.Conta},
				Campos: map[string]string{
					"entradas": juntarConjunto(c.Linhas),
					"curinga":  boolTxt(c.Curinga),
				},
			})
		}
		return out
	},
}

func nz(s, padrao string) string {
	if s == "" {
		return padrao
	}
	return s
}

// # a terceira leva: as persistências que o coletor já normalizava
//
// Estas quatro famílias não exigiram fato novo nenhum — os coletores já as
// entregavam prontas, e o que faltava era compará-las. É o caso mais barato de
// cobertura que existe, e por isso ele estava esquecido: não doía.

// O Trigger é a família mais ampla do registro: /etc/profile e profile.d,
// rc.local, init.d, udev, PAM, hooks de apt/dnf, generator de systemd,
// supervisor, ~/.bashrc, ~/.ssh/rc. Todas são arquivos que EXECUTAM em algum
// gatilho, e o coletor já as normalizou numa forma só.
var gatilhoDeExecucao = Classe{
	Tipo:     "startup.trigger",
	Titulo:   "arquivo que executa em gatilho",
	Requires: env.CapFilesystem,
	// DUAS FONTES, e a segunda não era conhecida por esta família.
	//
	// `f.Triggers` não sai só da varredura de gatilhos: o coletor de hooks de
	// git também escreve nela, e as falhas DELE vão para a chave `githook`.
	// Enquanto a família dependia só de `startup`, uma árvore de repositório
	// que ficasse ilegível fazia os hooks dela saírem como REMOVIDOS — a
	// família continuava se achando exaustiva sobre um conjunto que perdeu
	// metade da testemunha.
	//
	// A saída não é juntar as duas chaves num `Lacunas` maior: isso faria um
	// repositório ilegível suprimir a comparação do /etc/profile, que vem da
	// outra varredura e foi lido inteiro. A supressão é POR FONTE.
	FontesIncertas: func(f *facts.Facts) map[string]string {
		out := map[string]string{}
		if temLacuna(f, "startup") {
			out["startup"] = "a varredura de gatilhos declarou lacuna"
		}
		if temLacuna(f, "githook") {
			out["githook"] = "a varredura de hooks de git declarou lacuna"
		}
		if len(out) == 0 {
			return nil
		}
		return out
	},
	Exaustiva: true,
	Decide:    map[string]bool{"linhas": true, "usuario": true, "modo": true},
	// DÍVIDA DECLARADA: gatilho BINÁRIO trocado no lugar não produz drift.
	//
	// O coletor marca `Binario` e não extrai linha nenhuma — não há o que
	// avaliar num ELF —, então um /etc/rc.local compilado substituído por outro
	// com o mesmo caminho, dono e modo compara vazio com vazio e sai calado. O
	// `mod_utc` muda e entra na CONTAGEM, mas mtime é forjável com um `touch` e
	// por isso não decide em família nenhuma daqui.
	//
	// Fechar exige um resumo criptográfico do CONTEÚDO no coletor — que é
	// decisão de custo, não de modelagem: hoje nenhum coletor de gatilho lê o
	// arquivo inteiro. Gatilho TEXTUAL, que é a esmagadora maioria, está
	// coberto pelas linhas. O limite fica escrito aqui em vez de descoberto no
	// incidente.
	//
	// `ilegivel` é o próprio coletor dizendo que não leu o conteúdo: comparar as
	// linhas de um arquivo ilegível é comparar o vazio com o vazio.
	Observacional: map[string]bool{"linhas": true},
	Extrair: func(f *facts.Facts) []Entidade {
		out := make([]Entidade, 0, len(f.Triggers))
		for i := range f.Triggers {
			t := &f.Triggers[i]
			// LinhasExecutaveis, não t.Lines: para apt.conf.d o que executa é o
			// hook (AptHooks), e um hook adversário que muda entre dois retratos
			// não aparece em Lines. Sem isto, o drift do gatilho é cego ao mesmo
			// fato que subiu o SchemaVersion para existir.
			var linhas []string
			for _, l := range t.LinhasExecutaveis() {
				linhas = append(linhas, redact.Linha(l.Text))
			}
			conteudo := juntarSequencia(linhas)
			if t.Ilegvel {
				conteudo = ""
			}
			// A FONTE separa o que a varredura de gatilhos achou do que o
			// coletor de git achou: as duas enchem f.Triggers, e cada uma falha
			// do seu jeito.
			fonte := "startup"
			if t.Kind == "git_hook" {
				fonte = "githook"
			}
			out = append(out, Entidade{
				ID: t.File, Alvos: []string{t.File}, Fonte: fonte,
				Campos: map[string]string{
					"linhas":  conteudo,
					"usuario": t.User,
					"modo":    t.Modo,
					"quando":  t.When,
					"mod_utc": t.ModUTC,
				},
			})
		}
		return out
	},
}

// `install <mod> <comando>` no modprobe.d faz o kernel executar um COMANDO
// quando alguém tenta carregar aquele módulo — e o comando roda como root. É
// persistência com gatilho, num arquivo que ninguém abre.
var configDeModulo = Classe{
	Tipo:     "module.config",
	Titulo:   "configuração de módulo (modprobe.d/modules-load.d)",
	Requires: env.CapFilesystem,
	// A chave `modprobe` NÃO é de escritor único, e a versão anterior desta
	// classe afirmava por escrito que era.
	//
	// Quem mais a escreve é a caminhada de /lib/modules: subárvore que não
	// lista, teto de diretórios estourado. São perguntas diferentes — "o que o
	// boot manda carregar" e "quais .ko existem em disco" —, e enquanto a
	// família dependia da chave, um /lib/modules/<versão> ilegível suprimia a
	// comparação de um modprobe.d perfeitamente lido.
	//
	// É o limite da catraca que nasceu no commit anterior: ela impede DUAS
	// FAMÍLIAS de dividirem uma chave, e não consegue impedir UMA CHAVE de ter
	// dois escritores. O que fecha isso é o fato de completude, e a
	// LacunaConferida — que era o lugar onde alguém tinha de conferir isto à
	// mão — estava simplesmente errada.
	Incompleta: func(f *facts.Facts) string {
		if f.ModuleConfigCompleto {
			return ""
		}
		return "a configuração de módulo (modprobe.d, modules-load.d, /etc/modules) não pôde ser lida inteira deste lado"
	},
	Exaustiva: true,
	Decide:    map[string]bool{"cmd": true},
	Extrair: func(f *facts.Facts) []Entidade {
		out := make([]Entidade, 0, len(f.Modules))
		for i := range f.Modules {
			m := &f.Modules[i]
			// A linha não entra: ela anda. Arquivo, tipo e módulo identificam.
			out = append(out, Entidade{
				ID:     m.File + "|" + m.Kind + "|" + m.Module,
				Alvos:  []string{m.File, m.Module},
				Campos: map[string]string{"cmd": redact.Linha(m.Cmd)},
			})
		}
		return out
	},
}

// O helper do kernel é o programa que o KERNEL invoca sozinho: `core_pattern`,
// o caminho do modprobe, o do poweroff. Trocá-lo dá execução como root sem
// nenhum processo do atacante estar rodando — o kernel chama por conta própria.
var helperDoKernel = Classe{
	Tipo:   "kernel.helper",
	Titulo: "programa que o kernel invoca",
	// PROCFS, e não filesystem: os três valores moram em /proc/sys/kernel e
	// /sys/kernel, e esta família nunca leu um arquivo de disco. Declarar
	// CapFilesystem era afirmar uma dependência que não existe E esconder a que
	// existe — em modo image o procfs é negado por construção, e era isso que
	// devia ter recusado a comparação.
	Requires:        env.CapProcfs,
	Lacunas:         []string{"helper"},
	LacunaConferida: "chave de escritor único: o coletor de helpers do kernel",
	// E o fato, que é o que a família consome de verdade.
	//
	// Ele diz "esta fonte foi lida", e o cap diz "este retrato tinha /proc".
	// Hoje um implica o outro — o coletor só roda em modo live, e modo live é
	// o único que ganha procfs —, e mesmo assim os dois ficam: o cap é uma
	// propriedade do AMBIENTE, o fato é da FONTE, e o dia em que alguém montar
	// o /proc de uma imagem o cap deixa de responder pelo fato. Aqui a falha
	// custa um helper de kernel inventado como REMOVIDO, e é o lugar de pagar
	// uma linha a mais.
	Incompleta: func(f *facts.Facts) string {
		if f.HelpersLidos {
			return ""
		}
		return "os programas que o kernel invoca não foram lidos deste lado (a fonte é /proc e /sys: não existe em retrato de imagem)"
	},
	Exaustiva: true,
	Decide:    map[string]bool{"valor": true, "alvo": true},
	Extrair: func(f *facts.Facts) []Entidade {
		out := make([]Entidade, 0, len(f.Helpers))
		for i := range f.Helpers {
			h := &f.Helpers[i]
			out = append(out, Entidade{
				ID: h.Nome, Alvos: []string{h.Nome, h.Alvo},
				Campos: map[string]string{
					"valor": redact.Linha(h.Valor),
					"alvo":  h.Alvo,
				},
			})
		}
		return out
	},
}

// O binfmt em ARQUIVO é o irmão em disco do registrado no kernel: ele é o que
// volta no próximo boot, e a família `binfmt` (viva) não o alcança em modo
// imagem nem antes de o serviço rodar.
var configDeBinfmt = Classe{
	Tipo:     "binfmt.config",
	Titulo:   "interpretador declarado em arquivo (binfmt.d)",
	Requires: env.CapFilesystem,
	Incompleta: func(f *facts.Facts) string {
		if f.BinfmtConfigCompleto {
			return ""
		}
		return "os arquivos de binfmt.d não puderam ser lidos inteiros deste lado"
	},
	Exaustiva: true,
	Decide:    map[string]bool{"interpretador": true, "flags": true},
	Extrair: func(f *facts.Facts) []Entidade {
		out := make([]Entidade, 0, len(f.BinfmtConfig))
		for i := range f.BinfmtConfig {
			b := &f.BinfmtConfig[i]
			out = append(out, Entidade{
				ID: b.Fonte + "|" + b.Nome, Alvos: []string{b.Fonte, b.Interpreter},
				Campos: map[string]string{
					"interpretador": b.Interpreter,
					"flags":         b.Flags,
				},
			})
		}
		return out
	},
}

// Onde o loader PROCURA biblioteca. Um diretório novo em ld.so.conf.d que venha
// ANTES dos de sistema faz toda resolução de soname passar por ele — é o
// LD_LIBRARY_PATH da máquina inteira, e sobrevive a reboot.
var caminhoDoLoader = Classe{
	Tipo:     "loader.path",
	Titulo:   "caminho de busca do loader",
	Requires: env.CapFilesystem,
	Incompleta: func(f *facts.Facts) string {
		if f.LoaderPathCompleto {
			return ""
		}
		return "a cadeia do ld.so.conf não foi lida inteira: os diretórios de busca NÃO são exaustivos deste lado"
	},
	Exaustiva: true,
	Decide:    map[string]bool{"declarado_por": true, "existe": true},
	Extrair: func(f *facts.Facts) []Entidade {
		out := make([]Entidade, 0, len(f.Loader.SearchDirs))
		for i := range f.Loader.SearchDirs {
			d := &f.Loader.SearchDirs[i]
			out = append(out, Entidade{
				ID: d.Dir, Alvos: []string{d.Dir, d.From},
				Campos: map[string]string{
					"declarado_por": d.From,
					"existe":        boolTxt(d.Exists),
				},
			})
		}
		return out
	},
}

// A ORDEM da busca, que é um fato à parte de QUAIS diretórios são buscados.
//
// A família `loader.path` identifica cada entidade pelo próprio diretório, e por
// construção isso perde a precedência: os MESMOS diretórios reordenados são as
// mesmas entidades, com os mesmos campos, e produziam zero drift. Mas quem
// resolve soname é o loader, e ele para no PRIMEIRO que casar — mover
// /opt/.lib para a frente de /usr/lib sequestra toda biblioteca do host sem
// acrescentar nem remover nada.
//
// É a mesma lição do nsswitch, e a solução é a mesma: a cadeia inteira vira UMA
// entidade com a sequência como campo. Guardar a posição em cada diretório
// resolveria a detecção e estragaria o relatório — inserir um item no começo
// mudaria a posição de todos os outros, e uma mudança viraria N achados. Foi o
// que o cron ensinou com a multiplicidade.
var ordemDoLoader = Classe{
	Tipo:     "loader.order",
	Titulo:   "ordem de busca de biblioteca",
	Requires: env.CapFilesystem,
	// O MESMO fato do loader.path, e de propósito: as duas famílias leem a
	// mesma fonte (a cadeia do ld.so.conf), então compartilham a resposta sobre
	// a completude dela. O que a catraca proíbe é herdar a chave de OUTRA
	// fonte; `nss` e `nss_servico` fazem igual pelo mesmo motivo.
	Incompleta: func(f *facts.Facts) string {
		if f.LoaderPathCompleto {
			return ""
		}
		return "a cadeia do ld.so.conf não foi lida inteira: a ORDEM de busca deste lado está truncada"
	},
	Exaustiva: true,
	Decide:    map[string]bool{"cadeia": true},
	Extrair: func(f *facts.Facts) []Entidade {
		if len(f.Loader.SearchDirs) == 0 {
			return nil
		}
		dirs := make([]string, 0, len(f.Loader.SearchDirs))
		alvos := make([]string, 0, len(f.Loader.SearchDirs))
		for _, d := range f.Loader.SearchDirs {
			dirs = append(dirs, d.Dir)
			alvos = append(alvos, d.Dir)
		}
		return []Entidade{{
			ID:     "ld.so.conf",
			Alvos:  alvos,
			Campos: map[string]string{"cadeia": juntarSequencia(dirs)},
		}}
	},
}

// O LD_PRELOAD que não está no ld.so.preload.
//
// /etc/environment e /etc/security/pam_env.conf são lidos pelo PAM a cada
// sessão — inclusive por SSH —, e uma linha `LD_PRELOAD=/tmp/.so` ali tem o
// mesmo efeito da pré-carga global, num arquivo que ninguém olha com a mesma
// desconfiança. O check já acusava a linha; o que não existia era a comparação,
// e ela é a que pega a troca de UMA lib por outra, ou o LD_LIBRARY_PATH que
// ganha um diretório novo na frente.
//
// Família SEPARADA da precarga e do caminho do loader pela mesma razão que
// separou aquelas duas: são três fontes, com três modos de falhar, e juntá-las
// faz a falha de uma calar as outras.
var envDoLoader = Classe{
	Tipo:     "loader.env",
	Titulo:   "variável de ambiente que carrega código",
	Requires: env.CapFilesystem,
	Incompleta: func(f *facts.Facts) string {
		if f.LoaderEnvCompleto {
			return ""
		}
		return "/etc/environment ou /etc/security/pam_env.conf não pôde ser lido deste lado"
	},
	Exaustiva: true,
	Decide:    map[string]bool{"valor": true},
	Extrair: func(f *facts.Facts) []Entidade {
		out := make([]Entidade, 0, len(f.Loader.EnvVars))
		for i := range f.Loader.EnvVars {
			v := &f.Loader.EnvVars[i]
			// Arquivo E chave identificam: a MESMA variável definida nos dois
			// arquivos são duas definições, e qual vence depende da ordem em
			// que o PAM os lê — tratá-las como uma só esconderia a que foi
			// acrescentada.
			out = append(out, Entidade{
				ID:     v.File + "|" + v.Key,
				Alvos:  []string{v.File, v.Value},
				Campos: map[string]string{"valor": redact.Valor(v.Key, v.Value)},
			})
		}
		return out
	},
}

// A MESMA injeção pela porta do systemd: `Environment=` e `EnvironmentFile=`
// põem a variável no ambiente do serviço com o efeito do ld.so.preload.
//
// Família SEPARADA da `loader.env` porque as fontes falham diferente. Um
// EnvironmentFile= ilegível de UMA unit não pode pôr em dúvida o
// /etc/environment, nem as outras units — e é por isso que a incerteza aqui é
// declarada POR UNIT, e não por família: a `Fonte` da entidade é o nome da
// unit, e só as entidades dela saem de surgiu/sumiu.
//
// O valor comparado é o EFETIVO. O systemd deixa valendo a ÚLTIMA atribuição de
// uma variável, então trocar a ordem de duas linhas `Environment=LD_PRELOAD=`
// muda o que o serviço carrega — e comparar o conjunto de declarações daria
// zero drift para essa troca.
var envDeUnit = Classe{
	Tipo:     "unit.env",
	Titulo:   "variável de unit que carrega código",
	Requires: env.CapFilesystem,
	Incompleta: func(f *facts.Facts) string {
		if temLacuna(f, "unit") {
			return "a varredura de units não foi exaustiva deste lado"
		}
		return ""
	},
	FontesIncertas: func(f *facts.Facts) map[string]string {
		out := map[string]string{}
		for i := range f.Units {
			if u := &f.Units[i]; u.Efetiva() && len(u.EnvFilesIlegiveis) > 0 {
				out[u.Name] = "EnvironmentFile= ilegível"
			}
		}
		if len(out) == 0 {
			return nil
		}
		return out
	},
	Exaustiva: true,
	Decide:    map[string]bool{"valor": true},
	Extrair: func(f *facts.Facts) []Entidade {
		out := make([]Entidade, 0, len(f.Loader.EnvDeUnit))
		for i := range f.Loader.EnvDeUnit {
			v := &f.Loader.EnvDeUnit[i]
			var naoObs map[string]bool
			if v.Incerto {
				// A unit tem EnvironmentFile= que não abriu: o valor abaixo é o
				// visível, e o arquivo que faltou pode sobrescrevê-lo. Comparar
				// dois "visíveis" como se fossem dois efetivos afirmaria o que
				// ninguém leu.
				naoObs = map[string]bool{"valor": true}
			}
			out = append(out, Entidade{
				ID:           v.Unit + "|" + v.Key,
				Fonte:        v.Unit,
				Alvos:        []string{v.Unit, v.Value, v.DeclaradoEm},
				NaoObservado: naoObs,
				Campos: map[string]string{
					"valor": redact.Valor(v.Key, v.Value),
					// CORROBORA: mover a linha da unit para um drop-in muda o
					// arquivo e não muda o que o serviço carrega.
					"declarado_em": v.DeclaradoEm,
				},
			})
		}
		return out
	},
}

// A configuração POR DIRETÓRIO do servidor web (.htaccess, .user.ini): quem
// consegue escrever numa árvore de upload muda o que aquele diretório EXECUTA,
// sem privilégio nenhum.
var configWeb = Classe{
	Tipo:            "web.config",
	Titulo:          "configuração por diretório do servidor web",
	Requires:        env.CapFilesystem,
	Lacunas:         []string{"codigo"},
	LacunaConferida: "a varredura de código e a de config web são a MESMA caminhada, com os mesmos tetos: um corte de orçamento torna as duas não exaustivas — aqui a chave larga é a dependência CERTA",
	Exaustiva:       true,
	Decide:          map[string]bool{"linhas": true},
	Extrair: func(f *facts.Facts) []Entidade {
		out := make([]Entidade, 0, len(f.ConfigWeb))
		for i := range f.ConfigWeb {
			c := &f.ConfigWeb[i]
			var linhas []string
			for _, l := range c.Linhas {
				linhas = append(linhas, l.Motivo+":"+l.Text)
			}
			out = append(out, Entidade{
				ID: c.Path, Alvos: []string{c.Path},
				Campos: map[string]string{
					"linhas":  juntarSequencia(linhas),
					"mod_utc": c.ModUTC,
				},
			})
		}
		return out
	},
}
