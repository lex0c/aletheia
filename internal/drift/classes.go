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
			out = append(out, Entidade{ID: id, Campos: map[string]string{
				"exec":           juntar(execs),
				"user":           u.User,
				"enabled_by":     juntar(u.EnabledBy),
				"dropin_for":     u.DropInFor,
				"root_directory": u.RootDirectory,
				"root_image":     u.RootImage,
				"listen":         juntar(u.Listen),
				"watch_paths":    juntar(u.WatchPaths),
				"on_calendar":    juntar(u.OnCalendar),
				"environment":    juntar(envs),
				"binds":          juntar(binds),
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
	Decide:    map[string]bool{"cmd": true, "user": true, "schedule": true},
	Extrair: func(f *facts.Facts) []Entidade {
		out := make([]Entidade, 0, len(f.Cron))
		for i := range f.Cron {
			c := &f.Cron[i]
			id := c.File + "|" + c.Kind + "|" + c.User + "|" + c.Schedule
			out = append(out, Entidade{ID: id, Campos: map[string]string{
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
	Decide:    map[string]bool{"presente": true},
	Extrair: func(f *facts.Facts) []Entidade {
		out := make([]Entidade, 0, len(f.Sudoers))
		for i := range f.Sudoers {
			s := &f.Sudoers[i]
			out = append(out, Entidade{
				ID:     s.File + "|" + strings.Join(strings.Fields(s.Text), " "),
				Campos: map[string]string{"presente": "sim"},
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
			out = append(out, Entidade{ID: id, Campos: map[string]string{
				"options": k.Options,
				"type":    k.Type,
				"comment": k.Comment,
				"mod_utc": k.ModUTC,
			}})
		}
		return out
	},
}

// juntar serializa lista em valor comparável, com ordem estável. A ordem da
// coleta já é determinística (medido), mas depender disso faria uma mudança de
// ordem interna virar drift — e ninguém saberia dizer por quê.
func juntar(v []string) string {
	if len(v) == 0 {
		return ""
	}
	c := append([]string(nil), v...)
	sort.Strings(c)
	return strings.Join(c, "\x1f")
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
