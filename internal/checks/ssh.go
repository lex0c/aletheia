package checks

import (
	"strconv"
	"strings"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

func init() {
	check.Register(sshForcedCommand)
	check.Register(sshdBackdoor)
	check.Register(sshKeyInventory)
}

// sshForcedCommand — runbook §7.5.
//
// `command="..."` no início da linha executa algo a CADA login com aquela
// chave. É backdoor com gatilho: quem tem a chave não precisa nem de shell —
// o comando roda sozinho, e o `authorized_keys` continua parecendo um arquivo
// de chaves comum.
var sshForcedCommand = check.Check{
	ID:       "persist.ssh_forced_command",
	Ref:      "7.5",
	Title:    "chave SSH que executa um comando a cada login",
	Group:    "persist",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Wtf:      true,
	FalsePositives: []string{
		"`command=` tem usos legítimos e comuns: rrsync, borg, gitolite e " +
			"qualquer chave de automação restrita a UM comando. Nesses casos o " +
			"comando aponta para um binário conhecido e a chave tem dono claro",
		"`from=` e `no-pty` são RESTRIÇÕES — sinal de endurecimento, não de " +
			"backdoor. Só o `command=` executa algo, e uma chave que traz as duas " +
			"coisas cai para informativo justamente por isso",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		for i := range f.SSHKeys {
			k := &f.SSHKeys[i]
			cmd, ok := comandoForcado(k.Options)
			if !ok {
				continue
			}
			ev := []string{
				"command=" + cmd,
				"executa a cada login com esta chave, antes de qualquer shell",
				"arquivo: " + k.File + ":" + strconv.Itoa(k.Line) + " (usuário " + k.User + ")",
			}
			if k.Fingerprint != "" {
				// A impressão digital é o IOC de frota: a mesma chave em vários
				// hosts é a mesma pessoa, e isso vale mais que hash de binário.
				ev = append(ev, "impressão digital: "+k.Fingerprint)
			}
			if k.Comment != "" {
				ev = append(ev, "comentário: "+k.Comment+
					" — costuma ser user@host de quem GEROU a chave")
			}
			if k.ModUTC != "" {
				ev = append(ev, "arquivo modificado em "+k.ModUTC)
			}

			sev := check.SevWarn
			if _, s, susp := execSuspect(cmd); susp && s == check.SevCritical {
				sev = check.SevCritical
			}
			// A RESTRIÇÃO é o discriminador, e ela inverte o sinal.
			//
			// `command=` sozinho é a forma do atacante: ele quer que algo rode e
			// não se importa com o resto. `command=` com `no-pty` e `restrict` é a
			// forma do administrador — ele está justamente IMPEDINDO o shell que o
			// atacante quer. É o padrão de chave de backup (rrsync, borg), e num
			// servidor real ele aparece em toda parte.
			//
			// Uma chave endurecida assim continua no inventário, mas como
			// informação: acusá-la de backdoor faz o operador aprender a ignorar
			// este check, e aí ele perde o achado que importa.
			if r := restricoes(k.Options); len(r) > 0 && sev == check.SevWarn {
				sev = check.SevInfo
				ev = append(ev, "e vem com restrição: "+strings.Join(r, ", ")+
					" — é a forma ENDURECIDA, o oposto do backdoor: quem restringe "+
					"está impedindo o shell que o atacante quer")
			}
			fd := self.F(sev, k.User+":"+strconv.Itoa(k.Line), "", ev...)
			fd.NextSteps = []string{
				"a impressão digital é IOC de frota: procure a MESMA chave nos " +
					"outros hosts antes de concluir o alcance (runbook §23)",
				"o ctime do arquivo data a inserção mesmo que o conteúdo pareça " +
					"antigo (runbook §5.2)",
			}
			r.Findings = append(r.Findings, fd)
		}
		r.Partial = append(r.Partial, f.PersistDenied["ssh"]...)
		return r
	},
}

// sshdBackdoor — runbook §7.5 e §7.12.
//
// Duas diretivas mudam ONDE o sshd procura chave, e as duas escondem o acesso
// do `~/.ssh/authorized_keys` que todo mundo olha:
//
//	AuthorizedKeysFile     aponta o arquivo para outro caminho
//	AuthorizedKeysCommand  o sshd PERGUNTA a um programa quais chaves valem,
//	                       e aí não existe arquivo de chave nenhum para achar
var sshdBackdoor = check.Check{
	ID:       "persist.sshd_key_source",
	Ref:      "7.5",
	Title:    "sshd busca chave fora do lugar padrão",
	Group:    "persist",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Wtf:      true,
	FalsePositives: []string{
		"AuthorizedKeysCommand é o mecanismo PADRÃO de integração com diretório " +
			"central. As integrações conhecidas — systemd-userdb, SSSD, OS Login " +
			"do GCE, EC2 Instance Connect — são PULADAS quando o programa está em " +
			"diretório de sistema: o Arch entrega userdbctl por padrão, e disparar " +
			"nele faria toda varredura de Arch virar ruído",
		"a isenção é do programa NO LUGAR CERTO: um `userdbctl` em /tmp não herda " +
			"a reputação do de /usr/bin",
		"a leitura é do ARQUIVO, não do `sshd -T`: Match blocks e defaults " +
			"compilados não são resolvidos aqui. O que se vê é o que está escrito",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		c := f.SSH
		if len(c.Files) == 0 {
			// Sem sshd_config não há o que avaliar, e isso não é lacuna: host
			// sem servidor SSH é normal.
			return r
		}

		if cmd := c.AuthorizedKeysCommand; cmd != "" && !keyCommandConhecido(cmd) {
			ev := []string{
				"AuthorizedKeysCommand=" + cmd,
				"o sshd pergunta a este programa quais chaves valem: não existe " +
					"arquivo de chave para encontrar",
			}
			if c.AuthorizedKeysCommandUser != "" {
				ev = append(ev, "roda como: "+c.AuthorizedKeysCommandUser)
			}
			ev = append(ev, "declarado em: "+strings.Join(c.Files, " "))

			sev := check.SevWarn
			if _, s, susp := execSuspect(cmd); susp && s == check.SevCritical {
				sev = check.SevCritical
			}
			fd := self.F(sev, "AuthorizedKeysCommand", "", ev...)
			fd.NextSteps = []string{
				"leia o programa: ele decide quem entra, e ninguém o audita junto " +
					"com o authorized_keys",
				"confirme se a integração com diretório central existe de propósito",
			}
			r.Findings = append(r.Findings, fd)
		}

		if p := c.AuthorizedKeysFile; p != "" && !caminhoPadraoDeChave(p) {
			fd := self.F(check.SevWarn, "AuthorizedKeysFile", "", []string{
				"AuthorizedKeysFile=" + p,
				"as chaves NÃO estão em ~/.ssh/authorized_keys, que é onde todo " +
					"mundo olha primeiro",
				"declarado em: " + strings.Join(c.Files, " "),
			}...)
			fd.NextSteps = []string{
				"leia as chaves no caminho declarado, não no padrão (runbook §7.5)",
			}
			r.Findings = append(r.Findings, fd)
		}

		r.Partial = append(r.Partial, f.PersistDenied["ssh"]...)
		return r
	},
}

// sshKeyInventory — runbook §7.5.
//
// MANUAL de propósito. "Uma chave que ninguém reconhece" não é decidível por
// máquina: toda chave parece igual, e o que separa a do atacante da do time é
// alguém olhar e dizer "esta não é minha".
//
// O que a ferramenta pode fazer é montar a lista com o que decide — impressão
// digital para comparar entre hosts, comentário para reconhecer a origem, e a
// data do arquivo para datar a inserção.
var sshKeyInventory = check.Check{
	ID:       "persist.ssh_keys",
	Ref:      "7.5",
	Title:    "inventário de chaves SSH autorizadas",
	Group:    "persist",
	Mode:     check.ModeManual,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	FalsePositives: []string{
		"não é achado: é a lista para conferência humana. A pergunta que só uma " +
			"pessoa responde é 'esta chave é de alguém do time?'",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		if len(f.SSHKeys) == 0 {
			r.Partial = append(r.Partial, f.PersistDenied["ssh"]...)
			return r
		}

		porUsuario := map[string][]*facts.SSHKey{}
		var ordem []string
		for i := range f.SSHKeys {
			k := &f.SSHKeys[i]
			if _, ok := porUsuario[k.User]; !ok {
				ordem = append(ordem, k.User)
			}
			porUsuario[k.User] = append(porUsuario[k.User], k)
		}

		for _, u := range ordem {
			ks := porUsuario[u]
			ev := []string{strconv.Itoa(len(ks)) + " chave(s) autorizada(s) para " + u}
			for _, k := range ks {
				linha := "  " + nz(k.Fingerprint, "(impressão digital ilegível)")
				if k.Comment != "" {
					linha += "  " + k.Comment
				}
				if k.Options != "" {
					linha += "  [" + k.Options + "]"
				}
				ev = append(ev, linha)
			}
			if ks[0].ModUTC != "" {
				ev = append(ev, "arquivo "+ks[0].File+" modificado em "+ks[0].ModUTC+
					" — o ctime data a inserção mesmo que a chave pareça antiga (§5.2)")
			}

			fd := self.F(check.SevManual, u, "", ev...)
			fd.NextSteps = []string{
				"pergunte ao time: alguma dessas chaves não é de ninguém?",
				"a mesma impressão digital em vários hosts é a mesma pessoa — é o " +
					"melhor IOC de frota que existe (runbook §23)",
			}
			r.Findings = append(r.Findings, fd)
		}
		r.Partial = append(r.Partial, f.PersistDenied["ssh"]...)
		return r
	},
}

// comandoForcado extrai o valor de command="..." do bloco de opções.
func comandoForcado(opts string) (string, bool) {
	i := strings.Index(strings.ToLower(opts), "command=")
	if i < 0 {
		return "", false
	}
	v := opts[i+len("command="):]
	if !strings.HasPrefix(v, `"`) {
		// sem aspas: vai até a vírgula
		if j := strings.IndexByte(v, ','); j >= 0 {
			v = v[:j]
		}
		return v, v != ""
	}
	v = v[1:]
	if j := strings.IndexByte(v, '"'); j >= 0 {
		v = v[:j]
	}
	return v, v != ""
}

// keyCommandConhecidos são as integrações de diretório que as distribuições e
// as nuvens entregam por padrão. Isentá-las é o que separa este check de um
// gerador de ruído — o Arch configura userdbctl de fábrica.
//
// Mesma regra do runtime com JIT: a isenção vale para o programa em DIRETÓRIO
// DE SISTEMA. Um binário com o mesmo nome em /tmp não herda reputação nenhuma.
var keyCommandConhecidos = map[string]string{
	"userdbctl":               "systemd-userdb",
	"sss_ssh_authorizedkeys":  "SSSD (LDAP/AD)",
	"google_authorized_keys":  "OS Login do Google Compute Engine",
	"eic_run_authorized_keys": "AWS EC2 Instance Connect",
}

func keyCommandConhecido(cmd string) bool {
	bin := firstToken(cmd)
	if !strings.HasPrefix(bin, "/") {
		return false
	}
	emSistema := false
	for _, d := range []string{"/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/",
		"/usr/libexec/", "/usr/lib/", "/opt/aws/bin/", "/usr/local/bin/"} {
		if strings.HasPrefix(bin, d) {
			emSistema = true
			break
		}
	}
	if !emSistema {
		return false
	}
	_, ok := keyCommandConhecidos[baseDe(bin)]
	return ok
}

// caminhoPadraoDeChave reconhece as formas que o sshd usa por padrão. Qualquer
// outra coisa tira as chaves de onde o operador procura.
func caminhoPadraoDeChave(p string) bool {
	for _, campo := range strings.Fields(p) {
		switch campo {
		case ".ssh/authorized_keys", ".ssh/authorized_keys2",
			"%h/.ssh/authorized_keys", "%h/.ssh/authorized_keys2":
		default:
			return false
		}
	}
	return true
}

// restricoes devolve as opções de ENDURECIMENTO presentes na linha da chave.
//
// São o oposto de `command=`: elas tiram poder de quem entra. A presença delas
// junto de um comando forçado descreve chave de automação restrita, que é
// prática recomendada — e não backdoor.
func restricoes(opts string) []string {
	var out []string
	baixo := strings.ToLower(opts)
	for _, r := range []string{
		"restrict", "no-pty", "no-port-forwarding", "no-agent-forwarding",
		"no-x11-forwarding", "no-user-rc", "from=",
	} {
		if strings.Contains(baixo, r) {
			out = append(out, strings.TrimSuffix(r, "="))
		}
	}
	return out
}
