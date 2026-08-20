package checks

import (
	"strconv"
	"strings"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

func init() {
	check.Register(caPlantada)
	check.Register(hostsOverride)
	check.Register(cloudMetadata)
	check.Register(confiancaHostBased)
}

// confiancaHostBased — runbook §7.12, ATT&CK T1021.004.
//
// .rhosts, .shosts, /etc/hosts.equiv e /etc/shosts.equiv são a forma mais
// antiga de login SEM SENHA do Unix: um host listado entra COMO O DONO do
// arquivo, sem autenticar. Sobrevive porque quase ninguém olha — não há
// processo estranho, porta aberta nem erro; só um arquivo que concede acesso.
//
// A severidade sai do CONTEÚDO:
//
//	`+` sozinho   confia em QUALQUER host e QUALQUER usuário — acesso irrestrito
//	              sem senha. É o backdoor, e é CRÍTICO
//	host nomeado  confia num host específico. Raro em sistema moderno, e a
//	              pergunta é quem o colocou — AVISO
//
// Não confunda com known_hosts nem com authorized_keys: aqueles autenticam por
// CHAVE; este autentica por ENDEREÇO de origem, que o atacante forja.
var confiancaHostBased = check.Check{
	ID:       "persist.host_trust",
	Ref:      "7.12",
	Title:    "confiança host-based: login sem senha por .rhosts/hosts.equiv",
	Group:    "persist",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Wtf:      true,
	FalsePositives: []string{
		"host-based trust ainda é usado em cluster HPC e em automação legada de " +
			"laboratório — rsh/rlogin entre nós de confiança. Ali é desenho, e " +
			"alguém no time reconhece as máquinas listadas",
		"a presença do arquivo já é rara em sistema moderno; o `+` curinga quase " +
			"nunca é: é ele que separa 'confia num host' de 'confia em qualquer um'",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		for i := range f.ConfiancaDeHost {
			c := &f.ConfiancaDeHost[i]

			alvo := c.Path
			if c.Escopo == "usuario" && c.Conta != "" {
				alvo = c.Path + " (conta " + c.Conta + ")"
			}

			ev := []string{c.Path + " concede login SEM SENHA por confiança de endereço de origem"}
			if c.Escopo == "sistema" {
				ev = append(ev, "escopo de SISTEMA: vale para o host inteiro, não para uma conta")
			} else {
				ev = append(ev, "escopo de USUÁRIO: quem entrar vira a conta "+c.Conta+" sem autenticar")
			}
			if len(c.Linhas) > 0 {
				amostra := c.Linhas
				if len(amostra) > 6 {
					amostra = append(amostra[:6:6], "…")
				}
				ev = append(ev, "entradas: "+strings.Join(amostra, " · "))
			}
			if c.Gravavel {
				ev = append(ev, "e o arquivo é gravável por grupo/outros: qualquer conta "+
					"acrescenta um host de confiança nele")
			}

			sev := check.SevWarn
			if c.Curinga {
				sev = check.SevCritical
				ev = append(ev, "contém `+`: confia em QUALQUER host e QUALQUER usuário — "+
					"é login de root/da conta sem senha a partir de qualquer lugar")
			}

			fd := self.F(sev, alvo, "", ev...)
			fd.Quando, fd.QuandoFonte = c.ModUTC, "mtime do arquivo de confiança"
			fd.NextSteps = []string{
				"leia o arquivo: cada linha é um host (ou host+usuário) que entra sem senha",
				"host-based trust depende de rsh/rlogin ou de pam_rhosts — confira se " +
					"o serviço está ativo; mesmo inativo, o arquivo é " +
					"reativado ao subir o serviço",
				"se ninguém reconhecer as máquinas listadas, remova o arquivo e rotacione " +
					"o acesso da conta",
			}
			r.Findings = append(r.Findings, fd)
		}
		r.Partial = append(r.Partial, f.PersistDenied["trust"]...)
		return r
	},
}

// caPlantada — runbook §7.12.
//
// Uma CA raiz do atacante faz o host confiar em QUALQUER certificado que ele
// emitir: update de pacote, chamada de API e webhook passam a ser
// interceptáveis sem erro de TLS.
//
// Junto com uma linha em /etc/hosts, isto é um MITM completo e silencioso — o
// nome resolve para o atacante e o certificado dele é aceito. Nenhuma
// ferramenta reclama.
var caPlantada = check.Check{
	ID:       "persist.ca_planted",
	Ref:      "7.12",
	Title:    "âncora de confiança instalada fora do pacote de certificados",
	Group:    "persist",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Wtf:      true,
	FalsePositives: []string{
		"CA corporativa é instalada exatamente assim, e é comum: proxy de " +
			"inspeção TLS, PKI interna, ambiente de teste com certificado " +
			"próprio. O titular diz de quem ela é — e alguém no time reconhece",
		"o check olha só os diretórios em que o ADMINISTRADOR acrescenta " +
			"âncora. Os certificados do sistema vêm de pacote e não entram aqui",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		for i := range f.CACerts {
			c := &f.CACerts[i]
			ev := []string{"arquivo: " + c.File}
			if c.Erro != "" {
				ev = append(ev, "não foi possível decodificar: "+c.Erro+
					" — a PRESENÇA no diretório de âncoras já é o fato")
			} else {
				ev = append(ev,
					"titular: "+c.Subject,
					"emissor: "+c.Issuer)
				if c.AutoAssinado {
					ev = append(ev, "AUTO-ASSINADA: é uma CA raiz — o host passa a "+
						"confiar em tudo que ela emitir")
				}
				ev = append(ev, "válida de "+c.NotBefore+" a "+c.NotAfter)
			}
			if c.ModUTC != "" {
				ev = append(ev, "instalada em "+c.ModUTC)
			}
			ev = append(ev, "com uma linha em /etc/hosts isto vira MITM completo: "+
				"o nome resolve para o atacante e o certificado dele é aceito")

			fd := self.F(check.SevWarn, baseDe(c.File), "", ev...)
			fd.NextSteps = []string{
				"pergunte ao time de quem é esta CA antes de tratar como achado",
				"se ninguém a instalou, TODO tráfego TLS deste host desde a data " +
					"acima é suspeito — inclusive update de pacote",
			}
			r.Findings = append(r.Findings, fd)
		}
		r.Partial = append(r.Partial, f.PersistDenied["trust"]...)
		return r
	},
}

// hostsOverride — runbook §7.12.
//
// Um nome apontando para IP que não é local é redirecionamento. A forma que
// interessa é o nome de UPDATE ou de API: quem controla para onde o `apt`
// aponta controla o que o host instala.
var hostsOverride = check.Check{
	ID:       "persist.hosts_override",
	Ref:      "7.12",
	Title:    "/etc/hosts redireciona nome para endereço não local",
	Group:    "persist",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Wtf:      true,
	FalsePositives: []string{
		"apontar nome para IP da rede interna é prática comum e legítima: " +
			"registro de container, espelho de pacote interno, ambiente sem DNS " +
			"próprio. Por isso destino PRIVADO sai como aviso e destino PÚBLICO " +
			"sai como crítico",
		"entrada de loopback e o nome da própria máquina são o conteúdo NORMAL " +
			"do arquivo, e não entram aqui",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		for i := range f.Hosts {
			h := &f.Hosts[i]
			if h.Scope == facts.ScopeLoopback || h.Scope == "" {
				continue
			}
			// Nome sem ponto é apelido local, não domínio.
			var dominios []string
			for _, n := range h.Names {
				if strings.Contains(n, ".") {
					dominios = append(dominios, n)
				}
			}
			if len(dominios) == 0 {
				continue
			}

			sev := check.SevWarn
			ev := []string{
				strings.Join(dominios, " ") + " → " + h.IP,
				"/etc/hosts:" + strconv.Itoa(h.Line),
			}
			if h.Scope == facts.ScopePublic {
				sev = check.SevCritical
				ev = append(ev, "o destino é um endereço PÚBLICO: o nome deixou de "+
					"resolver pelo DNS e passa por um host que alguém escolheu")
			} else {
				ev = append(ev, "o destino é da rede interna — comum em espelho de "+
					"pacote e registro próprio, mas confirme que foi de propósito")
			}
			if atualizacao := dominioDeAtualizacao(dominios); atualizacao != "" {
				sev = check.SevCritical
				ev = append(ev, "é domínio de ATUALIZAÇÃO ou de pacote ("+atualizacao+
					"): quem controla para onde ele aponta controla o que o host instala")
			}
			if f.Resolver.HostsModUTC != "" {
				ev = append(ev, "/etc/hosts modificado em "+f.Resolver.HostsModUTC)
			}

			fd := self.F(sev, dominios[0], "", ev...)
			fd.NextSteps = []string{
				"confira se há CA plantada junto: as duas coisas formam um MITM " +
					"completo e silencioso",
				"o ctime do arquivo data a alteração",
			}
			r.Findings = append(r.Findings, fd)
		}
		return r
	},
}

// cloudMetadata — runbook §7.12.
//
// MANUAL porque é o único ponto de persistência que NÃO ESTÁ EM DISCO NENHUM.
// Quem tem credencial de nuvem define o startup-script da instância, e ele roda
// como root a cada boot — inclusive depois de você trocar o disco.
//
// Nenhum check deste catálogo encontra isso. Reportar a ausência como "nada
// encontrado" seria a mentira exata que a ferramenta existe para não contar, e
// por isso o achado é a PERGUNTA, não a resposta.
var cloudMetadata = check.Check{
	ID:       "persist.cloud_metadata",
	Ref:      "7.12",
	Title:    "startup-script no metadata da nuvem: fora do alcance desta varredura",
	Group:    "cloud",
	Mode:     check.ModeManual,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	FalsePositives: []string{
		"não é achado: é a declaração de um ponto cego. A varredura de " +
			"filesystem não alcança o metadata da instância, e ele roda como root " +
			"a cada boot",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result

		// Só perguntar se houver quem EXECUTE o metadata neste host.
		var agentes []string
		for i := range f.Units {
			u := &f.Units[i]
			for _, nome := range []string{"cloud-init", "google-startup-scripts",
				"google-guest-agent", "amazon-ssm-agent", "walinuxagent"} {
				if strings.HasPrefix(u.Name, nome) {
					agentes = append(agentes, u.Name)
				}
			}
		}
		if len(agentes) == 0 && f.Host.Virt == "" {
			return r
		}

		ev := []string{
			"este host executa script vindo do metadata da instância",
			"nenhum check deste catálogo alcança isso: não há arquivo, cron nem unit",
			"roda como ROOT a cada boot — inclusive depois de trocar o disco",
		}
		if len(agentes) > 0 {
			ev = append(ev, "quem executa: "+strings.Join(dedupeStr(agentes), " "))
		}
		if f.Host.Virt != "" {
			ev = append(ev, "virtualização detectada: "+f.Host.Virt)
		}

		fd := self.F(check.SevManual, "metadata da instância", "", ev...)
		fd.NextSteps = []string{
			"GCP: curl -s -H 'Metadata-Flavor: Google' " +
				"'http://169.254.169.254/computeMetadata/v1/instance/attributes/startup-script'",
			"AWS: curl -s http://169.254.169.254/latest/user-data",
			"a alteração aparece no audit da nuvem; se a credencial " +
				"da instância vazou, confira ANTES de declarar o host limpo",
		}
		r.Findings = append(r.Findings, fd)
		return r
	},
}

// dominiosDeAtualizacao são sufixos de domínio de pacote, atualização e
// registro. A lista é de PROJETOS, não de amostras: nomes de distribuição e de
// repositório público mudam em anos, não em semanas.
var dominiosDeAtualizacao = []string{
	"debian.org", "ubuntu.com", "canonical.com", "archlinux.org",
	"centos.org", "fedoraproject.org", "rockylinux.org", "almalinux.org",
	"alpinelinux.org", "opensuse.org", "redhat.com",
	"pypi.org", "npmjs.org", "npmjs.com", "rubygems.org", "crates.io",
	"docker.io", "docker.com", "ghcr.io", "quay.io",
	"github.com", "gitlab.com", "golang.org", "proxy.golang.org",
}

func dominioDeAtualizacao(nomes []string) string {
	for _, n := range nomes {
		low := strings.ToLower(n)
		for _, d := range dominiosDeAtualizacao {
			if low == d || strings.HasSuffix(low, "."+d) {
				return d
			}
		}
	}
	return ""
}

func dedupeStr(ss []string) []string {
	visto := map[string]bool{}
	var out []string
	for _, s := range ss {
		if !visto[s] {
			visto[s] = true
			out = append(out, s)
		}
	}
	return out
}
