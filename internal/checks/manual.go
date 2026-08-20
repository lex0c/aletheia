package checks

import (
	"sort"
	"strconv"
	"strings"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

func init() {
	check.Register(consultaAoAudit)
	check.Register(logDaNuvem)
	check.Register(integridadeDoCodigo)
	check.Register(volumeDeSaida)
}

// A promessa que faltava cumprir.
//
// A SPEC diz, na primeira página: onde um check não é automatizável a partir do
// host, a ferramenta NÃO SILENCIA — emite orientação manual PARAMETRIZADA pelo
// que ela mesma achou. Existiam dois checks manuais, e nenhuma das lacunas
// grandes tinha um.
//
// O efeito disso é o modo de falha que a ferramenta inteira existe para evitar:
// o silêncio de "isto não dá para automatizar" é indistinguível do silêncio de
// "não há nada aqui". Quem lê o relatório não tem como saber que a §11, a §16 e
// a §37 sequer foram consideradas.
//
// O que estes quatro fazem é diferente de imprimir o runbook: eles só aparecem
// quando o host TEM a pergunta, e chegam com PID, caminho, endereço e janela já
// preenchidos — que é o trabalho chato de fazer no meio do incidente.

// consultaAoAudit — runbook §11.
//
// O auditd é a fonte mais forte que existe num host Linux: grava no kernel, no
// momento da syscall, com ppid, auid e exe juntos. O `auid` é o carimbo do login
// original e NÃO muda com `su`/`sudo` — é o que liga uma ação de root de volta à
// pessoa que entrou. Nenhuma outra fonte do host faz isso.
//
// A ferramenta sabe dizer se ele está ligado (§11, antiforense.audit_disabled).
// O que ela não faz é CONSULTAR: `ausearch` é um programa do host, e executar
// programa do host é a coisa que esta ferramenta não faz (SPEC 4). Então ela
// entrega a consulta pronta.
var consultaAoAudit = check.Check{
	ID:       "manual.audit_query",
	Ref:      "11",
	Title:    "o auditd está ligado: a consulta que amarra o vetor",
	Group:    "priv",
	Mode:     check.ModeManual,
	Sources:  env.SourceLive,
	Requires: env.CapFilesystem,
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		// Desligado não é lacuna deste check: é achado do
		// antiforense.audit_disabled, e dizer duas vezes só gasta atenção.
		if !f.Audit.Instalada || f.Audit.Desligada {
			return r
		}
		pids, desde := alvosEjanela(f)
		if len(pids) == 0 {
			return r
		}

		passos := []string{
			"sudo ausearch -m EXECVE -ts " + check.Arg(desde) + " -i | less   # o que executou na janela",
		}
		for _, pid := range pids {
			passos = append(passos, "sudo ausearch -p "+strconv.Itoa(pid)+" -i   # tudo do processo "+strconv.Itoa(pid))
		}
		passos = append(passos,
			"o que amarra o vetor: um EXECVE de sh/curl/bash cujo PAI é o processo "+
				"da aplicação prova o pulo RCE → comando",
			"e o auid liga a ação de root de volta a quem entrou — ele não muda "+
				"com su nem sudo")

		fd := self.F(check.SevManual, "auditd", "",
			"o auditd está ATIVO neste host, e ele é a fonte mais forte que existe: "+
				"grava no kernel, no momento da syscall, com ppid, auid e exe juntos",
			"esta ferramenta não consulta o log: `ausearch` é programa do host, e "+
				"executar programa do host é o que ela não faz (SPEC 4)",
			"a janela abaixo vem do processo mais antigo que esta varredura marcou")
		fd.NextSteps = passos
		r.Findings = append(r.Findings, fd)
		return r
	},
}

// logDaNuvem — runbook §10.4 e §10.5.
//
// A evidência que mais importa pode estar FORA da caixa, e é a única que o
// atacante com root no host não consegue apagar: o log de auditoria do provedor.
// A ferramenta não fala com a rede (§2.1: consulta avisa o atacante), então ela
// entrega o comando com o host e a janela dentro.
var logDaNuvem = check.Check{
	ID:      "manual.cloud_audit",
	Ref:     "10.4",
	Title:   "a evidência que o root do host não apaga está fora da caixa",
	Group:   "cloud",
	Mode:    check.ModeManual,
	Sources: env.SourceLive | env.SourceImage,
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		provedor := provedorDeNuvem(f)
		if provedor == "" {
			return r
		}
		_, desde := alvosEjanela(f)
		host := f.Host.Hostname
		if host == "" {
			host = "<instância>"
		}

		fd := self.F(check.SevManual, "log da nuvem", "",
			"este host parece ser uma instância de "+provedor+", e o log de auditoria "+
				"do provedor está FORA do alcance de quem tem root aqui dentro",
			"é a única fonte que o atacante não apaga do host — e a que responde "+
				"'a credencial da instância foi usada de fora?'",
			"esta ferramenta não fala com a rede: consultar a API avisaria o "+
				"atacante")
		switch provedor {
		case "GCP":
			fd.NextSteps = []string{
				"gcloud logging read " + check.Arg(`resource.labels.instance_id="`+host+`" AND timestamp>="`+desde+`"`) + " --limit 200",
				"gcloud logging read " + check.Arg(`protoPayload.authenticationInfo.principalEmail=~"`+host+`"`) + " --freshness=7d",
				"e o uso da credencial DA INSTÂNCIA fora dela: procure a service " +
					"account do host em chamadas que não partiram dele",
			}
		case "AWS":
			fd.NextSteps = []string{
				"aws cloudtrail lookup-events --start-time " + check.Arg(desde) + " --max-results 200",
				`aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue=<role-da-instância>`,
				"a role da instância usada de um IP que não é o dela é roubo de " +
					"credencial de metadata",
			}
		default:
			fd.NextSteps = []string{
				"puxe o log de auditoria do provedor para a janela a partir de " + desde,
				"e confira se a credencial da instância foi usada de fora dela",
			}
		}
		r.Findings = append(r.Findings, fd)
		return r
	},
}

// integridadeDoCodigo — runbook §16.
//
// Aplicação versionada em git delata adulteração na hora, e o runbook dá a
// receita — `git status`, `diff origin`, `reflog`, `fsck --lost-found`. Todos
// exigem EXECUTAR o git do host, que é o que esta ferramenta não faz: o binário
// do alvo pode ser o implante, e um `git` trojanizado responderia "limpo".
//
// Então ela faz o que sabe fazer sem executar nada: acha os repositórios e
// entrega os comandos com o caminho preenchido — inclusive os três pontos cegos
// que um `status` limpo esconde.
var integridadeDoCodigo = check.Check{
	ID:       "manual.code_integrity",
	Ref:      "16",
	Title:    "código versionado em git: a comparação que esta ferramenta não pode fazer",
	Group:    "app",
	Mode:     check.ModeManual,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		if len(f.Repos) == 0 {
			return r
		}
		repos := corta(f.Repos, 5)

		fd := self.F(check.SevManual, "integridade do código", "",
			strconv.Itoa(len(f.Repos))+" repositório(s) git sob as árvores de aplicação: "+
				strings.Join(repos, " · "),
			"um `git status` limpo NÃO significa código íntegro — ele só enxerga "+
				"alteração não commitada",
			"esta ferramenta não roda o git do host: um binário trojanizado "+
				"responderia 'limpo'")
		var passos []string
		for _, repo := range repos {
			passos = append(passos,
				"git -C "+check.Arg(repo)+" status --ignored --short   # o que o .gitignore ESCONDE do status",
				"git -C "+check.Arg(repo)+" diff origin/HEAD --stat    # a comparação autoritativa é o REMOTO",
				"git -C "+check.Arg(repo)+" reflog --date=iso | head -30  # quando o ref se moveu, na hora local",
				"git -C "+check.Arg(repo)+" fsck --lost-found 2>/dev/null | grep commit  # o que foi 'amend'-ado")
		}
		passos = append(passos,
			"os três pontos cegos do status: commitou (as datas mentem — "+
				"GIT_AUTHOR_DATE é variável de ambiente), fez amend (o histórico "+
				"foi reescrito) e usou .gitignore")
		fd.NextSteps = passos
		r.Findings = append(r.Findings, fd)
		return r
	},
}

// volumeDeSaida — runbook §37.2.
//
// "O que saiu?" é a pergunta que o cliente faz, e o host não guarda a resposta:
// ele não conta bytes por conexão. A ferramenta sabe PARA ONDE o host falou —
// isso ela mede —, e o volume está em contadores que ela não lê e em fonte que
// ela não consulta.
var volumeDeSaida = check.Check{
	ID:       "manual.exfil_volume",
	Ref:      "37.2",
	Title:    "quanto saiu: o host mediu sem querer, em lugares que esta varredura não lê",
	Group:    "net",
	Mode:     check.ModeManual,
	Sources:  env.SourceLive,
	Requires: env.CapProcfs,
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		destinos := destinosPublicosDoHost(f)
		if len(destinos) == 0 {
			return r
		}
		fd := self.F(check.SevManual, "volume de saída", "",
			"esta varredura viu conexão de saída para "+strconv.Itoa(len(destinos))+
				" endereço(s) público(s): "+strings.Join(corta(destinos, 5), " · "),
			"ela sabe PARA ONDE o host falou; não sabe QUANTO saiu — o host não "+
				"conta bytes por conexão, e a resposta está em contadores e em "+
				"fontes fora do alcance de uma varredura única",
			"e o teto do que PODE ter saído é o alcance da credencial deste host, "+
				"não o tráfego observado")
		fd.NextSteps = []string{
			"vnstat -h · sar -n DEV 1 5 · cat /proc/net/dev   # o que o host contou sem querer",
			"conntrack -L | grep -E '" + strings.Join(corta(destinos, 3), "|") + "'   # bytes por fluxo, se o conntrack estiver ativo",
			"o log do balanceador, do proxy e do provedor têm o volume REAL: eles " +
				"ficam fora do host, e o root daqui não os apaga",
			"se houver banco, a exfiltração pode não ter virado arquivo nenhum: " +
				"olhe o log de queries",
		}
		r.Findings = append(r.Findings, fd)
		return r
	},
}

// alvosEjanela devolve os PIDs que esta varredura tem motivo para investigar e o
// instante a partir do qual olhar.
//
// A janela sai do processo suspeito mais ANTIGO: é o mesmo raciocínio do âncora
// da §9 — o primeiro sinal datado é o começo do que se sabe, e não o começo do
// incidente.
func alvosEjanela(f *facts.Facts) ([]int, string) {
	var pids []int
	desde := ""
	for i := range f.Processes {
		p := &f.Processes[i]
		if p.Self || p.Vanished || p.Exe == "" {
			continue
		}
		if _, suspeito := suspectDir(p.Exe); !suspeito && !p.ExeDeleted && !p.ExeMemfd {
			continue
		}
		pids = append(pids, p.PID)
		if p.StartUTC != "" && (desde == "" || p.StartUTC < desde) {
			desde = p.StartUTC
		}
	}
	sort.Ints(pids)
	if len(pids) > 4 {
		pids = pids[:4]
	}
	if desde == "" {
		desde = "<início da janela>"
	}
	return pids, desde
}

func provedorDeNuvem(f *facts.Facts) string {
	for _, u := range f.Units {
		switch {
		case strings.HasPrefix(u.Name, "google-"):
			return "GCP"
		case strings.HasPrefix(u.Name, "amazon-"), strings.HasPrefix(u.Name, "aws-"):
			return "AWS"
		case strings.HasPrefix(u.Name, "walinuxagent"):
			return "Azure"
		}
	}
	return ""
}

func destinosPublicosDoHost(f *facts.Facts) []string {
	visto := map[string]bool{}
	var out []string
	for i := range f.Sockets {
		s := &f.Sockets[i]
		if s.Dir != facts.DirOut || s.PeerScope != facts.ScopePublic || s.State != "ESTAB" {
			continue
		}
		if !visto[s.PeerIP] {
			visto[s.PeerIP] = true
			out = append(out, s.PeerIP)
		}
	}
	sort.Strings(out)
	return out
}
