package checks

import (
	"sort"
	"strconv"
	"strings"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

func init() { check.Register(persistRedundant) }

// persistRedundant — runbook §7, §19.
//
// O check que uma cadeia de invasão REAL expôs como faltando.
//
// Uma varredura contra uma comprometida completa — chave SSH, payload em
// /usr/local/sbin com nome plausível, unit habilitada, @reboot no cron e linha
// no .bashrc, tudo apontando para o mesmo binário — saía `RESULT: OK`. Cada
// mecanismo, isolado, parecia legítimo: o caminho é de sistema, o nome imita um
// serviço, o comando não baixa nada.
//
// O que NÃO parecia legítimo era a redundância. Software instalado por pacote
// se agenda de UM jeito. Quem se persiste de três jeitos diferentes está se
// protegendo contra a sua limpeza — e é por isso que a §19 manda remover a
// persistência ANTES de matar o processo.
//
// O sinal é ESTRUTURAL: não olha nome, caminho nem conteúdo. Renomear o binário,
// movê-lo para outro diretório de sistema ou trocar o payload não muda nada —
// continuam sendo três gatilhos apontando para o mesmo lugar.
var persistRedundant = check.Check{
	ID:       "correlate.persistence_redundant",
	Ref:      "7",
	Title:    "o mesmo alvo persistido por vários mecanismos diferentes",
	Group:    "persist",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Wtf:      true,
	FalsePositives: []string{
		"há um caso legítimo clássico: ferramenta que oferece timer de systemd E " +
			"linha de cron como alternativa, para funcionar nos dois mundos — o " +
			"certbot faz exatamente isso. São DOIS mecanismos, e por isso dois " +
			"saem como aviso e três ou mais saem como crítico",
		"pacote que instala unit e também script em /etc/init.d durante a " +
			"transição do SysV é PULADO: o alvo tem dono de pacote, e o rsyslogd " +
			"de qualquer Ubuntu cai exatamente nessa forma. Onde a base de " +
			"pacotes não pode ser consultada, o achado sai dizendo isso",
		"o check compara CAMINHO ABSOLUTO: comando resolvido pelo PATH não é " +
			"comparável e fica de fora",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result

		// alvo -> mecanismo -> onde. O mapa é por MECANISMO, não por
		// ocorrência: duas units apontando para o mesmo binário é uma unit e
		// sua cópia, não redundância.
		refs := map[string]map[string][]string{}
		add := func(alvo, mecanismo, onde string) {
			if !pareceCaminho(alvo) {
				return
			}
			if refs[alvo] == nil {
				refs[alvo] = map[string][]string{}
			}
			refs[alvo][mecanismo] = append(refs[alvo][mecanismo], onde)
		}

		for i := range f.Units {
			u := &f.Units[i]
			mec := "unit de systemd"
			if u.DropInFor != "" {
				mec = "drop-in de systemd"
			}
			for _, ex := range u.Exec {
				add(primeiroCaminho(ex.Cmd), mec, u.Name+" ("+ex.Key+")")
			}
		}
		for i := range f.Cron {
			c := &f.Cron[i]
			mec := "cron"
			if c.Kind == "at" {
				mec = "at"
			}
			add(primeiroCaminho(c.Cmd), mec, baseDe(c.File)+" — "+nz(c.Schedule, "at"))
		}
		for i := range f.Triggers {
			t := &f.Triggers[i]
			mec := mecanismoDoTrigger(t.Kind)
			for _, ln := range t.Lines {
				add(primeiroCaminho(linhaExecutavel(ln.Text)), mec,
					t.File+":"+strconv.Itoa(ln.N))
			}
		}

		// Ordem estável: sem isso o relatório muda de forma entre execuções
		// idênticas, e a agregação de frota passa a ver diferença onde não há.
		alvos := make([]string, 0, len(refs))
		for a := range refs {
			alvos = append(alvos, a)
		}
		sort.Strings(alvos)

		// Propriedade de pacote é o discriminador: distribuição em transição do
		// SysV entrega unit E script de init.d para o MESMO binário, e o
		// rsyslogd de qualquer Ubuntu 14.04 cai exatamente aqui.
		//
		// Quando NÃO dá para perguntar (rpm, host sem base), o achado sai
		// mesmo assim dizendo que a propriedade não foi confirmada — suprimir
		// por ignorância seria pior que o ruído.
		dono := map[string]bool{}
		for _, o := range f.Ownership {
			dono[o.Path] = o.Owned
		}

		for _, alvo := range alvos {
			porMec := refs[alvo]
			if len(porMec) < 2 {
				continue
			}
			if dono[alvo] {
				continue
			}
			mecs := make([]string, 0, len(porMec))
			for m := range porMec {
				mecs = append(mecs, m)
			}
			sort.Strings(mecs)

			sev := check.SevWarn
			if len(mecs) >= 3 {
				// Três é onde a explicação legítima acaba: ninguém instala a
				// mesma coisa por três caminhos por acidente.
				sev = check.SevCritical
			}

			ev := []string{
				strconv.Itoa(len(mecs)) + " mecanismos de persistência apontam para " + alvo,
			}
			for _, m := range mecs {
				ev = append(ev, "  "+m+": "+strings.Join(porMec[m], " · "))
			}
			ev = append(ev, "software de pacote se agenda de UM jeito. Persistir-se de "+
				"vários é proteção contra a SUA limpeza (runbook §19)")
			if !f.Pkg.Consultavel {
				ev = append(ev, "atenção: não foi possível confirmar se algum pacote "+
					"reivindica este alvo ("+f.Pkg.Motivo+")")
			}

			// Se o binário também está rodando, o achado deixa de ser sobre
			// disco e passa a ser sobre agora.
			if pids := pidsComExe(f, alvo); len(pids) > 0 {
				ev = append(ev, "e está EM EXECUÇÃO: "+strings.Join(pids, " "))
			}

			fd := self.F(sev, alvo, "", ev...)
			fd.NextSteps = []string{
				"remova TODOS os mecanismos antes de matar o processo: sobrando um, " +
					"ele volta (runbook §19)",
				"a lista acima é o roteiro de limpeza — e depois dela, `atq` (runbook §7.4)",
				"sudo cp " + alvo + " \"$IR/\"   # o binário é a amostra (runbook §6)",
			}
			fd.Irreversible = true
			r.Findings = append(r.Findings, fd)
		}
		for _, cat := range []string{"unit", "cron", "startup", "githook"} {
			r.Partial = append(r.Partial, f.PersistDenied[cat]...)
		}
		return r
	},
}

// mecanismoDoTrigger traduz o tipo interno para o nome que o operador reconhece
// — e que diz ONDE ele precisa mexer para limpar.
func mecanismoDoTrigger(kind string) string {
	switch kind {
	case "shell":
		return "inicialização de shell"
	case "rc":
		return "rc.local"
	case "initd":
		return "init.d"
	case "motd":
		return "MOTD"
	case "ssh_rc":
		return "sshrc"
	case "pkg_hook":
		return "hook de pacote"
	case "generator":
		return "generator de systemd"
	case "cron_script":
		return "script de diretório do cron"
	case "git_hook":
		return "hook de git"
	case "mail":
		return "alias de e-mail"
	case "supervisor":
		return "supervisor de processo"
	case "pam":
		return "PAM"
	case "udev":
		return "udev"
	default:
		return kind
	}
}

// primeiroCaminho devolve o caminho absoluto executado, sem os prefixos que o
// systemd aceita. Comando resolvido pelo PATH devolve vazio: sem caminho
// absoluto não há como afirmar que dois gatilhos apontam para o MESMO alvo.
func primeiroCaminho(cmd string) string {
	return strings.TrimLeft(firstToken(cmd), "-@+!:")
}

func pidsComExe(f *facts.Facts, exe string) []string {
	var out []string
	for i := range f.Processes {
		p := &f.Processes[i]
		if p.Exe == exe && !p.Self {
			out = append(out, "pid="+strconv.Itoa(p.PID))
			if len(out) >= 5 {
				break
			}
		}
	}
	return out
}
