package checks

import (
	"strconv"
	"strings"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

func init() { check.Register(auditoriaNeutralizada) }

// auditoriaNeutralizada — runbook §21.
//
// Não é uma pergunta sobre ataque. É a que vem ANTES de todas as outras numa
// resposta a incidente:
//
//	este host consegue dizer o que foi executado antes desta varredura?
//
// Sem regra de auditoria, o kernel não emite registro de execução nenhum. Não é
// uma defesa a menos — é a investigação cega para todo o passado, e a diferença
// entre reconstruir o incidente e adivinhá-lo.
//
// O check separa TRÊS estados que parecem o mesmo no relatório e não são:
//
//	nunca teve             não há configuração. É LIMITE da investigação,
//	                       não acusação de ninguém
//	instalado sem regra    o pacote veio com a distribuição e ninguém escreveu
//	                       regra. Mesmo limite, e é o estado de fábrica
//	tinha e perdeu         havia regra e alguém a neutralizou. Aí é achado,
//	                       porque quem apaga a trilha começa pela origem dela
//
// Confundir os dois primeiros com o terceiro é o erro que faria este check
// gritar em metade dos servidores do mundo — auditoria não é padrão em quase
// nenhuma distribuição, e várias das que trazem o pacote não o configuram.
var auditoriaNeutralizada = check.Check{
	ID:       "antiforense.audit_disabled",
	Ref:      "11",
	Title:    "capacidade de registrar execução neste host",
	Group:    "persist",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Optional: env.CapRoot,
	// Não é indicador de incêndio: é contexto para investigar, e o mesmo
	// critério dos inventários de login e de credencial.
	Wtf: false,
	FalsePositives: []string{
		"AUDITORIA NÃO É PADRÃO em quase nenhuma distribuição, e contêiner nunca " +
			"tem. Por isso 'nunca teve' sai como informação sobre o LIMITE da " +
			"investigação, e não como achado — dizer o contrário faria este check " +
			"gritar em metade dos servidores que existem",
		"regra que vigia só escrita em arquivo é uso legítimo e comum (PCI, " +
			"LGPD): ela não cobre execução, e o check diz isso em vez de contar " +
			"como se cobrisse",
		"`-e 2` trava as regras até o reboot e é RECOMENDADO em guia de " +
			"endurecimento — não é o mesmo que `-e 0`, que desliga",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		// A lacuna do coletor entra ANTES de qualquer saída — o padrão de
		// checks/bpf.go. Esta chave era EMITIDA pelo coletor e lida por check
		// nenhum: como o motor conta Coverage.Complete++ quando res.Partial
		// está vazio, o check saía COMPLETO sobre uma fonte que o coletor
		// tinha declarado ilegível.
		r.Partial = append(r.Partial, f.PersistDenied["audit"]...)
		a := &f.Audit

		// NUNCA TEVE, OU TEVE E NUNCA CONFIGUROU: nada é dito, e isso é
		// deliberado.
		//
		// A tentação era informar "este host não registra execução" como limite
		// da investigação. É verdade, e não vale uma linha por host: auditoria
		// não é padrão em quase nenhuma distribuição, então a linha apareceria
		// em praticamente todo host do mundo — e uma advertência que sai sempre
		// é papel de parede, não informação.
		//
		// A ferramenta JÁ diz, em toda varredura limpa, que o resultado não
		// prova host limpo. Repetir a mesma ressalva por outro caminho não
		// acrescenta nada.
		//
		// E há um limite de conhecimento junto: regra DELETADA e regra nunca
		// escrita são indistinguíveis em disco. Acusar sem poder separar as duas
		// seria acusar no escuro.
		if !a.Instalada || len(a.Regras) == 0 {
			return r
		}

		// TINHA E PERDEU: aqui é achado.
		if a.Desligada {
			var onde []string
			for _, g := range a.Regras {
				if campos := strings.Fields(g.Texto); len(campos) >= 2 &&
					campos[0] == "-e" && campos[1] == "0" {
					onde = append(onde, g.Arquivo+":"+strconv.Itoa(g.Linha))
				}
			}
			fd := self.F(check.SevCritical, "auditoria desligada", "",
				"`-e 0` desabilita o subsistema inteiro: "+strings.Join(onde, " "),
				"a configuração continua no lugar e as regras continuam escritas — "+
					"nada é registrado, e quem só verificar se o arquivo existe não "+
					"vê diferença",
				"o host TEM auditoria instalada, e alguém a desligou: é a origem da "+
					"trilha, e quem apaga rastro começa por ela",
				strconv.Itoa(len(a.Regras))+" regra(s) escritas, e nenhuma vale "+
					"enquanto isto estiver aqui",
				"NÃO religue antes de preservar: `auditctl -e 1` muda justamente o "+
					"estado que É a evidência",
			)
			fd.Irreversible = true
			fd.NextSteps = []string{
				"o ctime do arquivo data o desligamento",
				"tudo que aconteceu depois dessa data não tem registro de execução",
				"NÃO religue antes de preservar: `auditctl -e 1` muda o estado que " +
					"é a própria evidência",
			}
			r.Findings = append(r.Findings, fd)
			return r
		}

		// INSTALADA E SEM COBRIR EXECUÇÃO: meio caminho, e ele engana.
		if !a.CobreExec {
			fd := self.F(check.SevWarn, "auditoria sem execve", "",
				"há "+strconv.Itoa(len(a.Regras))+" regra(s), e nenhuma registra "+
					"execução",
				"vigiar escrita em arquivo é uso legítimo e comum — mas não responde "+
					"'o que rodou', e um host assim é tão cego quanto um sem regra "+
					"nenhuma para reconstruir execução",
				"a presença do auditd faz parecer que há trilha: é justamente por "+
					"isso que vale dizer que não há",
			)
			fd.NextSteps = []string{
				"confirme com o time se a ausência de regra de execve é deliberada",
			}
			r.Findings = append(r.Findings, fd)
		}
		return r
	},
}
