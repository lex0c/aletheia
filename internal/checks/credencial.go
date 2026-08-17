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
	check.Register(chavePrivadaSemSenha)
	check.Register(alcanceDoHost)
	check.Register(historicoDesligado)
}

// chavePrivadaSemSenha — runbook §7.5, §23.
//
// A ferramenta já lia `authorized_keys`, que responde quem ENTRA neste host.
// Faltava o caminho inverso, e ele importa tanto quanto: uma chave privada diz
// para onde este host CONSEGUE ir.
//
// Sem senha, ela é credencial de movimento lateral largada aberta. Quem lê o
// arquivo já pode usá-la — não precisa quebrar nada, não precisa de sessão, não
// deixa tentativa registrada em lugar nenhum. Um invasor que chegou aqui herda
// tudo que essa chave alcança.
var chavePrivadaSemSenha = check.Check{
	ID:       "cred.ssh_private_key",
	Ref:      "7.5",
	Title:    "chave SSH privada em disco: para onde este host consegue ir",
	Group:    "priv",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Optional: env.CapRoot,
	Wtf:      false, // é alcance, não incêndio: orienta a §23, não a §19
	FalsePositives: []string{
		"CHAVE SEM SENHA É A NORMA em automação: deploy, backup e provisionamento " +
			"precisam de chave que o processo use sozinho, e não há quem digite " +
			"nada. O achado descreve ALCANCE, não erro — a pergunta é se aquele " +
			"alcance é aceitável para um host comprometido",
		"chave de HOST (/etc/ssh/ssh_host_*) é sempre sem senha por desenho: o " +
			"sshd sobe no boot. Elas são reconhecidas e não entram",
		"sem root, o ~/.ssh de outros usuários é ilegível e as chaves deles não " +
			"aparecem — a cobertura diz quando foi esse o caso",
		"LIMITE de escopo: só ~/.ssh e /etc/ssh são examinados. Uma chave " +
			"copiada para /tmp ou para a raiz de um site NÃO é encontrada, e é " +
			"justamente ali que ela indicaria preparação de exfiltração",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		for i := range f.ChavesPrivadas {
			c := &f.ChavesPrivadas[i]
			if c.DeHost {
				continue
			}

			ev := []string{
				c.Path + " (" + c.Tipo + ")",
			}
			sev := check.SevManual
			if c.Cifrada {
				ev = append(ev, "protegida por senha: usá-la exige algo que não está "+
					"neste disco")
			} else {
				sev = check.SevWarn
				ev = append(ev, "SEM SENHA: quem lê este arquivo já pode usá-la — não "+
					"precisa quebrar nada e não deixa tentativa registrada em lugar "+
					"nenhum")
			}
			if c.ModUTC != "" {
				ev = append(ev, "modificada em "+c.ModUTC)
			}
			ev = append(ev, "o alcance dela é o que um invasor herda ao chegar aqui "+
				"(runbook §23)")

			fd := self.F(sev, c.Path, "", ev...)
			fd.NextSteps = []string{
				"descubra ONDE esta chave entra: a pública correspondente está no " +
					"`authorized_keys` dos destinos",
				"se o host for tratado como comprometido, a chave também é: " +
					"rotacione antes de reconectar qualquer coisa",
			}
			r.Findings = append(r.Findings, fd)
		}
		r.Partial = append(r.Partial, f.PersistDenied["ssh"]...)
		return r
	},
}

// alcanceDoHost — runbook §23.
//
// Dezenas de evidências desta ferramenta terminam em "procure a mesma coisa na
// frota" sem dizer QUAIS máquinas procurar. O `known_hosts` diz: é a lista de
// para onde este host já foi.
//
// Não é achado — é o tamanho do problema. Um servidor de aplicação com três
// destinos e um bastion com quatrocentos são incidentes de escalas diferentes,
// e a diferença aparece aqui e em nenhum outro lugar.
var alcanceDoHost = check.Check{
	ID:       "cred.known_hosts",
	Ref:      "23",
	Title:    "alcance deste host: para onde ele já se conectou",
	Group:    "priv",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Optional: env.CapRoot,
	Wtf:      false,
	FalsePositives: []string{
		"não é achado: é o raio de alcance, para dimensionar a §23. Um bastion " +
			"tem centenas de destinos legitimamente",
		"`HashKnownHosts` embaralha o nome do destino, e é o padrão em várias " +
			"distribuições. Nessas o destino não é recuperável — mas a CONTAGEM " +
			"continua dizendo o tamanho do alcance",
		"o arquivo registra para onde alguém se conectou DESTE host, não o que " +
			"este host aceita: quem entra está no authorized_keys",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		if len(f.Destinos) == 0 {
			r.Partial = append(r.Partial, f.PersistDenied["ssh"]...)
			return r
		}

		porArquivo := map[string][]facts.DestinoConhecido{}
		for i := range f.Destinos {
			d := &f.Destinos[i]
			porArquivo[d.Arquivo] = append(porArquivo[d.Arquivo], *d)
		}
		arquivos := make([]string, 0, len(porArquivo))
		for a := range porArquivo {
			arquivos = append(arquivos, a)
		}
		sort.Strings(arquivos)

		for _, a := range arquivos {
			ds := porArquivo[a]
			var nomes []string
			var hasheados int
			for _, d := range ds {
				if d.Hasheado {
					hasheados++
					continue
				}
				nomes = append(nomes, d.Host)
			}
			sort.Strings(nomes)
			if len(nomes) > 10 {
				nomes = append(nomes[:10:10], "…")
			}

			ev := []string{
				strconv.Itoa(len(ds)) + " destino(s) registrado(s)",
			}
			if len(nomes) > 0 {
				ev = append(ev, strings.Join(nomes, " · "))
			}
			if hasheados > 0 {
				ev = append(ev, strconv.Itoa(hasheados)+" com nome embaralhado "+
					"(HashKnownHosts): o destino não volta, mas a contagem continua "+
					"dizendo o tamanho do alcance")
			}
			ev = append(ev, "é isto que dimensiona a busca na frota: um invasor que "+
				"chegou aqui herda o caminho para cada um deles (runbook §23)")

			fd := self.F(check.SevManual, a, "", ev...)
			fd.NextSteps = []string{
				"cada destino precisa ser varrido também, e com a MESMA janela de " +
					"tempo (runbook §23)",
			}
			r.Findings = append(r.Findings, fd)
		}
		r.Partial = append(r.Partial, f.PersistDenied["ssh"]...)
		return r
	},
}

// historicoDesligado — runbook §13, §21.
//
// ANTI-FORENSE, e é uma categoria que nenhum outro check desta ferramenta
// cobria. O achado aqui não é o implante: é a AUSÊNCIA DELIBERADA de rastro.
//
// Ninguém aponta `.bash_history` para /dev/null por acidente. Ninguém escreve
// `unset HISTFILE` no `.bashrc` sem querer. São as formas mais baratas de
// apagar o próprio caminho — custam uma linha — e quem as usa estava contando
// que alguém fosse procurar.
//
// O que a ferramenta NÃO faz é ler o conteúdo do histórico. Julgar comando por
// comando é trabalho humano e cheio de falso positivo; dizer que o registro foi
// DESLIGADO é objetivo.
var historicoDesligado = check.Check{
	ID:       "antiforense.shell_history",
	Ref:      "21",
	Title:    "histórico de shell desligado ou desviado: rastro apagado de propósito",
	Group:    "persist",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Optional: env.CapRoot,
	Wtf:      true,
	FalsePositives: []string{
		"HIGIENE LEGÍTIMA existe: gente que digita segredo no terminal desliga o " +
			"histórico de propósito, e há guia de endurecimento que recomenda " +
			"isso. O que muda é QUEM fez e QUANDO — pergunta para o time",
		"conta de serviço com shell não interativo nunca grava histórico, e um " +
			"arquivo vazio ali é o normal e não aparece aqui",
		"imagem de contêiner costuma vir com HISTFILE desabilitado para não " +
			"gravar camada, e isso é do construtor da imagem",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result

		// O DESVIO é a forma mais direta: o arquivo aponta para o vazio.
		for i := range f.Historicos {
			h := &f.Historicos[i]
			if h.Desviado == "" {
				continue
			}
			ev := []string{
				h.Path + " aponta para " + h.Desviado,
				"nada do que for digitado é gravado, e o arquivo continua existindo " +
					"para quem só olhar se ele está lá",
				"conta: " + nz(h.User, "?"),
			}
			sev := check.SevWarn
			if strings.Contains(h.Desviado, "null") {
				sev = check.SevCritical
				ev = append(ev, "o destino é o dispositivo nulo: isto não tem uso "+
					"legítimo que não seja não deixar rastro")
			}
			fd := self.F(sev, h.Path, "", ev...)
			fd.Irreversible = true
			fd.NextSteps = []string{
				"o que já foi digitado NÃO está aqui: procure em wtmp, no journal e " +
					"no que a auditoria tiver (runbook §13)",
				"o ctime do link data a decisão de apagar o rastro (runbook §9)",
			}
			r.Findings = append(r.Findings, fd)
		}

		// E o DESLIGAMENTO, que mora no arquivo de inicialização do shell.
		for i := range f.Triggers {
			t := &f.Triggers[i]
			if t.Kind != "shell" {
				continue
			}
			for _, ln := range t.Lines {
				motivo, ok := facts.DesligaHistorico(ln.Text)
				if !ok {
					continue
				}
				ev := []string{
					ln.Text,
					motivo,
					"arquivo: " + t.File + ":" + strconv.Itoa(ln.N),
					"QUANDO vale: " + t.When,
					"escrever isto exige intenção — não há como digitar por engano",
				}
				if ln.Added {
					ev = append(ev, "e a linha NÃO existe no esqueleto que a "+
						"distribuição copia para cada home: foi acrescentada depois")
				}
				fd := self.F(check.SevWarn, t.File, "", ev...)
				fd.NextSteps = []string{
					"o ctime do arquivo data a inserção (runbook §9)",
					"pergunte ao time: desligar histórico é prática de quem digita " +
						"segredo, e também de quem não quer deixar rastro",
				}
				r.Findings = append(r.Findings, fd)
			}
		}

		r.Partial = append(r.Partial, f.PersistDenied["startup"]...)
		return r
	},
}
