package checks

import (
	"strconv"
	"strings"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

func init() {
	check.Register(moduloSemArquivo)
	check.Register(protecaoDoKernel)
}

// moduloSemArquivo — runbook §35.3.
//
// # A pergunta
//
// A ferramenta faz esta mesma pergunta sobre binário em execução desde a fase 7:
// que ARQUIVO entregou isto? Para módulo de kernel ela nunca tinha sido feita, e
// é onde a resposta importa mais — código de módulo roda dentro do kernel, com
// acesso a tudo, e é a partir dali que todos os outros checks passam a poder
// receber mentira.
//
//	insmod /tmp/x.ko && rm /tmp/x.ko
//
// Depois disso o módulo continua carregado, `/proc/modules` continua listando, e
// não existe arquivo nenhum em disco que o explique. É a versão em kernel do
// `proc.exe_deleted`, e nenhum outro check deste catálogo a alcançava.
//
// # Por que não é sempre crítico
//
// Existe uma causa legítima e comum: atualizar o pacote do kernel REMOVE os
// arquivos dos módulos da versão antiga, e a máquina continua rodando a antiga
// até reiniciar. Todo servidor que aplica atualização sem reiniciar passa por
// esse estado — e passa nele por semanas.
//
// O que separa os dois casos é o que o PRÓPRIO KERNEL diz sobre o módulo: as
// letras de taint. Módulo da distribuição é assinado e não marca nada; `O`, `E`
// ou `F` significam fora da árvore, sem assinatura válida ou carregado à força.
// Um módulo que o kernel não reconhece como assinado E que não tem arquivo é a
// forma completa do implante.
var moduloSemArquivo = check.Check{
	ID:       "kernel.module_no_file",
	Ref:      "35.3",
	Title:    "módulo carregado sem arquivo em disco que o explique",
	Group:    "kernel",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive,
	Requires: env.CapProcfs | env.CapFilesystem,
	// A DETECÇÃO não precisa de root: /proc/modules e /lib/modules são legíveis
	// por qualquer um. O que precisa é o passo seguinte — /sys/module/<n>/sections,
	// srcversion e /proc/kcore são de root —, e sem ele o operador recebe o
	// achado sem conseguir instruí-lo. Cobertura degradada é a resposta certa
	// para isso, e é a mesma convenção dos outros checks de kernel.
	Optional: env.CapRoot,
	Wtf:      true,
	FalsePositives: []string{
		"ATUALIZAÇÃO DE KERNEL sem reboot é a causa legítima mais comum: o pacote " +
			"novo remove os .ko da versão antiga, e a máquina segue rodando a " +
			"antiga por semanas. O módulo continua carregado e o arquivo já não " +
			"existe — sem nada de errado acontecendo",
		"módulo compilado à mão e carregado direto do diretório de build, sem " +
			"instalar: é o que todo desenvolvimento de driver faz",
		"a comparação é por NOME, e o nome é escolha de quem compilou: um " +
			"implante que se chame `ext4` casa com o arquivo do ext4 e não " +
			"aparece aqui. Este check pega quem não se deu esse trabalho",
		"árvore de módulos em caminho fora do padrão (nem /lib/modules nem " +
			"/usr/lib/modules) faria todo módulo parecer sem arquivo — por isso a " +
			"ausência da árvore vira cobertura degradada, e não achado",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result

		// EM CONTÊINER ISTO NÃO PODE SER PERGUNTADO: o /proc/modules que se lê
		// aqui dentro é o do HOST — contêiner compartilha o kernel —, enquanto
		// /lib/modules é o da IMAGEM, quase sempre vazio. Comparar os dois
		// acusaria todos os módulos do host de uma vez, com toda a confiança.
		//
		// E o silêncio aqui NÃO é lacuna de cobertura. A distinção é a mesma que
		// o proc.container_boundary já pagou para aprender: marcar parcial faria
		// TODA varredura feita dentro de contêiner sair incompleta e com exit 1,
		// inclusive a de um contêiner limpo. Não é "não consegui olhar" nem "não
		// encontrei" — é "esta pergunta é sobre o HOST, e esta execução fala
		// sobre o contêiner". Quem declara esse escopo é o boundary, uma vez,
		// em vez de N checks o repetirem como degradação.
		if f.Host.EmContainer {
			return r
		}
		// Sem a árvore lida, ausência de arquivo não significa ausência: significa
		// que ninguém olhou. O coletor já declarou o motivo — e só o declara
		// quando há módulo carregado, porque sem módulo não há pergunta.
		if !f.ArvoreDeModulos {
			r.Partial = append(r.Partial, f.Partial["modulo"]...)
			return r
		}
		r.Partial = append(r.Partial, f.Partial["modulo"]...)

		for i := range f.Carregados {
			m := &f.Carregados[i]
			if !m.SemArquivo() {
				continue
			}

			sev := check.SevWarn
			porque := "nenhum arquivo .ko com este nome existe em /lib/modules: o " +
				"código está dentro do kernel e o que o entregou não está em disco"
			if m.NaoAssinado() {
				// O kernel está dizendo que este módulo não veio do conjunto
				// assinado da distribuição, E não há arquivo. As duas coisas
				// juntas não têm explicação de rotina.
				sev = check.SevCritical
				porque = "o próprio kernel marcou este módulo como " +
					descreveTaint(m.Letras) + ", E não há arquivo em disco que o " +
					"explique: a atualização de kernel sem reboot não produz isso"
			}

			ev := []string{
				porque,
				"módulo=" + m.Nome + " tamanho=" + strconv.Itoa(m.Tamanho) +
					" refs=" + strconv.Itoa(m.Refs) + nz2(" estado=", m.Estado) +
					nz2(" taint=", m.Letras),
			}
			if !m.NoSys {
				ev = append(ev, "e ele NÃO aparece em /sys/module: as duas interfaces "+
					"do kernel discordam sobre a existência dele (§35.5)")
			}
			ev = append(ev, contextoDeProtecao(f)...)

			fd := self.F(sev, "módulo "+m.Nome, "", ev...)
			fd.Ator = "módulo " + m.Nome
			// Irreversível: `rmmod` descarrega o módulo e o código sai da memória
			// do kernel para sempre. Não há como copiá-lo depois.
			fd.Irreversible = true
			fd.NextSteps = []string{
				"NÃO descarregue antes de preservar: o código só existe dentro do " +
					"kernel, e o rmmod o destrói (runbook §19)",
				"sudo cp /proc/kcore \"$IR/\"   # o kernel inteiro, se houver espaço; " +
					"a região do módulo está em /sys/module/" + m.Nome + "/sections/",
				"sudo cat /sys/module/" + m.Nome + "/sections/.text   # onde ele foi carregado",
				"a partir daqui, a análise honesta é DE FORA: um módulo hostil " +
					"mente para todos os outros checks (runbook §35.6)",
			}
			r.Findings = append(r.Findings, fd)
		}
		return r
	},
}

// descreveTaint traduz as letras que importam para este check. O resto do
// alfabeto de taint tem check próprio (kernel.taint_unexplained).
func descreveTaint(letras string) string {
	var ps []string
	if strings.Contains(letras, "O") {
		ps = append(ps, "construído FORA da árvore do kernel")
	}
	if strings.Contains(letras, "E") {
		ps = append(ps, "SEM assinatura válida")
	}
	if strings.Contains(letras, "F") {
		ps = append(ps, "carregado À FORÇA, ignorando a checagem de versão")
	}
	return strings.Join(ps, " e ")
}

// contextoDeProtecao acrescenta ao achado o que o kernel deixa acontecer com ele
// mesmo. Não é enfeite: num host que exige assinatura, um módulo sem arquivo e
// sem assinatura só entrou porque alguém desligou algo — e isso muda o que o
// respondedor vai procurar em seguida.
func contextoDeProtecao(f *facts.Facts) []string {
	p := f.Protecao
	var out []string
	switch p.SigEnforce {
	case "Y":
		out = append(out, "este kernel EXIGE assinatura de módulo (sig_enforce=Y): "+
			"o que está carregado passou por essa verificação, ou ela foi contornada")
	case "N":
		out = append(out, "este kernel NÃO exige assinatura de módulo "+
			"(sig_enforce=N): qualquer .ko compatível carrega")
	}
	if p.Lockdown != "" && p.Lockdown != "none" {
		out = append(out, "lockdown do kernel em modo "+p.Lockdown)
	}
	if p.ModulesDisabled == "1" {
		out = append(out, "o carregamento de módulos está TRANCADO agora "+
			"(modules_disabled=1): isto foi carregado ANTES da tranca")
	}
	return out
}

func nz2(prefixo, v string) string {
	if v == "" {
		return ""
	}
	return prefixo + v
}

// protecaoDoKernel — runbook §34, e a entrada do `readiness`.
//
// Não é achado: é o inventário do que este kernel permite a si mesmo. Sai como
// INFO porque a pergunta que ele responde não é "há algo errado?", e sim "o que
// eu posso concluir do que os outros checks disseram?".
//
// Um exemplo do porquê: `kernel.module_no_file` num host com `sig_enforce=Y` e
// num host sem trava nenhuma são o mesmo achado com pesos muito diferentes. Sem
// este bloco, o respondedor teria de ir levantar isso à mão — no meio do
// incidente, no host que ele não conhece.
var protecaoDoKernel = check.Check{
	ID:       "kernel.protection_context",
	Ref:      "34",
	Title:    "o que este kernel permite a si mesmo: assinatura, lockdown, IMA",
	Group:    "kernel",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive,
	Requires: env.CapProcfs,
	// Sem root, lockdown, IMA e o efivar do Secure Boot são ilegíveis: o
	// inventário sai menor, e a cobertura precisa dizer isso.
	Optional: env.CapRoot,
	FalsePositives: []string{
		"não é achado: é contexto. Nenhuma das linhas aqui indica comprometimento " +
			"sozinha — elas dizem o que o kernel permite, e é isso que dá peso aos " +
			"achados de módulo e de eBPF",
		"ausência de lockdown e de IMA é o PADRÃO da maioria das distribuições: " +
			"não é configuração errada, é o que vem de fábrica",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		p := f.Protecao

		// Nada lido não vira inventário de "não determinado": vira lacuna. Seis
		// linhas dizendo "não sei" gastam a atenção do operador e não entregam
		// contexto nenhum — e é isto que mantém o check calado sobre uma coleta
		// que não alcançou o kernel.
		if !p.Lido() {
			r.Partial = append(r.Partial, "nenhum dos parâmetros de proteção do "+
				"kernel pôde ser lido: o contexto que pesa os achados de módulo e "+
				"de eBPF não está disponível nesta execução")
			return r
		}

		ev := []string{
			"assinatura de módulo obrigatória: " + simNaoOuDesconhecido(p.SigEnforce, "Y"),
			"carregamento de módulo trancado: " + simNaoOuDesconhecido(p.ModulesDisabled, "1"),
			"lockdown: " + nzTexto(p.Lockdown, "não disponível neste kernel"),
			"IMA (medição de integridade): " + simNao(p.IMA),
			"Secure Boot: " + nzTexto(p.SecureBoot, "não determinado (sem EFI, ou sem privilégio)"),
			"ptrace_scope=" + nzTexto(p.PtraceScope, "?") +
				" · kptr_restrict=" + nzTexto(p.KptrRestrict, "?") +
				" · dmesg_restrict=" + nzTexto(p.DmesgRestrict, "?") +
				" · unprivileged_bpf_disabled=" + nzTexto(p.UnprivBPF, "?"),
		}
		if !p.SecurityFS {
			// Declarar em vez de montar: a ferramenta é read-only, e montar um
			// filesystem para responder a uma pergunta alteraria o host.
			// Dito no PRÓPRIO inventário, e não como cobertura degradada: quem
			// lê este bloco está lendo justamente a lista do que o kernel
			// permite, e a linha que falta aparece ali, na frente dele. Degradar
			// a cobertura por isso marcaria como incompleta toda execução em
			// contêiner e em guest mínimo — gastando a mesma atenção que uma
			// lacuna de verdade, por uma ausência que já está escrita.
			ev = append(ev, "/sys/kernel/security NÃO está montado: lockdown e IMA "+
				"não puderam ser lidos. Esta ferramenta não monta nada para descobrir")
		}
		for _, n := range p.NaoLidos {
			r.Partial = append(r.Partial, "ilegível: "+n)
		}

		fd := self.F(check.SevInfo, "kernel", "", ev...)
		r.Findings = append(r.Findings, fd)
		return r
	},
}

func simNao(b bool) string {
	if b {
		return "sim"
	}
	return "não"
}

func simNaoOuDesconhecido(v, sim string) string {
	switch v {
	case "":
		return "não determinado"
	case sim:
		return "SIM"
	}
	return "não"
}

func nzTexto(v, padrao string) string {
	if v == "" {
		return padrao
	}
	return v
}
