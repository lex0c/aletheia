package checks

import (
	"strings"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

func init() { check.Register(cmdlineEnfraquecida) }

// cmdlineEnfraquecida — runbook §35.7.
//
// # A camada anterior a toda a §7
//
// Os outros checks de persistência perguntam o que faz este host EXECUTAR
// alguma coisa: unit, cron, perfil de shell, hook de pacote. A linha de boot
// responde uma pergunta anterior — com que REGRAS o kernel sobe. Um parâmetro
// ali decide se módulo precisa de assinatura, se o LSM confina alguém, se a
// auditoria grava desde o primeiro segundo e qual programa vira o PID 1.
//
// Nada disso deixa rastro em unit, em cron ou em log de aplicação. Deixa rastro
// em uma linha de um arquivo de texto, e o gatilho é o reboot.
//
// # Por que ele não é um scanner de hardening
//
// "SELinux desligado" sozinho é postura, não incidente: metade dos servidores
// roda assim de propósito, e um check que acusasse isso seria ruído em toda
// frota. O que esta ferramenta acrescenta são duas confrontações que um
// scanner de configuração não faz:
//
//	rodando × configurado   o parâmetro que está valendo AGORA e não está na
//	                        configuração não sobrevive a um reboot: alguém
//	                        subiu este kernel assim. O contrário — configurado
//	                        e ainda não valendo — é a proteção que cai no
//	                        próximo boot
//	pedido × efeito         o kernel já foi perguntado sobre lockdown, sobre
//	                        assinatura de módulo e sobre SELinux. Dizer "a
//	                        linha pede X" junto de "o kernel reporta Y" é o que
//	                        separa intenção de efeito
//
// # Severidade
//
// WARN para controle desligado, INFO para mitigação de CPU e ASLR — que é
// afinação de desempenho em host normal e não indica incidente. CRITICAL fica
// só para o `init=`, e pelo motivo de sempre: ali o kernel executa um programa
// como PID 1, e a pergunta "que pacote entregou este arquivo?" tem resposta.
var cmdlineEnfraquecida = check.Check{
	ID:       "persist.kernel_cmdline_weakening",
	Ref:      "35.7",
	Title:    "a linha de boot do kernel desliga uma proteção",
	Group:    "persist",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Optional: env.CapRoot | env.CapPkgDB,
	Wtf:      true,
	FalsePositives: []string{
		"POSTURA DE FÁBRICA não é ataque: distribuição sem SELinux nem AppArmor, " +
			"host afinado com `mitigations=off` e laboratório com `nokaslr` existem " +
			"e são a norma em parte das frotas — por isso a mitigação sai como INFO",
		"provisionamento (Ansible, cloud-init, imagem dourada) põe estes mesmos " +
			"parâmetros na configuração de propósito: o mesmo valor em vários hosts " +
			"da frota é provisionamento, num só é alteração",
		"BOOT SEM BOOTLOADER — QEMU com `-append`, iPXE, kexec, contêiner — não " +
			"tem configuração para comparar. A divergência só é afirmada quando " +
			"alguma configuração foi de fato LIDA; sem ela o que sai é a linha " +
			"rodando, sozinha, e dita como tal. Ausência de configuração NÃO " +
			"derruba a cobertura: nesses ambientes ela nunca existiria, e chamar " +
			"isso de lacuna faria todo host limpo ali sair INCOMPLETE. O que " +
			"derruba é configuração que EXISTE e não abriu",
		"`init=` legítimo existe: initramfs e algumas distribuições o passam " +
			"apontando para o próprio systemd. O que dispara é o alvo estar em " +
			"diretório gravável ou nenhum pacote reivindicá-lo",
		"em modo image não há /proc/cmdline: só a configuração é avaliada, e o " +
			"que estava valendo no host vivo não pôde ser comparado",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result

		var rodando string
		var temRodando bool
		var configs []facts.LinhaDeBoot
		for _, b := range f.Boot {
			if b.Rodando {
				rodando, temRodando = b.Valor, true
				continue
			}
			configs = append(configs, b)
		}

		if !temRodando && len(configs) == 0 {
			// Nem uma fonte nem outra. NÃO é "nada enfraquecido": é não ter
			// olhado, e a diferença é o motivo desta ferramenta existir.
			r.Partial = append(r.Partial, "nenhuma linha de boot pôde ser lida — "+
				"nem /proc/cmdline nem configuração de bootloader: os parâmetros com "+
				"que este kernel sobe NÃO foram avaliados")
			r.Partial = append(r.Partial, f.PersistDenied["boot"]...)
			return r
		}

		for _, reg := range enfraquecimentos {
			naRodando := temRodando && reg.casa(rodando)
			var fontes []string
			for _, c := range configs {
				if reg.casa(c.Valor) {
					fontes = append(fontes, c.Fonte)
				}
			}
			if !naRodando && len(fontes) == 0 {
				continue
			}

			ev := []string{reg.token() + " — " + reg.Efeito}
			sev := reg.Sev
			switch {
			case naRodando && len(fontes) > 0:
				ev = append(ev, "está valendo AGORA e também na configuração ("+
					firstN(dedupOrdenado(fontes), 2)+"): sobrevive ao próximo boot")
			case naRodando:
				// A configuração precisa ter sido LIDA para que a ausência dela
				// signifique alguma coisa. Sem isso, todo host que boota por
				// -append viraria achado de "subiu diferente do configurado".
				if f.BootConfigLido {
					ev = append(ev, "está valendo AGORA e NÃO está na configuração do "+
						"bootloader: alguém subiu este kernel assim, e um reboot desfaz")
				} else {
					ev = append(ev, "está valendo agora; não havia configuração de "+
						"bootloader legível para comparar")
				}
			case temRodando:
				ev = append(ev, "está na configuração ("+firstN(dedupOrdenado(fontes), 2)+
					") e NÃO na linha que está rodando: ainda não vale, e passa a "+
					"valer no próximo boot")
			default:
				// Sem a linha rodando — modo image — dizer "ainda não vale"
				// afirmaria o que ninguém olhou: o host está desligado, e o que
				// ele tinha em /proc/cmdline não existe mais para ser comparado.
				ev = append(ev, "está na configuração ("+firstN(dedupOrdenado(fontes), 2)+
					"): é o que o próximo boot aplica. Se já estava valendo no host "+
					"vivo, isto aqui não responde")
			}
			if nota := reg.confronto(f); nota != "" {
				ev = append(ev, nota)
			}

			fd := self.F(sev, reg.token(), "", ev...)
			fd.NextSteps = passosDeBoot(reg.token(), fontes)
			r.Findings = append(r.Findings, fd)
		}

		r.Findings = append(r.Findings, achadosDeInit(self, f, temRodando, rodando, configs)...)

		if !temRodando && e.Source != env.SourceImage {
			r.Partial = append(r.Partial, "/proc/cmdline não foi lido: o que está "+
				"valendo NESTE kernel não pôde ser comparado com a configuração")
		}
		// AUSÊNCIA DE BOOTLOADER NÃO É LACUNA — é resposta.
		//
		// Havia aqui um Partial para `!BootConfigLido`, e ele confundia "não há"
		// com "não consegui ver" — a mesma confusão que o cruzarModulos já tinha
		// nomeado do outro lado ("um guest sem módulo carregado tem /proc/modules
		// vazio, e isso é uma resposta completa").
		//
		// O custo foi grande e demorou a aparecer, porque não aparece como
		// achado: contêiner, VM com `-append`, iPXE e kexec NÃO TÊM configuração
		// de bootloader, e nunca vão ter. Marcar isso como cobertura degradada
		// fazia toda varredura nesses ambientes sair INCOMPLETE com exit 1 —
		// inclusive a de um host limpo, que é precisamente o que o
		// proc.container_boundary e o kernel.module_no_file já tinham pago para
		// aprender (ver o comentário em internal/checks/modulo.go).
		//
		// A lacuna de verdade continua declarada, e vem do coletor: ele separa
		// "o arquivo não existe" (segue em frente) de "o arquivo existe e não
		// abriu" (denyPersist). É esse segundo caso que precisa derrubar a
		// cobertura, e é só ele que a linha abaixo propaga.
		r.Partial = append(r.Partial, f.PersistDenied["boot"]...)
		return r
	},
}

// regraDeBoot é um parâmetro que enfraquece, com o que ele faz.
type regraDeBoot struct {
	Chave string
	// Valores que enfraquecem. Vazio significa que a PRESENÇA já enfraquece —
	// `nokaslr` não tem valor, e exigir um faria a regra nunca casar.
	Valores []string
	Sev     check.Severity
	Efeito  string
	// Confronta compara o PEDIDO da linha com o EFEITO que o kernel reporta.
	// É o que separa "alguém pediu" de "e conseguiu".
	Confronta func(f *facts.Facts) string
}

func (r regraDeBoot) token() string {
	if len(r.Valores) == 0 {
		return r.Chave
	}
	return r.Chave + "=" + r.Valores[0]
}

func (r regraDeBoot) casa(linha string) bool {
	if len(r.Valores) == 0 {
		for _, t := range facts.TokensDeBoot(linha) {
			if t.Chave == r.Chave {
				return true
			}
		}
		return false
	}
	v, ok := facts.ValorDeBoot(linha, r.Chave)
	if !ok {
		return false
	}
	for _, aceito := range r.Valores {
		if strings.EqualFold(v, aceito) {
			return true
		}
	}
	return false
}

func (r regraDeBoot) confronto(f *facts.Facts) string {
	if r.Confronta == nil {
		return ""
	}
	return r.Confronta(f)
}

// enfraquecimentos são os parâmetros que desligam alguma coisa. A lista é
// curta de propósito: cada linha aqui precisa ter uma frase que diga ao
// operador o que muda no host, e parâmetro sem essa frase é ruído com nome
// técnico.
var enfraquecimentos = []regraDeBoot{
	{
		Chave: "module.sig_enforce", Valores: []string{"0"}, Sev: check.SevWarn,
		Efeito: "pede que o kernel NÃO exija assinatura em módulo",
		// O kernel mainline registra este parâmetro de um jeito que só o LIGA:
		// escrever 0 não desliga o que a configuração de compilação forçou. Por
		// isso o achado é sobre INTENÇÃO, e o estado que vale é o que o próprio
		// kernel reporta — que a ferramenta já leu.
		Confronta: func(f *facts.Facts) string {
			switch f.Protecao.SigEnforce {
			case "Y":
				return "o kernel, perguntado direto, responde que EXIGE assinatura: o " +
					"parâmetro não teve efeito, e o que ele revela é a intenção de quem o pôs"
			case "N":
				return "e o kernel, perguntado direto, responde que NÃO exige assinatura: " +
					"um .ko sem assinatura carrega neste host"
			}
			return ""
		},
	},
	{
		Chave: "lockdown", Valores: []string{"none"}, Sev: check.SevWarn,
		Efeito: "desliga o lockdown: o root volta a poder ler e escrever a memória do kernel",
		Confronta: func(f *facts.Facts) string {
			if f.Protecao.Lockdown != "" {
				return "o kernel reporta lockdown=" + f.Protecao.Lockdown
			}
			return ""
		},
	},
	{
		Chave: "selinux", Valores: []string{"0"}, Sev: check.SevWarn,
		Efeito:    "desliga o SELinux desde o boot: nada é confinado e nada é negado",
		Confronta: func(f *facts.Facts) string { return confrontoSELinux(f) },
	},
	{
		Chave: "enforcing", Valores: []string{"0"}, Sev: check.SevWarn,
		Efeito:    "põe o SELinux em permissivo desde o boot: ele registra e não impede",
		Confronta: func(f *facts.Facts) string { return confrontoSELinux(f) },
	},
	{
		Chave: "apparmor", Valores: []string{"0"}, Sev: check.SevWarn,
		Efeito: "desliga o AppArmor desde o boot: nenhum perfil confina nada",
	},
	{
		Chave: "security", Valores: []string{"none"}, Sev: check.SevWarn,
		Efeito: "escolhe LSM nenhum: o host sobe sem controle de acesso obrigatório",
	},
	{
		Chave: "audit", Valores: []string{"0"}, Sev: check.SevWarn,
		Efeito: "desliga a auditoria desde o boot: as regras de auditoria não gravam nada, " +
			"e a ausência de registro passa a ser explicada pela configuração",
	},
	{
		Chave: "ima_appraise", Valores: []string{"off", "log", "fix"}, Sev: check.SevWarn,
		Efeito: "tira o IMA de aplicar: a medição de integridade deixa de barrar arquivo alterado",
	},
	{
		Chave: "rd.break", Sev: check.SevWarn,
		Efeito: "abre um shell dentro do initramfs, ANTES de o sistema de arquivos " +
			"raiz assumir: quem tem console tem root sem senha",
	},
	{
		Chave: "systemd.unit", Valores: []string{"rescue.target", "emergency.target"}, Sev: check.SevWarn,
		Efeito: "sobe em modo de recuperação: shell de root sem os serviços normais",
	},
	// Mitigação de CPU e ASLR: INFO. É afinação de desempenho em host normal, e
	// tratá-la como aviso encheria de ruído toda frota de banco de dados e de
	// virtualização — sem apontar para incidente nenhum.
	{
		Chave: "mitigations", Valores: []string{"off"}, Sev: check.SevInfo,
		Efeito: "desliga as mitigações de CPU: escolha comum por desempenho, e " +
			"também o que um vizinho malicioso na mesma máquina precisa",
	},
	{
		Chave: "nokaslr", Sev: check.SevInfo,
		Efeito: "desliga a aleatorização de endereços do kernel: os símbolos ficam " +
			"em endereço previsível, que é o que um exploit de kernel quer",
	},
	{
		Chave: "kaslr", Valores: []string{"off"}, Sev: check.SevInfo,
		Efeito: "desliga a aleatorização de endereços do kernel",
	},
	{
		Chave: "nopti", Sev: check.SevInfo,
		Efeito: "desliga o isolamento de tabela de páginas (Meltdown)",
	},
	{
		Chave: "pti", Valores: []string{"off"}, Sev: check.SevInfo,
		Efeito: "desliga o isolamento de tabela de páginas (Meltdown)",
	},
}

// confrontoSELinux usa o que a ferramenta já sabe sobre MAC. A linha de boot
// diz o que foi PEDIDO; /etc/selinux/config diz o que o administrador quis, e o
// selinuxfs diz o que está valendo.
func confrontoSELinux(f *facts.Facts) string {
	if f.MAC.Configurado == "" && !f.MAC.FSPresente {
		return "este host não tem SELinux configurado: o parâmetro não muda nada aqui"
	}
	if f.MAC.Configurado != "" {
		nota := "e /etc/selinux/config pede " + f.MAC.Configurado
		if f.MAC.Configurado == "enforcing" {
			nota += " — a linha de boot CONTRADIZ a configuração do administrador"
		}
		return nota
	}
	return ""
}

// achadosDeInit trata o parâmetro que não é uma chave a desligar, e sim um
// programa a executar.
//
// É a mesma pergunta do §7.12 — o que o kernel executa como root sem ninguém
// pedir —, com o gatilho mais cedo que existe: aqui não há userland ainda,
// não há unit para achar, não há log para consultar. Por isso o discriminador
// também é o mesmo: de onde veio o arquivo.
func achadosDeInit(self check.Check, f *facts.Facts, temRodando bool,
	rodando string, configs []facts.LinhaDeBoot) []check.Finding {
	semDono := caminhosSemDono(f)
	visto := map[string]bool{}
	var out []check.Finding

	avaliar := func(linha, fonte string, agora bool) {
		for _, chave := range []string{"init", "rdinit"} {
			alvo, ok := facts.ValorDeBoot(linha, chave)
			if !ok || alvo == "" || visto[chave+alvo] {
				continue
			}
			visto[chave+alvo] = true

			sev, nota, acusa := pesoDoInit(alvo, semDono)
			if !acusa {
				continue
			}
			quando := "está na configuração (" + fonte + "): vale no próximo boot"
			if agora {
				quando = "é com isto que este kernel SUBIU"
			}
			fd := self.F(sev, chave+"="+alvo, "",
				chave+"="+alvo+" — o kernel executa este programa como PID 1, antes "+
					"de existir unit, log ou qualquer coisa que registre",
				quando, nota)
			fd.Irreversible = true
			fd.NextSteps = append([]string{
				"guarde o binário antes de mexer: sudo cp " + check.Arg(alvo) + " \"$IR/\"",
			}, passosDeBoot(chave+"=", []string{fonte})...)
			out = append(out, fd)
		}
	}

	if temRodando {
		avaliar(rodando, "/proc/cmdline", true)
	}
	for _, c := range configs {
		avaliar(c.Valor, c.Fonte, false)
	}
	return out
}

// pesoDoInit é a escada do §24, e ela é a mesma do pesoDoHelper por decisão: o
// que separa um init legítimo de um implante não é o mecanismo — é de onde veio
// o programa e em que diretório ele está.
func pesoDoInit(alvo string, semDono map[string]bool) (check.Severity, string, bool) {
	if motivo, gravavel := suspectDir(alvo); gravavel {
		return check.SevCritical, "e o programa está " + motivo +
			": nada se instala ali de propósito, muito menos o PID 1", true
	}
	if semDono[alvo] {
		if dirDePacote(alvo) {
			return check.SevCritical, "e o programa está em diretório do gerenciador " +
				"de pacotes e nenhum pacote o reivindica: tudo ali deveria vir de um pacote", true
		}
		return check.SevWarn, "e nenhum pacote reivindica o programa", true
	}
	if shells[baseDe(alvo)] {
		// Vem de pacote e é um shell. Não é implante — é console de root sem
		// senha, e num host em produção isso é decisão de alguém com acesso
		// físico ou ao console da nuvem.
		return check.SevWarn, "e o programa é um SHELL: quem chegar ao console " +
			"deste host vira root sem senha", true
	}
	return check.SevInfo, "", false
}

func passosDeBoot(token string, fontes []string) []string {
	passos := []string{
		"compare com outro host da frota: o mesmo parâmetro em vários é " +
			"provisionamento, num só é alteração",
	}
	for _, fonte := range dedupOrdenado(fontes) {
		if strings.HasPrefix(fonte, "/proc/") {
			continue
		}
		passos = append(passos, "veja QUANDO a configuração mudou: stat "+check.Arg(fonte))
	}
	passos = append(passos, "o parâmetro só passa a valer no boot: o próximo reboot "+
		"deste host aplica o que estiver na configuração")
	return passos
}
