package facts

import (
	"os"
	"sort"
	"strings"

	"github.com/lex0c/aletheia/internal/env"
)

// Os programas que o KERNEL invoca sozinho (runbook §7.12).
//
// # Por que esta família existe
//
// Toda a §7 pergunta "o que faz este host executar alguma coisa?" — e responde
// olhando unit, cron, perfil de shell, hook de pacote. Todos esses são
// mecanismos de USERLAND: alguém agenda, alguém inicia, alguém faz login.
//
// Existe uma classe que não passa por nenhum deles: caminhos onde o próprio
// kernel guarda o nome de um programa e o executa, como root, por conta
// própria. Não há unit, não há cron, não há processo pai suspeito — há uma
// linha num arquivo de uma linha, e o gatilho é um evento comum do sistema.
//
//	modprobe       o kernel executa isto ao precisar carregar um módulo
//	core_pattern   com "|" na frente, o kernel PIPA o core dump para o programa,
//	               como root — e qualquer processo que morra com SIGSEGV dispara
//	uevent_helper  invocado a cada evento de dispositivo (legado; hoje vazio)
//
// O binfmt_misc é da mesma família, mas tem fatos e checks próprios
// (BinfmtRegistro e binfmt.go): são DUAS perguntas — o kernel roteia execução
// AGORA, e a configuração em disco a recria no boot —, e cada uma merece a sua.
//
// # O que decide o falso positivo
//
// Os três TÊM valor legítimo, e vêm preenchidos de fábrica: num host com
// systemd o core_pattern aponta para o `systemd-coredump`, no Ubuntu para o
// `apport`, e o modprobe é /sbin/modprobe.
//
// O discriminador é o mesmo da §24, e ele resolve os três de uma vez: o
// programa que o kernel invoca deveria vir de um PACOTE. Quando não vem — ou
// quando está em diretório gravável —, é a forma mais silenciosa de persistência
// com execução como root que existe neste sistema.
type HelperDoKernel struct {
	// Nome é o mecanismo: modprobe, core_pattern ou uevent_helper.
	Nome  string `json:"name"`
	Fonte string `json:"source"`
	Valor string `json:"value"`
	// Alvo é o programa extraído do valor, quando o valor aponta para um. Vazio
	// significa que aquele valor NÃO executa nada — o core_pattern sem "|" é um
	// modelo de nome de arquivo, e não um programa.
	Alvo string `json:"target,omitempty"`
	// Padrao diz que o valor é o de fábrica daquele mecanismo.
	Padrao bool `json:"default,omitempty"`
}

// padroesDeUevent é o valor de FÁBRICA dos kernels antigos.
//
// "Vazio é o normal" vale para kernel moderno, e virou um falso positivo contra
// um guest de 3.18: até a série 4.x o CONFIG_UEVENT_HELPER_PATH vinha
// preenchido com /sbin/hotplug, e acusar isso é acusar o estado de fábrica de
// uma máquina de 2014.
//
// O que continua protegido é o caso que importa: se alguém CRIAR um
// /sbin/hotplug, o arquivo passa a existir, a pergunta de propriedade é feita, e
// um binário sem dono num diretório de pacote continua sendo crítico.
var padroesDeUevent = map[string]bool{
	"/sbin/hotplug":     true,
	"/usr/sbin/hotplug": true,
}

// padroesDeModprobe são os caminhos que a distribuição usa. O kernel monta o
// valor a partir do CONFIG_MODPROBE_PATH, e as duas formas abaixo cobrem o que
// as distribuições entregam — o usrmerge move um para o outro.
var padroesDeModprobe = map[string]bool{
	"/sbin/modprobe":     true,
	"/usr/sbin/modprobe": true,
	"/bin/modprobe":      true,
	"/usr/bin/modprobe":  true,
}

func collectHelpers(f *Facts, e *env.Env) {
	if e.Source != env.SourceLive {
		// São todos /proc e /sys: não existem numa imagem montada. A
		// persistência equivalente EM DISCO — um sysctl.d que reescreve o valor
		// no boot — é outra pergunta, e ela não está feita.
		//
		// HelpersLidos fica FALSO aqui, e é isso que separa "este kernel não
		// invoca nada" de "esta fonte não existe neste modo". Sem ele, comparar
		// um retrato vivo com um de imagem lia a lista vazia como helper
		// REMOVIDO — e um core_pattern que some é justamente o que um
		// implante faria depois de usá-lo.
		return
	}
	f.HelpersLidos = true

	// ler declara a lacuna quando o arquivo EXISTE e não pôde ser lido.
	//
	// Os três caminhos abaixo são programas que o KERNEL invoca sozinho, como
	// root, sem passar por unit, cron ou shell — é a superfície do
	// persist.kernel_helper. Um readTrim que devolve ok=false não distinguia
	// "este kernel não tem uevent_helper" de "não pude ler o valor", e o
	// segundo saía como o primeiro: silêncio sobre o caminho que o kernel
	// executa. Ausente é resposta; ilegível é lacuna.
	ler := func(p string) (string, bool) {
		v, err := readTrimErr(p)
		if err != nil {
			if !os.IsNotExist(err) {
				f.partial("helper", p+" existe e não pôde ser lido ("+
					env.MotivoDoErro(err)+"): o programa que o KERNEL invoca por "+
					"este mecanismo NÃO foi examinado")
			}
			return "", false
		}
		return v, true
	}

	// modprobe: o kernel executa este caminho ao autoloadar módulo.
	if v, ok := ler("/proc/sys/kernel/modprobe"); ok && v != "" {
		f.Helpers = append(f.Helpers, HelperDoKernel{
			Nome: "modprobe", Fonte: "/proc/sys/kernel/modprobe",
			Valor: v, Alvo: v, Padrao: padroesDeModprobe[v],
		})
	}

	// core_pattern: com "|" na frente, o kernel PIPA o core para o programa.
	// Sem "|", é um modelo de nome de arquivo e não executa nada.
	if v, ok := ler("/proc/sys/kernel/core_pattern"); ok && v != "" {
		h := HelperDoKernel{
			Nome: "core_pattern", Fonte: "/proc/sys/kernel/core_pattern", Valor: v,
		}
		h.Alvo, h.Padrao = alvoDeCorePattern(v)
		f.Helpers = append(f.Helpers, h)
	}

	// uevent_helper: em sistema moderno é VAZIO — o udev escuta por netlink, e
	// o kernel não precisa executar nada. Valor preenchido é o caso raro.
	if v, ok := ler("/sys/kernel/uevent_helper"); ok {
		if v == "" {
			f.Helpers = append(f.Helpers, HelperDoKernel{
				Nome: "uevent_helper", Fonte: "/sys/kernel/uevent_helper", Padrao: true,
			})
		} else {
			alvo := primeiroCampo(v)
			f.Helpers = append(f.Helpers, HelperDoKernel{
				Nome: "uevent_helper", Fonte: "/sys/kernel/uevent_helper",
				Valor: v, Alvo: alvo, Padrao: padroesDeUevent[alvo],
			})
		}
	}

	collectBinfmt(f) // preenche f.Binfmt (registros vivos)

	sort.Slice(f.Helpers, func(i, j int) bool { return f.Helpers[i].Nome < f.Helpers[j].Nome })
}

// alvoDeCorePattern separa as duas formas do core_pattern, que fazem coisas
// completamente diferentes:
//
//	|/usr/lib/systemd/systemd-coredump …   EXECUTA o programa, como root
//	core.%p                               é modelo de NOME DE ARQUIVO
//
// Tratar as duas igual acusaria todo host que apenas escolheu onde gravar o
// core.
func alvoDeCorePattern(v string) (alvo string, padrao bool) {
	cano, ok := strings.CutPrefix(v, "|")
	if !ok {
		return "", true
	}
	return primeiroCampo(cano), false
}

func primeiroCampo(s string) string {
	fs := strings.Fields(s)
	if len(fs) == 0 {
		return ""
	}
	return fs[0]
}
