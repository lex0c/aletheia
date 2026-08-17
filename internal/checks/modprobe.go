package checks

import (
	"strconv"
	"strings"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

func init() { check.Register(modprobeInstall) }

// modprobeInstall — runbook §7.12.
//
// A diretiva `install` do modprobe é persistência que quase ninguém procura,
// porque o nome engana: ela NÃO carrega módulo. Ela executa um comando.
//
//	install pcspkr /bin/sh -c "/caminho/do/implante; modprobe --ignore-install pcspkr"
//
// A partir dessa linha, qualquer pedido de carga daquele módulo — no boot, ao
// conectar um dispositivo, ao subir uma interface — roda o comando como root. O
// arquivo fica em /etc/modprobe.d entre dezenas de `blacklist` legítimos, e a
// auditoria que procura "o que roda no boot" olha systemd e cron, não isto.
//
// A mesma armadilha vale para `alias`: apontar um alias para um comando faz o
// modprobe executá-lo.
var modprobeInstall = check.Check{
	ID:       "persist.modprobe_install",
	Ref:      "7.12",
	Title:    "diretiva de modprobe que executa comando em vez de carregar módulo",
	Group:    "persist",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Wtf:      true,
	FalsePositives: []string{
		"`install <mod> /bin/true` e `install <mod> /bin/false` são a forma " +
			"idiomática de DESABILITAR um módulo, e aparecem em guia de " +
			"endurecimento de praticamente toda distribuição — são pulados",
		"pacote de driver e de virtualização usa `install` legitimamente para " +
			"encadear carga (`modprobe --ignore-install` seguido de outro " +
			"módulo). O que separa é o comando executar um SHELL ou um caminho " +
			"fora das ferramentas de módulo",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		for i := range f.Modules {
			m := &f.Modules[i]
			if m.Kind == "load" || m.Cmd == "" {
				continue
			}
			// Desabilitar módulo é o uso majoritário e legítimo da diretiva.
			if desabilitaModulo(m.Cmd) {
				continue
			}
			// Encadeamento de carga é o outro uso legítimo: a diretiva chama o
			// próprio modprobe e nada mais.
			if soChamaModprobe(m.Cmd) {
				continue
			}
			// E o arquivo entregue INTACTO por um pacote não é achado. O driver
			// TrueScale da Intel encadeia carga chamando um script em
			// /usr/lib/rdma, vem em /lib/modprobe.d/truescale.conf, e é legítimo
			// — foi o falso positivo do primeiro host real testado.
			//
			// "Intacto" e não só "com dono": editar o arquivo de um pacote
			// mantém a procedência e muda o conteúdo, que é justamente a forma
			// que interessa aqui.
			if entregueIntactoPeloPacote(f, m.File) {
				continue
			}

			sev := check.SevWarn
			ev := []string{
				m.Kind + " " + m.Module + " " + m.Cmd,
				"a diretiva `" + m.Kind + "` NÃO carrega módulo: ela EXECUTA este " +
					"comando, como root, sempre que alguém pedir o módulo " + m.Module,
				"arquivo: " + m.File + ":" + strconv.Itoa(m.Line),
				"o pedido de carga vem do boot, de um dispositivo conectado ou de " +
					"uma interface subindo — não precisa de ninguém logado",
			}
			if motivo, s, ok := execSuspect(m.Cmd); ok {
				sev = s
				ev = append(ev, motivo)
			} else if chamaShell(m.Cmd) {
				sev = check.SevCritical
				ev = append(ev, "e o comando invoca um SHELL: encadeamento de driver "+
					"legítimo chama o modprobe, não o shell")
			}

			fd := self.F(sev, m.Module, "", ev...)
			fd.NextSteps = []string{
				"`modprobe --show-depends " + m.Module + "` mostra o que a diretiva " +
					"faz de verdade, já resolvendo o encadeamento",
				"o ctime do arquivo data a inserção (runbook §9)",
				"a mesma diretiva na frota é provisionamento; num host só, é " +
					"alteração (runbook §23)",
			}
			r.Findings = append(r.Findings, fd)
		}
		r.Partial = append(r.Partial, f.PersistDenied["modprobe"]...)
		return r
	},
}

// desabilitaModulo reconhece a forma idiomática de proibir a carga. É o uso
// majoritário da diretiva, e sem esta exclusão todo guia de endurecimento vira
// dezenas de achados.
func desabilitaModulo(cmd string) bool {
	c := strings.TrimSpace(cmd)
	return c == "/bin/true" || c == "/bin/false" || c == "true" || c == "false" ||
		c == "/usr/bin/true" || c == "/usr/bin/false"
}

// soChamaModprobe reconhece o encadeamento legítimo de carga: a diretiva chama
// o próprio modprobe e nada além disso.
func soChamaModprobe(cmd string) bool {
	for _, tok := range strings.Fields(cmd) {
		if strings.HasPrefix(tok, "-") || tok == "" {
			continue
		}
		b := baseDe(tok)
		if b == "modprobe" || b == "insmod" || b == "true" {
			continue
		}
		// Nome de módulo (argumento do modprobe) não tem barra.
		if !strings.Contains(tok, "/") {
			continue
		}
		return false
	}
	return true
}

func chamaShell(cmd string) bool {
	for _, tok := range strings.Fields(cmd) {
		if shells[baseDe(tok)] {
			return true
		}
	}
	return false
}
