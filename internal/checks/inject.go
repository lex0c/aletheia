package checks

import (
	"strconv"
	"strings"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

func init() {
	check.Register(mapsRWXAnon)
	check.Register(nsDivergent)
}

// mapsRWXAnon — runbook §3.10.
//
// Região gravável E executável, sem arquivo nenhum por trás: código que nunca
// existiu em disco. É o que o malfind do Volatility procura, e o que
// `MemoryDenyWriteExecute=yes` torna impossível (runbook §34.1).
//
// O que o check NÃO faz é disparar em rwx com arquivo por trás, nem em runtime
// com JIT. Java, Node e .NET geram código em memória o tempo todo — é a
// operação normal deles, e reportá-los transformaria o check em ruído de fundo
// em metade dos hosts.
var mapsRWXAnon = check.Check{
	ID:       "proc.maps_rwx_anon",
	Ref:      "3.10",
	Title:    "região de memória gravável, executável e sem arquivo por trás",
	Group:    "proc",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive,
	Requires: env.CapProcfs,
	Optional: env.CapRoot,
	Wtf:      true,
	FalsePositives: []string{
		"runtime com JIT (Java, Node, .NET, navegador, QEMU) usa rwx anônimo por " +
			"projeto — os conhecidos, rodando de diretório de sistema, são pulados",
		"empacotador (UPX e afins) descomprime para memória rwx: binário legítimo " +
			"empacotado cai aqui",
		"BLIND SPOT do descarte acima: código injetado DENTRO de uma JVM ou de um " +
			"processo Node não é visto por este check. Para esses, o sinal é o " +
			"proc.tracer e a §29 (dump de memória)",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		var denied int
		for i := range f.Processes {
			p := &f.Processes[i]
			if p.Self || p.Vanished {
				continue
			}
			if p.MapsDenied {
				denied++
				continue
			}
			var anon []string
			for _, m := range p.MapsRWX {
				if strings.Contains(m, "(anônimo)") {
					anon = append(anon, m)
				}
			}
			if len(anon) == 0 || isJITRuntime(p) {
				continue
			}

			ev := []string{
				strconv.Itoa(len(anon)) + " região(ões) rwx sem arquivo: " + firstN(anon, 3),
				"exe=" + nz(p.Exe, "?") + " comm=" + p.Comm + " uid=" + strconv.Itoa(p.UID),
			}
			if len(p.MapsOdd) > 0 {
				// Biblioteca carregada de fora dos diretórios de sistema junto
				// com memória rwx é a forma de LD_PRELOAD (runbook §7.8).
				ev = append(ev, "e mapeia biblioteca fora dos diretórios de sistema: "+
					firstN(p.MapsOdd, 3))
			}
			for _, t := range p.Truncated {
				ev = append(ev, "atenção: "+t)
			}

			fd := self.F(check.SevWarn, "pid="+strconv.Itoa(p.PID), "", ev...)
			fd.Irreversible = true
			fd.NextSteps = []string{
				"o código só existe na memória deste processo: matá-lo destrói a " +
					"única cópia (runbook §29)",
				"sudo gcore -o \"$IR/pid-" + strconv.Itoa(p.PID) + ".core\" " + strconv.Itoa(p.PID),
				"o binário em disco não explica o que está rodando — compare com " +
					"a §24 antes de concluir que o pacote está íntegro",
			}
			r.Findings = append(r.Findings, fd)
		}
		if denied > 0 {
			r.Partial = []string{strconv.Itoa(denied) +
				" processos com /proc/<pid>/maps ilegível não foram avaliados"}
		}
		return r
	},
}

// nsDivergent — runbook §3.15.
//
// Namespace próprio sem container é `unshare` na mão. Explica dois
// "impossíveis" sem precisar de rootkit: o arquivo que o cwd aponta e o `ls`
// não acha, e a conexão que o tcpdump vê e o `ss` não lista.
//
// A dificuldade aqui é o oposto da dos outros checks: divergência de namespace
// é COMUM em host moderno. Toda unit com PrivateTmp=yes tem mount namespace
// próprio. Por isso o critério não é "divergiu", é "divergiu em lugar onde
// ninguém configurou isso".
var nsDivergent = check.Check{
	ID:       "proc.ns_divergent",
	Ref:      "3.15",
	Title:    "namespace próprio fora de container e fora de unit",
	Group:    "proc",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive,
	Requires: env.CapProcfs,
	Optional: env.CapRoot,
	Wtf:      true,
	FalsePositives: []string{
		"navegador, Flatpak, Snap e Podman rootless criam namespace de usuário para " +
			"sandbox — em estação de trabalho isto é constante; em servidor, não",
		"BLIND SPOT deliberado: processo sob uma unit de systemd é pulado por " +
			"inteiro. PrivateTmp=, PrivateNetwork= e PrivateUsers= criam mount, " +
			"rede e usuário próprios legitimamente — num desktop, udevd, polkit, " +
			"upower e accounts-daemon já somam dezenas. Quem comprometeu uma unit " +
			"não aparece aqui; aparece nos outros checks",
		"sem root, /proc/<pid>/ns/* de processo alheio é ilegível e não há o que comparar",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result

		// Sem a linha de base não existe divergência a medir. Dizer "nenhum
		// namespace divergente" sem ter lido o do PID 1 seria inventar.
		init1 := f.ProcessByPID(1)
		if init1 == nil || len(init1.NS) == 0 {
			r.Partial = []string{"os namespaces do PID 1 não puderam ser lidos: sem " +
				"linha de base, divergência nenhuma pôde ser avaliada"}
			return r
		}

		var denied int
		for i := range f.Processes {
			p := &f.Processes[i]
			if p.Self || p.Vanished || p.PID == 1 {
				continue
			}
			if p.NSDenied || len(p.NS) == 0 {
				denied++
				continue
			}
			// Container e unit ficam de fora: nos dois, namespace próprio é
			// configuração, não anomalia. Sobra o caso da §3.15 — namespace
			// criado por quem não tinha por que criar, tipicamente `unshare`
			// a partir de uma sessão.
			if isContainerCgroup(p.Cgroup) || isUnitCgroup(p.Cgroup) {
				continue
			}

			var diff []string
			for _, kind := range []string{"mnt", "net", "pid", "user"} {
				mine, base := p.NS[kind], init1.NS[kind]
				if mine == "" || base == "" || mine == base {
					continue
				}
				diff = append(diff, kind+"="+mine+" (PID 1: "+base+")")
			}
			if len(diff) == 0 {
				continue
			}

			ev := []string{
				"namespace próprio: " + strings.Join(diff, " · "),
				"exe=" + nz(p.Exe, "?") + " comm=" + p.Comm + " uid=" + strconv.Itoa(p.UID),
				"cgroup=" + nz(p.Cgroup, "(nenhum)") + " — não é container nem unit de systemd",
			}
			if p.Cwd != "" {
				ev = append(ev, "cwd="+p.Cwd+" — este caminho é resolvido no namespace DELE, não no seu")
			}

			fd := self.F(check.SevWarn, "pid="+strconv.Itoa(p.PID), "", ev...)
			fd.NextSteps = []string{
				"olhe de DENTRO: sudo nsenter -t " + strconv.Itoa(p.PID) + " -a ls -la /",
				"o `find` da §8 e o `ss` da §2 não enxergam o que está aqui — descarte " +
					"isto antes de concluir rootkit (runbook §35)",
			}
			r.Findings = append(r.Findings, fd)
		}
		if denied > 0 {
			r.Partial = append(r.Partial, strconv.Itoa(denied)+
				" processos com /proc/<pid>/ns/* ilegível não foram avaliados")
		}
		return r
	},
}

// jitRuntimes gera código em memória por projeto. A isenção só vale para o
// binário RODANDO DE DIRETÓRIO DE SISTEMA: um "node" em /tmp não herda a
// reputação do node.
var jitRuntimes = map[string]bool{
	"java": true, "node": true, "deno": true, "bun": true,
	"dotnet": true, "mono": true, "mono-sgen": true,
	"chrome": true, "chromium": true, "chromium-browser": true,
	"firefox": true, "thunderbird": true, "electron": true,
	"wine": true, "wineserver": true, "wine-preloader": true,
	"luajit": true, "julia": true, "php": true, "php-fpm": true,
	"beam.smp": true, "erl": true, "qemu-system-x86_64": true,
}

var systemDirs = []string{"/usr/", "/opt/", "/snap/", "/nix/store/", "/var/lib/flatpak/", "/app/"}

func isJITRuntime(p *facts.Process) bool {
	if p.Exe == "" {
		return false
	}
	inSystem := false
	for _, d := range systemDirs {
		if strings.HasPrefix(p.Exe, d) {
			inSystem = true
			break
		}
	}
	if !inSystem {
		return false
	}
	return jitRuntimes[p.Exe[strings.LastIndexByte(p.Exe, '/')+1:]]
}

// containerMarkers são os caminhos de cgroup que os runtimes escrevem. Um
// processo dentro de container tem namespace próprio por definição, e não é
// disso que a §3.15 fala.
var containerMarkers = []string{
	"docker", "containerd", "crio", "cri-o", "libpod", "kubepods",
	"lxc", "machine.slice", "garden", "podman",
}

func isContainerCgroup(cg string) bool {
	for _, m := range containerMarkers {
		if strings.Contains(cg, m) {
			return true
		}
	}
	return false
}

// isUnitCgroup diz se o processo roda sob uma unit de systemd — onde as opções
// de isolamento explicam qualquer divergência de namespace.
//
// Contains e não HasSuffix: o cgroup de um serviço com subgrupo é
// `/system.slice/systemd-udevd.service/udev`, e testar o sufixo deixava passar
// 25 processos de uma vez.
func isUnitCgroup(cg string) bool {
	return strings.Contains(cg, ".service")
}

func firstN(ss []string, n int) string {
	if len(ss) <= n {
		return strings.Join(ss, " · ")
	}
	return strings.Join(ss[:n], " · ") + " · … (+" + strconv.Itoa(len(ss)-n) + ")"
}
