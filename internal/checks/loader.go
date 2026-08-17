package checks

import (
	"strings"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

func init() {
	check.Register(ldPreloadGlobal)
	check.Register(ldSoConfOdd)
	check.Register(envPreload)
}

// ldPreloadGlobal — runbook §7.8.
//
// O loader carrega o que está aqui ANTES da libc, em TODO processo dinâmico.
// Quem chega primeiro vence a resolução do símbolo: reescrevendo readdir(),
// open() ou accept(), a biblioteca esconde arquivos, processos e conexões do
// ls, do ps e do ss — sem tocar no kernel.
//
// Este check é o único que muda o valor de TODOS os outros. Se ele dispara, o
// userland deste host mente, e achado vindo de binário do host deixa de valer
// como prova (SPEC 7.5) — é por isso que o ID está na lista de trustBreakers
// do motor.
var ldPreloadGlobal = check.Check{
	ID:       "persist.ld_preload_global",
	Ref:      "7.8",
	Title:    "/etc/ld.so.preload existe: biblioteca injetada em todo processo",
	Group:    "persist",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Wtf:      true,
	FalsePositives: []string{
		"o arquivo normalmente NÃO EXISTE. Quando existe legitimamente é por " +
			"instrumentação declarada — libsnoopy, jemalloc via preload, alguns " +
			"agentes de APM. São poucos, e alguém no time sabe o nome",
		"em imagem montada o arquivo pode ser de um chroot de build, não do host",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		l := f.Loader
		if !l.PreloadExists {
			return r
		}

		ev := []string{"/etc/ld.so.preload existe — o normal é NÃO existir"}
		if l.PreloadErr != "" {
			ev = append(ev, "e não pôde ser lido: "+l.PreloadErr+
				" — a existência já é o achado")
		}
		for _, lib := range l.PreloadLibs {
			ev = append(ev, "carrega: "+lib)
		}
		ev = append(ev,
			"toda chamada de biblioteca de todo processo dinâmico passa por essa lib ANTES da libc")

		fd := self.F(check.SevCritical, "/etc/ld.so.preload", "", ev...)
		fd.Irreversible = true
		fd.NextSteps = []string{
			"preserve a lib ANTES de remover a linha: ela é a amostra (runbook §6)",
			"sudo cp /etc/ld.so.preload \"$IR/\" && for l in $(cat /etc/ld.so.preload); do sudo cp \"$l\" \"$IR/\"; done",
			"confira o que ela esconde comparando com binário ESTÁTICO: `ls` contra " +
				"`busybox ls` no mesmo diretório discordam se há rootkit (runbook §7.8)",
			"deste ponto em diante, resultado vindo de binário do host não vale como " +
				"prova — repita a análise sobre a imagem montada (runbook §35.6)",
		}
		r.Findings = append(r.Findings, fd)
		r.Partial = append(r.Partial, f.PersistDenied["loader"]...)
		return r
	},
}

// ldSoConfOdd — runbook §7.8.
//
// A versão persistente do mesmo truque: um diretório de busca de bibliotecas
// onde o atacante consegue escrever. Não injeta nada por si — mas a próxima
// biblioteca resolvida sai de lá.
var ldSoConfOdd = check.Check{
	ID:       "persist.ld_so_conf_odd",
	Ref:      "7.8",
	Title:    "diretório de busca de bibliotecas fora dos caminhos de sistema",
	Group:    "persist",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Wtf:      true,
	FalsePositives: []string{
		"software instalado fora do gerenciador de pacotes acrescenta caminho " +
			"legitimamente — CUDA, Oracle, drivers proprietários e SDKs em /opt " +
			"fazem isso, e o arquivo que declara costuma ter o nome do fornecedor",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		for _, d := range f.Loader.SearchDirs {
			if libSearchOK(d.Dir) {
				continue
			}
			ev := []string{
				"diretório de busca: " + d.Dir,
				"declarado em: " + d.From,
			}
			if !d.Exists {
				// Diretório declarado e inexistente é pior que estranho: quem
				// conseguir criá-lo passa a fornecer biblioteca para o sistema.
				ev = append(ev, "o diretório NÃO existe: quem conseguir criá-lo "+
					"passa a fornecer biblioteca para todo binário do host")
			}
			fd := self.F(check.SevWarn, d.Dir, "", ev...)
			fd.NextSteps = []string{
				"confira quem pode escrever ali: `ls -ld` no diretório e nos pais",
				"se ninguém instalou nada nesse caminho de propósito, trate como " +
					"persistência de userland (runbook §7.8)",
			}
			r.Findings = append(r.Findings, fd)
		}
		r.Partial = append(r.Partial, f.PersistDenied["loader"]...)
		return r
	},
}

// envPreload — runbook §7.8.
//
// /etc/environment e o pam_env são lidos pelo PAM em TODA sessão. Definir
// LD_PRELOAD ali tem o efeito do ld.so.preload, num arquivo que ninguém associa
// a execução de código.
var envPreload = check.Check{
	ID:       "persist.env_preload",
	Ref:      "7.8",
	Title:    "LD_PRELOAD definido em arquivo lido a cada sessão",
	Group:    "persist",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Wtf:      true,
	FalsePositives: []string{
		"LD_LIBRARY_PATH em /etc/environment aparece em host com software " +
			"proprietário instalado à mão — é mau costume comum, não " +
			"necessariamente ataque. LD_PRELOAD e LD_AUDIT ali são bem mais raros",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		for _, v := range f.Loader.EnvVars {
			sev := check.SevWarn
			if v.Key == "LD_PRELOAD" || v.Key == "LD_AUDIT" {
				// Estes CARREGAM código; LD_LIBRARY_PATH só muda onde procurar.
				sev = check.SevCritical
			}
			fd := self.F(sev, v.File, "", []string{
				v.Key + "=" + v.Value,
				"em " + v.File + ", que o PAM lê a cada sessão — inclusive por SSH",
				"efeito equivalente ao /etc/ld.so.preload, num arquivo de configuração comum",
			}...)
			fd.NextSteps = []string{
				"trate a biblioteca apontada como amostra antes de remover a linha (runbook §6)",
				"procure a mesma variável em ~/.bashrc, ~/.profile e drop-in de unit (runbook §7.6, §7.2)",
			}
			r.Findings = append(r.Findings, fd)
		}
		r.Partial = append(r.Partial, f.PersistDenied["loader"]...)
		return r
	},
}

// libSearchOK reconhece os caminhos onde biblioteca legitimamente mora. É
// deliberadamente generoso com /opt e /usr/local: software fora do gerenciador
// de pacotes instala ali por convenção, e reclamar disso seria ruído.
func libSearchOK(dir string) bool {
	dir = strings.TrimSuffix(dir, "/")
	for _, ok := range []string{
		"/lib", "/lib32", "/lib64", "/libx32",
		"/usr/lib", "/usr/lib32", "/usr/lib64", "/usr/libx32",
		"/usr/local/lib", "/usr/local/lib64", "/opt", "/nix/store", "/snap",
	} {
		if dir == ok || strings.HasPrefix(dir, ok+"/") {
			return true
		}
	}
	return false
}
