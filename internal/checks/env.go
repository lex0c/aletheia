package checks

import (
	"sort"
	"strconv"
	"strings"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
	"github.com/lex0c/aletheia/internal/tools"
)

func init() {
	check.Register(procLdPreload)
	check.Register(envToolMarker)
}

// procLdPreload — runbook §7.8.
//
// A versão por processo do /etc/ld.so.preload: a biblioteca é injetada só em
// quem herdou a variável, o que é mais discreto e não deixa arquivo global.
//
// Como o preload global, este check muda o valor de TODOS os outros — o ID está
// na lista de trustBreakers do motor. Um processo com LD_PRELOAD pode estar
// mentindo para toda ferramenta que rode sob ele.
var procLdPreload = check.Check{
	ID:       "proc.ld_preload_env",
	Ref:      "7.8",
	Title:    "LD_PRELOAD no ambiente de um processo em execução",
	Group:    "proc",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive,
	Requires: env.CapProcfs,
	Optional: env.CapRoot,
	Wtf:      true,
	FalsePositives: []string{
		"instrumentação e depuração usam LD_PRELOAD legitimamente: fakeroot, " +
			"jemalloc, libeatmydata, sanitizers e o sandbox do Firefox. Esses " +
			"apontam para lib de pacote ou usam nome relativo, e saem como AVISO",
		"SDK e runtime instalados no home fazem preload de lib própria a partir " +
			"dali — Android SDK e toolchains, por exemplo. Estruturalmente é a " +
			"mesma forma de um implante, e sai como CRÍTICO: em estação de " +
			"desenvolvimento é rotina, em servidor de produção quase nunca",
		"sem root, o environ de processo alheio é ilegível: o achado só se forma " +
			"nos processos do próprio usuário",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		var semEnviron int
		for i := range f.Processes {
			p := &f.Processes[i]
			if p.Self || p.Vanished {
				continue
			}
			// Sem root o environ alheio é ilegível, e "sem LD_PRELOAD" ali é
			// desconhecimento, não ausência.
			if len(p.EnvKeys) == 0 && !p.ExeMissing {
				semEnviron++
				continue
			}
			for _, k := range []string{"LD_PRELOAD", "LD_AUDIT"} {
				v, ok := p.Env[k]
				if !ok || v == "" {
					continue
				}
				// A variável é HERDADA: o processo principal do Firefox e seus
				// nove filhos dariam nove achados idênticos. Reporta a raiz.
				if pai := f.ProcessByPID(p.PPID); pai != nil && !pai.Self &&
					pai.Env[k] == v {
					continue
				}
				sev, porque := preloadSev(v)
				ev := []string{
					k + "=" + v,
					"exe=" + nz(p.Exe, "?") + " comm=" + p.Comm + " " + uidStr(p),
					"a lib é carregada ANTES da libc: ela decide o que este processo enxerga",
					porque,
				}
				if p.PPID > 0 {
					// A variável é HERDADA: quem a definiu costuma ser o pai, e
					// é lá que está o gatilho.
					ev = append(ev, "ppid="+strconv.Itoa(p.PPID)+
						" — a variável é herdada: o gatilho costuma estar no pai (runbook §7.6)")
				}
				if n := descendentesComEnv(f, p.PID, k, v); n > 0 {
					ev = append(ev, strconv.Itoa(n)+" processos descendentes herdaram: "+
						"é este que a definiu")
				}
				fd := self.F(sev, "pid="+strconv.Itoa(p.PID), "", ev...)
				fd.Quando, fd.QuandoFonte = p.StartUTC, "início do processo"
				fd.Irreversible = true
				fd.NextSteps = []string{
					"preserve a lib antes de matar o processo: ela é a amostra (runbook §6)",
					"sudo cp " + check.Arg(v) + " \"$IR/\"",
					"ache quem DEFINIU: environ do pai, ~/.bashrc, /etc/environment, drop-in de unit",
				}
				r.Findings = append(r.Findings, fd)
			}
		}
		if semEnviron > 0 {
			r.Partial = []string{strconv.Itoa(semEnviron) +
				" processos com environ ilegível não foram avaliados"}
		}
		return r
	},
}

// sevDoRisco traduz a leitura do catálogo para a severidade do relatório.
// Alto = não há por que isto estar num servidor; médio = ferramenta legítima
// cuja CAPACIDADE mudou o escopo da investigação.
func sevDoRisco(r tools.Risk) check.Severity {
	if r == tools.RiskAlto {
		return check.SevCritical
	}
	return check.SevWarn
}

// envToolMarker — runbook §5.10 e §3.6.
//
// O check mais barato do catálogo, e o de maior alavanca: ele não prova nada
// sobre o host — prova sobre a FERRAMENTA, e o nome dela rebaixa e promove
// ações inteiras do runbook antes de qualquer engenharia reversa.
var envToolMarker = check.Check{
	ID:       "proc.env_tool_marker",
	Ref:      "5.10",
	Title:    "variável de ambiente que identifica a família da ferramenta",
	Group:    "proc",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive,
	Requires: env.CapProcfs,
	Optional: env.CapRoot,
	Wtf:      true,
	FalsePositives: []string{
		"TODAS as ferramentas da lista são legítimas e de uso duplo. ngrok, " +
			"cloudflared e rclone rodam em produção por bons motivos — o achado " +
			"diz que a CAPACIDADE está presente, não que houve abuso",
		"prefixo curto colide: GS_ pode ser de outra coisa num ambiente próprio. " +
			"O achado aponta ONDE pesquisar, não conclui a família sozinho",
		"a variável é HERDADA: só a RAIZ da herança vira achado, e os descendentes " +
			"viram contagem nela. Um wrapper legítimo que a define contamina toda " +
			"a árvore, e reportar cada processo apontaria para as folhas",
		"sem root o environ alheio é ilegível, e a maioria dos processos não pode " +
			"ser avaliada",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		// vistos conta quantos processos carregam cada família, para a rede de
		// segurança lá embaixo: a supressão por herança NUNCA pode zerar um
		// achado que existe.
		vistos := map[string][]int{}
		reportados := map[string]bool{}

		for i := range f.Processes {
			p := &f.Processes[i]
			if p.Self || p.Vanished || len(p.EnvKeys) == 0 {
				continue
			}
			for _, fam := range tools.All {
				achadas := keysComQualquerPrefixo(p.EnvKeys, fam.Env)
				if len(achadas) == 0 {
					continue
				}
				vistos[fam.Name] = append(vistos[fam.Name], p.PID)
				// A variável é HERDADA: um processo com o marcador contamina
				// toda a sua descendência. Reportar cada um vira parede, e pior,
				// aponta para o lugar errado — o gatilho está na RAIZ da
				// herança, não nas folhas.
				//
				// Só a raiz vira achado; os descendentes viram contagem nela.
				// A PRÓPRIA ferramenta não conta como origem. `sh -c` faz exec
				// no último comando, então a aletheia frequentemente VIRA o pai
				// do que foi plantado na mesma sessão — e como ela herdou a
				// variável, a supressão apagava o achado inteiro. Foi um
				// cenário que pegou isto.
				if pai := f.ProcessByPID(p.PPID); pai != nil && !pai.Self &&
					len(keysComQualquerPrefixo(pai.EnvKeys, fam.Env)) > 0 {
					break
				}
				ev := []string{
					"variáveis de ambiente: " + strings.Join(achadas, " "),
					"assinatura de: " + fam.Name,
					fam.Nota,
					"exe=" + nz(p.Exe, "?") + " comm=" + p.Comm + " " + uidStr(p),
				}
				if n := descendentesComMarcador(f, p.PID, fam.Env); n > 0 {
					ev = append(ev, strconv.Itoa(n)+" processos descendentes herdaram a "+
						"variável — é este aqui que a definiu")
				}
				fd := self.F(sevDoRisco(fam.Risk), "pid="+strconv.Itoa(p.PID), "", ev...)
				fd.Quando, fd.QuandoFonte = p.StartUTC, "início do processo"
				fd.NextSteps = []string{
					"leia a §5.10 com o nome em mãos: ele muda a PRIORIDADE do resto " +
						"da resposta, não só o diagnóstico",
					"capacidade não é prova de uso — o veredito de exfiltração continua " +
						"sendo a §37.7, e pode ser INDETERMINADO",
				}
				r.Findings = append(r.Findings, fd)
				reportados[fam.Name] = true
				break // uma família por processo basta
			}
		}

		// Rede de segurança: se a família foi VISTA e nenhum achado saiu, a
		// supressão por herança comeu o sinal — provavelmente porque a cadeia
		// inteira visível carrega a variável. Silêncio aqui seria o pior
		// resultado possível: a ferramenta enxergou e não disse.
		for _, fam := range tools.All {
			pids := vistos[fam.Name]
			if len(pids) == 0 || reportados[fam.Name] {
				continue
			}
			reportados[fam.Name] = true
			p := f.ProcessByPID(pids[0])
			fd := self.F(sevDoRisco(fam.Risk), "pid="+strconv.Itoa(pids[0]), "", []string{
				"variáveis da família presentes em " + strconv.Itoa(len(pids)) + " processos",
				"assinatura de: " + fam.Name,
				fam.Nota,
				"exe=" + nz(procExe(p), "?"),
				"não foi possível isolar a RAIZ da herança: toda a cadeia visível " +
					"carrega a variável",
			}...)
			r.Findings = append(r.Findings, fd)
		}
		return r
	},
}

// descendentesComMarcador conta quem herdou a variável a partir daquele PID.
// A contagem substitui N achados idênticos por um número no achado certo.
// preloadSev separa injeção de instrumentação pelo LUGAR da biblioteca.
//
// Software legítimo que usa LD_PRELOAD aponta para lib de pacote, em diretório
// de sistema — ou usa nome relativo, resolvido pela busca normal do loader
// (é o que o sandbox do Firefox faz). Implante aponta para onde ele consegue
// ESCREVER: /tmp, /dev/shm, um home.
//
// Errar aqui para CRITICAL enche a tela de desktop; errar para WARN esconde o
// rootkit de userland mais comum. O corte é o mesmo do ld.so.conf.
func preloadSev(valor string) (check.Severity, string) {
	for _, lib := range strings.FieldsFunc(valor, func(r rune) bool {
		return r == ' ' || r == ':'
	}) {
		if !strings.HasPrefix(lib, "/") {
			continue // nome relativo: resolvido pela busca normal de bibliotecas
		}
		dir := lib
		if i := strings.LastIndexByte(lib, '/'); i > 0 {
			dir = lib[:i]
		}
		if !libSearchOK(dir) {
			return check.SevCritical, "a lib está em " + dir +
				", fora dos diretórios de biblioteca: é onde o atacante consegue escrever"
		}
	}
	return check.SevWarn, "a lib está em diretório de biblioteca ou tem nome relativo — " +
		"é a forma que instrumentação legítima usa (sandbox, fakeroot, sanitizer)"
}

// descendentesComEnv conta quem herdou a MESMA definição a partir daquele PID.
func descendentesComEnv(f *facts.Facts, raiz int, k, v string) int {
	filhosDe := map[int][]int{}
	for i := range f.Processes {
		p := &f.Processes[i]
		if p.Env[k] == v {
			filhosDe[p.PPID] = append(filhosDe[p.PPID], p.PID)
		}
	}
	n, fila := 0, []int{raiz}
	visto := map[int]bool{raiz: true}
	for len(fila) > 0 {
		cur := fila[0]
		fila = fila[1:]
		for _, c := range filhosDe[cur] {
			if visto[c] {
				continue
			}
			visto[c] = true
			n++
			fila = append(fila, c)
		}
	}
	return n
}

func procExe(p *facts.Process) string {
	if p == nil {
		return ""
	}
	return p.Exe
}

func descendentesComMarcador(f *facts.Facts, raiz int, prefixos []string) int {
	filhosDe := map[int][]int{}
	for i := range f.Processes {
		p := &f.Processes[i]
		if len(keysComQualquerPrefixo(p.EnvKeys, prefixos)) > 0 {
			filhosDe[p.PPID] = append(filhosDe[p.PPID], p.PID)
		}
	}
	n, fila := 0, []int{raiz}
	visto := map[int]bool{raiz: true}
	for len(fila) > 0 {
		cur := fila[0]
		fila = fila[1:]
		for _, c := range filhosDe[cur] {
			if visto[c] {
				continue // ciclo de ppid não pode virar laço infinito
			}
			visto[c] = true
			n++
			fila = append(fila, c)
		}
	}
	return n
}

func keysComQualquerPrefixo(keys, prefixos []string) []string {
	var out []string
	for _, k := range keys {
		for _, p := range prefixos {
			if strings.HasPrefix(k, p) {
				out = append(out, k)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}
