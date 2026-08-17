package facts

import (
	"strings"

	"github.com/lex0c/aletheia/internal/env"
)

// Hooks de INTERPRETADOR — o LD_PRELOAD de quem não é ELF.
//
// Esta lacuna veio de um corpus externo, e é por isso que ela vale mais que as
// que eu mesmo teria escolhido. O `atomic-red-team` tem 122 técnicas com teste
// para Linux; 95 não estavam no meu mapa, e a maioria delas é COMPORTAMENTO que
// retrato nenhum vê — rodar `whoami` não deixa artefato. Quinze tocavam caminho
// de persistência, e uma delas apontou para algo que eu deveria ter deduzido
// sozinho:
//
//	esta ferramenta trata LD_PRELOAD como quebra de confiança — com razão,
//	porque o loader injeta biblioteca em TODO processo dinâmico
//
//	e nunca fez a MESMA pergunta a python, node, perl, ruby, java ou bash,
//	que têm exatamente o mesmo mecanismo, com nomes diferentes
//
// Foi um ponto cego de enquadramento: quem escreve o check e quem escreve o
// cenário eram a mesma pessoa, e os dois olhavam para o mesmo lado. Corpus de
// fora é o que enxerga isso.
//
// # O que cada um faz
//
// Todos executam código de terceiro em todo processo daquele interpretador, sem
// tocar em nenhum arquivo do programa alvo:
//
//	BASH_ENV           lido por TODO bash NÃO-INTERATIVO — inclusive o script
//	                   que o cron dispara. É o mais silencioso da lista
//	ENV                o mesmo, para sh POSIX
//	PYTHONSTARTUP      arquivo executado antes de todo REPL
//	PYTHONPATH         precede sys.path: um módulo chamado `os.py` ali VENCE o
//	                   da biblioteca padrão
//	NODE_OPTIONS       aceita `--require`: carrega módulo em todo processo node
//	PERL5OPT           aceita `-M`: idem
//	PERL5LIB           idem PYTHONPATH
//	RUBYOPT            aceita `-r`: idem
//	JAVA_TOOL_OPTIONS  aceita `-javaagent`: carrega agente em toda JVM. É a
//	_JAVA_OPTIONS      forma documentada de instrumentar Java sem tocar no jar
//
// # E os arquivos
//
// `sitecustomize.py` e `usercustomize.py` são importados pelo python na
// inicialização, sem ninguém pedir. A tentação é acusar a presença, e uma
// medição mata a ideia: o Debian ENVIA `/usr/lib/python3.11/sitecustomize.py`,
// entregue pelo `libpython3.11-minimal`. Presença é estado de fábrica.
//
// O que separa é a pergunta de sempre — quem empacotou isto? —, e por isso os
// caminhos entram na lista de candidatos a propriedade em vez de virarem check
// próprio.

// HookInterp é uma variável de ambiente que faz um interpretador carregar
// código de terceiro.
type HookInterp struct {
	// Onde foi definida: caminho de arquivo, nome de unit, ou "pid=N".
	Fonte string `json:"source"`
	Key   string `json:"key"`
	Value string `json:"value,omitempty"`
	// Global marca o que atinge TODO processo do host — /etc/environment e
	// pam_env valem para toda sessão. Uma unit atinge só ela; um environ, só
	// aquele processo.
	Global bool `json:"global,omitempty"`
}

// chavesDeInterpretador são as variáveis que carregam código, com o motivo. A
// lista é curta de propósito: só entra o que EXECUTA, não o que configura.
var chavesDeInterpretador = map[string]string{
	"BASH_ENV":          "todo bash não-interativo lê este arquivo — inclusive o que o cron dispara",
	"ENV":               "todo sh POSIX não-interativo lê este arquivo",
	"PYTHONSTARTUP":     "arquivo executado antes de todo REPL python",
	"PYTHONPATH":        "precede sys.path: um módulo com nome de módulo de sistema vence o original",
	"NODE_OPTIONS":      "aceita --require: carrega módulo em todo processo node",
	"PERL5OPT":          "aceita -M: carrega módulo em todo perl",
	"PERL5LIB":          "precede @INC: um módulo com nome de módulo de sistema vence o original",
	"RUBYOPT":           "aceita -r: carrega biblioteca em todo ruby",
	"JAVA_TOOL_OPTIONS": "aceita -javaagent: carrega agente em toda JVM",
	"_JAVA_OPTIONS":     "aceita -javaagent: carrega agente em toda JVM",
}

// MotivoDoHook devolve por que aquela variável executa código.
func MotivoDoHook(k string) string { return chavesDeInterpretador[k] }

// hooksDeArquivo são os módulos que o python importa sozinho na inicialização.
var hooksDeArquivo = []string{"sitecustomize.py", "usercustomize.py"}

// raizesPython são onde esses módulos moram. A lista é fixa e rasa: varrer o
// filesystem atrás de site-packages custaria mais que todo o resto da coleta.
var raizesPython = []string{
	"/usr/lib", "/usr/local/lib", "/usr/lib64", "/usr/local/lib64",
}

func collectInterpretador(f *Facts, e *env.Env) {
	// 1. Os arquivos lidos a cada sessão, pelas mesmas fontes do LD_PRELOAD.
	for _, p := range []string{"/etc/environment", "/etc/security/pam_env.conf"} {
		b, err := e.ReadFile(p)
		if err != nil {
			continue
		}
		for _, ln := range strings.Split(string(b), "\n") {
			ln = strings.TrimSpace(ln)
			if ln == "" || strings.HasPrefix(ln, "#") {
				continue
			}
			for k := range chavesDeInterpretador {
				if v, ok := envAssign(ln, k); ok {
					f.HooksInterp = append(f.HooksInterp, HookInterp{
						Fonte: p, Key: k, Value: v, Global: true,
					})
				}
			}
		}
	}

	// 2. Environment= de unit. Atinge só os processos daquela unit, e por isso
	// não é global — mas continua sendo execução de código de terceiro num
	// serviço que alguém confia.
	for i := range f.Units {
		for _, s := range f.Units[i].Environment {
			if _, ok := chavesDeInterpretador[s.Key]; ok {
				f.HooksInterp = append(f.HooksInterp, HookInterp{
					Fonte: f.Units[i].Name, Key: s.Key, Value: s.Value,
				})
			}
		}
	}

	// 3. O environ de processo VIVO. É o caso do invasor que já está dentro e
	// não deixou arquivo — a mesma forma do `proc.ld_preload_env`.
	for i := range f.Processes {
		p := &f.Processes[i]
		if p.Self {
			continue
		}
		for k, v := range p.Env {
			if _, ok := chavesDeInterpretador[k]; ok {
				f.HooksInterp = append(f.HooksInterp, HookInterp{
					Fonte: "pid=" + itoa(p.PID), Key: k, Value: v,
				})
			}
		}
	}
}

// hooksDePython devolve os sitecustomize/usercustomize encontrados, para
// entrarem na pergunta de PROPRIEDADE.
//
// Eles não viram achado por existir: o Debian entrega
// /usr/lib/python3.11/sitecustomize.py pelo libpython3.11-minimal, e acusar
// presença acusaria toda instalação de python do mundo. Quem responde é o
// gerenciador de pacotes.
func hooksDePython(e *env.Env) []string {
	var out []string
	for _, raiz := range raizesPython {
		for _, d := range e.ReadDirNames(raiz) {
			if !strings.HasPrefix(d, "python") {
				continue
			}
			// python3.11/ e python3.11/site-packages/ — dois níveis, e para.
			base := raiz + "/" + d
			dirs := []string{base, base + "/site-packages", base + "/dist-packages"}
			for _, dir := range dirs {
				for _, h := range hooksDeArquivo {
					p := dir + "/" + h
					if fi, err := e.Lstat(p); err == nil && !fi.IsDir() {
						out = append(out, p)
					}
				}
			}
		}
	}
	return out
}

// CaminhosDoValor extrai os caminhos absolutos de dentro do valor.
//
// As formas variam por interpretador — PYTHONPATH é lista separada por ":",
// NODE_OPTIONS é linha de flags com "--require /caminho", JAVA_TOOL_OPTIONS tem
// "-javaagent:/caminho". Em vez de um parser por linguagem, pega-se todo token
// que PARECE caminho absoluto: o que se quer saber é para onde aponta, e errar
// para mais só faz perguntar propriedade de algo que existe.
func CaminhosDoValor(v string) []string {
	var out []string
	campos := strings.FieldsFunc(v, func(r rune) bool {
		return r == ' ' || r == ':' || r == '\t' || r == '=' || r == ','
	})
	for _, c := range campos {
		c = strings.Trim(c, `"'`)
		if strings.HasPrefix(c, "/") && len(c) > 1 {
			out = append(out, c)
		}
	}
	return out
}
