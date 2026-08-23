package facts

import (
	"sort"
	"strings"

	"github.com/lex0c/aletheia/internal/env"
)

// hookPointsApt são os caminhos de configuração COMPLETOS que o apt executa como
// shell (via RunScripts). Comparação por caminho inteiro, não por sufixo:
// `Foo::Pre-Invoke` termina em pre-invoke e o apt NÃO o executa — só os subtrees
// abaixo é que são chamados.
var hookPointsApt = map[string]bool{
	"dpkg::pre-invoke":                 true,
	"dpkg::post-invoke":                true,
	"dpkg::pre-install-pkgs":           true,
	"apt::update::pre-invoke":          true,
	"apt::update::post-invoke":         true,
	"apt::update::post-invoke-success": true,
	"apt::update::post-invoke-stats":   true,
}

// ehHookApt diz se um caminho de config é executado pelo apt. RunScripts pega a
// ÁRVORE do hook e executa o valor de cada FILHO, então um item nomeado —
// `DPkg::Pre-Invoke::backdoor "/x"` — é executado igual. A regra é "é o ponto de
// hook, ou está SOB ele", sem voltar ao erro de casar qualquer coisa terminada
// em pre-invoke: `Foo::Pre-Invoke::x` não bate porque não começa com um ponto
// conhecido.
func ehHookApt(caminho string) bool {
	for h := range hookPointsApt {
		if caminho == h || strings.HasPrefix(caminho, h+"::") {
			return true
		}
	}
	return false
}

// analisarAptHooks extrai os hooks ATIVOS de um apt.conf — as diretivas que o
// apt executa como shell —, com o lexer do apt sobre os bytes crus.
//
// # Por que na COLETA, e por que com lexer próprio
//
// O apt tem três formas de comentário — // e # até o fim da linha, e o bloco
// /* … */ que cruza linhas — e resolve o BLOCO antes dos de linha. Isso importa
// contra entrada adversária:
//
//	/*
//	# */ DPkg::Pre-Invoke {"/implant";};
//
// A segunda linha COMEÇA dentro do bloco. O apt acha o */, fecha o bloco, e o
// resto — o hook — fica ATIVO. Mas o parser genérico de gatilho descarta toda
// linha que começa com #, e o hook some da representação inteira. Reconstruir a
// gramática depois é impossível — a informação não está mais lá.
//
// O lexer é ciente de ASPAS (# ou /* dentro de "…" é dado), reconhece a diretiva
// pelo CAMINHO COMPLETO — combinando a pilha de escopos com o nome, então
// `DPkg { Pre-Invoke {…} }` e `DPkg::Pre-Invoke {…}` dão o mesmo `dpkg::pre-invoke`
// — e conta a chave a partir da chave DO HOOK, não do escopo que a envolve.
func analisarAptHooks(raw []byte) []TriggerLine {
	return hooksDeTokens(lexApt(raw))
}

func hooksDeTokens(toks []aptToken) []TriggerLine {
	var escopo []string
	var out []TriggerLine
	for i := 0; i < len(toks); i++ {
		tk := toks[i]
		if tk.str || tk.dir || vazio(tk) {
			continue
		}
		if tk.text == "}" {
			if len(escopo) > 0 {
				escopo = escopo[:len(escopo)-1]
			}
			continue
		}
		if tk.text == "{" || tk.text == ";" {
			continue
		}
		// tk é uma chave de configuração. O que vem a seguir decide: { abre um
		// bloco (escopo ou hook), ou uma string é o valor escalar.
		j := i + 1
		for j < len(toks) && vazio(toks[j]) {
			j++
		}
		caminho := caminhoApt(escopo, tk.text)
		if j < len(toks) && toks[j].text == "{" {
			if ehHookApt(caminho) {
				cmds, ate := comandosDoHook(toks, j)
				out = append(out, cmdsOuPlaceholder(cmds, tk, caminho)...)
				i = ate
			} else {
				// Escopo aninhado: empilha e entra. O } correspondente desempilha.
				escopo = append(escopo, segmentosApt(tk.text)...)
				i = j
			}
			continue
		}
		// Forma escalar: DPkg::Pre-Invoke "cmd";
		if ehHookApt(caminho) {
			cmds, ate := comandosDoHook(toks, i+1)
			out = append(out, cmdsOuPlaceholder(cmds, tk, caminho)...)
			i = ate
		}
	}
	return out
}

func cmdsOuPlaceholder(cmds []TriggerLine, dir aptToken, caminho string) []TriggerLine {
	if len(cmds) > 0 {
		return cmds
	}
	// Hook sem comando literal (variável, include): o poder existe mesmo sem o
	// texto, e não pode sumir.
	return []TriggerLine{{N: dir.line, Text: caminho}}
}

// caminhoApt monta o caminho de config COMPLETO de uma chave, em minúsculas.
func caminhoApt(escopo []string, chave string) string {
	segs := append(append([]string{}, escopo...), segmentosApt(chave)...)
	return strings.ToLower(strings.Join(segs, "::"))
}

// segmentosApt separa uma chave pelos :: e descarta o vazio das pontas.
func segmentosApt(chave string) []string {
	var out []string
	for _, s := range strings.Split(chave, "::") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// comandosDoHook junta as strings do hook que começa em `de` (um { ou a 1ª
// string sem chave), respeitando o escopo: se abre chave, vai até a chave DELE
// fechar. Devolve os comandos e o índice do último token consumido.
func comandosDoHook(toks []aptToken, de int) ([]TriggerLine, int) {
	var cmds []TriggerLine
	i := de
	for i < len(toks) && vazio(toks[i]) {
		i++
	}
	if i >= len(toks) {
		return nil, i
	}
	if toks[i].text == "{" {
		prof := 1
		for i++; i < len(toks) && prof > 0; i++ {
			switch {
			case toks[i].str:
				if txt := strings.TrimSpace(toks[i].text); txt != "" {
					cmds = append(cmds, TriggerLine{N: toks[i].line, Text: txt})
				}
			case toks[i].text == "{":
				prof++
			case toks[i].text == "}":
				prof--
			}
		}
		return cmds, i - 1
	}
	for ; i < len(toks) && toks[i].text != ";"; i++ {
		if toks[i].str {
			if txt := strings.TrimSpace(toks[i].text); txt != "" {
				cmds = append(cmds, TriggerLine{N: toks[i].line, Text: txt})
			}
		}
	}
	return cmds, i
}

func vazio(t aptToken) bool { return !t.str && strings.TrimSpace(t.text) == "" }

// aptToken é um pedaço do apt.conf já sem comentário: uma string, um caractere
// estrutural ({ } ;), ou um trecho de código entre eles.
type aptToken struct {
	str  bool
	dir  bool // diretiva #include / #clear
	text string
	line int
}

// lexApt tokeniza um apt.conf resolvendo comentário e aspas na ordem do parser
// real: bloco /* … */ primeiro, depois // e #, string "…" protege os dois, e {
// } ; saem como tokens próprios para a contagem de escopo ser exata.
func lexApt(raw []byte) []aptToken {
	s := string(raw)
	var toks []aptToken
	var code strings.Builder
	line, codeLine := 1, 1
	flush := func() {
		if code.Len() > 0 {
			toks = append(toks, aptToken{text: code.String(), line: codeLine})
			code.Reset()
		}
	}
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == '\n':
			line++
			if code.Len() > 0 {
				code.WriteByte(' ')
			}
			i++
		case c == '/' && i+1 < len(s) && s[i+1] == '*':
			flush()
			i += 2
			for i < len(s) {
				if s[i] == '\n' {
					line++
				}
				if s[i] == '*' && i+1 < len(s) && s[i+1] == '/' {
					i += 2
					break
				}
				i++
			}
		case c == '#':
			// #include e #clear são DIRETIVAS do apt, não comentário — o cpp do
			// apt as processa. Qualquer outro # é comentário de linha.
			resto := strings.TrimLeft(s[i+1:], " \t")
			low := strings.ToLower(resto)
			if strings.HasPrefix(low, "include") || strings.HasPrefix(low, "clear") {
				flush()
				fim := i
				for fim < len(s) && s[fim] != '\n' {
					fim++
				}
				toks = append(toks, aptToken{dir: true, text: s[i:fim], line: line})
				i = fim
				break
			}
			flush()
			for i < len(s) && s[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(s) && s[i+1] == '/':
			flush()
			for i < len(s) && s[i] != '\n' {
				i++
			}
		case c == '"':
			flush()
			i++
			startLine := line
			var b strings.Builder
			for i < len(s) && s[i] != '"' {
				if s[i] == '\\' && i+1 < len(s) {
					b.WriteByte(s[i+1])
					i += 2
					continue
				}
				if s[i] == '\n' {
					line++
				}
				b.WriteByte(s[i])
				i++
			}
			i++
			toks = append(toks, aptToken{str: true, text: b.String(), line: startLine})
		case c == '{' || c == '}' || c == ';':
			flush()
			toks = append(toks, aptToken{text: string(c), line: line})
			i++
		default:
			if code.Len() == 0 {
				codeLine = line
			}
			code.WriteByte(c)
			i++
		}
	}
	flush()
	return toks
}

// diretivasApt colhe os alvos de #include e #clear de um apt.conf já lexado.
func diretivasApt(toks []aptToken) (includes, clears []string) {
	for _, t := range toks {
		if !t.dir {
			continue
		}
		corpo := strings.TrimLeft(strings.TrimPrefix(strings.TrimSpace(t.text), "#"), " \t")
		low := strings.ToLower(corpo)
		switch {
		case strings.HasPrefix(low, "include"):
			if alvo := alvoDaDiretiva(corpo[len("include"):]); alvo != "" {
				includes = append(includes, alvo)
			}
		case strings.HasPrefix(low, "clear"):
			if alvo := alvoDaDiretiva(corpo[len("clear"):]); alvo != "" {
				clears = append(clears, strings.ToLower(alvo))
			}
		}
	}
	return
}

// alvoDaDiretiva extrai o argumento de um #include/#clear: entre aspas, ou o
// primeiro token até ; ou espaço.
func alvoDaDiretiva(s string) string {
	s = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(s), ";"))
	if i := strings.IndexByte(s, '"'); i >= 0 {
		if j := strings.IndexByte(s[i+1:], '"'); j >= 0 {
			return s[i+1 : i+1+j]
		}
	}
	return strings.TrimSpace(strings.SplitN(s, " ", 2)[0])
}

// maxIncludeApt limita a recursão de #include: config circular ou funda não
// derruba a coleta.
const maxIncludeApt = 8

// resolverAptHooks devolve os hooks EFETIVOS de um apt.conf, resolvendo #include
// (que o apt trata como carregar outro arquivo, não como comentário). Um hook
// escondido num arquivo incluído — o clássico `#include "/opt/.apt-hidden"` —
// deixa de ser falso negativo.
//
// #clear é DECLARADO como limite, não resolvido: ele pode zerar um subtree
// definido por OUTRO fragmento, e resolver isso exigiria mesclar toda a config do
// apt na ordem de carga. Aqui a honestidade é dizer que o estado efetivo pode
// diferir — um hook limpo alhures ainda aparece —, em vez de fingir que resolveu.
func resolverAptHooks(f *Facts, e *env.Env, path string, raw []byte, vistos map[string]bool, prof int) []TriggerLine {
	toks := lexApt(raw)
	hooks := hooksDeTokens(toks)
	includes, clears := diretivasApt(toks)
	if len(clears) > 0 {
		f.partial("apt", path+" usa #clear: um hook removido por este ou por "+
			"outro fragmento pode ainda aparecer como ATIVO — o estado efetivo da "+
			"config do apt não foi resolvido")
	}
	if prof >= maxIncludeApt {
		f.partial("apt", path+" excedeu a profundidade de #include: parte da "+
			"config do apt NÃO foi avaliada")
		return hooks
	}
	for _, inc := range includes {
		alvo := caminhoDeInclude(path, inc)
		// #include de DIRETÓRIO: o apt carrega o diretório inteiro. Lê cada
		// arquivo com nome válido, em ordem estável.
		if strings.HasSuffix(inc, "/") || e.IsDir(alvo) {
			nomes, derr := e.ReadDirNamesErr(alvo)
			if derr != nil {
				f.partial("apt", path+" faz #include do diretório "+alvo+" e ele não "+
					"pôde ser listado: os hooks incluídos NÃO foram avaliados")
				continue
			}
			sort.Strings(nomes)
			for _, n := range nomes {
				hooks = append(hooks, incluirArquivoApt(f, e, strings.TrimRight(alvo, "/")+"/"+n, vistos, prof)...)
			}
			continue
		}
		hooks = append(hooks, incluirArquivoApt(f, e, alvo, vistos, prof)...)
	}
	return hooks
}

// incluirArquivoApt resolve UM arquivo incluído, marcando a ORIGEM em cada hook —
// o comando pode morar num arquivo diferente do que fez o #include, e a evidência
// precisa apontar o certo.
func incluirArquivoApt(f *Facts, e *env.Env, alvo string, vistos map[string]bool, prof int) []TriggerLine {
	if vistos[alvo] {
		return nil
	}
	vistos[alvo] = true
	b, err := e.ReadFile(alvo)
	if err != nil {
		f.partial("apt", "#include de "+alvo+" não pôde ser lido: os hooks "+
			"incluídos NÃO foram avaliados")
		return nil
	}
	hooks := resolverAptHooks(f, e, alvo, b, vistos, prof+1)
	for i := range hooks {
		if hooks[i].File == "" {
			hooks[i].File = alvo
		}
	}
	return hooks
}

// caminhoDeInclude resolve o alvo de um #include: absoluto vale como está;
// relativo é ancorado no diretório do arquivo que inclui.
func caminhoDeInclude(base, inc string) string {
	if strings.HasPrefix(inc, "/") {
		return inc
	}
	return diretorioDe(base) + "/" + inc
}

// diretorioDe é path.Dir sem importar path/filepath para uma linha só.
func diretorioDe(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[:i]
	}
	return "."
}
