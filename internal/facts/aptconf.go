package facts

import "strings"

// hooksApt são os pontos de configuração que o apt EXECUTA como shell — o último
// segmento `::` de uma diretiva de hook. Comparação por segmento COMPLETO, não
// por substring: `Foo::Pre-Invoke-Disabled` contém "pre-invoke" e não roda nada.
var hooksApt = map[string]bool{
	"pre-invoke":          true,
	"post-invoke":         true,
	"post-invoke-success": true,
	"pre-install-pkgs":    true,
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
// linha que começa com #, e o hook some da representação inteira: nem o timestomp
// nem o persist.trigger_exec o veem. É um falso negativo determinístico numa
// superfície que o atacante controla, e reconstruir a gramática depois é
// impossível — a informação não está mais lá.
//
// O lexer é ciente de ASPAS (# ou /* dentro de "…" é dado), reconhece a diretiva
// pelo SEGMENTO completo (não por substring) e conta a chave a partir da chave DO
// HOOK, não do escopo que a envolve — então `DPkg { Pre-Invoke{…}; Post-Invoke{…}; }`
// separa os dois comandos sem um consumir o outro.
func analisarAptHooks(raw []byte) []TriggerLine {
	toks := lexApt(raw)
	var out []TriggerLine
	for i := 0; i < len(toks); i++ {
		if !ehDiretivaDeHook(toks[i]) {
			continue
		}
		cmds, ate := comandosDoHook(toks, i+1)
		if len(cmds) == 0 {
			// Hook cujo comando não é string literal (variável, include): o poder
			// existe mesmo sem o texto, e não pode sumir.
			out = append(out, TriggerLine{N: toks[i].line,
				Text: strings.TrimSpace(toks[i].text)})
		} else {
			out = append(out, cmds...)
		}
		if ate > i {
			i = ate
		}
	}
	return out
}

// ehDiretivaDeHook diz se o token é a diretiva de um hook — o último segmento
// `::` do nome bate EXATAMENTE com um ponto que o apt executa.
func ehDiretivaDeHook(t aptToken) bool {
	if t.str || estrutural(t.text) {
		return false
	}
	seg := t.text
	if i := strings.LastIndex(seg, "::"); i >= 0 {
		seg = seg[i+2:]
	}
	return hooksApt[strings.ToLower(strings.TrimSpace(seg))]
}

// comandosDoHook junta as strings do hook que começa DEPOIS de `de`, respeitando
// o escopo: se abre chave, vai até a chave DELE fechar; se não, até o ;.
// Devolve os comandos e o índice do último token consumido.
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
	// Forma sem chave: DPkg::Pre-Invoke "cmd"; — a string até o ;.
	for ; i < len(toks) && toks[i].text != ";"; i++ {
		if toks[i].str {
			if txt := strings.TrimSpace(toks[i].text); txt != "" {
				cmds = append(cmds, TriggerLine{N: toks[i].line, Text: txt})
			}
		}
	}
	return cmds, i
}

func estrutural(s string) bool { return s == "{" || s == "}" || s == ";" }
func vazio(t aptToken) bool    { return !t.str && strings.TrimSpace(t.text) == "" }

// aptToken é um pedaço do apt.conf já sem comentário: uma string, um caractere
// estrutural ({ } ;), ou um trecho de código entre eles.
type aptToken struct {
	str  bool
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
			toks = append(toks, aptToken{false, code.String(), codeLine})
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
		case (c == '/' && i+1 < len(s) && s[i+1] == '/') || c == '#':
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
			i++ // aspa de fechamento (ou fim: idempotente)
			toks = append(toks, aptToken{true, b.String(), startLine})
		case c == '{' || c == '}' || c == ';':
			flush()
			toks = append(toks, aptToken{false, string(c), line})
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
