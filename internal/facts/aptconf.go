package facts

import "strings"

// analisarAptHooks extrai os hooks ATIVOS de um apt.conf — as diretivas que o
// apt executa como shell: Pre-Install-Pkgs, Pre-Invoke e Post-Invoke.
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
// linha que começa com #, e o hook some da representação inteira: nem o check de
// timestomp nem o persist.trigger_exec o veem. É um falso negativo determinístico
// numa superfície que o atacante controla.
//
// Reconstruir a gramática do apt depois que a linha já foi descartada é
// impossível — a informação não está mais lá. Por isso o lexer roda sobre os
// BYTES CRUS, na coleta, e o que ele extrai vira fato semântico que os checks
// leem em vez de reparsear texto.
//
// O lexer é ciente de ASPAS: um # ou /* dentro de "…" é dado, não comentário, e
// uma diretiva só conta quando aparece FORA de aspas. Isso fecha as duas
// divergências que um mini-parser sobre linhas tinha com o lexer real do apt.
func analisarAptHooks(raw []byte) []TriggerLine {
	toks := lexApt(raw)
	var out []TriggerLine
	for i := 0; i < len(toks); i++ {
		if toks[i].str {
			continue // diretiva dentro de aspas é valor, não hook
		}
		low := strings.ToLower(toks[i].text)
		if !strings.Contains(low, "pre-invoke") &&
			!strings.Contains(low, "post-invoke") &&
			!strings.Contains(low, "pre-install-pkgs") {
			continue
		}
		// Fora de comentário e fora de aspas, essas palavras só existem como a
		// diretiva de hook: nome de opção do apt não as contém. A partir daqui
		// junta os comandos (as strings) até o fim do statement.
		cmds := comandosDoHook(toks, i)
		if len(cmds) == 0 {
			// Hook cujo comando não é string literal (variável, include): o poder
			// existe mesmo sem o texto, e não pode sumir.
			out = append(out, TriggerLine{N: toks[i].line, Text: strings.TrimSpace(toks[i].text)})
			continue
		}
		out = append(out, cmds...)
	}
	return out
}

// comandosDoHook junta as strings que seguem a diretiva no token `de`, até o
// fim do statement: fecha a chave que abriu, ou o ; quando não há chave.
func comandosDoHook(toks []aptToken, de int) []TriggerLine {
	var cmds []TriggerLine
	prof := strings.Count(toks[de].text, "{") - strings.Count(toks[de].text, "}")
	temChave := prof > 0
	for j := de + 1; j < len(toks); j++ {
		if toks[j].str {
			if txt := strings.TrimSpace(toks[j].text); txt != "" {
				cmds = append(cmds, TriggerLine{N: toks[j].line, Text: txt})
			}
			if !temChave {
				break // forma sem chave: um valor e o statement acaba
			}
			continue
		}
		if strings.Contains(toks[j].text, "{") {
			temChave = true
		}
		prof += strings.Count(toks[j].text, "{") - strings.Count(toks[j].text, "}")
		if temChave && prof <= 0 {
			break
		}
		if !temChave && strings.Contains(toks[j].text, ";") {
			break
		}
	}
	return cmds
}

// aptToken é um pedaço do apt.conf já sem comentário: código ou uma string.
type aptToken struct {
	str  bool
	text string
	line int
}

// lexApt tokeniza um apt.conf resolvendo comentário e aspas na ordem do parser
// real: bloco /* … */ primeiro, depois // e #, e string "…" protege o conteúdo
// dos dois.
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
