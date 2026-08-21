package facts

import "strings"

// AlvoEfetivoDeExec desembrulha os wrappers que executam OUTRO programa e
// devolve o que de fato roda. Vive em facts (a camada baixa) porque DOIS
// consumidores precisam da MESMA resposta: a pergunta de propriedade (que monta
// os candidatos) e os checks de execução. Antes, o check pedia propriedade do
// alvo desembrulhado enquanto a coleta perguntava só pelo primeiro token — então
// `ExecStart=/usr/bin/env /bin/.backdoor` deixava o /bin/.backdoor fora da
// pergunta de propriedade, e unit_unowned não disparava end-to-end.
//
//	sudo|env|nohup|setsid|doas|exec|stdbuf|tcpd PROG  ->  PROG (pulando flags e VAR=val)
//	env -S "PROG …"                                   ->  PROG (o -S vira linha)
//	sh|bash|… -c "PROG …"                             ->  o primeiro PROG de verdade
//	PROG (sem wrapper)                                ->  PROG
//
// O segundo retorno é INDETERMINADO: a linha executa algo e não deu para provar
// o quê. Existe porque a alternativa é pior — a versão anterior devolvia o
// primeiro token cru do `-c`, e isso produzia alvos que não são programa:
//
//	sh -c 'X=1 /bin/shellserver'         ->  "X=1"
//	sh -c 'exec /bin/shellserver'        ->  "exec"
//	sh -c 'cd /tmp && /bin/shellserver'  ->  "cd"
//
// Um alvo falso não é neutro: o unit_unowned pergunta propriedade DELE, não
// acha nada em diretório de pacote e cala. Binário órfão em /bin escapava por
// um prefixo `exec`, que ainda por cima é idioma legítimo de wrapper.
func AlvoEfetivoDeExec(cmd string) (string, bool) {
	toks := strings.Fields(colapsaBrancoExec(cmd))
	for passo := 0; passo < 8 && len(toks) > 0; passo++ {
		base := baseCaminhoExec(strings.TrimLeft(toks[0], "-@+!:"))
		switch {
		case ehWrapperExec(base):
			comArg := wrapperOpcaoComArgExec[base]
			toks = toks[1:]
			usouDuracao := false
			for len(toks) > 0 {
				t := toks[0]
				if t == "--" { // fim das opções: o próximo token é o programa
					toks = toks[1:]
					break
				}
				// `env -S "cmd args"` NÃO consome o argumento como valor opaco: o
				// -S liga o SPLIT, e o que segue é a própria linha de comando. O
				// programa está DENTRO desse argumento — tratá-lo como valor de
				// opção engolia o payload. Removendo -S do conjunto de arity, o
				// token seguinte (o programa, com a aspa da borda) é processado
				// normalmente e a aspa é descascada na saída.
				if strings.HasPrefix(t, "-") && t != "-" {
					toks = toks[1:]
					if strings.ContainsRune(t, '=') {
						continue // valor anexado
					}
					if comArg[t] && len(toks) > 0 {
						toks = toks[1:] // forma separada: consome o valor
					}
					continue
				}
				if base == "env" && strings.ContainsRune(t, '=') {
					toks = toks[1:] // VAR=val do env
					continue
				}
				if base == "timeout" && !usouDuracao && ehDuracaoExec(t) {
					usouDuracao = true
					toks = toks[1:]
					continue
				}
				break // este é o programa
			}
		case interpretadoresExec[base]:
			for i := 1; i < len(toks); i++ {
				if toks[i] == "-c" && i+1 < len(toks) {
					alvo, indet := alvoDeLinhaDeShell(strings.Join(toks[i+1:], " "))
					if indet {
						return "", true
					}
					if alvo != "" {
						return descascaAspaBorda(alvo), false
					}
					return toks[0], false
				}
			}
			return toks[0], false
		default:
			return descascaAspaBorda(toks[0]), false
		}
	}
	return "", false
}

// alvoDeLinhaDeShell acha o primeiro PROGRAMA de uma linha de `sh -c`.
//
// Não é um shell: é uma peneira conservadora com três regras, e ela prefere
// dizer "não sei" a apontar para o token errado.
//
//	atribuição   VAR=val no começo não é o programa — o shell as consome
//	transparente exec/command/nohup/setsid/time rodam o que vem depois
//	builtin      cd/umask/export não executam arquivo nenhum; o programa, se
//	             houver, está depois do próximo separador
//
// Encontrar um separador não interrompe a busca — `cd /tmp && /bin/x` roda
// /bin/x, e apontar para /tmp seria pior que não apontar. O que interrompe é
// substituição de comando e subshell: ali o alvo depende de execução, e afirmar
// qualquer coisa seria inventar.
func alvoDeLinhaDeShell(linha string) (string, bool) {
	toks := strings.Fields(separaOperadoresDeShell(descascaAspaBorda(strings.TrimSpace(linha))))
	for i := 0; i < len(toks); i++ {
		t := descascaAspaBorda(toks[i])
		switch {
		case t == "":
			continue
		case ehSubstituicaoDeShell(t):
			// $(...), `...`, subshell: o programa é resultado de execução.
			return "", true
		case ehSeparadorDeShell(t):
			continue
		case ehAtribuicaoDeShell(t), transparenteDeShell[t]:
			continue
		case builtinDeShell[t]:
			// Consome até o próximo separador: o argumento do builtin não é
			// programa, e devolvê-lo era o defeito.
			for i+1 < len(toks) && !ehSeparadorDeShell(descascaAspaBorda(toks[i+1])) {
				i++
			}
		default:
			return strings.TrimLeft(t, "-@+!:"), false
		}
	}
	// Só atribuição, prefixo e builtin: a linha não aponta para programa nenhum
	// que este parser consiga nomear.
	return "", true
}

// separaOperadoresDeShell põe espaço em volta de ;, &&, ||, | e &.
//
// O shell não exige espaço, e `umask 077; /bin/x` chega como um token "077;" —
// sem isto o separador passava despercebido e a busca pelo programa depois do
// builtin consumia a linha inteira. Um espaço a mais dentro de aspas no máximo
// leva a "indeterminado", que é o lado seguro de errar.
func separaOperadoresDeShell(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != ';' && c != '|' && c != '&' {
			b.WriteByte(c)
			continue
		}
		b.WriteByte(' ')
		b.WriteByte(c)
		if i+1 < len(s) && s[i+1] == c { // && e ||
			b.WriteByte(c)
			i++
		}
		b.WriteByte(' ')
	}
	return b.String()
}

func ehSeparadorDeShell(t string) bool {
	switch t {
	case ";", "&&", "||", "|", "&", ";;", "\n":
		return true
	}
	return false
}

func ehSubstituicaoDeShell(t string) bool {
	return strings.ContainsAny(t, "`$") || strings.HasPrefix(t, "(") ||
		strings.HasPrefix(t, "{")
}

func ehAtribuicaoDeShell(t string) bool {
	i := strings.IndexByte(t, '=')
	if i <= 0 {
		return false
	}
	for j := 0; j < i; j++ {
		c := t[j]
		if c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(j > 0 && c >= '0' && c <= '9') {
			continue
		}
		return false
	}
	return true
}

// transparenteDeShell roda o que vem DEPOIS: o alvo real está adiante.
var transparenteDeShell = map[string]bool{
	"exec": true, "command": true, "builtin": true, "nohup": true,
	"setsid": true, "time": true,
}

// builtinDeShell não executa arquivo: o argumento dele NÃO é programa.
var builtinDeShell = map[string]bool{
	"cd": true, "umask": true, "ulimit": true, "export": true, "set": true,
	"unset": true, "trap": true, "read": true, "shift": true, "wait": true,
	"echo": true, "printf": true, "true": true, "false": true, ":": true,
	"source": true, ".": true, "eval": true, "sleep": true,
}

// descascaAspaBorda tira a aspa de abertura/fechamento que um argumento de
// `-c`/`-S` carrega quando o comando veio entre aspas.
func descascaAspaBorda(s string) string {
	return strings.Trim(s, "'\"")
}

func ehWrapperExec(base string) bool {
	switch base {
	case "sudo", "env", "nohup", "setsid", "doas", "exec", "stdbuf", "tcpd",
		"ionice", "nice", "timeout":
		return true
	}
	return false
}

// wrapperOpcaoComArgExec: opções em forma SEPARADA que consomem o próximo token.
// `-S`/`--split-string` do env ficam DE FORA de propósito (ver AlvoEfetivoDeExec).
var wrapperOpcaoComArgExec = map[string]map[string]bool{
	"sudo": {"-u": true, "--user": true, "-g": true, "--group": true,
		"-h": true, "--host": true, "-p": true, "--prompt": true,
		"-C": true, "--close-from": true, "-R": true, "--chroot": true,
		"-D": true, "--chdir": true, "-U": true, "--other-user": true,
		"-r": true, "--role": true, "-t": true, "--type": true},
	"doas":    {"-u": true, "-C": true, "-a": true},
	"env":     {"-u": true, "--unset": true, "-C": true, "--chdir": true},
	"exec":    {"-a": true},
	"stdbuf":  {"-i": true, "--input": true, "-o": true, "--output": true, "-e": true, "--error": true},
	"timeout": {"-s": true, "--signal": true, "-k": true, "--kill-after": true},
	"nice":    {"-n": true, "--adjustment": true},
	"ionice":  {"-c": true, "--class": true, "-n": true, "--classdata": true, "-p": true, "--pid": true},
}

var interpretadoresExec = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true,
	"ash": true, "busybox": true, "fish": true,
	"python": true, "python2": true, "python3": true,
	"perl": true, "ruby": true, "php": true, "node": true, "lua": true,
}

func ehDuracaoExec(s string) bool {
	if s == "" {
		return false
	}
	s = strings.TrimRight(s, "smhd")
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if (s[i] < '0' || s[i] > '9') && s[i] != '.' {
			return false
		}
	}
	return true
}

func baseCaminhoExec(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

// primeiroCaminhoExec devolve o PRIMEIRO token (sem os prefixos do systemd) — o
// programa que o shell roda. Não é "o primeiro token com barra": pegar um
// argumento (`cd /x && …`) no lugar do programa geraria alvo errado.
func primeiroCaminhoExec(cmd string) string {
	return strings.TrimLeft(firstTokenExec(cmd), "-@+!:")
}

func firstTokenExec(s string) string {
	if i := strings.IndexAny(strings.TrimSpace(s), " \t"); i > 0 {
		return strings.TrimSpace(s)[:i]
	}
	return strings.TrimSpace(s)
}

// colapsaBrancoExec normaliza espaços e $IFS para uma única forma.
func colapsaBrancoExec(s string) string {
	s = strings.ReplaceAll(s, "$IFS", " ")
	return strings.Join(strings.Fields(s), " ")
}
