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
//	sh|bash|… -c "PROG …"                             ->  o primeiro caminho de PROG
//	PROG (sem wrapper)                                ->  PROG
func AlvoEfetivoDeExec(cmd string) string {
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
					if c := primeiroCaminhoExec(strings.Join(toks[i+1:], " ")); c != "" {
						return descascaAspaBorda(c)
					}
					return toks[0]
				}
			}
			return toks[0]
		default:
			return descascaAspaBorda(toks[0])
		}
	}
	return ""
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
