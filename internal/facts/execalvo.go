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
func AlvosEfetivosDeExec(cmd string) ([]string, bool) {
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
					alvos, indet := alvosDeLinhaDeShell(strings.Join(toks[i+1:], " "))
					// A LACUNA NÃO APAGA O QUE FOI OBSERVADO.
					//
					// Antes, `indet` fazia return ("", true) e jogava fora os
					// alvos já provados. Numa linha como
					// `/usr/bin/legit; eval "$CMD"` isso trocava uma resposta
					// parcial correta — "vi este, e há uma parte que não sei" —
					// por silêncio total sobre o que estava provado.
					for i := range alvos {
						alvos[i] = descascaAspaBorda(alvos[i])
					}
					if len(alvos) == 0 {
						// Só builtin, atribuição e prefixo: a linha não aponta
						// para programa nenhum que este parser consiga nomear.
						// Contrato de sempre — devolver o interpretador aqui
						// mandaria a pergunta de propriedade para /bin/sh, que
						// é ruído com dono de pacote.
						return nil, true
					}
					return alvos, indet
				}
			}
			return []string{toks[0]}, false
		default:
			return []string{descascaAspaBorda(toks[0])}, false
		}
	}
	// Sair do laço é INDETERMINADO, não "alvo provado vazio".
	//
	// Chega-se aqui de dois jeitos: oito wrappers encadeados sem alcançar o
	// programa, ou um wrapper que consumiu todos os tokens restantes
	// (`ExecStart=/usr/bin/sudo -u root`). Nos dois casos a linha EXECUTA
	// alguma coisa e a ferramenta não conseguiu dizer o quê.
	//
	// Era `return "", false`, e o `false` ali é AlvoIndeterminado — ou seja,
	// "alvo provado". A combinação afirmava ter provado que a linha não aponta
	// para lugar nenhum, e isso apagava o binário da pergunta de propriedade nos
	// dois lados: `add("")` cai fora pelo guarda de prefixo "/" em pkg.go, e o
	// ramo `if ex.AlvoIndeterminado` de checks/systemd.go — que existe para
	// declarar exatamente esta lacuna — era pulado. Um
	// `ExecStart=/usr/bin/env … (×8) /usr/lib/systemd/.upd` saía do relatório em
	// silêncio, com cobertura declarada completa.
	return nil, true
}

// AlvoEfetivoDeExec é a fachada de UM alvo, para quem só sabe lidar com um.
//
// Ela é FAIL-CLOSED na cardinalidade, e isso é o conserto: uma linha com mais
// de um programa não tem "o" alvo, e devolver o primeiro era a evasão que
// motivou o plural. `sh -c '/usr/bin/true && /usr/lib/.backdoor'` respondia
// /usr/bin/true com AlvoIndeterminado=false, e o backdoor sumia da pergunta de
// propriedade sem deixar lacuna — sem depender de test, source, eval ou de
// sintaxe complicada nenhuma. Bastava um `&&`.
//
// Quem precisa da resposta inteira chama AlvosEfetivosDeExec.
func AlvoEfetivoDeExec(cmd string) (string, bool) {
	alvos, indet := AlvosEfetivosDeExec(cmd)
	if len(alvos) != 1 {
		return "", true
	}
	return alvos[0], indet
}

// alvosDeLinhaDeShell acha TODOS os programas de uma linha de `sh -c`.
//
// Não é um shell: é uma peneira conservadora, e ela prefere dizer "não sei" a
// apontar para o token errado.
//
// # Por que TODOS, e não "o" programa
//
// A versão anterior devolvia o PRIMEIRO e parava. `ExecLine` tinha um campo
// Target, singular, e o modelo inteiro assumia que uma linha de shell tem um
// alvo. Uma linha de shell não tem: `/usr/bin/true && /usr/lib/.backdoor` tem
// dois, e o segundo desaparecia da pergunta de propriedade com
// AlvoIndeterminado=false — sem depender de test, source, eval ou de sintaxe
// complicada. Bastava um `&&`.
//
// Adicionar mais palavras à peneira não resolveria: o defeito não era a lista,
// era a CARDINALIDADE do fato. Um teste chegava a fixar a evasão, exigindo
// "/bin/cat" para `/bin/cat /etc/x | /tmp/y` — onde /tmp/y também executa.
//
// # E a lacuna não apaga o observado
//
// `indet` deixou de ser um return imediato: uma parte irresolúvel marca a
// linha como incompleta E preserva os alvos já provados. Em
// `/usr/bin/legit; eval "$CMD"` a resposta honesta é "vi /usr/bin/legit, e há
// uma parte que não sei" — não silêncio sobre os dois.
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
func alvosDeLinhaDeShell(linha string) ([]string, bool) {
	toks := camposDeShell(separaOperadoresDeShell(descascaAspaBorda(strings.TrimSpace(linha))))

	var alvos []string
	indet := false
	// pularArgumentos anda até o próximo separador: o que vem depois de um
	// programa (ou de um builtin) são ARGUMENTOS dele, e não outro programa.
	// Só depois de um `;`, `&&`, `||` ou `|` começa um comando novo.
	pularArgumentos := func(i int) int {
		for i+1 < len(toks) && !ehSeparadorDeShell(descascaAspaBorda(toks[i+1])) {
			i++
		}
		return i
	}

	for i := 0; i < len(toks); i++ {
		t := descascaAspaBorda(toks[i])
		switch {
		case t == "":
			continue
		case ehSeparadorDeShell(t):
			continue
		case ehAtribuicaoDeShell(t), transparenteDeShell[t]:
			continue

		case palavraReservadaDeShell[t]:
			// ESTRUTURA DE CONTROLE: a gramática daqui para a frente não é
			// seguível por este parser, então nem o comando atual nem os
			// seguintes podem ser afirmados. Devolve o que JÁ foi provado e
			// marca o resto como desconhecido.
			return alvos, true

		case ehSubstituicaoDeShell(t):
			// $(...), `...`, subshell: o programa é RESULTADO de execução.
			indet = true
			i = pularArgumentos(i)
		case executaCodigoDeShell[t]:
			// eval, source, ., trap: a linha executa código que este parser não
			// segue. O comando é desconhecido, e os outros da linha continuam
			// valendo.
			indet = true
			i = pularArgumentos(i)
		case t == "!" || t == "test" || t == "[" || t == "]":
			// Negação e teste condicional: o programa de verdade está adiante,
			// atrás de um && ou de um ;. O `!` era o pior dos três — o TrimLeft
			// o reduzia a string VAZIA com AlvoIndeterminado=false, e aí o
			// chamador caía no `return toks[0]` e afirmava o próprio
			// INTERPRETADOR (/bin/sh) como alvo provado da unit.
			indet = true
			i = pularArgumentos(i)
		case strings.HasPrefix(t, "-"):
			// OPÇÃO, e não programa. O TrimLeft de "-@+!:" existe para os
			// prefixos de ExecStart do systemd, que só valem no PRIMEIRO token
			// de uma linha de unit — dentro de `sh -c` um traço à frente é
			// opção de comando, e aplicá-lo aqui fabricava alvo a partir de
			// letra: `command -v foo` devolvia "v", `exec -a nome` devolvia
			// "a", os dois marcados como PROVADOS.
			indet = true
			i = pularArgumentos(i)

		case builtinDeShell[t]:
			// Builtin não executa arquivo: o argumento dele NÃO é programa, e
			// devolvê-lo era o defeito original. Não é lacuna — é certeza de
			// que não há alvo NESTE comando.
			i = pularArgumentos(i)

		default:
			if alvo := strings.TrimLeft(t, "@+:"); alvo != "" {
				alvos = append(alvos, alvo)
			} else {
				indet = true
			}
			i = pularArgumentos(i)
		}
	}
	return alvos, indet
}

// separaOperadoresDeShell põe espaço em volta de ;, &&, ||, | e &.
//
// O shell não exige espaço, e `umask 077; /bin/x` chega como um token "077;" —
// sem isto o separador passava despercebido e a busca pelo programa depois do
// builtin consumia a linha inteira. Um espaço a mais dentro de aspas no máximo
// leva a "indeterminado", que é o lado seguro de errar.
func separaOperadoresDeShell(s string) string {
	var b strings.Builder
	// DENTRO DE ASPAS não há operador.
	//
	// O comentário acima apostava que um espaço a mais dentro de aspas "no
	// máximo leva a indeterminado, que é o lado seguro de errar". Medido, não
	// levava: `sh -c 'echo "texto; /bin/nao-roda"'` devolvia
	// alvo=/bin/nao-roda com indeterminado=false. O `;` forjado dentro da
	// string encerrava o consumo do builtin `echo`, e o resto do TEXTO virava
	// um programa afirmado — uma pergunta de propriedade sobre um caminho que
	// nunca executa, e o `echo` real desaparecendo do lugar dele.
	//
	// O rastreamento é o mínimo: aspa simples não interpreta nada até a próxima
	// aspa simples; aspa dupla idem, respeitando a barra invertida.
	var aspa byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case aspa != 0:
			if c == '\\' && aspa == '"' && i+1 < len(s) {
				b.WriteByte(c)
				i++
				b.WriteByte(s[i])
				continue
			}
			if c == aspa {
				aspa = 0
			}
			b.WriteByte(c)
			continue
		case c == '\'' || c == '"':
			aspa = c
			b.WriteByte(c)
			continue
		}
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
//
// `trap`, `source`, `.` e `eval` SAÍRAM daqui — ver executaCodigoDeShell. Eles
// estavam listados como "não executa arquivo", que é falso para os quatro, e a
// consequência era pior que um alvo errado: em
// `sh -c 'source /usr/lib/.backdoor; /bin/true'` o parser consumia o backdoor
// como argumento inofensivo e resolvia `/bin/true` como alvo PROVADO. A linha
// executa o conteúdo do backdoor, e o fato serializado dizia que o alvo efetivo
// era /bin/true.
var builtinDeShell = map[string]bool{
	"cd": true, "umask": true, "ulimit": true, "export": true, "set": true,
	"unset": true, "read": true, "shift": true, "wait": true,
	"echo": true, "printf": true, "true": true, "false": true, ":": true,
	"sleep": true,
}

// executaCodigoDeShell é o conjunto que RESOLVE OU EXECUTA código que este
// parser não consegue seguir. Encontrou um, a linha é indeterminada — e ponto.
//
// A diferença para builtinDeShell é a que decide o achado: um `cd` desvia o
// caminho e o programa continua adiante na linha; um `source` EXECUTA outro
// arquivo, e depois dele o que vier já não é "o alvo efetivo" da unit — é o
// segundo comando de uma linha que já rodou código de outro lugar.
var executaCodigoDeShell = map[string]bool{
	"eval": true, "source": true, ".": true, "trap": true,
	"exec": false, // exec é transparente de verdade: substitui o processo pelo próximo
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

// palavraReservadaDeShell é a gramática de controle que este parser NÃO
// interpreta — e por isso declara indeterminado em vez de apontar um token.
//
// A peneira é conservadora de propósito: cada entrada aqui é uma construção
// cujo programa de verdade está em outro lugar da linha. Nomear o token de
// controle como alvo é a pior das duas respostas possíveis, porque tira o
// binário real da pergunta de propriedade SEM deixar lacuna.
var palavraReservadaDeShell = map[string]bool{
	"if": true, "then": true, "elif": true, "else": true, "fi": true,
	"for": true, "select": true, "while": true, "until": true,
	"do": true, "done": true, "in": true,
	"case": true, "esac": true, "function": true,
	"{": true, "}": true, "[[": true, "]]": true,
	// `time` NÃO entra aqui: ele já está em transparenteDeShell, que é o
	// tratamento certo — a forma reservada mede o comando SEGUINTE, então
	// pular o `time` e resolver o que vem depois é mais informação, não menos.
	// Listá-lo nos dois lugares fazia a peneira desistir de uma linha que ela
	// sabe ler.
	"coproc": true,
}

// camposDeShell separa por branco, mas trata TRECHO ENTRE ASPAS como um token.
//
// O strings.Fields não sabe de aspas, e por isso a proteção do
// separaOperadoresDeShell não bastava sozinha: em
// `echo "a | /bin/nao-roda"` o `|` já vem cercado de espaços DENTRO da string,
// então o Fields o promovia a token próprio sem ninguém ter inserido nada. O
// builtin `echo` parava de consumir naquele separador falso e o resto do TEXTO
// — `/bin/nao-roda"` — caía no default e virava um programa afirmado.
//
// O efeito é uma pergunta de propriedade sobre um caminho que nunca executa, e
// o programa real desaparecendo do lugar dele. Com o trecho citado inteiro num
// token só, o builtin o consome como argumento e a linha responde
// indeterminado — que é a verdade.
//
// Aspa não fechada leva o resto da linha para um token só, e daí para
// indeterminado: o lado seguro de errar.
func camposDeShell(s string) []string {
	var out []string
	var b strings.Builder
	var aspa byte
	empurra := func() {
		if b.Len() > 0 {
			out = append(out, b.String())
			b.Reset()
		}
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case aspa != 0:
			if c == '\\' && aspa == '"' && i+1 < len(s) {
				b.WriteByte(c)
				i++
				b.WriteByte(s[i])
				continue
			}
			if c == aspa {
				aspa = 0
			}
			b.WriteByte(c)
		case c == '\'' || c == '"':
			aspa = c
			b.WriteByte(c)
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			empurra()
		default:
			b.WriteByte(c)
		}
	}
	empurra()
	return out
}
